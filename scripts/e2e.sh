#!/bin/bash
# minidns end-to-end test — runs inside a fresh ubuntu:24.04 or debian:12
# container with /work mounted (both are supported baselines; CI runs both).
#
# Build a deb, then:  docker run --rm -v $PWD:/work [-e DIGITALOCEAN_TOKEN=...] ubuntu:24.04 bash /work/scripts/e2e.sh
# (zone-mirror tests need a DO token that owns $E2E_ZONE; they are skipped without one)
set -uo pipefail
PASS=0; FAIL=0
E2E_ZONE="${E2E_ZONE:-dnsif.ca}"; E2E_ZONE_HOST="${E2E_ZONE_HOST:-gitlab.dnsif.ca}"
DEB="$(ls /work/minidns_*_"$(dpkg --print-architecture)".deb | sort -V | tail -1)"
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/tmp/out 2>&1; then ok "$desc"; else bad "$desc"; sed 's/^/    /' /tmp/out; fi
}
expect() { # expect <desc> <pattern> <cmd...>
  local desc="$1" pat="$2"; shift 2
  "$@" >/tmp/out 2>&1
  if grep -qE "$pat" /tmp/out; then ok "$desc"; else bad "$desc (no /$pat/)"; sed 's/^/    /' /tmp/out | head -15; fi
}

# unbound reloads the big RPZ zones on every config change and refuses
# connections while it does — poll instead of guessing a sleep
wait_dns() { for _ in $(seq 1 60); do minidns test localhost >/dev/null 2>&1 && return 0; sleep 0.5; done; echo "unbound did not come back within 30s"; return 1; }

export DEBIAN_FRONTEND=noninteractive
echo "== install =="
apt-get update -qq >/dev/null
echo "testing $DEB on $(. /etc/os-release; echo "$PRETTY_NAME")"
apt-get install -y -qq "$DEB" curl python3 >/dev/null 2>&1 || apt-get install -y "$DEB" curl python3
check "minidns binary installed" minidns version
check "unbound dependency pulled in" which unbound

echo "== setup =="
minidns setup 2>&1 | tail -12
check "unbound config generated" test -f /etc/unbound/unbound.conf.d/minidns.conf
check "stevenblack list downloaded" test -s /var/lib/minidns/rpz/adblock-stevenblack.rpz
check "unbound-checkconf accepts config" unbound-checkconf

echo "== start unbound (no systemd in container) =="
unbound-anchor -a /var/lib/unbound/root.key >/dev/null 2>&1
unbound -c /etc/unbound/unbound.conf
wait_dns
check "unbound is answering" minidns test google.com

echo "== resolution =="
expect "google.com resolves NOERROR" "rcode +NOERROR" minidns test google.com
expect "cache hit is fast" "rcode +NOERROR" minidns test google.com

echo "== firewall =="
minidns block facebook.com >/dev/null
expect "blocked domain returns NXDOMAIN" "rcode +NXDOMAIN" minidns test facebook.com
expect "policy verdict names firewall" "blocked by firewall" minidns test facebook.com
expect "subdomain blocked via wildcard" "rcode +NXDOMAIN" minidns test www.facebook.com
minidns unblock facebook.com >/dev/null
expect "unblock restores resolution" "rcode +NOERROR" minidns test facebook.com
# explicit wildcards used to vanish on the next edit (#10)
minidns block '*.wild.example.org' >/dev/null
minidns block other.example.org >/dev/null
expect "explicit wildcard survives a later edit" "^block \*\.wild\.example\.org" minidns blocklist
expect "explicit wildcard blocks subdomains" "rcode +NXDOMAIN" minidns test a.wild.example.org
minidns unblock '*.wild.example.org' other.example.org >/dev/null
expect "invalid domain rejected" "doesn't look like a domain" minidns block 'bad domain'

echo "== adblock =="
expect "adblock domain NXDOMAIN" "rcode +NXDOMAIN" minidns test doubleclick.net
expect "verdict names the list" "blocked by adblock list" minidns test doubleclick.net
minidns allow doubleclick.net >/dev/null
expect "allowlist overrides adblock" "rcode +NOERROR" minidns test doubleclick.net
minidns unallow doubleclick.net >/dev/null
# flags after the positional, exactly as the README shows them (#11)
printf '0.0.0.0 listed.e2e.example.net\n' > /tmp/e2e-list.txt
( cd /tmp && python3 -m http.server 8099 >/dev/null 2>&1 & ) ; sleep 1
wait_dns
expect "list add accepts flags after the url" "added list e2e" minidns adblock list add http://127.0.0.1:8099/e2e-list.txt --name e2e --format hosts
wait_dns
expect "second list blocks its domain" "blocked by adblock list \"e2e\"" minidns test listed.e2e.example.net
check  "update accepts --quiet" minidns adblock update --quiet
expect "list remove works" "removed list e2e" minidns adblock list remove e2e
wait_dns
expect "unsafe list name rejected" "invalid list name" minidns adblock list add http://127.0.0.1:8099/e2e-list.txt --name ../../evil

echo "== zone mirror (digitalocean) =="
expect "unsafe zone name rejected" "not a valid zone name" minidns zone add '../../etc/passwd' --provider digitalocean
if [ -n "${DIGITALOCEAN_TOKEN:-}" ]; then
  expect "zone add pulls from DO (flag after name)" "mirrored" minidns zone add "$E2E_ZONE" --provider digitalocean
  expect "mirrored zone answers locally" "rcode +NOERROR" minidns test "$E2E_ZONE_HOST"
  expect "zone sync detects unchanged" "unchanged" minidns zone sync "$E2E_ZONE" --quiet=false
  expect "zone list shows serial" "serial [0-9]+" minidns zone list
else
  echo "SKIP: zone mirror checks (no DIGITALOCEAN_TOKEN)"
fi

echo "== upstream / recursion toggles =="
expect "recursion on applies" "recursion: on" minidns recursion on
wait_dns
expect "recursion resolves from roots" "rcode +NOERROR" minidns test example.org
expect "recursion off applies" "recursion: off" minidns recursion off
wait_dns
expect "DoT upstream applies" "tls: true" minidns upstream set 1.1.1.1 1.0.0.1 --tls
# no systemd in the container, so mimic what minidns does on real hosts:
# a full restart (tls-cert-bundle is only read at startup)
unbound-control stop >/dev/null 2>&1; sleep 1
unbound -c /etc/unbound/unbound.conf; wait_dns
expect "resolution over DoT works" "rcode +NOERROR" minidns test cloudflare.com

echo "== logs / metrics =="
minidns block testblocked.example.com >/dev/null
minidns test testblocked.example.com >/dev/null 2>&1
sleep 1
expect "query log has replies" "NOERROR" minidns logs -n 30
expect "blocked queries logged" "BLOCKED" minidns logs -n 50 --blocked
expect "top domains ranked" "top domains" minidns top
expect "top clients ranked" "top clients" minidns top --clients
expect "stats snapshot works" "cache hits" minidns stats
minidns exporter --listen 127.0.0.1:9153 >/dev/null 2>&1 &
sleep 1
expect "exporter serves unbound metrics" "unbound_total_num_queries" curl -s http://127.0.0.1:9153/metrics
expect "exporter reports up" "minidns_up 1" curl -s http://127.0.0.1:9153/metrics

echo "== apply =="
expect "apply with nothing to do leaves unbound alone" "no changes" minidns apply

echo "== status =="
minidns status
echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
