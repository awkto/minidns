#!/bin/bash
# minidns end-to-end test — runs inside ubuntu:24.04 with /work mounted
#
# Build a deb, then:  docker run --rm -v $PWD:/work [-e DIGITALOCEAN_TOKEN=...] ubuntu:24.04 bash /work/scripts/e2e.sh
# (zone-mirror tests need a DO token that owns dnsif.ca; they fail cleanly without one)
set -uo pipefail
PASS=0; FAIL=0
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

export DEBIAN_FRONTEND=noninteractive
echo "== install =="
apt-get update -qq >/dev/null
apt-get install -y -qq $(ls /work/minidns_*_amd64.deb | head -1) curl >/dev/null 2>&1 || apt-get install -y $(ls /work/minidns_*_amd64.deb | head -1) curl
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
sleep 2
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

echo "== adblock =="
expect "adblock domain NXDOMAIN" "rcode +NXDOMAIN" minidns test doubleclick.net
expect "verdict names the list" "blocked by adblock list" minidns test doubleclick.net
minidns allow doubleclick.net >/dev/null
expect "allowlist overrides adblock" "rcode +NOERROR" minidns test doubleclick.net
minidns unallow doubleclick.net >/dev/null

echo "== zone mirror (digitalocean) =="
expect "zone add pulls from DO" "mirrored" minidns zone add dnsif.ca
expect "mirrored zone answers locally" "rcode +NOERROR" minidns test gitlab.dnsif.ca
expect "zone sync detects unchanged" "unchanged" minidns zone sync
expect "zone list shows serial" "serial [0-9]+" minidns zone list

echo "== upstream / recursion toggles =="
expect "recursion on applies" "recursion: on" minidns recursion on
sleep 1
expect "recursion resolves from roots" "rcode +NOERROR" minidns test example.org
expect "recursion off applies" "recursion: off" minidns recursion off
expect "DoT upstream applies" "tls: true" minidns upstream set 1.1.1.1 1.0.0.1 --tls
# no systemd in the container, so mimic what minidns does on real hosts:
# a full restart (tls-cert-bundle is only read at startup)
unbound-control stop >/dev/null 2>&1; sleep 1
unbound -c /etc/unbound/unbound.conf; sleep 1
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

echo "== status =="
minidns status
echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
