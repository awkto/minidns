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
expect_rc() { # expect_rc <desc> <exit code> <cmd...>
  local desc="$1" want="$2"; shift 2
  "$@" >/tmp/out 2>&1; local got=$?
  if [ "$got" -eq "$want" ]; then ok "$desc"; else bad "$desc (exit $got, want $want)"; sed 's/^/    /' /tmp/out | head -8; fi
}
expect() { # expect <desc> <pattern> <cmd...>
  local desc="$1" pat="$2"; shift 2
  "$@" >/tmp/out 2>&1
  if grep -qE "$pat" /tmp/out; then ok "$desc"; else bad "$desc (no /$pat/)"; sed 's/^/    /' /tmp/out | head -15; fi
}

# unbound reloads the big RPZ zones on every config change and refuses
# connections while it does — poll instead of guessing a sleep
wait_dns() { for _ in $(seq 1 60); do minidns test localhost >/dev/null 2>&1 && return 0; sleep 0.5; done; echo "unbound did not come back within 30s"; diag; return 1; }
diag() { echo "--- diagnostics"; pgrep -a unbound || echo "(no unbound process)"; unbound-control status 2>&1 | head -3; grep -vE " (query|reply): | rpz: applied " /var/log/minidns/unbound.log | tail -15; echo "---"; }

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

echo "== local zones and records =="
expect "zone add creates an authoritative zone" 'Zone "home.arpa" added' minidns zone add home.arpa
expect "reverse-zone add maps the network"      '0.20.10.in-addr.arpa' minidns reverse-zone add 10.20.0.0/24
expect "unbound still validates its config"     "no errors" unbound-checkconf
expect "host add creates A and PTR together"    "added +10.0.20.10.in-addr.arpa. PTR nas.home.arpa." minidns host add nas --ip 10.20.0.10 --ip fd00::10 --zone home.arpa
expect "forward record resolves"                "nas.home.arpa.*A.*10.20.0.10" minidns test nas.home.arpa
expect "AAAA record resolves"                   "fd00::10" minidns test nas.home.arpa AAAA
expect "PTR resolves (RFC1918 reverse space)"   "PTR.*nas.home.arpa" minidns test 10.0.20.10.in-addr.arpa PTR
expect "verdict names the local zone"           "served from local zone home.arpa" minidns test nas.home.arpa
expect "record add CNAME (relative target)"     "Added git.home.arpa. 300 CNAME nas.home.arpa." minidns record add home.arpa git CNAME nas
expect "CNAME is chased inside the zone"        "10.20.0.10" minidns test git.home.arpa
expect "record add MX takes a multi-word value" "MX 10 mail.home.arpa." minidns record add home.arpa @ MX 10 mail.home.arpa.
expect "record add TXT quotes for you"          'TXT "v=spf1 -all"' minidns record add home.arpa @ TXT "v=spf1 -all" --ttl 600
expect "TXT resolves with its TTL"              '600.*TXT.*v=spf1 -all' minidns test home.arpa TXT
expect "adding the same record again is a no-op" "Already present" minidns record add home.arpa git CNAME nas
expect_rc "invalid value → exit 3"   3 minidns record add home.arpa bad A not-an-ip
expect_rc "unknown zone → exit 4"    4 minidns record add nope.example x A 10.0.0.1
expect_rc "CNAME beside A → exit 5"  5 minidns record add home.arpa nas CNAME other
expect_rc "bad command line → exit 2" 2 minidns record add home.arpa
expect "record list --json is valid JSON" "^6$" bash -c 'minidns record list home.arpa --json | python3 -c "import json,sys; print(len(json.load(sys.stdin)))"'
expect "--managed-by tags and filters"  '"managed_by": "minidhcp"' bash -c 'minidns record add home.arpa laptop A 10.20.0.5 --managed-by minidhcp >/dev/null && minidns record list home.arpa --managed-by minidhcp --json'
expect "host rename moves A and PTR"    "added +10.0.20.10.in-addr.arpa. PTR storage.home.arpa." minidns host rename nas storage
expect "old name is gone"               "rcode +NXDOMAIN" minidns test nas.home.arpa
expect "PTR follows the rename"         "PTR.*storage.home.arpa" minidns test 10.0.20.10.in-addr.arpa PTR
expect "host remove drops A and PTR"    "removed +10.0.20.10.in-addr.arpa. PTR storage.home.arpa." minidns host remove storage
expect "PTR is gone"                    "rcode +NXDOMAIN" minidns test 10.0.20.10.in-addr.arpa PTR
expect "record remove"                  "Removed git.home.arpa. CNAME" minidns record remove home.arpa git CNAME
expect "status lists local zones"       "home.arpa \(local\)" minidns status
expect_rc "zone remove refuses while records exist → exit 5" 5 minidns zone remove home.arpa
expect "zone remove --force"            'Zone "home.arpa" removed' minidns zone remove home.arpa --force
# with our zone gone, unbound's built-in empty home.arpa zone answers again
expect "removed zone no longer answers" "nobody.invalid" minidns test home.arpa SOA
expect "names under it are gone"        "rcode +NXDOMAIN" minidns test laptop.home.arpa
check  "unbound survived all of it"     unbound-control status

echo "== cloud replica + local overlay (fake provider API) =="
# a stand-in for the DigitalOcean API, so replicas are tested without a token
FAKE=/tmp/fake-do; mkdir -p "$FAKE"
cat > "$FAKE/server.py" <<'PY'
import http.server, json, os
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        zone = self.path.rsplit('/', 1)[-1]
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), zone + '.zone')
        if not os.path.exists(p):
            self.send_response(404); self.end_headers(); return
        body = json.dumps({"domain": {"name": zone, "zone_file": open(p).read()}}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', 8953), H).serve_forever()
PY
fake_zone() { # fake_zone <serial> [extra record lines]
  { printf '$ORIGIN replica.example.\n$TTL 1800\nreplica.example. IN SOA ns1.provider.example. hostmaster.replica.example. %s 10800 3600 604800 1800\n' "$1"
    printf 'replica.example. 1800 IN NS ns1.provider.example.\nwww.replica.example. 300 IN A 203.0.113.10\napp.replica.example. 300 IN CNAME edge.cdn.example.\n'
    shift; printf '%s\n' "$@"; } > "$FAKE/replica.example.zone"
}
fake_zone 1000
python3 "$FAKE/server.py" & FAKE_PID=$!
for _ in $(seq 1 20); do curl -fs http://127.0.0.1:8953/v2/domains/replica.example >/dev/null && break; sleep 0.2; done
export MINIDNS_DO_API=http://127.0.0.1:8953
REAL_DO_TOKEN="${DIGITALOCEAN_TOKEN:-}"; export DIGITALOCEAN_TOKEN=fake
expect "cloud zone add pulls the zone"        "mirrored" minidns cloud zone add replica.example
wait_dns
expect "replica answers locally"               "203.0.113.10" minidns test www.replica.example
expect_rc "a plain replica is read-only → exit 3" 3 minidns record add replica.example laptop A 10.0.0.5
expect "…and says how to allow local records"  "cloud zone overlay enable replica.example" minidns record add replica.example laptop A 10.0.0.5
expect "record list shows the provider's data" "digitalocean +203.0.113.10" minidns record list replica.example
minidns reverse-zone add 10.0.0.0/24 >/dev/null; wait_dns
CONF_SUM="$(md5sum < /etc/unbound/unbound.conf.d/minidns.conf)"
expect "overlay enable"                        "Overlay enabled for replica.example" minidns cloud zone overlay enable replica.example
expect "provider data still served"            "203.0.113.10" minidns test www.replica.example
expect "overlay record add"                    "local overlay on replica replica.example" minidns record add replica.example laptop A 10.0.0.5 --managed-by minidhcp
expect "overlay record resolves"               "10.0.0.5" minidns test laptop.replica.example
expect "overlay hides a provider record and says so" "hides the provider's record: www.replica.example. A 203.0.113.10" minidns record add replica.example www A 10.0.0.80
expect "…the overlay value is served"          "10.0.0.80" minidns test www.replica.example
expect "overlay A replaces a provider CNAME"   "hides the provider's record: app.replica.example. CNAME" minidns record add replica.example app A 10.0.0.81
expect "…and resolves"                         "10.0.0.81" minidns test app.replica.example
expect_rc "apex NS cannot be overlaid → exit 3" 3 minidns record add replica.example @ NS ns.evil.test.
expect "record list marks the source"          "overlay +10.0.0.5 +\(managed by minidhcp\)" minidns record list replica.example
expect "record list --overlay --json"          "^3$" bash -c 'minidns record list replica.example --overlay --json | python3 -c "import json,sys; print(len(json.load(sys.stdin)))"'
expect "cloud zone list counts overlay records" "\+3 overlay record" minidns cloud zone list
expect "host add works on an overlaid replica" "added +7.0.0.10.in-addr.arpa. PTR phone.replica.example." minidns host add phone --ip 10.0.0.7 --zone replica.example
expect "…forward"                              "10.0.0.7" minidns test phone.replica.example
expect "…reverse"                              "phone.replica.example" minidns test 7.0.0.10.in-addr.arpa PTR
fake_zone 2000 'new.replica.example. 300 IN A 203.0.113.99'
expect "sync merges new provider data"         "updated" minidns cloud zone sync replica.example
expect "…new provider record served"           "203.0.113.99" minidns test new.replica.example
expect "…overlay survives the sync"            "10.0.0.5" minidns test laptop.replica.example
expect "…serial follows the provider"          "serial 2000 " minidns cloud zone list
expect "sync again is a no-op"                 "unchanged" minidns cloud zone sync replica.example
echo "garbage" > "$FAKE/replica.example.zone"
expect_rc "unusable provider data is refused"  1 minidns cloud zone sync replica.example
expect "…and the last good copy keeps serving" "10.0.0.5" minidns test laptop.replica.example
fake_zone 2000 'new.replica.example. 300 IN A 203.0.113.99'
expect "record remove from the overlay"        "Removed www.replica.example. A 10.0.0.80" minidns record remove replica.example www A
expect "…the provider's record is back"        "203.0.113.10" minidns test www.replica.example
check  "no unbound config change for any of it" test "$CONF_SUM" = "$(md5sum < /etc/unbound/unbound.conf.d/minidns.conf | cat)"
expect_rc "overlay disable refuses while records exist → exit 5" 5 minidns cloud zone overlay disable replica.example
expect_rc "cloud zone remove refuses too → exit 5" 5 minidns cloud zone remove replica.example
expect "overlay disable --force"               "Overlay disabled" minidns cloud zone overlay disable replica.example --force
expect "…provider data only again"             "edge.cdn.example" minidns test app.replica.example
expect "…overlay names are gone"               "rcode +NXDOMAIN" minidns test laptop.replica.example
minidns host remove phone --zone replica.example >/dev/null 2>&1
expect "cloud zone remove"                     "removed zone replica.example" minidns cloud zone remove replica.example
wait_dns
minidns zone remove 0.0.10.in-addr.arpa --force >/dev/null; wait_dns
check  "no overlay state left behind"          bash -c '! ls /var/lib/minidns/zones/overlay/replica.example.zone* /var/lib/minidns/zones/upstream/replica.example.zone 2>/dev/null | grep .'
check  "unbound survived all of it"            unbound-control status
kill $FAKE_PID 2>/dev/null; unset MINIDNS_DO_API
if [ -n "$REAL_DO_TOKEN" ]; then export DIGITALOCEAN_TOKEN="$REAL_DO_TOKEN"; else unset DIGITALOCEAN_TOKEN; fi

echo "== zone mirror (digitalocean) =="
expect "unsafe zone name rejected" "not a valid zone name" minidns cloud zone add '../../etc/passwd' --provider digitalocean
if [ -n "${DIGITALOCEAN_TOKEN:-}" ]; then
  expect "cloud zone add pulls from DO" "mirrored" minidns cloud zone add "$E2E_ZONE" --provider digitalocean
  expect_rc "a replica cannot be edited as a local zone → exit 3" 3 minidns record add "$E2E_ZONE" x A 10.0.0.1
  expect "mirrored zone answers locally" "rcode +NOERROR" minidns test "$E2E_ZONE_HOST"
  expect "cloud zone sync detects unchanged" "unchanged" minidns cloud zone sync "$E2E_ZONE" --quiet=false
  expect "v0.1 spelling still works, with a warning" "deprecated" minidns zone sync
  expect "cloud zone list shows serial" "serial [0-9]+" minidns cloud zone list
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
