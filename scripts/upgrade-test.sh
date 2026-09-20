#!/bin/bash
# minidns upgrade test — installs the previous release, builds up state,
# upgrades to the candidate deb and proves nothing was lost.
#
# Runs as root on a disposable host: a container (no systemd; unbound is
# started by hand) or a VM (systemd; the package scripts do the work).
#
#   docker run --rm -v $PWD:/work debian:12 bash /work/scripts/upgrade-test.sh
#   FROM_VERSION=v0.1.0 CANDIDATE=/path/to.deb bash upgrade-test.sh
set -uo pipefail
FROM_VERSION="${FROM_VERSION:-v0.1.0}"
ARCH="$(dpkg --print-architecture)"
CANDIDATE="${CANDIDATE:-$(ls /work/minidns_*_"$ARCH".deb | sort -V | tail -1)}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check()  { local d="$1"; shift; if "$@" >/tmp/out 2>&1; then ok "$d"; else bad "$d"; sed 's/^/    /' /tmp/out | head -15; fi; }
expect() { local d="$1" p="$2"; shift 2; "$@" >/tmp/out 2>&1; if grep -qE "$p" /tmp/out; then ok "$d"; else bad "$d (no /$p/)"; sed 's/^/    /' /tmp/out | head -15; fi; }
SYSTEMD=no; [ -d /run/systemd/system ] && SYSTEMD=yes
restart_unbound() { # containers only — on systemd hosts minidns does this itself
  [ "$SYSTEMD" = yes ] && return
  unbound-control stop >/dev/null 2>&1; sleep 1; unbound -c /etc/unbound/unbound.conf; sleep 1
}

export DEBIAN_FRONTEND=noninteractive
echo "== install $FROM_VERSION ($ARCH, systemd=$SYSTEMD, $(. /etc/os-release; echo "$PRETTY_NAME")) =="
apt-get update -qq >/dev/null
apt-get install -y -qq curl >/dev/null 2>&1
OLD="/tmp/minidns_${FROM_VERSION#v}_${ARCH}.deb"
curl -fsSL -o "$OLD" "https://github.com/awkto/minidns/releases/download/${FROM_VERSION}/minidns_${FROM_VERSION#v}_${ARCH}.deb" || { echo "cannot download $FROM_VERSION"; exit 1; }
apt-get install -y -qq "$OLD" >/dev/null 2>&1 || apt-get install -y "$OLD"
expect "old version installed" "${FROM_VERSION}" minidns version
minidns setup 2>&1 | tail -3
[ "$SYSTEMD" = no ] && { unbound-anchor -a /var/lib/unbound/root.key >/dev/null 2>&1; unbound -c /etc/unbound/unbound.conf; sleep 2; }

echo "== build state on $FROM_VERSION =="
minidns block blocked.upgrade.example >/dev/null
minidns allow doubleclick.net >/dev/null
minidns upstream set 1.1.1.1 1.0.0.1 --tls >/dev/null; restart_unbound
if [ -n "${DIGITALOCEAN_TOKEN:-}" ]; then
  ( umask 077; printf '%s' "$DIGITALOCEAN_TOKEN" > /etc/minidns/do.token )
  sed -i 's|token_file: ""|token_file: /etc/minidns/do.token|' /etc/minidns/config.yaml
  minidns zone add "${E2E_ZONE:-dnsif.ca}" >/dev/null 2>&1
fi
expect "pre-upgrade: block works"     "rcode +NXDOMAIN" minidns test blocked.upgrade.example
expect "pre-upgrade: resolution works" "rcode +NOERROR"  minidns test example.org
cp /etc/unbound/unbound.conf.d/minidns.conf /tmp/minidns.conf.before
cp /etc/minidns/config.yaml /tmp/config.yaml.before
UP_BEFORE="$(unbound-control status 2>/dev/null | awk '/^uptime/{print $2}')"

echo "== upgrade to $(basename "$CANDIDATE") =="
apt-get install -y "$CANDIDATE" 2>&1 | grep -E "minidns:|Unpacking|Setting up minidns|WARNING" | sed 's/^/    /'
NEW="$(dpkg-deb -f "$CANDIDATE" Version)"
expect "new version installed" "${NEW%%~*}" minidns version

echo "== state survived =="
check  "config.yaml untouched"            cmp /tmp/config.yaml.before /etc/minidns/config.yaml
check  "unbound-checkconf accepts config" unbound-checkconf
expect "manual block still listed"   "block blocked.upgrade.example" minidns blocklist
expect "allow entry still listed"    "allow doubleclick.net"         minidns blocklist
expect "block still enforced"        "rcode +NXDOMAIN" minidns test blocked.upgrade.example
expect "allowlist still wins"        "rcode +NOERROR"  minidns test doubleclick.net
expect "DoT upstream kept"           "DNS-over-TLS"    minidns upstream
expect "resolution works"            "rcode +NOERROR"  minidns test example.org
if [ -n "${DIGITALOCEAN_TOKEN:-}" ]; then
  expect "replica still configured"  "${E2E_ZONE:-dnsif.ca}" minidns zone list
  expect "replica still answers"     "rcode +NOERROR" minidns test "${E2E_ZONE_HOST:-gitlab.dnsif.ca}"
  check  "replica sync works on new version" minidns zone sync
fi
if cmp -s /tmp/minidns.conf.before /etc/unbound/unbound.conf.d/minidns.conf; then
  ok "generated unbound config identical across the upgrade"
  UP_AFTER="$(unbound-control status 2>/dev/null | awk '/^uptime/{print $2}')"
  if [ "${UP_AFTER:-0}" -ge "${UP_BEFORE:-0}" ]; then ok "unbound was not restarted (cache kept)"; else bad "unbound restarted although its config did not change"; fi
else
  echo "NOTE: generated config changed across the upgrade:"; diff /tmp/minidns.conf.before /etc/unbound/unbound.conf.d/minidns.conf | sed 's/^/    /'
fi
if [ "$SYSTEMD" = yes ]; then
  check "adblock timer still enabled"  systemctl is-enabled --quiet minidns-adblock.timer
  check "zonesync timer still enabled" systemctl is-enabled --quiet minidns-zonesync.timer
  check "unbound active"               systemctl is-active --quiet unbound
fi

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
