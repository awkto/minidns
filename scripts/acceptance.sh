#!/bin/bash
# The end-to-end acceptance scenario of docs/SPEC.md §20.4, command for command,
# on a clean supported host with systemd (a VM, not a container):
#
#   sudo apt install ./minidns_<version>_<arch>.deb && sudo bash acceptance.sh
#
# Steps that belong to a later milestone are reported as PENDING, not failed.
set -uo pipefail
PASS=0; FAIL=0; PENDING=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; sed 's/^/    /' /tmp/acc.out | head -12; }
step() { # step <desc> <pattern> <cmd...>
  local desc="$1" pat="$2"; shift 2
  echo "\$ $*"
  "$@" >/tmp/acc.out 2>&1; local rc=$?
  if [ $rc -eq 0 ] && grep -qE "$pat" /tmp/acc.out; then ok "$desc"; else bad "$desc (exit $rc)"; fi
}
pending() { # pending <milestone> <cmd...>
  local m="$1"; shift
  if "$@" >/tmp/acc.out 2>&1; then ok "$*"; else PENDING=$((PENDING+1)); echo "PENDING ($m): $*"; fi
}

step "install"                          "minidns is up"            minidns install
step "zone add"                         'Zone "home.example" added' minidns zone add home.example
step "reverse-zone add"                 "0.20.10.in-addr.arpa"     minidns reverse-zone add 10.20.0.0/24
step "host add creates A and PTR"       "PTR nas.home.example."    minidns host add nas --ip 10.20.0.10 --zone home.example
step "forwarder add"                    "1.1.1.1"                  minidns forwarder add 1.1.1.1
step "block add"                        "Blocked: telemetry.example" minidns block add telemetry.example
step "device add"                       'Device "laptop" added'    minidns device add laptop --ip 10.20.0.5
# become 10.20.0.5 for a moment, so there is something to attribute
ip addr add 10.20.0.5/32 dev lo 2>/dev/null
step "a query from 10.20.0.5"           "NOERROR"                  minidns query example.org --source 10.20.0.5 --server 10.20.0.5
step "…and a blocked one"               "NXDOMAIN"                 minidns query telemetry.example --source 10.20.0.5 --server 10.20.0.5
step "forward record resolves"          "10.20.0.10"               minidns query nas.home.example
step "reverse record resolves"          "nas.home.example"         minidns query 10.20.0.10
step "external names resolve through the forwarder" "NOERROR"      minidns query example.org
step "the blocked name gets the blocking response"  "NXDOMAIN"     minidns query telemetry.example
step "…and block explain says why"      "manual block"             minidns block explain telemetry.example
sleep 1
step "queries from 10.20.0.5 display as laptop" "laptop +A +NOERROR +example.org" minidns query-log list --device laptop
step "…the blocked one too"             "laptop +A +BLOCKED \[block\] +telemetry.example" minidns query-log list --device laptop
step "stats top-domains --device"       "example.org +1 "          minidns stats top-domains --device laptop
ip addr del 10.20.0.5/32 dev lo 2>/dev/null
step "configuration and zones validate" "Configuration is valid"   minidns config validate
step "doctor: unbound healthy, nothing failed" " 0 failed"         minidns doctor
step "unbound is active under systemd"  "^active"                  systemctl is-active unbound

echo; echo "RESULT: $PASS passed, $FAIL failed, $PENDING pending"
[ "$FAIL" -eq 0 ]
