#!/bin/bash
# Build the minidns .deb.
# Usage: build-deb.sh <version> <arch> <path-to-minidns-binary> [outdir]
#   version:  0.1.0 (leading v is stripped)
#   arch:     amd64 | arm64
set -euo pipefail

VERSION="${1:?version required}"
ARCH="${2:?arch required}"
BINARY="${3:?binary path required}"
OUTDIR="${4:-.}"

VERSION="${VERSION#v}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKGROOT="$SCRIPT_DIR/../packaging"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

PKGDIR="$STAGE/minidns_${VERSION}_${ARCH}"
mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/usr/bin" \
  "$PKGDIR/lib/systemd/system" "$PKGDIR/etc/logrotate.d"

install -m 0755 "$BINARY" "$PKGDIR/usr/bin/minidns"
install -m 0644 "$PKGROOT"/systemd/* "$PKGDIR/lib/systemd/system/"
install -m 0644 "$PKGROOT/logrotate/minidns" "$PKGDIR/etc/logrotate.d/minidns"
install -m 0755 "$PKGROOT/debian/postinst" "$PKGDIR/DEBIAN/postinst"
install -m 0755 "$PKGROOT/debian/prerm" "$PKGDIR/DEBIAN/prerm"
install -m 0755 "$PKGROOT/debian/postrm" "$PKGDIR/DEBIAN/postrm"

cat > "$PKGDIR/DEBIAN/conffiles" <<EOF
/etc/logrotate.d/minidns
EOF

cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: minidns
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: unbound (>= 1.13), unbound-anchor, ca-certificates
Recommends: logrotate
Maintainer: awkto <me@awkto.dev>
Homepage: https://github.com/awkto/minidns
Description: Tiny home DNS server manager (unbound under the hood)
 One command to run a fast local resolver with a DNS firewall, adblocking
 via subscription lists, local mirrors of cloud-hosted zones that survive
 ISP outages, per-client query logging, and Prometheus-friendly metrics.
 Forwards to public resolvers by default; full recursion is one flag away.
EOF

dpkg-deb --build --root-owner-group "$PKGDIR" "$OUTDIR/minidns_${VERSION}_${ARCH}.deb"
