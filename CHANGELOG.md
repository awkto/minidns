# Changelog

## Unreleased (v0.2.0)

### Added
- **Local authoritative zones**: `zone add|list|show|remove`. Zone files are the single copy of the data, rendered deterministically, serial bumped automatically, served by unbound auth-zones.
- **Records**: `record add|list|remove` for A, AAAA, CNAME, MX, TXT, NS, SRV, CAA and PTR — values are validated by parsing them, TXT is quoted/split for you, CNAME coexistence is enforced, adding the same record twice is a no-op. `--ttl`, `--managed-by <tool>` (for minidhcp and friends).
- **Reverse zones and hosts**: `reverse-zone add <cidr>` (IPv4 and IPv6), `host add|rename|remove` manages A/AAAA and the matching PTRs together.
- **Overlay records on a cloud replica**: `cloud zone overlay enable <zone>` lets `record` and `host` add local-only records on top of a read-only replica (e.g. LAN device names under your public domain). The provider's zone is never written to; its pristine copy, the overlay and the merged served file are kept apart and re-merged on every sync. An overlay record hides a provider record of the same name and type (and says so). `record list <replica>` shows every record with its source.
- **Forwarders**: `forwarder add|remove|list|test`, global or `--zone <suffix|reverse zone>` (IPv4/IPv6, `ip@port#tls-name`, `--tls`). Zone forwarders work in both resolver modes and get the private-zone exceptions they need (`local-zone transparent`, `domain-insecure`); a forwarder on 127.0.0.1 works. `forwarder test` asks each server directly and tells unreachable from refused from fine — an unreachable private forwarder is still valid configuration.
- **`query <name|ip> [type]`** with `--server`, `--trace` (walks the delegation from the roots), `--full`, `--json`. An IP address is looked up in reverse.
- **`block add|remove|list|test|explain`**, **`allow add|remove|list`**. `block explain <name>` reports whether the name is blocked, the matching rule, where it comes from (manual block or which subscribed list), any allowlist override, and matches in rule sets that are switched off.
- **`blocklist add|list|status|update|enable|disable|remove`** for subscribed lists, with per-list enable/disable.
- **Safe blocklist refreshes**: downloads are size-limited; every format — native RPZ feeds included — is reduced to validated domain names and re-rendered (a feed can only ever add blocks); an empty, unparseable or implausibly shrunken download (less than half the active list) is refused and the active copy kept; if unbound does not come back with the new data the previous files are restored. Last attempt, last success, entry count and last error are recorded (`blocklist status`). Credentials in private list URLs are never printed.
- Every record change hot-reloads just that zone (cache untouched), verifies unbound serves the new serial, and rolls the file back if it doesn't.
- `--json` on the new commands and a documented, stable exit-code table (2 usage, 3 invalid, 4 not found, 5 conflict, 6 apply failed, …). Shell completion via `minidns completion`.

### Changed
- **`zone` now means local zones.** The DigitalOcean replicas moved to `cloud zone add|list|sync|remove` (+ `cloud provider list`). `zone sync` and `zone add --provider` still work with a deprecation warning. `config.yaml`'s `zones:` key is migrated to `cloud_zones:` on upgrade; the original is kept as `config.yaml.pre-v0.2`.

- `upstream`, `block <domain>`, `unblock`, `allow <domain>`, `unallow`, `blocklist` (no verb) and `adblock …` keep working with a deprecation warning. The blocklist timer now calls `blocklist update`.
- Configuration changes made by the new commands are transactional: validated, applied, and `config.yaml` plus the generated unbound config restored if unbound rejects them.
- With DNS-over-TLS, forwarders given as `ip@853` now also get the well-known TLS name of Cloudflare/Google/Quad9 (their certificates are actually verified); IPv6 addresses of the same providers are recognized.

## v0.1.1 — 2026-09-20

Bug-fix release. No command changes; the generated unbound config is
byte-identical to v0.1.0's, so upgrading does not restart unbound.

### Fixed
- **Wildcard blocks were silently deleted.** `minidns block '*.example.com'` was accepted but hidden from `blocklist` and dropped by the next `block`/`unblock`.
- **Flags after an argument were rejected**, so the README's own examples failed: `adblock list add <url> --name x --format rpz`, `zone add example.com --provider …`, `zone sync <zone> --quiet`.
- **`setup` failed on stock Ubuntu** with "can't bind socket: Address already in use for 0.0.0.0 port 53". Setup now turns off systemd-resolved's stub listener with a drop-in and repoints `/etc/resolv.conf` at resolved's uplink file, so the host keeps resolving as before. Removing the package undoes both.
- **Package upgrades now re-apply the configuration** (validated, with the previous config kept if validation fails). unbound is left alone when the generated config did not change.
- **A bad provider response can no longer replace a working replica**: fetched zone data must parse, have one SOA at the apex and stay inside the zone before it is activated.
- **Removing a blocklist or replica could kill unbound.** `unbound-control reload` only queues the reload; the file was deleted while the daemon was still re-reading a config that referenced it, and unbound exits when a zone file is missing. Reloads are now waited on, and files are deleted only after unbound has stopped referencing them. (Found by CI.)
- **Every blocklist refresh reloaded unbound even when nothing changed**, because the generated file's serial is a timestamp. Unchanged lists are now left untouched, so the daily timer no longer drops the cache for nothing.
- `test` named the wrong blocklist when several were configured (it checked them in a different order than unbound applies them).
- `logs -f` could lose a line that unbound was still writing.
- Files are written world-readable regardless of root's umask (a `umask 077` root shell used to produce zone files unbound could not read, which took the daemon down on reload).

### Security
- Blocklist and zone names are validated before they are used in file names and generated config (`--name ../../x` is refused; a hand-edited config with such names is rejected at load).
- Mutating commands take an exclusive lock, so the adblock/zonesync timers and an interactive command can no longer rewrite the same files concurrently.

### Project
- CI on every push: gofmt, vet, unit tests, golden-file tests for the unbound config, and the end-to-end suite on Ubuntu 24.04 and Debian 12, plus an upgrade test from the previous release. Releases are gated on the same tests.
- `docs/SPEC.md`, `docs/DECISIONS.md`, `docs/STATUS.md`, `docs/ROLLOUT.md`.

## v0.1.0 — 2026-08-08

First release: unbound-based home DNS with firewall, adblock, DigitalOcean zone mirror, query logs and Prometheus metrics.
