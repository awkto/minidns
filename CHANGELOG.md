# Changelog

## v0.3.0 — 2026-09-21

Who asks for what. The query log moves into a small local database, machines get
names, and every "top …" question is answered in about a second — by device, for
any period, without anything leaving the host.

### Added
- **Devices**: `device add|list|show|rename|set|remove` and `device address add|remove`. A device is a name plus the addresses it uses (IPv4/IPv6, optional MAC for your own reference — minidns does not observe MACs). Names are applied when a report is read, so naming or renaming a device relabels its history; when an address moves on, what the device asked from it stays with the device. Clients without a name stay visible as IP addresses.
- **Statistics**: `stats` (totals, blocked share and by which list, query types, answers, resolver cache numbers, top domains, top devices), `stats top-domains`, `stats top-devices`, `stats blocked`, `stats reverse` (most looked-up addresses, shown as the address with its device name), `stats device <name>`. All take a period (`--last 24h|7d|2w` or `--from/--to`), `--device` or `--client`, `--type`, `--domain`, `--blocked/--allowed`, `-n`, `--json`; `--group-by registered` counts subdomains under their registrable domain (`www.example.co.uk` → `example.co.uk`).
- **Block from a report**: `stats top-domains --pick` blocks the rows you name; in scripts, `… --json | jq -r '.rows[].key' | minidns block add -` (`block add -` and `allow add -` read names from standard input).
- **Query log**: `query-log list` with filters for period, device, client, domain (exact or with subdomains), type, response code, blocked/allowed; `query-log tail` follows live with device names; `query-log enable|disable` (with a privacy notice), `status`, `retention --events/--hourly/--daily`, `purge --expired|--all`.
- **Storage**: a SQLite database (`/var/lib/minidns/minidns.db`, pure Go — the static binary stays) fed from unbound's log by `minidns-ingest.timer` every 5 minutes and before any report. Ingestion is incremental and exact across restarts and logrotate; the first run imports the logs already on disk, so statistics start with history. Kept by default: individual queries 7 days, hourly counts 35 days, daily counts 400 days. Zones, records, rules and `config.yaml` stay in files; nothing on the DNS path depends on the database.
- **Exporter**: named metrics next to the raw `unbound_*` ones — `minidns_queries_total`, `minidns_cache_hit_ratio`, `minidns_queries_per_second`, `minidns_blocked_total`, `minidns_answers_total{rcode=…}`, `minidns_recursion_time_avg_seconds`. Labels are bounded sets only, never a domain or a client.
- `query --source <address>` sends the question from a specific local address (what would that client get?).
- `doctor` checks the database and the ingest timer; `backup` includes a consistent database snapshot — devices and counts, not the individual queries unless `--with-queries`.

### Changed
- **Privacy**: the log directory is now `0750 unbound:adm` (it was world-readable), the database is `0600`; devices, statistics and the query log need `sudo`.
- The exporter service runs as the unprivileged `unbound` user in a systemd sandbox instead of as root.
- `logs` and `top` keep working with a deprecation warning (`query-log`, `stats`). `stats` is now the statistics overview; the resolver cache numbers it used to print are part of it.
- Built with Go 1.25; the binary grows from 11 MB to 22 MB (the embedded database).

## v0.2.0 — 2026-09-21

minidns grows from "resolver + blocking" into a small DNS server manager: local
authoritative zones and records, hosts with their PTRs, overlay records on cloud
replicas, per-zone forwarders, a query tool, `doctor`, backups — behind a
consistent `minidns <noun> <verb>` command line with `--json`, `--dry-run` and
stable exit codes. Every v0.1 command keeps working (with a deprecation
warning). For a v0.1 configuration the generated unbound config is
byte-identical, so **upgrading does not restart unbound**; `config.yaml` is
migrated in place with the original kept.

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
- **`doctor`**: read-only health checks (engine, generated config vs config.yaml, checkconf, trust anchor, AppArmor, port 53 / systemd-resolved, recursion exposure, every zone valid and actually served, replica freshness, blocklist refresh state, forwarders answering, timers, disk) with a fix hint per finding; `--json`; non-zero exit when a check fails.
- **`config show|validate|render|diff|apply`**: `validate` checks config.yaml, all zone files and the unbound config they would produce without touching anything; `diff` shows what `apply` would change.
- **`backup create|list`** and **`restore <file>`**: configuration, credentials, local zones, overlay records, replica copies and manual rules in one private tarball (last 10 kept). `restore` backs up the current state first and puts it back if unbound rejects the restored one; archives with paths outside the minidns directories are refused. A backup is taken automatically before a config migration.
- **`cloud provider set-token <provider>`** reads the token from stdin or `--from-file` — never from the command line.
- **`install`** (was `setup`): refuses unsupported platforms before touching anything (Debian 12+, Ubuntu 22.04+, Raspberry Pi OS; amd64/arm64; `--force` overrides), and ends with where it listens, who it answers, a privacy note about query logging, and next commands. Re-running never overwrites config, zones or rules.
- **IPv6**: new installs listen on `::0` as well when the host has IPv6, and allow `::1`, `fc00::/7` and `fe80::/10`. Existing configurations are not changed.
- **`--dry-run`** for `record`, `host`, `forwarder`, `recursion` and `blocklist enable|disable`: the change is validated (zone parse, `unbound-checkconf` on the prospective config) and described, with the unbound config diff where there is one; nothing is written. Every other mutating command *refuses* `--dry-run` rather than ignore it.
- `status --json`, `recursion status --json`. v0.1-style commands without JSON output (`logs`, `top`, `stats`) say so instead of printing text.
- Every record change hot-reloads just that zone (cache untouched), verifies unbound serves the new serial, and rolls the file back if it doesn't.
- `--json` on the new commands and a documented, stable exit-code table (2 usage, 3 invalid, 4 not found, 5 conflict, 6 apply failed, …). Shell completion via `minidns completion`.

### Changed
- **`zone` now means local zones.** The DigitalOcean replicas moved to `cloud zone add|list|sync|remove` (+ `cloud provider list`). `zone sync` and `zone add --provider` still work with a deprecation warning. `config.yaml`'s `zones:` key is migrated to `cloud_zones:` on upgrade; the original is kept as `config.yaml.pre-v0.2`.

- **Provider tokens moved out of `config.yaml`** into `/etc/minidns/credentials.yaml` (root-only). A token found in config.yaml is moved on upgrade (the untouched original stays in `config.yaml.pre-v0.2`, mode 0600). config.yaml is now world-readable — unless a blocklist URL carries credentials — so **read-only commands work without sudo** (`status`, `query`, `test`, `block explain`, `zone|record|forwarder|blocklist list`, `config show`, `doctor`). Commands that change the system say so and exit 8 when run without root.
- `upstream`, `block <domain>`, `unblock`, `allow <domain>`, `unallow`, `blocklist` (no verb) and `adblock …` keep working with a deprecation warning. The blocklist timer now calls `blocklist update`.
- **Configuration changes are transactional**: validated, applied, and `config.yaml` plus the generated unbound config restored if unbound rejects them (exit 6). `config.yaml` itself is validated more strictly (listen addresses, port, `allow_networks`).
- `apply` reloads unbound instead of restarting it, unless an option that is only read at startup changed (TLS bundle, interfaces, port, threads).
- With DNS-over-TLS, forwarders given as `ip@853` now also get the well-known TLS name of Cloudflare/Google/Quad9 (their certificates are actually verified); IPv6 addresses of the same providers are recognized.

### Testing
- The end-to-end suite grew to 225 checks and runs on Ubuntu 24.04 and Debian 12 on amd64 **and on arm64** (native runner), each followed by an upgrade test from the previous release; replicas are tested against a stand-in provider API, so CI covers them without a token. Releases are gated on all of it.
- `scripts/acceptance.sh` (the spec's acceptance scenario) and `scripts/upgrade-pi-shape.sh` (upgrade + rollback rehearsal of a host shaped like the first production install) run on real systemd VMs.

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
