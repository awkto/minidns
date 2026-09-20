# Requirement status

Spec requirement → state in the code, as of v0.1.0 + the v0.1.1 work. `#n` = tracker issue at gitlab.dnsif.ca/github/minidns.

| Spec | Requirement | State | Notes / issue |
|---|---|---|---|
| §5.1 | Single source of truth, no silent drift | complete | files canonical (D3); SQLite holds only devices, query data and cursors (#43, D8) |
| §5.3 | Narrow privilege | complete | read-only commands run without root (config.yaml 0644, token in root-only credentials.yaml); changes need sudo, exit 8 (#67 #56) |
| §6 | Targets, SSH remote, default rules | missing | #50 #51 #52 #53 |
| §7.1 | `install` | complete | platform gate, safe re-run, listen/ACL/privacy report (#25); `setup` deprecated |
| §7.2 | Secure defaults (closed recursion, no AXFR, hide version) | complete | private v4+v6 ACLs, `::0` when the host has IPv6 (#22), hide-identity/version; `doctor` warns on public ACLs |
| §7.3 | `status` | complete | |
| §7.3 | `doctor`, `config show/validate/render/diff/apply` | complete | #29 #27 |
| §8 | Global forwarders | complete | `forwarder add|remove|list|test`, DoT, IPv6 (#35); `upstream` deprecated |
| §8 | Zone-specific forwarders | complete | `--zone`, forward and reverse, both resolver modes (#35) |
| §8 | Recursion mode | complete | `recursion on|off` kept (D7) |
| §9.1 | Local authoritative zones | complete | `zone add/list/show/remove` (v0.2 branch) |
| §9.2 | Records | complete | `record add/list/remove`, 9 types, `--managed-by` (#65) |
| §9.3 | Reverse zones, `host` | complete | `reverse-zone add`, `host add/rename/remove` |
| §10 | `query` | complete | `--server`, `--trace`, `--full`, `--json`, reverse by IP (#36); `test` kept |
| §11 | Devices | complete | `device add|list|show|rename|set|remove`, `device address add|remove`; time-bounded addresses, attribution at read time (#46) |
| §12 | Query log: enable/tail/list | complete | `query-log list|tail|enable|disable|status|retention|purge` with all §12.2 filters (#47); incremental, rotation-safe ingestion (#44) |
| §12.3 | Bounded storage, rotation, retention | complete | queries 7 d, hourly counts 35 d, daily counts 400 d, all configurable; daily prune; `purge` (#45) |
| §12.4 | Privacy notice | complete | at `install` and `query-log enable`; log dir 0750, database 0600, backups leave individual queries out |
| §13 | Statistics | complete | `stats`, `top-domains`, `top-devices`, `blocked`, `reverse`, `device <name>`; periods, device/client/type/domain filters, registered-domain grouping, `--json` (#48); exporter metrics with bounded labels (#49) |
| §14.1 | Manual blocks (RPZ) | complete | `block add|remove|list|test|explain` (#38); NXDOMAIN is the only action |
| §14.2 | Subscribed blocklists | complete | `blocklist …` with per-list enable/disable and status (#39); safe refresh with last-known-good (#40) |
| §14.3 | Allowlist precedence | complete | allow zone rendered first |
| §14.3 | `block explain` | complete | rule, origin, allow override, switched-off matches (#41) |
| §15 | Cloud replicas, read-only | partial | DigitalOcean under `cloud zone …`; validated before activation; opt-in local overlay records (#68); status/diff/LKG #55 |
| §15.3 | Credential handling | partial | 0600 config or token_file/env; #56 |
| §15.4 | More providers | missing | Cloudflare #5, Route 53 #57, Azure #58 |
| §16 | Transactional apply + rollback | partial | zones, overlays, forwarders, blocklist toggles and refreshes roll back on failure; remaining legacy writers #26 |
| §16 | Backup / restore | complete | `backup create|list`, `restore` with safety backup + rollback; automatic backup before a config migration (#28) |
| §17 | Noun-verb CLI, `--json`, exit codes, `--dry-run` | complete* | all v0.2 nouns; old spellings deprecated (#24); `--dry-run` on record/host/forwarder/recursion/blocklist toggles, refused elsewhere (#23). *`logs`/`top`/`stats` become `query-log`/`stats` in v0.3 |
| §19 | Input validation, path safety | complete | names validated before use in paths/config; write lock; restore refuses foreign archive paths |
| §19 | Timeouts, size limits | complete | HTTP timeouts, 200 MB list cap, 10 MB provider response cap |
| §20.1 | Unit tests | partial | rpz + qlog only; render golden tests #19 |
| §20.2 | Integration tests on a real engine | partial | `scripts/e2e.sh` (Ubuntu only, manual) → CI matrix #18 |
| §20.3 | Remote target tests | missing | #52 |
| §20.4 | Acceptance scenario | complete | `scripts/acceptance.sh`, every step, on systemd VMs (#37) |
| §21 | Packaging (deb amd64/arm64, units, apt repo) | complete | upgrade re-render #13, upgrade harness #20 |
| — | DoT upstream, serve-expired, Prometheus exporter | complete | kept (Amendment 4); derived metrics #49 |
| §3.3 | BIND engine, minidhcp, external sinks, per-device policy | deferred | #59 #60 #61 #62 |
