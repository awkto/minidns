# Requirement status

Spec requirement → state in the code, as of v0.1.0 + the v0.1.1 work. `#n` = tracker issue at gitlab.dnsif.ca/github/minidns.

| Spec | Requirement | State | Notes / issue |
|---|---|---|---|
| §5.1 | Single source of truth, no silent drift | partial | files canonical (D3); no SQLite yet #43 |
| §5.3 | Narrow privilege | partial | reads mostly work unprivileged; #29 |
| §6 | Targets, SSH remote, default rules | missing | #50 #51 #52 #53 |
| §7.1 | `install` | partial | exists as `setup`; no platform gate #25; systemd-resolved #12 |
| §7.2 | Secure defaults (closed recursion, no AXFR, hide version) | complete | RFC1918 ACLs, hide-identity/version; IPv6 ACLs #22 |
| §7.3 | `status` | complete | |
| §7.3 | `doctor`, `config validate/diff` | missing | #29 #27 |
| §8 | Global forwarders | partial | `upstream set` (replace-all, DoT) → `forwarder` family #35 |
| §8 | Zone-specific forwarders | missing | #35 |
| §8 | Recursion mode | complete | `recursion on|off` kept (D7) |
| §9.1 | Local authoritative zones | complete | `zone add/list/show/remove` (v0.2 branch) |
| §9.2 | Records | complete | `record add/list/remove`, 9 types, `--managed-by` (#65) |
| §9.3 | Reverse zones, `host` | complete | `reverse-zone add`, `host add/rename/remove` |
| §10 | `query` | partial | exists as `test` (no `--server/--trace/--json`) #36 |
| §11 | Devices | missing | #46 |
| §12 | Query log: enable/tail/list | partial | `logs` with `--client/--blocked/--since`; text re-parse, IP only → #44 #47 |
| §12.3 | Bounded storage, rotation, retention | partial | logrotate 30 d; no SQLite, no purge #45 |
| §12.4 | Privacy notice | missing | #25 #47 |
| §13 | Statistics | partial | `top`, `stats`; slow, no device/date-range/rollups → #48 |
| §14.1 | Manual blocks (RPZ) | complete* | *wildcard-loss bug #10; noun-verb #38 |
| §14.2 | Subscribed blocklists | partial | works + daily jittered timer; enable/disable/status #39, staged safety #40 |
| §14.3 | Allowlist precedence | complete | allow zone rendered first |
| §14.3 | `block explain` | partial | verdict inside `test`; list order bug #16; #41 |
| §15 | Cloud replicas, read-only | partial | DigitalOcean under `cloud zone …`; validated before activation; opt-in local overlay records (#68); status/diff/LKG #55 |
| §15.3 | Credential handling | partial | 0600 config or token_file/env; #56 |
| §15.4 | More providers | missing | Cloudflare #5, Route 53 #57, Azure #58 |
| §16 | Transactional apply + rollback | partial | conf file validated + restored; zones/RPZ not staged, restart not rolled back #26 |
| §16 | Backup / restore | missing | #28 |
| §17 | Noun-verb CLI, `--json`, exit codes, `--dry-run` | partial | cobra root, exit-code table, `--json` on new commands; v0.1 commands not yet renamed, no `--dry-run` #23 #24 |
| §19 | Input validation, path safety | partial | domains validated; list/zone names not #15; no write lock #17 |
| §19 | Timeouts, size limits | partial | HTTP timeouts yes; download size cap no #40 |
| §20.1 | Unit tests | partial | rpz + qlog only; render golden tests #19 |
| §20.2 | Integration tests on a real engine | partial | `scripts/e2e.sh` (Ubuntu only, manual) → CI matrix #18 |
| §20.3 | Remote target tests | missing | #52 |
| §20.4 | Acceptance scenario | missing | #37 |
| §21 | Packaging (deb amd64/arm64, units, apt repo) | complete | upgrade re-render #13, upgrade harness #20 |
| — | DoT upstream, serve-expired, Prometheus exporter | complete | kept (Amendment 4); derived metrics #49 |
| §3.3 | BIND engine, minidhcp, external sinks, per-device policy | deferred | #59 #60 #61 #62 |
