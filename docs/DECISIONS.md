# Architecture decisions

Short log of material choices, newest last. Spec references are to `docs/SPEC.md`.

## D1 — unbound is the engine (2026-09-20)
The handover spec assumed BIND; v0.1.0 shipped on unbound and the owner chose to keep it. BIND may be added later as an optional second engine (tracker #59). Nothing is abstracted for that today — an engine interface gets designed when there is a second engine to fit it to.

Practical notes recorded while comparing the two on Ubuntu 24.04: unbound's log carries replies with rcode, latency and cache-hit flags, and is built with dnstap; BIND 9.18 there has neither, and cannot forward over TLS.

## D2 — No daemon, no API; SSH for remote (2026-09-20)
Spec §2.3/§6. Remote management invokes the remote `minidns` binary over SSH and exchanges JSON. Periodic work (list updates, replica sync, log ingestion) runs from systemd timers. A long-running helper is only acceptable if a timer demonstrably cannot do the job.

## D3 — Files stay canonical; SQLite holds only what files can't (2026-09-20)
Spec §5.1 leaves this open. Zone files and RPZ files are what unbound actually reads, they diff and back up trivially, and having them as the single copy means the database and the active configuration cannot drift apart. `config.yaml` remains the settings file (the spec's TOML suggestion is a minor convention, §4). SQLite (`/var/lib/minidns/minidns.db`, pure-Go driver so the static build survives) holds devices, query events, rollups, ingestion cursors and sync/list metadata.

## D4 — Devices are manual name↔IP; no MAC capture in MiniDNS (2026-09-20)
A neighbour-table MAC capture was considered and dropped as over-engineered for this stage. `device_addresses` is time-bounded from the start so minidhcp lease history can be imported later (#60). Attribution is resolved when reading, not when ingesting, so naming a device fixes its history too.

## D5 — Query statistics are local (2026-09-20)
Measured on pi.dnsif.ca: ~190k queries/day, ~130 clients, ~8k distinct names/week; re-parsing a week of text logs takes 18 s. Hourly rollups keyed `(hour, client_ip, qname, qtype, result, blocked_by)` in SQLite answer every "top …" question locally. Prometheus/Postgres/Loki/Grafana remain optional sinks (#61) and never a dependency.

## D6 — Two supported baselines (2026-09-20)
Ubuntu 24.04 (unbound 1.19) and Debian 12 (unbound 1.17 — the production Pi). CI runs the end-to-end suite on both; every release is upgrade-tested from the previous one before it reaches a live host.

## D7 — v0.1 command names survive one release as deprecated aliases (2026-09-20)
v0.2.0 adopts the spec's `minidns <noun> <verb>` model. Old spellings keep working with a warning, except `zone` (now local authoritative zones; replicas move to `cloud zone`) and `blocklist` (now subscribed lists; manual entries are `block list`), whose meanings change.

## D8 — How query data is stored (2026-09-21)
Implements D3/D5. One table of individual queries (`query_events`, 7 days by default) for `query-log list`, and one of counts (`query_rollups`) for every statistic: per hour for 35 days, then folded into per-day rows (UTC days) kept for 400 days. Names and client addresses are dictionary-encoded so the big tables hold integers. Ingestion is cursor-based (inode + offset + first line of the file, to recognise copytruncate rotation even when the file has regrown), only ever consumes complete lines, pairs each RPZ line with the reply it explains, and commits events, counts and cursor in one transaction — a crash or a concurrent run can neither lose nor double-count a query. It runs from `minidns-ingest.timer` every 5 minutes and opportunistically before any report. The first run imports whatever logrotate has kept, so statistics start with history.

Measured with a synthetic week of pi.dnsif.ca-scale traffic (1.3 M queries, 134 clients, 8 k names) on a small x86 VM: first import 17 s, database 72 MB, `stats top-domains --last 7d` 1.1 s (the v0.1 text re-parse took 18 s on the Pi), `--last 24h` 0.14 s.

Privacy: the database is 0600 root, the log directory 0750 `unbound:adm`; backups carry devices and counts but not the individual queries unless `--with-queries`; the exporter never uses a domain or a client address as a label. Nothing leaves the host.

The price is binary size: the pure-Go SQLite driver takes the static release binary from 11 MB to 16 MB. Accepted — it keeps the single CGO-free binary (amd64 and arm64) and avoids a database service.
