# MiniDNS Product and Build Specification

**Status:** Implementation handover, amended 2026-09-20 (see Amendments)  
**Audience:** Claude Code / Fable and human maintainers  
**Product:** MiniDNS  
**Purpose:** Guide continued development of the existing MiniDNS project without requiring every low-level decision to be made in advance.

---

## Amendments (2026-09-20)

This specification was drafted without sight of the repository and assumed BIND. The owner reviewed it against the shipped v0.1.0 (which is built on unbound) and decided:

1. **The engine is unbound, not BIND.** Every engine reference below has been changed accordingly. BIND may become an *optional second engine* later (§3.3); nothing in the current build should be shaped around it.
2. **The sibling DHCP project is `minidhcp`** (the draft said "MiniKea").
3. **MiniDNS does not capture MAC addresses itself.** Devices are a manual name↔IP mapping; IP↔MAC history will come from minidhcp when it exists (§11.2).
4. **Shipped v0.1.0 capabilities the draft did not mention are kept:** DNS-over-TLS to upstream forwarders, serve-expired during upstream outages, and the Prometheus exporter for unbound statistics.
5. **Existing conventions retained** (allowed by §4): `config.yaml` (not TOML) stays the configuration file; zone and RPZ files stay canonical on disk with SQLite used only for devices, query data and sync metadata; `recursion on|off` stays the explicit resolver-mode switch. See `docs/DECISIONS.md`.

Requirement-by-requirement status lives in `docs/STATUS.md`.

---

## 1. Executive summary

MiniDNS is an opinionated command-line tool for installing, configuring, and operating a useful DNS server with minimal DNS administration knowledge.

The intended experience is comparable to PiVPN, but for DNS:

```bash
minidns install
minidns zone add home.example
minidns record add home.example nas A 10.20.0.10
minidns forwarder add 1.1.1.1
minidns block add telemetry.example
minidns query-log tail
```

MiniDNS uses a single unbound instance. It may provide authoritative DNS for locally managed zones while also resolving or forwarding other queries. Production-style separation of authoritative and recursive roles is deliberately outside the initial product scope.

MiniDNS must remain small enough for a Raspberry Pi or similarly constrained home-lab server. It must not require a web UI, API server, central controller, Kubernetes, PostgreSQL, Prometheus, or Grafana. It may expose clean integration points for external monitoring and storage later.

The existing repository is authoritative for the programming language, build system, current command structure, working features, and established conventions. The implementation agent must inspect it before changing code, preserve working behaviour, and evolve it rather than replacing it unnecessarily.

---

## 2. Product definition

### 2.1 One-sentence definition

MiniDNS is a lightweight CLI that turns unbound into an approachable home-lab DNS platform with authoritative zones, recursion or forwarding, DNS filtering, device-aware query visibility, and local replicas of cloud-hosted zones.

### 2.2 Target users

- Home-lab users who want a real DNS server without hand-editing unbound configuration.
- Small networks that need local forward and reverse zones.
- Users who want Pi-hole-like visibility and filtering on top of a real validating resolver.
- Users who want an offline local copy of a cloud DNS zone.
- Technical users managing one or several DNS hosts locally or through SSH.

### 2.3 Product principles

1. **Simple by default:** common operations should require one obvious command.
2. **Unbound-powered:** support unbound well instead of supporting several DNS engines poorly.
3. **Safe changes:** render, validate, activate, reload, and roll back where necessary.
4. **No required daemon or API:** remote management uses SSH. A small local helper, timer, or log-ingestion process is acceptable when justified, but it must not become a network control plane.
5. **Useful without an observability stack:** local query logs and basic statistics must work on the DNS host.
6. **Extensible without premature complexity:** remote PostgreSQL, Prometheus, and Grafana may be supported later through exporters or sinks.
7. **Readable output:** humans should understand what MiniDNS changed and which target it changed.
8. **Automation-friendly:** commands need stable exit codes and structured JSON output.

---

## 3. Scope boundaries

### 3.1 In scope

- Install and configure unbound.
- Run a single unbound instance.
- Authoritative forward and reverse zones.
- Common DNS record management.
- Recursive resolution, global forwarding, and zone-specific forwarding.
- Local and SSH-managed targets.
- Querying DNS through the MiniDNS CLI.
- Query logging, filtering, retention, and basic statistics.
- Friendly device names and attribution of queries to known devices.
- Manual blocked domains/zones and subscribed blocklists.
- Allowlist overrides and an explanation of why a name was blocked.
- Read-only local replicas of cloud-hosted DNS zones.
- Backup, validation, diagnostics, and safe configuration application.
- Machine-readable output for automation.

### 3.2 Explicitly out of scope for the initial product

- A web UI.
- A REST, GraphQL, gRPC, or other persistent management API.
- Multi-node clustering, quorum, or a central management server.
- Production DDI/IPAM workflows provided by FoxDDI.
- Automated HA/failover between multiple MiniDNS servers.
- Support for BIND, dnsmasq, PowerDNS, CoreDNS, or other DNS engines (BIND may become an optional second engine later — see 3.3).
- Separate authoritative and recursive deployment profiles.
- Full DHCP management; that belongs to minidhcp.
- Storing unbounded query history on a Raspberry Pi.
- Exporting individual domain names as Prometheus labels.
- A full parental-control product. Per-device filtering can be considered later.

### 3.3 Future-compatible, but not required now

- minidhcp integration for lease-to-device history and dynamic DNS updates.
- PostgreSQL or another external query-event sink.
- Prometheus metrics for bounded, low-cardinality measurements.
- Grafana dashboards supplied as optional examples.
- Per-device or per-group DNS policies.
- Additional cloud DNS providers.
- BIND as an optional second DNS engine, only once a concrete need justifies an engine abstraction.

---

## 4. Required discovery before implementation

Before writing or restructuring code, the implementation agent must:

1. Inspect the repository, README, current CLI help, tests, packaging, configuration files, migrations, and existing unbound config renderer.
2. Run the current test suite and record the baseline result.
3. Identify which capabilities in this document already work.
4. Preserve existing command compatibility unless there is a compelling reason to change it.
5. Prefer incremental refactoring over a rewrite.
6. Create a short implementation plan mapping existing capabilities, gaps, migrations, and test work.

If this specification conflicts with a working existing convention in a minor way, Fable may retain the existing convention. It should document the difference. Material product decisions—unbound-only, one unbound instance, SSH remote management, target defaults, and the basic CLI model—should not be changed silently.

---

## 5. High-level architecture

```text
User / automation
       |
       v
MiniDNS CLI
       |
       +-- target selection (implicit default or explicit override)
       |
       +-- local execution
       |       |
       |       v
       |   MiniDNS operations
       |
       +-- SSH execution
               |
               v
          remote MiniDNS operations
               |
               v
        desired state + renderer
               |
               v
      generated unbound configuration
               |
       validate / activate / reload
               |
               v
             unbound
```

### 5.1 Source of truth

MiniDNS should own the objects it manages. SQLite is the preferred local store for structured state such as devices, targets, blocklist metadata, cloud synchronization state, log cursors, query events, and statistical rollups.

Fable may choose whether zones and records are canonical in SQLite, canonical in generated zone files, or stored using a carefully designed hybrid. The result must satisfy these requirements:

- A change cannot leave the database and active unbound configuration disagreeing silently.
- Existing MiniDNS-managed data must be migratable.
- Generated output must be deterministic enough to diff and test.
- Operators must be able to back up and restore all MiniDNS-managed state.
- MiniDNS must not overwrite unrelated manually managed unbound configuration.

### 5.2 Suggested filesystem layout

The precise layout may follow existing repository conventions. A typical Linux layout is:

```text
/etc/minidns/minidns.toml
/etc/minidns/generated/
/var/lib/minidns/minidns.db
/var/lib/minidns/backups/
/var/log/minidns/
```

Generated files must clearly state that they are managed by MiniDNS. Secrets must not be placed in world-readable files or printed in normal command output.

### 5.3 Privilege model

Reading status and local MiniDNS data should not require unnecessary privilege. Installing packages, writing unbound configuration, binding privileged ports, and reloading services will normally require root or an approved privilege escalation mechanism.

Fable may decide the exact privilege boundary based on the existing implementation. Avoid running the entire CLI as root when a narrower privileged operation is practical, but do not introduce a complex privileged daemon solely for this purpose.

---

## 6. Target model

MiniDNS manages the local host or a remote host running MiniDNS. Remote execution is through SSH; no MiniDNS API service is required.

### 6.1 Target selection rules

1. If no targets are configured, commands operate locally.
2. The first explicitly configured target becomes the default.
3. Adding later targets does not change the default.
4. The default target is stored explicitly; it is not continually inferred from display order.
5. `--target NAME` overrides the default for one command.
6. If the default is deleted, MiniDNS selects the oldest remaining target, clearly reports the change, or returns to implicit local mode when none remain.
7. Mutating commands report the target they modified.

### 6.2 Target commands

Illustrative interface:

```bash
minidns target add local-pi --local
minidns target add lab-dns --ssh admin@10.20.0.2
minidns target add parents-dns --ssh admin@dns.example.net --port 2222

minidns target list
minidns target show lab-dns
minidns target test lab-dns
minidns target default lab-dns
minidns target remove lab-dns

minidns status
minidns --target parents-dns status
```

Fable may choose `target default NAME`, `target set-default NAME`, or an equivalent spelling consistent with the existing CLI. One spelling must be canonical in documentation.

### 6.3 Remote execution contract

The preferred model is that the MiniDNS client invokes a compatible MiniDNS binary remotely over SSH and exchanges structured data, rather than editing remote files or building ad hoc shell command strings.

Requirements:

- Use normal SSH configuration and key handling where possible.
- Support a configurable SSH user, host, port, and identity file if the existing stack permits it cleanly.
- Do not store SSH private keys in the MiniDNS database.
- Detect an absent or incompatible remote MiniDNS version and give an actionable error.
- Avoid interactive prompts during machine-readable operations.
- Escape arguments safely; never interpolate untrusted DNS names or record values into a shell command.
- Prefer a versioned internal JSON protocol over parsing human-readable remote output.

Fable may define the internal SSH/RPC command and compatibility policy.

---

## 7. Installation and base server configuration

### 7.1 Installation

```bash
minidns install
```

The installer should:

- Detect the supported operating system and architecture.
- Install or verify a supported unbound package.
- Create MiniDNS directories with safe ownership and permissions.
- Initialize or migrate the local data store.
- Establish a clearly isolated MiniDNS-managed unbound include.
- Configure a safe resolver baseline.
- Validate unbound configuration before starting or reloading it.
- Enable and start the service where appropriate.
- Report listening addresses, recursion policy, and next useful commands.

### 7.2 Secure defaults

- Recursion must not be open to the public internet.
- Default recursion ACLs should cover loopback and discovered/configured private networks, with a clear way to change them.
- unbound's control channel (`unbound-control`) and MiniDNS state must not be exposed unnecessarily.
- Zone transfers should be denied by default unless explicitly configured.
- Version disclosure should be minimized where practical.
- Configuration changes must be validated before activation.

### 7.3 Status and diagnostics

```bash
minidns status
minidns doctor
minidns config validate
minidns config diff
```

`status` should be fast and summarize service health. `doctor` should perform deeper checks such as:

- unbound installed and running.
- Configuration parses successfully.
- MiniDNS include is active.
- Expected ports are listening.
- Recursion is not publicly exposed according to known configuration.
- Managed zone files exist and validate.
- Forwarders are reachable where testing is safe.
- Disk usage and query-log retention are reasonable.
- SQLite schema is current and accessible.

---

## 8. Resolver and forwarders

MiniDNS supports direct recursion or forwarding through a single unbound instance. The existing repository should determine whether resolver mode is represented explicitly or inferred from forwarder configuration.

### 8.1 Terminology

- **Forwarder:** a global upstream DNS server used for ordinary non-local queries.
- **Zone forwarder:** an upstream server used only for a specific DNS suffix or reverse zone.

Internally these may map to different unbound constructs, but they belong to one user-facing `forwarder` command family.

### 8.2 Canonical command model

```bash
# Global forwarders
minidns forwarder add 1.1.1.1
minidns forwarder add 1.0.0.1

# Zone-specific forwarders
minidns forwarder add 10.20.0.53 --zone corp.example
minidns forwarder add 10.30.0.53 --zone 30.10.in-addr.arpa

minidns forwarder list
minidns forwarder list --global
minidns forwarder list --zones
minidns forwarder list --zone corp.example

minidns forwarder remove 1.1.1.1
minidns forwarder remove 10.20.0.53 --zone corp.example

minidns forwarder test
minidns forwarder test --zone corp.example
```

`forwarder list` without a filter should show both global and zone-specific forwarders in clearly separated sections.

Fable may support multiple addresses in one `add` command if the parsing and error behaviour remain unambiguous. IPv4 and IPv6 forwarder addresses should be supported. Friendly provider shortcuts such as Cloudflare or Quad9 are optional conveniences, not core data types.

### 8.3 Validation

- Validate IP address syntax.
- Normalize zone names.
- Prevent meaningless duplicates.
- Clearly distinguish a test failure from an invalid configuration.
- Do not reject an intentionally unreachable private forwarder merely because it cannot be contacted during configuration; allow validation without mandatory reachability.

---

## 9. Authoritative zones and records

### 9.1 Zone operations

```bash
minidns zone add home.example
minidns zone list
minidns zone show home.example
minidns zone remove home.example
```

Minimum zone behaviour:

- Normalize names consistently, including trailing-dot handling.
- Create valid SOA and NS records with sensible defaults.
- Manage zone serials automatically.
- Validate each zone before activation.
- Refuse destructive removal when dependencies exist unless the user confirms or supplies an explicit non-interactive force flag.
- Offer JSON output for listing and inspection.

### 9.2 Record operations

```bash
minidns record add home.example nas A 10.20.0.10
minidns record add home.example nas AAAA fd00::10
minidns record add home.example git CNAME nas.home.example.
minidns record add home.example @ MX "10 mail.home.example."
minidns record list home.example
minidns record remove home.example nas A
```

At minimum, support the record types already implemented plus the common home-lab types: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, and PTR where appropriate. Fable may phase less common record types if the existing parser or storage model requires it.

Record values must be type-validated without preventing legitimate advanced values. Preserve TXT quoting correctly. Enforce CNAME coexistence rules where practical.

### 9.3 Reverse zones and host convenience commands

Reverse DNS should be a first-class feature:

```bash
minidns reverse-zone add 10.20.0.0/24
minidns host add nas --ip 10.20.0.10 --zone home.example
minidns host rename nas storage
minidns host remove storage
```

The `host` abstraction is a convenience that can manage forward A/AAAA records and matching PTR records together. It must not replace raw record management.

Fable may decide the exact method for selecting a reverse zone when multiple zones overlap. The behaviour must be deterministic and report what was created or changed.

---

## 10. DNS query command

MiniDNS should provide a simple query interface so users can test their configured server without reaching for a separate tool.

```bash
minidns query example.com
minidns query example.com A
minidns query example.com --server 10.20.0.2
minidns query example.com --trace
minidns query example.com --json
```

The default query server should be the selected MiniDNS target when meaningful. The implementation may wrap `dig`, use an existing DNS library, or retain the current implementation. Human output should be concise, with an option for detailed/raw output.

---

## 11. Devices and friendly names

Device awareness exists primarily to make query logs and statistics understandable.

### 11.1 Device model

A device may contain:

- Stable internal ID.
- Unique CLI name or slug.
- Display name.
- One or more current IPv4/IPv6 addresses.
- Optional MAC address or other stable identifier.
- Optional group/tags.
- Optional description or owner.
- Source of the mapping, such as manual or minidhcp.
- Valid-from and valid-until timestamps for address history when available.

Example commands:

```bash
minidns device add altan-laptop --ip 10.20.0.5
minidns device add living-room-tv --ip 10.20.0.21 --mac 00:11:22:33:44:55
minidns device list
minidns device show altan-laptop
minidns device rename altan-laptop altan-framework
minidns device address add altan-framework fd00::5
minidns device remove living-room-tv
```

Exact nested command spelling may be adapted to the existing CLI.

### 11.2 Attribution rules

unbound query logs normally identify clients by IP address, not MAC address. MiniDNS must not claim that unbound directly observed a MAC address.

Query attribution should map the client IP and query timestamp to the best matching known device. Initial implementation may use the current address mapping. The data model should permit time-bounded mappings later so old queries are not reassigned incorrectly after DHCP addresses change.

Potential mapping sources, in priority order, may include:

1. minidhcp historical lease/reservation integration, when built.
2. MiniDNS manual device mappings.
3. Imported DHCP lease data.
4. Reverse DNS or local host records as a display fallback.
5. The raw IP address when no device is known.

Fable may choose a simpler initial priority, but unknown clients must remain visible rather than being discarded.

---

## 12. Query logging

### 12.1 User experience

```bash
minidns query-log enable
minidns query-log disable
minidns query-log tail
minidns query-log list --last 1h
minidns query-log list --device altan-laptop
minidns query-log list --domain youtube.com
minidns query-log list --blocked
minidns query-log retention 7d
minidns query-log purge
```

Illustrative output:

```text
TIME       DEVICE          CLIENT       DOMAIN               TYPE  RESULT
10:14:03   altan-laptop    10.20.0.5    youtube.com          A     allowed
10:14:05   living-room-tv  10.20.0.21   telemetry.vendor.io  A     blocked
```

### 12.2 Required filters

- Time range or relative duration.
- Client IP.
- Device.
- Domain exact match or suffix match.
- Query type.
- Allowed/blocked result when determinable.
- Response code when available.

### 12.3 Storage and ingestion

MiniDNS must work locally without an external database. SQLite is suitable for bounded query history and aggregates. Raw unbound log files must rotate and must not grow without limit.

Fable may select one of these patterns after inspecting the current code:

- Incremental ingestion when query-log commands run.
- A lightweight systemd timer.
- A small local log-tail helper service.
- Direct parsing with cached cursors and periodic aggregation.

Whichever pattern is chosen must:

- Handle log rotation.
- Avoid repeatedly parsing the entire log.
- Avoid duplicate events after restart.
- Apply retention consistently.
- Tolerate malformed or version-varying unbound log lines.
- Keep the DNS service functional if the analytics layer fails.

### 12.4 Privacy

Query logs reveal browsing-related metadata. Setup and enablement must make this clear. Provide configurable retention and complete purge. Do not transmit logs externally by default.

An anonymized mode is optional. If implemented, its exact semantics must be documented; it must not be described as anonymous if stable identifiers permit re-identification.

---

## 13. Statistics

MiniDNS should offer useful local summaries:

```bash
minidns stats
minidns stats top-domains
minidns stats top-devices
minidns stats blocked
minidns stats device altan-laptop
minidns stats top-domains --device living-room-tv --last 24h
```

Desired metrics where data is available:

- Total queries.
- Queries over time.
- Queries by type.
- Response codes.
- Blocked query count and percentage.
- Unique clients/devices.
- Top domains globally.
- Top domains for a device.
- Top devices by query count.
- Cache statistics if unbound exposes them reliably.
- Resolver failures such as SERVFAIL.

Hourly/daily rollups may be used to preserve useful trends after raw events expire.

Future Prometheus support must use bounded labels. Domain names must not be exported as unbounded metric labels. A future external event sink may carry full domain-level events to PostgreSQL, Loki, ClickHouse, or another suitable system.

---

## 14. DNS firewall and blocklists

### 14.1 Manual blocks

```bash
minidns block add ads.example
minidns block add telemetry.example --action nxdomain
minidns block remove ads.example
minidns block list
minidns block test ads.example
minidns block explain telemetry.example
```

RPZ (as implemented by unbound's `respip` module) is the preferred underlying mechanism unless the existing project has a sound alternative.

Supported actions may initially be limited to NXDOMAIN. If additional actions are already practical, they can include NODATA or redirect/sinkhole. The CLI must not advertise actions that are not implemented consistently.

### 14.2 Subscribed blocklists

```bash
minidns blocklist add hagezi --url https://example.invalid/list.txt
minidns blocklist list
minidns blocklist update
minidns blocklist update hagezi
minidns blocklist disable hagezi
minidns blocklist enable hagezi
minidns blocklist remove hagezi
minidns blocklist status hagezi
```

Blocklist updates must:

- Download to staging rather than replacing active data directly.
- Set reasonable download size and timeout limits.
- Parse supported formats defensively.
- Normalize names and remove duplicates.
- Reject unexpectedly empty or clearly invalid updates.
- Generate and validate the RPZ representation.
- Atomically activate a valid result.
- Retain the last known-good version if update or reload fails.
- Record last attempt, last success, source, entry count, and error state.
- Avoid logging credentials embedded in private URLs.

Automatic updates may use a system timer. The default schedule is a Fable decision, but it must include jitter or otherwise avoid an avoidable synchronized load pattern.

### 14.3 Allowlist and explanation

```bash
minidns allow add example.com
minidns allow remove example.com
minidns allow list
minidns block explain telemetry.example
```

Allowlist overrides must take precedence over subscribed blocklists and manual block rules unless the implementation explicitly introduces a higher-priority deny rule later.

`block explain` should identify:

- Whether the queried name is blocked.
- The matching rule.
- The originating manual rule or blocklist.
- Any allowlist override.
- The effective action.

Per-device filtering is deferred. Device-aware logs and statistics are required before device-specific enforcement.

---

## 15. Cloud-zone replicas

### 15.1 Purpose

MiniDNS can maintain a local, read-only copy of a DNS zone hosted by a cloud provider. This allows local clients to resolve the zone during an internet or provider outage and gives the home lab a controlled local copy.

### 15.2 User experience

The exact provider setup syntax may follow current implementation. Desired operations include:

```bash
minidns cloud provider add cloudflare
minidns cloud provider list

minidns cloud zone add example.com --provider cloudflare
minidns cloud zone list
minidns cloud zone status example.com
minidns cloud zone diff example.com
minidns cloud zone sync example.com
minidns cloud zone remove example.com
```

If the existing CLI calls this feature `cloud-zone`, Fable may retain that naming instead of introducing an unnecessary breaking change.

### 15.3 Required behaviour

- Cloud replicas are read-only locally by default.
- Credentials use least privilege and are stored securely.
- Credentials are never shown in ordinary output or logs.
- A failed or empty synchronization never destroys the active last-known-good zone.
- New zone data is staged, normalized, compared, validated, and atomically activated.
- Status shows the last attempt, last successful sync, provider, record count, current error, and whether local data is stale.
- Provider-specific records unsupported by unbound must be handled explicitly: transform safely, skip with a visible warning, or fail the sync. Never silently create an invalid zone.
- Synchronization should preserve DNS semantics including root records, relative/absolute names, TTLs, priorities, and multi-value record sets.
- Scheduled synchronization is optional for the first implementation if manual synchronization is reliable.

### 15.4 Provider scope

Preserve any providers already implemented. Fable may choose the first fully supported provider based on the existing repository and available testability. The provider interface should permit later support for Cloudflare, AWS Route 53, Azure DNS, DigitalOcean, RFC 2136, or zone transfer where appropriate. Do not implement all providers merely to satisfy the interface.

---

## 16. Transactional configuration changes

Every operation that changes active DNS behaviour should follow this conceptual process:

1. Validate user input.
2. Update or stage desired state.
3. Render complete affected configuration into a staging location.
4. Validate global unbound configuration and affected zone files.
5. Create a recoverable snapshot or retain the previous generated version.
6. Atomically activate the new generated files.
7. Reload or reconfigure unbound.
8. Verify the service accepted the configuration.
9. Commit application state and report success.
10. On failure, restore the last known-good configuration and clearly report the cause.

Fable may adjust transaction ordering to fit the current storage model, but a failed validation or reload must not leave partially applied configuration.

Useful commands:

```bash
minidns config show
minidns config validate
minidns config render
minidns config diff
minidns config apply
minidns backup create
minidns backup list
minidns restore BACKUP_ID
```

Not every command is mandatory for the first milestone if equivalent safety exists internally. `validate` and backup/restore capability are strongly preferred.

---

## 17. CLI conventions

### 17.1 General rules

- Commands should read as `minidns <noun> <verb>` where established conventions allow it.
- Use singular nouns consistently: `zone`, `record`, `device`, `target`, `forwarder`.
- `list` produces a concise table for humans.
- `show` provides detailed information for one object.
- `add` is idempotent where safe or returns a clear already-exists error.
- `remove` should be explicit and automation-safe.
- All significant read commands and mutation results should support `--json`.
- Use stable non-zero exit codes for validation, connection, authorization, not-found, conflict, and apply failures. Fable may define the exact code table.
- Errors go to stderr; structured stdout must remain parseable.
- Avoid interactive confirmation when stdin is not a TTY; require `--force` or fail clearly.

### 17.2 Target indication

Successful mutations should name the effective target:

```text
Zone "home.example" added on lab-dns (10.20.0.2).
```

Commands need not print noisy target banners for every local read, but users must be able to determine the effective target easily.

### 17.3 Dry run

A global `--dry-run` for mutating commands is desirable. If implemented, it should validate and render the prospective change, show a useful summary or diff, and make no persistent or active configuration change.

---

## 18. Data model guidance

The exact schema belongs to Fable and should fit existing migrations. The conceptual model includes:

- `targets`
- `settings`, including explicit default target
- `zones`
- `records`
- `forwarders`, optionally scoped to a zone
- `devices`
- `device_addresses`, eventually time-bounded
- `manual_blocks`
- `allow_rules`
- `blocklists`
- `blocklist_versions` or equivalent last-known-good metadata
- `cloud_providers`
- `cloud_zones`
- `cloud_sync_runs`
- `query_events`, subject to retention
- `query_rollups`
- `log_ingestion_state`
- `schema_migrations`

Secrets should not be stored directly in ordinary table columns when an operating-system credential facility or protected credential file is more suitable. If credentials must be stored locally, permissions and threat assumptions must be documented.

Use migrations from the beginning or preserve and extend the existing migration mechanism. Upgrades must not discard existing zones, records, blocks, devices, or cloud configuration.

---

## 19. Reliability and security requirements

- Treat zone names, record values, URLs, SSH destinations, and provider data as untrusted input.
- Never build shell commands by unsafe string concatenation.
- Use argument arrays or appropriate libraries for subprocess execution.
- Put timeouts on network and subprocess operations.
- Limit blocklist download size and cloud-provider pagination.
- Use atomic file replacement on the same filesystem.
- Use restrictive permissions for credentials, databases containing sensitive data, and control keys.
- Avoid following attacker-controlled symlinks when writing privileged files.
- Ensure generated paths cannot escape managed directories.
- Do not expose open recursion by default.
- Preserve the last-known-good unbound configuration.
- Make repeated commands and interrupted operations recoverable.
- Redact tokens, passwords, private URL credentials, and sensitive headers from errors and debug logs.
- Query analytics failure must never stop unbound from answering DNS.

---

## 20. Testing strategy

### 20.1 Unit tests

Cover at least:

- DNS name normalization.
- Record type validation and rendering.
- Forwarder parsing, including IPv6.
- Zone and reverse-zone calculations.
- unbound configuration rendering.
- Blocklist parsing and precedence.
- Cloud-record normalization.
- Target selection rules.
- Query log parsing and device attribution.
- Retention and statistical aggregation.
- Redaction of secrets.

### 20.2 Integration tests

Run a real supported unbound version in a container, VM, or isolated CI environment. Verify:

- Fresh installation/rendered configuration validates.
- Authoritative forward and reverse queries work.
- Recursion or global forwarding works.
- Zone forwarders route only the intended suffix.
- Records can be added and removed without corrupting zones.
- RPZ blocks and allowlist overrides work.
- Query logs are parsed and associated with devices.
- A bad proposed change is rejected while the old configuration remains active.
- Cloud synchronization retains last-known-good data after a failed update.

### 20.3 Remote target tests

Test the SSH execution protocol without requiring public infrastructure. Include:

- Successful remote command.
- Authentication/connection failure.
- Missing remote MiniDNS.
- Version incompatibility.
- Arguments containing spaces and shell metacharacters.
- JSON output remaining valid.

### 20.4 End-to-end acceptance scenario

A clean supported Linux host should be able to complete this workflow:

```bash
minidns install
minidns zone add home.example
minidns reverse-zone add 10.20.0.0/24
minidns host add nas --ip 10.20.0.10 --zone home.example
minidns forwarder add 1.1.1.1
minidns block add telemetry.example
minidns device add laptop --ip 10.20.0.5
minidns query nas.home.example
minidns query telemetry.example
minidns query-log list --device laptop
minidns stats top-domains --device laptop
minidns doctor
```

Expected outcome:

- unbound remains healthy.
- Forward and reverse local records resolve.
- External resolution works through the configured forwarder.
- The blocked name returns the configured blocking response.
- Queries from `10.20.0.5` display as `laptop`.
- Configuration and zone validation pass.

---

## 21. Packaging and supported platforms

Fable should preserve the current packaging method where reasonable. The intended environments are mainstream Linux distributions used on x86_64 and ARM64 home-lab systems.

The first documented support matrix may be deliberately narrow—for example, one Debian/Ubuntu family baseline and Raspberry Pi OS—provided unsupported environments fail clearly rather than partially configuring the host.

Packaging should eventually provide:

- The MiniDNS executable.
- Database migrations.
- unbound templates or embedded renderers.
- Service/timer units if query ingestion or scheduled updates require them.
- Shell completion if easy within the existing CLI framework.
- An uninstall path that explains what will happen to unbound and user data.

Do not remove a pre-existing independently managed unbound installation or its configuration during uninstall.

---

## 22. Delivery phases

The repository may already contain portions of several phases. Treat these as dependency ordering, not a requirement to discard or hide existing working features.

### Phase 1: foundation and safe unbound management

- Repository discovery and baseline tests.
- Installation and supported-platform detection.
- Managed unbound include and deterministic rendering.
- Validation, safe activation, reload, status, and doctor.
- Preserve/migrate existing functionality.

### Phase 2: authoritative DNS and resolution

- Forward zones and common records.
- Reverse zones and host convenience commands.
- Recursion/global forwarders.
- Zone forwarders through the unified `forwarder` CLI.
- DNS query command.

### Phase 3: filtering

- Manual blocks.
- RPZ generation.
- Blocklist subscriptions and safe updates.
- Allowlist overrides.
- `block explain`.

### Phase 4: devices, logs, and statistics

- Device CRUD and address mapping.
- Query-log ingestion and rotation handling.
- Filters and friendly device display.
- Top domains and top devices.
- Retention and rollups.

### Phase 5: targets

- Implicit local operation.
- Named local and SSH targets.
- First-target/default behaviour.
- Structured remote execution and compatibility checks.

### Phase 6: cloud replicas

- Harden existing implementation or implement the first provider.
- Staged synchronization, diff, validation, and last-known-good state.
- Status and optional scheduling.
- Provider extension interface.

---

## 23. Definition of done

A capability is complete when:

- It is reachable through a documented CLI command.
- Human output is understandable.
- JSON output is stable enough for automation.
- Inputs and failure cases are validated.
- It works against a real supported unbound instance.
- It cannot leave active unbound configuration partially written after a normal failure.
- Unit and integration tests cover its important behaviour.
- Existing user data is preserved through any schema or configuration migration.
- Documentation includes at least one practical example.

The overall handover is complete when the main end-to-end acceptance scenario passes on a clean supported Linux host and the existing test suite has no unexplained regressions.

---

## 24. Decisions delegated to Fable

Fable is explicitly allowed to decide the following after inspecting the repository:

- Internal package/module organization.
- SQLite library and migration tooling.
- Whether query ingestion runs on demand, through a timer, or through a lightweight helper.
- Exact unbound include and generated-file layout.
- Exact internal SSH JSON protocol.
- Precise exit-code assignments.
- Human table formatting and colour use.
- Exact spelling of minor subcommands where existing conventions are stronger.
- Initial supported Linux distributions and unbound versions.
- First fully supported cloud provider.
- Whether less-common record types ship together or incrementally.
- Backup representation and retention defaults.
- Query-log and aggregate retention defaults.
- Test container/VM approach.

Fable should favour the smallest reliable design and record material choices in an architecture decision document or implementation notes.

Fable should not independently change these settled decisions:

- unbound is the only DNS backend for now (BIND is a possible later addition, not a replacement).
- MiniDNS uses one unbound instance; there is no separate deployment profile.
- Global and zone-specific forwarding share the `forwarder` command family.
- Zone forwarding is identified with `--zone` or an equivalently unambiguous syntax.
- No persistent management API server is required.
- Remote management uses SSH.
- Commands operate locally when no targets are configured.
- The first configured target becomes the explicit default, which users can inspect and change.
- Local query logs and useful per-device statistics must work without external infrastructure.
- Prometheus/PostgreSQL/Grafana integrations are optional future architecture, not installation requirements.
- The product should remain clearly smaller and simpler than FoxDDI.

---

## 25. Suggested first task for the implementation agent

Do not start by implementing every item in this document. Begin with a repository assessment:

1. Inventory the existing commands and behaviours.
2. Map each requirement to `complete`, `partial`, `missing`, or `deferred`.
3. Run tests and manually exercise the safest available unbound workflow.
4. Identify data-loss, unsafe-apply, or command-consistency risks first.
5. Propose a sequence of small, testable changes.
6. Implement the first vertical slice completely, including tests and documentation.

The first vertical slice should preferably be the smallest missing path that proves the desired architecture, such as a safely applied unified forwarder workflow or one fully transactional zone/record workflow. Preserve working features and avoid a speculative rewrite.
