# Rolling a release out to a live host

`pi.dnsif.ca` (Debian 12 arm64, unbound 1.17) serves DNS for the LAN, so a
release reaches it only after the automated gates and with a way back.

## Gates before any live host (automated)

1. `go vet`, unit tests, golden render tests — CI, every push.
2. `scripts/e2e.sh` fresh install on **ubuntu:24.04** and **debian:12** — CI and the release workflow.
3. `scripts/upgrade-test.sh` previous release → candidate on both — CI and the release workflow.
4. For releases that touch install/upgrade/systemd behaviour: run both scripts on real systemd VMs
   (`awkto vm create -hostname minidns-… -distro debian-12|ubuntu-2404`).

5. `scripts/acceptance.sh` — the spec §20.4 scenario, command for command, on a clean systemd VM.
6. `scripts/upgrade-pi-shape.sh` — rehearsal on a Debian 12 VM built like the Pi: v0.1.0, `dnsif.ca`
   replica through `token_file`, exporter on, adblock off, and a foreign unbound fragment with PTR
   `local-data` beside ours (the Pi has `gen-reverse.py` + `minidns-reverse.timer` producing one).
   It asserts the generated config is byte-identical, unbound keeps its PID (cache kept), the units
   run with the new binary, the replica file other tools parse is untouched, `doctor` is clean —
   and then rolls back to v0.1.0 and checks that too.

**Status: pi.dnsif.ca stays on v0.1.0 until the owner says otherwise (2026-09-20).** Nothing in
the pipeline or in any test touches it; the rehearsal exists so that the day it is upgraded is boring.

## Upgrade a live host

```sh
# 1. snapshot (seconds; everything minidns owns)
sudo tar czf /root/minidns-pre-$(minidns version | awk '{print $2}')-$(date +%F).tgz \
  /etc/minidns /var/lib/minidns /etc/unbound/unbound.conf.d/minidns.conf
dpkg-query -W -f='${Version}\n' minidns        # note the version you are leaving

# 2. upgrade
sudo apt update && sudo apt install minidns
#    postinst re-renders the unbound config, validates it, and only restarts
#    unbound if the generated config actually changed.

# 3. verify
sudo minidns status
sudo minidns test example.org          # NOERROR
sudo minidns test doubleclick.net      # NXDOMAIN if adblock is on
sudo minidns cloud zone list           # replicas present, recently synced (v0.1: `zone list`)
sudo minidns doctor                    # v0.2+: every check, with a fix hint per finding
systemctl is-active unbound minidns-zonesync.timer minidns-adblock.timer
curl -s localhost:9153/metrics | grep -c '^unbound_'   # if the exporter is enabled
dig @<lan-ip> <a-name-clients-use> +short              # from another machine
```

## Roll back

```sh
sudo tar xzf /root/minidns-pre-….tgz -C /       # brings back the old config.yaml first
sudo apt install --allow-downgrades minidns=<previous-version>     # still in apt.pro.dnsif.ca
sudo unbound-checkconf && sudo systemctl restart unbound
```

From v0.2 the upgrade rewrites `config.yaml` (`zones:` → `cloud_zones:`, provider token →
`credentials.yaml`); v0.1 cannot read the new layout, which is why the old file goes back
*before* the old package. The upgrade keeps it for you as `/etc/minidns/config.yaml.pre-v0.2`
and as a `…-before-migration.tar.gz` under `/var/lib/minidns/backups/`.

The owner confirms before each production upgrade; nothing on the Pi is
upgraded automatically by the release pipeline.
