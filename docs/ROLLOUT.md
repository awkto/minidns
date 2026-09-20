# Rolling a release out to a live host

`pi.dnsif.ca` (Debian 12 arm64, unbound 1.17) serves DNS for the LAN, so a
release reaches it only after the automated gates and with a way back.

## Gates before any live host (automated)

1. `go vet`, unit tests, golden render tests — CI, every push.
2. `scripts/e2e.sh` fresh install on **ubuntu:24.04** and **debian:12** — CI and the release workflow.
3. `scripts/upgrade-test.sh` previous release → candidate on both — CI and the release workflow.
4. For releases that touch install/upgrade/systemd behaviour: run both scripts on real systemd VMs
   (`awkto vm create -hostname minidns-… -distro debian-12|ubuntu-2404`).

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
sudo minidns zone list                 # replicas present, recently synced
systemctl is-active unbound minidns-zonesync.timer minidns-adblock.timer
curl -s localhost:9153/metrics | grep -c '^unbound_'   # if the exporter is enabled
dig @<lan-ip> <a-name-clients-use> +short              # from another machine
```

## Roll back

```sh
sudo apt install minidns=<previous-version>     # still in apt.pro.dnsif.ca
sudo tar xzf /root/minidns-pre-….tgz -C /
sudo unbound-checkconf && sudo systemctl restart unbound
```

The owner confirms before each production upgrade; nothing on the Pi is
upgraded automatically by the release pipeline.
