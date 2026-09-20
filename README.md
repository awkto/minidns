# minidns

A tiny home DNS server manager — think *pivpn, but for DNS*. One CLI drives
[unbound](https://nlnetlabs.nl/projects/unbound/) to give your LAN the DNS
features home users don't usually get:

- **DNS firewall** — block domains (and their subdomains) with one command
- **Adblock** — subscription blocklists (StevenBlack by default), auto-updated daily
- **Zone mirror** — keep a local authoritative copy of your cloud-hosted DNS
  zone (DigitalOcean today; Route53/Azure/Cloudflare on the roadmap) that keeps
  resolving even when your ISP is down
- **Fast resolver** — forwards to 1.1.1.1/8.8.8.8 by default (optionally over
  TLS), or flip on full recursion; caches aggressively, serves stale answers
  during upstream outages
- **Query logs** — per-client logs kept for 30 days, `top`-style domain/client
  rankings
- **Metrics** — a built-in Prometheus exporter for unbound's statistics; run
  Prometheus/Grafana wherever you like

No web GUI. No daemon of its own — unbound does the serving, minidns writes
its config.

## Install

```sh
# from the awkto apt repo
curl -fsSL https://gist.githubusercontent.com/awkto/7630588151f0a5c52c32efdff693d98e/raw/add-awkto-apt.sh | bash -s -- minidns

# then
sudo minidns setup
```

Point your router's DHCP DNS at the host's LAN IP and you're done. Debs are
also attached to [GitHub releases](https://github.com/awkto/minidns/releases).

Supported and tested on every push: **Ubuntu 24.04** and **Debian 12**
(including Raspberry Pi OS), amd64 and arm64. On Ubuntu, `setup` takes port 53
over from systemd-resolved's stub listener and gives it back if you remove the
package.

## Usage

```
minidns status                          what's running, what's blocked, what's mirrored
minidns test doubleclick.net            resolve locally + explain the policy verdict

minidns block ads.example.com           firewall: block a domain + subdomains
minidns allow good.example.com          allowlist (always wins)

minidns adblock update                  refresh lists now (timer does this daily)
minidns adblock list add https://big.oisd.nl/rpz --name oisd --format rpz

minidns zone add example.com            mirror a zone from DigitalOcean
minidns zone sync                       pull fresh copies (timer: every 5 min)

minidns upstream set 9.9.9.9 --tls      change forwarders (DNS-over-TLS)
minidns recursion on                    resolve from the roots, skip forwarders

minidns logs -f                         live query log
minidns logs --client 192.168.1.23      one device's history
minidns top --since 24h                 top domains, with counts
minidns top --clients                   noisiest devices
minidns top --blocked                   most-blocked domains
minidns stats                           cache hit rate, latency, rcodes
```

Configuration lives in `/etc/minidns/config.yaml`; run `minidns apply` after
editing it by hand. The generated unbound fragment goes to
`/etc/unbound/unbound.conf.d/minidns.conf`.

### Zone mirroring

Put a DigitalOcean API token (read scope is enough) in the config:

```yaml
providers:
  digitalocean:
    token: dop_v1_...
```

`minidns zone add example.com` pulls the full zone file from the DO API and
unbound serves it authoritatively to your LAN. A systemd timer re-syncs every
5 minutes and hot-reloads only when the zone actually changed — so if your
ISP (or DigitalOcean) is unreachable, `example.com` still resolves at home.

### Metrics

Set `exporter.enabled: true` in the config (and re-run `minidns setup`, or
`systemctl enable --now minidns-exporter`), then scrape
`http://<host>:9153/metrics` from Prometheus. All of unbound's extended
statistics are exposed (`unbound_total_num_queries`,
`unbound_num_rpz_action_nxdomain`, cache sizes, rcode counts, …).

Query logs are plain text under `/var/log/minidns/` (epoch timestamps,
rotated daily, 30 days kept) if you want to feed them to Loki & friends.

## Building from source

```sh
go build ./cmd/minidns
sudo ./minidns setup
```

Releases: tag `vX.Y.Z` → GitHub Actions builds amd64/arm64 debs and attaches
them to the release.
