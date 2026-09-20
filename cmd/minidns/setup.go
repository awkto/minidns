package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/adblock"
	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/rpz"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zones"
)

// apparmorLocal is appended to the local unbound AppArmor override on
// distros that confine unbound (Ubuntu), so it may read our zone files and
// write the query log.
const apparmorLocal = `# added by minidns
/var/lib/minidns/ r,
/var/lib/minidns/** r,
/var/log/minidns/ r,
/var/log/minidns/** rw,
/run/unbound.control rw,
`

// Root zone trust anchors (KSK-2017 and KSK-2024), from
// https://data.iana.org/root-anchors/root-anchors.xml
const rootDS = `. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
`

// checkPlatform refuses hosts minidns is not built and tested for, before
// anything is touched.
func checkPlatform() error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("unsupported architecture %s (supported: amd64, arm64)", runtime.GOARCH)
	}
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("cannot tell which OS this is (no /etc/os-release); supported: Debian 12+, Ubuntu 22.04+, Raspberry Pi OS")
	}
	osr := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			osr[k] = strings.Trim(v, `"`)
		}
	}
	major, _ := strconv.Atoi(strings.SplitN(osr["VERSION_ID"], ".", 2)[0])
	switch id := osr["ID"]; {
	case id == "ubuntu" && major >= 22:
	case (id == "debian" || id == "raspbian") && (major >= 12 || osr["VERSION_ID"] == ""): // testing/sid carry no VERSION_ID
	default:
		return fmt.Errorf("%s is not a supported platform (supported: Debian 12+, Ubuntu 22.04+, Raspberry Pi OS)", osr["PRETTY_NAME"])
	}
	if _, err := unbound.FindBin("unbound"); err != nil {
		return fmt.Errorf("unbound is not installed — `sudo apt install unbound` (the minidns .deb pulls it in)")
	}
	return nil
}

// hostHasIPv6 reports whether the kernel has IPv6 addresses configured;
// binding ::0 on a host with IPv6 disabled would keep unbound from starting.
func hostHasIPv6() bool {
	b, err := os.ReadFile("/proc/net/if_inet6")
	return err == nil && len(strings.TrimSpace(string(b))) > 0
}

func installCmd() *cobra.Command {
	var force bool
	run := func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "setup" {
			deprecated("setup", "install")
		}
		if os.Getenv("MINIDNS_PREFIX") == "" {
			if err := checkPlatform(); err != nil {
				if !force {
					return fmt.Errorf("%w (nothing was changed; --force tries anyway)", err)
				}
				note("warning: %v — continuing because of --force", err)
			}
		}
		return cmdSetup(nil)
	}
	install := &cobra.Command{
		Use: "install", Short: "First run: check the platform, configure unbound safely, start it, enable the timers", Args: cobra.NoArgs,
		Long: "Safe to re-run: it never overwrites an existing config.yaml, zones or rules.",
		RunE: run, GroupID: groupSetup,
	}
	install.Flags().BoolVar(&force, "force", false, "continue on an unsupported platform")
	return install
}

func setupAliasCmd() *cobra.Command {
	c := installCmd()
	c.Use, c.Hidden = "setup", true
	return c
}

func cmdSetup(args []string) error {
	if os.Geteuid() != 0 && os.Getenv("MINIDNS_PREFIX") == "" {
		return fmt.Errorf("install must run as root (sudo minidns install)")
	}

	fmt.Println("==> preparing directories")
	for _, d := range []string{paths.ConfigDir(), paths.RPZDir(), paths.ZoneDir(), paths.LogDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	chownUnbound(paths.LogDir())

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if _, err := os.Stat(paths.ConfigFile()); os.IsNotExist(err) {
		if hostHasIPv6() {
			cfg.Listen = append(cfg.Listen, "::0")
		}
		fmt.Println("==> writing default config to", paths.ConfigFile())
		if err := config.Save(cfg); err != nil {
			return err
		}
	}

	// seed empty firewall zones so they're wired into unbound from day one
	for _, p := range []string{paths.AllowRPZ(), paths.BlockRPZ()} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			action := rpz.ActionBlock
			if p == paths.AllowRPZ() {
				action = rpz.ActionPassthru
			}
			if _, err := rpz.Write(p, nil, action, true); err != nil {
				return err
			}
		}
	}

	setupAppArmor()
	ensureTrustAnchor()
	if os.Getenv("MINIDNS_PREFIX") == "" {
		freePort53(cfg)
	}

	if cfg.Adblock.Enabled && len(cfg.Adblock.Lists) > 0 {
		fmt.Println("==> downloading adblock lists")
		for _, l := range cfg.Adblock.Lists {
			n, _, err := adblock.Update(l, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    %s: %v (continuing; retry with `minidns blocklist update`)\n", l.Name, err)
				continue
			}
			fmt.Printf("    %s: %d domains\n", l.Name, n)
		}
	}

	fmt.Println("==> generating unbound config")
	if err := cmdApply(false); err != nil {
		return err
	}

	fmt.Println("==> starting unbound")
	systemdOK := true
	if out, err := exec.Command("systemctl", "enable", "--now", "unbound").CombinedOutput(); err != nil {
		systemdOK = false
		fmt.Fprintf(os.Stderr, "    warning: could not enable unbound via systemd: %s\n", strings.TrimSpace(string(out)))
		fmt.Fprintln(os.Stderr, "    start it manually: unbound -c /etc/unbound/unbound.conf")
	}
	if systemdOK {
		if out, err := exec.Command("systemctl", "restart", "unbound").CombinedOutput(); err != nil {
			return fmt.Errorf("restart unbound: %s", strings.TrimSpace(string(out)))
		}
	}

	// timers ship in the deb; running from source without them is fine
	for _, unit := range []string{"minidns-adblock.timer", "minidns-zonesync.timer"} {
		exec.Command("systemctl", "enable", "--now", unit).Run()
	}
	if cfg.Exporter.Enabled {
		exec.Command("systemctl", "enable", "--now", "minidns-exporter.service").Run()
	}

	fmt.Println()
	if systemdOK {
		if err := unbound.WaitReady(30 * time.Second); err != nil {
			return fmt.Errorf("unbound did not come up: %w — `minidns doctor` says why", err)
		}
	}
	fmt.Println("minidns is up.")
	fmt.Printf("  listening on   %s, port %d\n", strings.Join(hostAddresses(cfg), ", "), cfg.Port)
	fmt.Printf("  answers for    %s (everyone else is refused)\n", strings.Join(cfg.AllowNetworks, ", "))
	if cfg.Logging.Queries {
		fmt.Println("  query logging  ON — every lookup is stored with the client's IP address, for 30 days,")
		fmt.Println("                 on this host only. Tell the people on your network, or turn it off")
		fmt.Println("                 (logging.queries: false in " + paths.ConfigFile() + ", then `minidns apply`).")
	}
	fmt.Println()
	fmt.Println("Next: point your router's DHCP DNS setting at this host, then try")
	fmt.Println("  minidns doctor  |  minidns query example.org  |  minidns block explain doubleclick.net  |  minidns logs -f")
	return nil
}

// cmdApplyQuiet renders the config and, if it changed, reloads unbound and
// waits for it — without the restart cmdApply does (no startup-only option
// is involved when zones come and go) and without printing anything.
func cmdApplyQuiet() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	rendered := unbound.Render(cfg)
	current, _ := os.ReadFile(paths.UnboundConfFile())
	if err := unbound.WriteConf(rendered); err != nil {
		return err
	}
	if string(current) == rendered || !unbound.Active() {
		return nil
	}
	// a reload keeps the process; options only read at startup need a restart
	activate := unbound.Reload
	if startupOptions(string(current)) != startupOptions(rendered) {
		activate = unbound.Restart
	}
	if err := activate(); err != nil {
		// put the previous config back so the daemon can start again
		if len(current) > 0 {
			os.WriteFile(paths.UnboundConfFile(), current, 0o644)
			unbound.Reload()
		}
		return err
	}
	return nil
}

// hostAddresses lists where clients can reach the server: the configured
// addresses, with a wildcard expanded to the host's own addresses.
func hostAddresses(cfg *config.Config) []string {
	var out []string
	for _, l := range cfg.Listen {
		addr, _, _ := strings.Cut(l, "@")
		if addr != "0.0.0.0" && addr != "::0" && addr != "::" {
			out = append(out, addr)
			continue
		}
		ifaces, _ := net.InterfaceAddrs()
		for _, a := range ifaces {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || (ipn.IP.To4() != nil) != (addr == "0.0.0.0") {
				continue
			}
			out = append(out, ipn.IP.String())
		}
	}
	if len(out) == 0 {
		return []string{"127.0.0.1"}
	}
	return out
}

// engineUp reports whether unbound is serving. Without root the control
// socket is off limits, so an answered query counts as well.
func engineUp(cfg *config.Config) bool {
	if unbound.Active() {
		return true
	}
	if os.Geteuid() == 0 {
		return false
	}
	_, _, err := exchange(serverAddr(cfg), "localhost", dns.TypeA, true)
	return err == nil
}

// startupOptions extracts the generated options unbound reads only when it
// starts (a reload ignores changes to them).
func startupOptions(conf string) string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		for _, opt := range []string{"tls-cert-bundle:", "interface:", "port:", "num-threads:", "module-config:"} {
			if strings.HasPrefix(t, opt) {
				out = append(out, t)
			}
		}
	}
	return strings.Join(out, "\n")
}

// persistMigration rewrites a config that still used v0.1 keys, keeping the
// original next to it.
func persistMigration(cfg *config.Config) {
	if !cfg.Migrated {
		return
	}
	if old, err := os.ReadFile(paths.ConfigFile()); err == nil {
		os.WriteFile(paths.ConfigFile()+".pre-v0.2", old, 0o600)
		os.Chmod(paths.ConfigFile()+".pre-v0.2", 0o600)
	}
	if path, _, err := createBackup("before-migration", ""); err == nil {
		fmt.Println("backup of the pre-migration state:", path)
	}
	if err := config.Save(cfg); err == nil {
		fmt.Println("config migrated to the v0.2 layout (zones: → cloud_zones:, provider token → credentials.yaml); previous file kept as config.yaml.pre-v0.2")
		cfg.Migrated = false
	}
}

// cmdApply regenerates the unbound config fragment and (optionally) reloads.
func cmdApply(reload bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	persistMigration(cfg)
	rendered := unbound.Render(cfg)
	current, _ := os.ReadFile(paths.UnboundConfFile())
	if err := unbound.WriteConf(rendered); err != nil {
		return err
	}
	if reload && string(current) == rendered && unbound.Active() {
		// nothing for the daemon to pick up — keep its cache warm
		fmt.Println("applied (no changes)")
		return nil
	}
	if reload && unbound.Active() {
		// restart rather than reload: some options (tls-cert-bundle) are
		// only read at startup, and reload drops the cache anyway
		if err := unbound.Restart(); err != nil {
			return err
		}
		fmt.Println("applied + restarted unbound")
	} else if reload {
		fmt.Println("applied (unbound not running — start it with `minidns setup` or systemctl)")
	}
	return nil
}

type statusZone struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // local | replica
	Provider string `json:"provider,omitempty"`
	Serial   uint32 `json:"serial,omitempty"`
	Records  int    `json:"records,omitempty"`
	Overlay  int    `json:"overlay_records,omitempty"`
	Synced   string `json:"synced,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

type statusReport struct {
	Engine     string         `json:"engine"`
	Running    bool           `json:"running"`
	Mode       string         `json:"mode"` // forwarding | recursion
	Forwarders []string       `json:"forwarders"`
	TLS        bool           `json:"forwarders_tls"`
	Listen     []string       `json:"listen"`
	Port       int            `json:"port"`
	Firewall   bool           `json:"manual_blocks_enabled"`
	Blocked    int            `json:"manual_blocks"`
	Allowed    int            `json:"allowlist_entries"`
	Blocklists []blocklistRow `json:"blocklists"`
	Zones      []statusZone   `json:"zones"`
	ZoneFwd    []forwarderRow `json:"zone_forwarders"`
	Queries    string         `json:"queries,omitempty"`
	CacheHit   float64        `json:"cache_hit_percent,omitempty"`
	Uptime     string         `json:"uptime,omitempty"`
	Exporter   string         `json:"exporter"`
}

func cmdStatus(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	blocks, _ := rpz.ReadDomains(paths.BlockRPZ())
	allows, _ := rpz.ReadDomains(paths.AllowRPZ())
	r := statusReport{Engine: "unbound", Running: engineUp(cfg), Mode: "forwarding", Forwarders: cfg.Upstreams, TLS: cfg.UpstreamTLS,
		Listen: cfg.Listen, Port: cfg.Port, Firewall: cfg.Firewall.Enabled, Blocked: len(blocks), Allowed: len(allows),
		Blocklists: blocklistRows(cfg, ""), Zones: []statusZone{}, ZoneFwd: forwarderRows(cfg, false, true, ""), Exporter: "disabled"}
	if cfg.Recursion {
		r.Mode = "recursion"
	}
	if cfg.Exporter.Enabled {
		r.Exporter = "enabled on " + cfg.Exporter.Listen
	}
	for _, z := range cfg.LocalZones {
		sz := statusZone{Name: z, Kind: "local"}
		if lz, err := zones.Load(z); err == nil {
			sz.Serial, sz.Records = lz.Serial, len(lz.UserRecords())
		} else {
			sz.Problem = "unreadable: " + err.Error()
		}
		r.Zones = append(r.Zones, sz)
	}
	for _, z := range cfg.CloudZones {
		sz := statusZone{Name: z.Name, Kind: "replica", Provider: z.Provider}
		synced := paths.ZoneFile(z.Name)
		if z.Overlay {
			synced = paths.UpstreamFile(z.Name)
			if ov, err := zones.LoadOverlay(z.Name); err == nil {
				sz.Overlay = len(ov.Records)
			}
		}
		if st, err := os.Stat(synced); err == nil {
			sz.Synced = ago(st.ModTime())
		} else {
			sz.Problem = "not synced yet"
		}
		r.Zones = append(r.Zones, sz)
	}
	if r.Running {
		if stats, err := unbound.Stats(); err == nil {
			r.Queries = stats["total.num.queries"]
			hits, _ := strconv.ParseFloat(stats["total.num.cachehits"], 64)
			if total, _ := strconv.ParseFloat(r.Queries, 64); total > 0 {
				r.CacheHit = float64(int(1000*hits/total)) / 10
			}
			up, _ := strconv.ParseFloat(stats["time.up"], 64)
			r.Uptime = (time.Duration(up) * time.Second).String()
		}
	}

	return emit(r, func() {
		fmt.Printf("engine      unbound (%s)\n", map[bool]string{true: "running", false: "stopped"}[r.Running])
		mode := fmt.Sprintf("forwarder → %s", strings.Join(cfg.Upstreams, ", "))
		if cfg.UpstreamTLS {
			mode += " (DoT)"
		}
		if cfg.Recursion {
			mode = "full recursion (no forwarding)"
		}
		fmt.Printf("mode        %s\n", mode)
		for _, f := range r.ZoneFwd {
			fmt.Printf("            %s → %s\n", f.Zone, f.Address)
		}
		fmt.Printf("listen      %s port %d\n", strings.Join(cfg.Listen, ", "), cfg.Port)
		if cfg.Firewall.Enabled {
			fmt.Printf("firewall    on — %d blocked, %d allowed\n", r.Blocked, r.Allowed)
		} else {
			fmt.Println("firewall    off")
		}
		if cfg.Adblock.Enabled {
			var parts []string
			for _, l := range r.Blocklists {
				switch {
				case !l.Enabled:
					parts = append(parts, l.Name+": disabled")
				case l.ActiveEntries == 0:
					parts = append(parts, l.Name+": not downloaded yet")
				default:
					parts = append(parts, fmt.Sprintf("%s: %d entries (updated %s)", l.Name, l.ActiveEntries, ago(l.LastSuccess)))
				}
			}
			if len(parts) == 0 {
				parts = []string{"on — no lists configured"}
			}
			fmt.Printf("adblock     %s\n", strings.Join(parts, "; "))
		} else {
			fmt.Println("adblock     off")
		}
		if len(r.Zones) == 0 {
			fmt.Println("zones       none")
		}
		for _, z := range r.Zones {
			switch {
			case z.Problem != "":
				fmt.Printf("zone        %s (%s) — %s\n", z.Name, z.Kind, strings.ToUpper(z.Problem))
			case z.Kind == "local":
				fmt.Printf("zone        %s (local) — %d records, serial %d\n", z.Name, z.Records, z.Serial)
			case z.Overlay > 0:
				fmt.Printf("zone        %s (replica of %s) — synced %s, +%d overlay record(s)\n", z.Name, z.Provider, z.Synced, z.Overlay)
			default:
				fmt.Printf("zone        %s (replica of %s) — synced %s\n", z.Name, z.Provider, z.Synced)
			}
		}
		if r.Queries != "" {
			fmt.Printf("stats       %s queries, %.1f%% cache hits, up %s\n", r.Queries, r.CacheHit, r.Uptime)
		}
		fmt.Printf("exporter    %s\n", r.Exporter)
	})
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func chownUnbound(path string) {
	u, err := user.Lookup("unbound")
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	os.Chown(path, uid, gid)
}

// ensureTrustAnchor creates any DNSSEC trust anchor file the distro config
// references but the unbound postinst didn't create (fresh installs,
// containers) — without it unbound-checkconf refuses the whole config.
func ensureTrustAnchor() {
	confs, _ := filepath.Glob(filepath.Join(paths.UnboundConfD(), "*.conf"))
	re := regexp.MustCompile(`auto-trust-anchor-file:\s*"?([^"\s]+)"?`)
	for _, c := range confs {
		b, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			anchor := m[1]
			if _, err := os.Stat(anchor); err == nil {
				continue
			}
			fmt.Println("==> fetching DNSSEC trust anchor", anchor)
			os.MkdirAll(filepath.Dir(anchor), 0o755)
			// exit code 1 just means "anchor was updated" — not an error
			exec.Command("unbound-anchor", "-a", anchor).Run()
			if _, err := os.Stat(anchor); err != nil {
				// no unbound-anchor binary (or offline): seed with the
				// published root DS records; RFC 5011 tracking takes over
				os.WriteFile(anchor, []byte(rootDS), 0o644)
			}
			chownUnbound(anchor)
			chownUnbound(filepath.Dir(anchor))
		}
	}
}

// setupAppArmor widens Ubuntu's unbound confinement to our directories.
func setupAppArmor() {
	profile := "/etc/apparmor.d/usr.sbin.unbound"
	if _, err := os.Stat(profile); err != nil {
		return
	}
	local := "/etc/apparmor.d/local/usr.sbin.unbound"
	existing, _ := os.ReadFile(local)
	if strings.Contains(string(existing), "minidns") {
		return
	}
	os.MkdirAll("/etc/apparmor.d/local", 0o755)
	f, err := os.OpenFile(local, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	f.WriteString(apparmorLocal)
	f.Close()
	exec.Command("apparmor_parser", "-r", profile).Run()
}
