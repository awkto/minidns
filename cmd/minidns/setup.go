package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/awkto/minidns/internal/adblock"
	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/rpz"
	"github.com/awkto/minidns/internal/unbound"
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

func cmdSetup(args []string) error {
	if os.Geteuid() != 0 && os.Getenv("MINIDNS_PREFIX") == "" {
		return fmt.Errorf("setup must run as root (sudo minidns setup)")
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
			n, _, err := adblock.Update(l)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    %s: %v (continuing; retry with `minidns adblock update`)\n", l.Name, err)
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
	fmt.Println("minidns is up. Point your router's DHCP DNS at this host's LAN IP.")
	fmt.Println("Try:  minidns status   |   minidns test doubleclick.net   |   minidns logs -f")
	return nil
}

// cmdApply regenerates the unbound config fragment and (optionally) reloads.
func cmdApply(reload bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
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

func cmdStatus(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	state := "stopped"
	if unbound.Active() {
		state = "running"
	}
	fmt.Printf("engine      unbound (%s)\n", state)

	mode := fmt.Sprintf("forwarder → %s", strings.Join(cfg.Upstreams, ", "))
	if cfg.UpstreamTLS {
		mode += " (DoT)"
	}
	if cfg.Recursion {
		mode = "full recursion (no forwarding)"
	}
	fmt.Printf("mode        %s\n", mode)
	fmt.Printf("listen      %s port %d\n", strings.Join(cfg.Listen, ", "), cfg.Port)

	blocks, _ := rpz.ReadDomains(paths.BlockRPZ())
	allows, _ := rpz.ReadDomains(paths.AllowRPZ())
	fw := "off"
	if cfg.Firewall.Enabled {
		fw = fmt.Sprintf("on — %d blocked, %d allowed", len(blocks), len(allows))
	}
	fmt.Printf("firewall    %s\n", fw)

	if cfg.Adblock.Enabled {
		var parts []string
		for _, l := range cfg.Adblock.Lists {
			p := paths.AdblockRPZ(l.Name)
			if st, err := os.Stat(p); err == nil {
				parts = append(parts, fmt.Sprintf("%s: %d entries (updated %s)",
					l.Name, rpz.CountEntries(p), ago(st.ModTime())))
			} else {
				parts = append(parts, l.Name+": not downloaded yet")
			}
		}
		if len(parts) == 0 {
			parts = []string{"on — no lists configured"}
		}
		fmt.Printf("adblock     %s\n", strings.Join(parts, "; "))
	} else {
		fmt.Println("adblock     off")
	}

	if len(cfg.Zones) == 0 {
		fmt.Println("zones       none mirrored")
	}
	for _, z := range cfg.Zones {
		p := paths.ZoneFile(z.Name)
		if st, err := os.Stat(p); err == nil {
			fmt.Printf("zone        %s (%s) — synced %s\n", z.Name, z.Provider, ago(st.ModTime()))
		} else {
			fmt.Printf("zone        %s (%s) — NOT SYNCED YET\n", z.Name, z.Provider)
		}
	}

	if state == "running" {
		if stats, err := unbound.Stats(); err == nil {
			q := stats["total.num.queries"]
			hits, _ := strconv.ParseFloat(stats["total.num.cachehits"], 64)
			total, _ := strconv.ParseFloat(q, 64)
			ratio := 0.0
			if total > 0 {
				ratio = 100 * hits / total
			}
			up, _ := strconv.ParseFloat(stats["time.up"], 64)
			fmt.Printf("stats       %s queries, %.1f%% cache hits, up %s\n",
				q, ratio, (time.Duration(up) * time.Second).String())
		}
	}

	exp := "disabled"
	if cfg.Exporter.Enabled {
		exp = "enabled on " + cfg.Exporter.Listen
	}
	fmt.Printf("exporter    %s\n", exp)
	return nil
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
