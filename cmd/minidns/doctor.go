package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/adblock"
	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zonefile"
)

type finding struct {
	Check  string `json:"check"`
	Status string `json:"status"` // ok | warn | fail | skip
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

type doctor struct {
	findings []finding
	root     bool
}

func (d *doctor) add(check, status, detail, fix string) {
	d.findings = append(d.findings, finding{check, status, detail, fix})
}
func (d *doctor) ok(check, detail string)        { d.add(check, "ok", detail, "") }
func (d *doctor) warn(check, detail, fix string) { d.add(check, "warn", detail, fix) }
func (d *doctor) fail(check, detail, fix string) { d.add(check, "fail", detail, fix) }
func (d *doctor) skip(check, detail string)      { d.add(check, "skip", detail, "") }

func doctorCmd() *cobra.Command {
	var skipNetwork bool
	cmd := &cobra.Command{
		Use: "doctor", Short: "Check the installation and say how to fix what is wrong", Args: cobra.NoArgs,
		Long: "Runs read-only checks of the engine, the generated configuration, zones, replicas,\n" +
			"blocklists, forwarders, timers and disk. Exits non-zero when a check fails;\n" +
			"warnings do not change the exit code. Some checks need root and are skipped without it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := &doctor{root: os.Geteuid() == 0}
			cfg := d.checkConfig()
			if cfg != nil {
				d.checkEngine(cfg)
				d.checkExposure(cfg)
				d.checkZones(cfg)
				d.checkBlocklists(cfg)
				if skipNetwork {
					d.skip("forwarders", "skipped (--no-network)")
				} else {
					d.checkForwarders(cfg)
				}
				d.checkHousekeeping(cfg)
			}
			fails, warns := 0, 0
			for _, f := range d.findings {
				switch f.Status {
				case "fail":
					fails++
				case "warn":
					warns++
				}
			}
			out := map[string]any{"healthy": fails == 0, "failed": fails, "warnings": warns, "checks": d.findings}
			if err := emit(out, func() {
				mark := map[string]string{"ok": "ok  ", "warn": "WARN", "fail": "FAIL", "skip": "skip"}
				for _, f := range d.findings {
					fmt.Printf("[%s] %-22s %s\n", mark[f.Status], f.Check, f.Detail)
					if f.Fix != "" {
						fmt.Printf("       %-22s → %s\n", "", f.Fix)
					}
				}
				fmt.Printf("\n%d check(s), %d failed, %d warning(s)\n", len(d.findings), fails, warns)
			}); err != nil {
				return err
			}
			if fails > 0 {
				return fmt.Errorf("%d check(s) failed", fails)
			}
			return nil
		},
	}
	cmd.GroupID = groupSetup
	cmd.Flags().BoolVar(&skipNetwork, "no-network", false, "do not contact forwarders")
	markReadOnly(cmd)
	return cmd
}

func (d *doctor) checkConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		if os.IsPermission(err) {
			d.fail("config", "config.yaml is not readable by this user", "run `sudo minidns doctor` (config.yaml is private while a blocklist URL carries credentials)")
		} else {
			d.fail("config", err.Error(), "fix "+paths.ConfigFile()+" (`minidns config validate` checks it)")
		}
		return nil
	}
	if _, err := os.Stat(paths.ConfigFile()); err != nil {
		d.fail("config", "there is no "+paths.ConfigFile()+" yet", "run `sudo minidns setup`")
		return nil
	}
	d.ok("config", paths.ConfigFile()+" is valid")
	if cfg.Migrated {
		d.warn("config layout", "config.yaml still uses the v0.1 layout (zones: key, or a provider token inside it)", "run `sudo minidns apply` — it migrates the file and keeps the original")
	}
	if st, err := os.Stat(paths.CredentialsFile()); err == nil && st.Mode().Perm()&0o077 != 0 {
		d.fail("credentials", fmt.Sprintf("%s is readable by other users (mode %o)", paths.CredentialsFile(), st.Mode().Perm()), "sudo chmod 600 "+paths.CredentialsFile())
	}
	return cfg
}

func (d *doctor) checkEngine(cfg *config.Config) {
	path, err := unbound.FindBin("unbound")
	if err != nil {
		d.fail("unbound installed", "the unbound binary is not on this host", "sudo apt install unbound")
		return
	}
	version := ""
	if out, err := exec.Command(path, "-V").Output(); err == nil {
		version = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	}
	d.ok("unbound installed", version)

	current, err := os.ReadFile(paths.UnboundConfFile())
	switch {
	case err != nil:
		d.fail("generated config", paths.UnboundConfFile()+" does not exist", "run `sudo minidns apply`")
	case string(current) != unbound.Render(cfg):
		d.warn("generated config", "the unbound config is older than config.yaml (or was edited by hand)", "run `sudo minidns apply` (`minidns config diff` shows the difference)")
	default:
		d.ok("generated config", "matches config.yaml")
	}
	if err := unbound.CheckConf(); err != nil {
		if d.root {
			d.fail("unbound-checkconf", err.Error(), "")
		} else {
			d.skip("unbound-checkconf", "needs root")
		}
	} else {
		d.ok("unbound-checkconf", "the full unbound configuration is accepted")
	}

	anchors := 0
	confs, _ := filepath.Glob(filepath.Join(paths.UnboundConfD(), "*.conf"))
	re := regexp.MustCompile(`(?m)^\s*auto-trust-anchor-file:\s*"?([^"\s]+)"?`)
	for _, c := range confs {
		b, _ := os.ReadFile(c)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			anchors++
			if _, err := os.Stat(m[1]); err != nil {
				d.fail("DNSSEC trust anchor", m[1]+" is missing", "run `sudo minidns setup`")
				anchors = -1000
			}
		}
	}
	if anchors > 0 {
		d.ok("DNSSEC trust anchor", "present")
	}

	if b, err := os.ReadFile("/etc/apparmor.d/usr.sbin.unbound"); err == nil && len(b) > 0 {
		local, _ := os.ReadFile("/etc/apparmor.d/local/usr.sbin.unbound")
		if strings.Contains(string(local), "minidns") {
			d.ok("AppArmor", "unbound may read the minidns directories")
		} else {
			d.fail("AppArmor", "unbound is confined and not allowed into "+paths.StateDir(), "run `sudo minidns setup`")
		}
	}

	if !engineUp(cfg) {
		// anything listening on 127.0.0.53 while unbound is down is
		// systemd-resolved's stub, the usual reason unbound cannot bind
		if stubListening() && listenConflictsWithStub(cfg) {
			d.fail("port 53", "systemd-resolved's stub listener holds 127.0.0.53:53, which collides with the configured listen address", "run `sudo minidns setup` (it turns the stub off and keeps the host resolving)")
		}
		d.fail("unbound running", "the unbound service is not running", "sudo systemctl start unbound; journalctl -u unbound -n 30")
		return
	}
	d.ok("unbound running", "the daemon is up")
	resp, rtt, err := exchange(serverAddr(cfg), "localhost", dns.TypeA, true)
	if err != nil {
		d.fail("answers queries", fmt.Sprintf("no answer on %s: %s", serverAddr(cfg), shortNetErr(err)), "check `listen:` in config.yaml and `ss -lunp | grep :53`")
	} else {
		d.ok("answers queries", fmt.Sprintf("%s answered %s in %s", serverAddr(cfg), dns.RcodeToString[resp.Rcode], rtt.Round(100*time.Microsecond)))
	}
}

func (d *doctor) checkExposure(cfg *config.Config) {
	var public []string
	for _, n := range cfg.AllowNetworks {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			if a, err2 := netip.ParseAddr(n); err2 == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				d.fail("recursion ACL", fmt.Sprintf("allow_networks entry %q is not a network", n), "fix it in "+paths.ConfigFile())
				continue
			}
		}
		a := p.Addr()
		if !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) || p.Bits() == 0 {
			public = append(public, n)
		}
	}
	if len(public) > 0 {
		d.warn("recursion ACL", "recursion is allowed from public address space: "+strings.Join(public, ", "), "an open resolver gets abused for amplification attacks — restrict allow_networks unless this is deliberate and firewalled")
	} else {
		d.ok("recursion ACL", "recursion is limited to private networks: "+strings.Join(cfg.AllowNetworks, ", "))
	}
}

func (d *doctor) checkZones(cfg *config.Config) {
	running := engineUp(cfg)
	for _, name := range cfg.LocalZones {
		check := "zone " + name
		b, err := os.ReadFile(paths.LocalZoneFile(name))
		if err != nil {
			d.fail(check, "is in config.yaml but its zone file is missing", "re-create it (`minidns zone add "+name+"`) or remove it from local_zones")
			continue
		}
		info, err := zonefile.Validate(name, string(b))
		if err != nil {
			d.fail(check, "the zone file is not valid: "+err.Error(), "restore it from a backup (`minidns backup list`)")
			continue
		}
		if running {
			if got, err := servedSerial(cfg, name); err != nil || got != info.Serial {
				d.fail(check, fmt.Sprintf("the file has serial %d but unbound does not serve it (%v)", info.Serial, err), "run `sudo minidns apply`")
				continue
			}
		}
		d.ok(check, fmt.Sprintf("valid, %d records, serial %d", info.Records, info.Serial))
	}
	for _, z := range cfg.CloudZones {
		check := "replica " + z.Name
		st, err := os.Stat(paths.ZoneFile(z.Name))
		if err != nil {
			d.fail(check, "has never been synced", "sudo minidns cloud zone sync "+z.Name)
			continue
		}
		synced := st.ModTime()
		if z.Overlay {
			us, err := os.Stat(paths.UpstreamFile(z.Name))
			if err != nil {
				d.fail(check, "overlay is on but the provider copy is missing", "sudo minidns cloud zone sync "+z.Name)
				continue
			}
			synced = us.ModTime()
		}
		if age := time.Since(synced); age > time.Hour {
			d.warn(check, fmt.Sprintf("last successful sync was %s (it still serves that copy)", ago(synced)), "run `sudo minidns cloud zone sync "+z.Name+"` to see the error; check the provider token and the zonesync timer")
		} else {
			d.ok(check, "synced "+ago(synced))
		}
	}
}

func (d *doctor) checkBlocklists(cfg *config.Config) {
	if !cfg.Adblock.Enabled {
		return
	}
	state := adblock.LoadState()
	for _, l := range cfg.Adblock.Lists {
		if l.Disabled {
			continue
		}
		check := "blocklist " + l.Name
		st, err := os.Stat(paths.AdblockRPZ(l.Name))
		s := state[l.Name]
		last := s.LastSuccess
		if last.IsZero() && err == nil {
			last = st.ModTime()
		}
		switch {
		case err != nil:
			d.fail(check, "has never been downloaded", "sudo minidns blocklist update "+l.Name)
		case s.Error != "":
			d.warn(check, "the last refresh failed (the previous copy is still active): "+s.Error, "sudo minidns blocklist update "+l.Name)
		case time.Since(last) > 72*time.Hour:
			d.warn(check, "has not been refreshed for over 3 days", "check the timer: systemctl status minidns-adblock.timer")
		default:
			d.ok(check, "active")
		}
	}
}

func (d *doctor) checkForwarders(cfg *config.Config) {
	rows := forwarderRows(cfg, false, false, "")
	var active []forwarderRow
	for _, r := range rows {
		if r.Active {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		d.ok("forwarders", "none in use (full recursion)")
		return
	}
	deadByZone, totalByZone := map[string][]string{}, map[string]int{}
	for _, r := range active {
		totalByZone[r.Zone]++
		if p := probeForwarder(r); !p.OK {
			deadByZone[r.Zone] = append(deadByZone[r.Zone], fmt.Sprintf("%s (%s)", r.Address, p.Result))
		}
	}
	for zone, total := range totalByZone {
		check := "forwarders " + scopeLabel(zone)
		dead := deadByZone[zone]
		switch {
		case len(dead) == 0:
			d.ok(check, fmt.Sprintf("%d of %d answer", total, total))
		case len(dead) == total:
			d.fail(check, "none of them answers: "+strings.Join(dead, ", "), "`minidns forwarder test` — then replace them, or switch to `minidns recursion on`")
		default:
			d.warn(check, "not answering: "+strings.Join(dead, ", "), "`minidns forwarder test`")
		}
	}
}

func (d *doctor) checkHousekeeping(cfg *config.Config) {
	if !systemdBooted() {
		d.skip("timers", "this host does not run systemd")
	} else {
		want := map[string]bool{"minidns-adblock.timer": cfg.Adblock.Enabled && len(cfg.Adblock.Lists) > 0, "minidns-zonesync.timer": len(cfg.CloudZones) > 0}
		for _, unit := range []string{"minidns-adblock.timer", "minidns-zonesync.timer"} {
			if !want[unit] {
				continue
			}
			if exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil {
				d.ok("timer "+strings.TrimSuffix(strings.TrimPrefix(unit, "minidns-"), ".timer"), "active")
			} else {
				d.fail("timer "+strings.TrimSuffix(strings.TrimPrefix(unit, "minidns-"), ".timer"), unit+" is not active, so nothing refreshes automatically", "sudo systemctl enable --now "+unit)
			}
		}
	}

	var fs syscall.Statfs_t
	if err := syscall.Statfs(paths.LogDir(), &fs); err == nil && fs.Blocks > 0 {
		freeMB := fs.Bavail * uint64(fs.Bsize) >> 20
		pct := 100 * fs.Bavail / fs.Blocks
		logMB := int64(0)
		if entries, err := os.ReadDir(paths.LogDir()); err == nil {
			for _, e := range entries {
				if info, err := e.Info(); err == nil {
					logMB += info.Size()
				}
			}
			logMB >>= 20
		}
		detail := fmt.Sprintf("%d MB free (%d%%) where the query log lives; logs use %d MB", freeMB, pct, logMB)
		if freeMB < 200 || pct < 5 {
			d.fail("disk", detail, "free some space — unbound stops logging (and may stop) on a full disk")
		} else if pct < 15 {
			d.warn("disk", detail, "")
		} else {
			d.ok("disk", detail)
		}
	}
	if cfg.Logging.Queries {
		if _, err := os.Stat("/etc/logrotate.d/minidns"); err != nil && os.Getenv("MINIDNS_PREFIX") == "" {
			d.warn("log rotation", "query logging is on but /etc/logrotate.d/minidns is missing — the log will grow without bound", "reinstall the minidns package")
		}
	}
}

func systemdBooted() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}
