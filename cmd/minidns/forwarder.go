package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zones"
)

// changeConfig applies one change to config.yaml as a transaction: the new
// config is validated, saved and handed to unbound; if unbound does not take
// it, config.yaml and the generated unbound config go back to what they were.
func changeConfig(mutate func(cfg *config.Config) error) (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	previous, _ := os.ReadFile(paths.ConfigFile())
	if err := mutate(cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", zones.ErrInvalid, err)
	}
	if dryRun {
		rendered := unbound.Render(cfg)
		if err := unbound.CheckRendered(rendered); err != nil {
			return nil, applyError{fmt.Errorf("unbound would reject this change: %w", err)}
		}
		if d := confDiff(rendered); d != "" {
			note("unbound config change:\n%s", d)
		} else {
			note("(no change to the unbound config)")
		}
		return cfg, nil
	}
	if err := config.Save(cfg); err != nil {
		return nil, err
	}
	if err := cmdApplyQuiet(); err != nil {
		if len(previous) > 0 {
			os.WriteFile(paths.ConfigFile(), previous, 0o600)
		} else {
			os.Remove(paths.ConfigFile())
		}
		cmdApplyQuiet()
		return nil, applyError{fmt.Errorf("unbound rejected the change (previous configuration restored): %w", err)}
	}
	return cfg, nil
}

type forwarderRow struct {
	Zone    string `json:"zone"` // "." = global
	Address string `json:"address"`
	TLS     bool   `json:"tls"`
	Active  bool   `json:"active"` // false for global forwarders while full recursion is on
}

func forwarderRows(cfg *config.Config, global, zonesOnly bool, zone string) []forwarderRow {
	rows := []forwarderRow{}
	if !zonesOnly && zone == "" {
		for _, u := range cfg.Upstreams {
			rows = append(rows, forwarderRow{".", u, cfg.UpstreamTLS, !cfg.Recursion})
		}
	}
	if !global {
		zfs := append([]config.ZoneForwarder(nil), cfg.ZoneForwarders...)
		sort.Slice(zfs, func(i, j int) bool { return zfs[i].Zone < zfs[j].Zone })
		for _, zf := range zfs {
			if zone != "" && zf.Zone != zone {
				continue
			}
			for _, u := range zf.Servers {
				rows = append(rows, forwarderRow{zf.Zone, u, zf.TLS, true})
			}
		}
	}
	return rows
}

func parseForwarders(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		f, err := config.ParseForwarder(a)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", zones.ErrInvalid, err)
		}
		out = append(out, f.String())
	}
	return out, nil
}

func forwardZoneName(s string) (string, error) {
	z := zones.NormalizeZone(s)
	if !zones.ValidZoneName(z) {
		return "", fmt.Errorf("%w: %q is not a valid zone name", zones.ErrInvalid, s)
	}
	return z, nil
}

func forwarderCmd() *cobra.Command {
	fw := &cobra.Command{
		Use: "forwarder", Short: "Upstream DNS servers: global, or for one zone",
		Long: "Global forwarders answer everything that is not served locally (unless full\n" +
			"recursion is on — see `minidns recursion`). A zone forwarder sends one suffix or\n" +
			"reverse zone to its own servers, in either mode; DNSSEC validation is off for\n" +
			"that suffix, since internal zones have no chain of trust from the root.\n\n" +
			"Addresses are ip, ip@port or ip@port#tls-name (IPv4 or IPv6).",
	}

	var zoneFlag string
	var useTLS, noTLS bool
	add := &cobra.Command{
		Use: "add <address>... [--zone <zone>] [--tls]", Short: "Add forwarders", Args: cobra.MinimumNArgs(1),
		Example: "  minidns forwarder add 9.9.9.9 149.112.112.112 --tls\n  minidns forwarder add 10.20.0.53 --zone corp.example\n  minidns forwarder add 10.30.0.53 --zone 30.10.in-addr.arpa",
		RunE: func(cmd *cobra.Command, args []string) error {
			addrs, err := parseForwarders(args)
			if err != nil {
				return err
			}
			if useTLS && noTLS {
				return usagef("--tls and --no-tls exclude each other")
			}
			zone := ""
			if zoneFlag != "" {
				if zone, err = forwardZoneName(zoneFlag); err != nil {
					return err
				}
			}
			var added []string
			cfg, err := changeConfig(func(cfg *config.Config) error {
				if zone != "" && (cfg.HasLocalZone(zone) || cfg.FindZone(zone) != nil) {
					return fmt.Errorf("%w: %s is served from this host; a zone is either served here or forwarded", zones.ErrConflict, zone)
				}
				list, tlsFlag := &cfg.Upstreams, &cfg.UpstreamTLS
				if zone != "" {
					zf := cfg.FindZoneForwarder(zone)
					if zf == nil {
						cfg.ZoneForwarders = append(cfg.ZoneForwarders, config.ZoneForwarder{Zone: zone})
						zf = &cfg.ZoneForwarders[len(cfg.ZoneForwarders)-1]
					}
					list, tlsFlag = &zf.Servers, &zf.TLS
				}
				for _, a := range addrs {
					if !contains(*list, a) {
						*list = append(*list, a)
						added = append(added, a)
					}
				}
				if useTLS {
					*tlsFlag = true
				}
				if noTLS {
					*tlsFlag = false
				}
				return nil
			})
			if err != nil {
				return err
			}
			scope := scopeName(zone)
			return emit(map[string]any{"zone": dotIfEmpty(zone), "added": added, "changed": len(added) > 0 || useTLS || noTLS}, func() {
				if len(added) == 0 {
					fmt.Printf("Already configured for %s: %s\n", scope, strings.Join(addrs, ", "))
				} else {
					fmt.Printf("Added %s forwarder(s): %s\n", scope, strings.Join(added, ", "))
				}
				if zone == "" && cfg.Recursion {
					fmt.Println("note: full recursion is on, so global forwarders are not used — `minidns recursion off` switches to forwarding")
				}
			})
		},
	}
	add.Flags().StringVar(&zoneFlag, "zone", "", "forward only this suffix or reverse zone")
	add.Flags().BoolVar(&useTLS, "tls", false, "use DNS-over-TLS for this set of forwarders")
	add.Flags().BoolVar(&noTLS, "no-tls", false, "use plain DNS for this set of forwarders")

	var rmZone string
	remove := &cobra.Command{
		Use: "remove <address>... [--zone <zone>]", Short: "Remove forwarders", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addrs, err := parseForwarders(args)
			if err != nil {
				return err
			}
			zone := ""
			if rmZone != "" {
				if zone, err = forwardZoneName(rmZone); err != nil {
					return err
				}
			}
			_, err = changeConfig(func(cfg *config.Config) error {
				list := &cfg.Upstreams
				if zone != "" {
					zf := cfg.FindZoneForwarder(zone)
					if zf == nil {
						return fmt.Errorf("%w: no forwarders are configured for zone %s", zones.ErrNotFound, zone)
					}
					list = &zf.Servers
				}
				for _, a := range addrs {
					if !contains(*list, a) {
						return fmt.Errorf("%w: %s is not a %s forwarder", zones.ErrNotFound, a, scopeName(zone))
					}
					*list = without(*list, a)
				}
				switch {
				case zone == "" && len(*list) == 0 && !cfg.Recursion:
					return fmt.Errorf("%w: that would leave no forwarder while forwarding is the resolver mode — add another first, or switch to full recursion with `minidns recursion on`", zones.ErrConflict)
				case zone != "" && len(*list) == 0:
					out := cfg.ZoneForwarders[:0]
					for _, zf := range cfg.ZoneForwarders {
						if zf.Zone != zone {
							out = append(out, zf)
						}
					}
					cfg.ZoneForwarders = out
				}
				return nil
			})
			if err != nil {
				return err
			}
			return emit(map[string]any{"zone": dotIfEmpty(zone), "removed": addrs}, func() {
				fmt.Printf("Removed %s forwarder(s): %s\n", scopeName(zone), strings.Join(addrs, ", "))
			})
		},
	}
	remove.Flags().StringVar(&rmZone, "zone", "", "the zone the forwarder belongs to")

	var onlyGlobal, onlyZones bool
	var listZone string
	list := &cobra.Command{
		Use: "list [--global | --zones | --zone <zone>]", Short: "Show forwarders", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			rows := forwarderRows(cfg, onlyGlobal, onlyZones, zones.NormalizeZone(listZone))
			return emit(rows, func() { printForwarders(cfg, rows, onlyGlobal, onlyZones || listZone != "") })
		},
	}
	list.Flags().BoolVar(&onlyGlobal, "global", false, "only global forwarders")
	list.Flags().BoolVar(&onlyZones, "zones", false, "only zone forwarders")
	list.Flags().StringVar(&listZone, "zone", "", "only this zone's forwarders")

	var testZone string
	test := &cobra.Command{
		Use: "test [--zone <zone>]", Short: "Ask each forwarder directly and report which ones answer", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			rows := forwarderRows(cfg, false, false, zones.NormalizeZone(testZone))
			if len(rows) == 0 {
				return fmt.Errorf("%w: no forwarders to test", zones.ErrNotFound)
			}
			results := make([]probeResult, len(rows))
			failed := 0
			for i, r := range rows {
				results[i] = probeForwarder(r)
				if !results[i].OK {
					failed++
				}
			}
			err = emit(results, func() {
				fmt.Printf("%-24s %-34s %-12s %s\n", "ZONE", "FORWARDER", "RESULT", "DETAIL")
				for _, p := range results {
					fmt.Printf("%-24s %-34s %-12s %s\n", scopeLabel(p.Zone), p.Address, p.Result, p.Detail)
				}
			})
			if err == nil && failed > 0 {
				return connError{fmt.Errorf("%d of %d forwarder(s) did not answer usefully (the configuration itself is valid)", failed, len(rows))}
			}
			return err
		},
	}
	test.Flags().StringVar(&testZone, "zone", "", "only this zone's forwarders")

	markReadOnly(list, test)
	supportsDryRun(add, remove)
	fw.AddCommand(add, remove, list, test)
	return fw
}

func printForwarders(cfg *config.Config, rows []forwarderRow, onlyGlobal, onlyZones bool) {
	var global, zoned []forwarderRow
	for _, r := range rows {
		if r.Zone == "." {
			global = append(global, r)
		} else {
			zoned = append(zoned, r)
		}
	}
	if !onlyZones {
		mode := "in use"
		if cfg.Recursion {
			mode = "NOT in use: full recursion is on"
		}
		fmt.Printf("Global forwarders (%s)\n", mode)
		if len(global) == 0 {
			fmt.Println("  none")
		}
		for _, r := range global {
			fmt.Printf("  %-34s %s\n", r.Address, tlsLabel(r.TLS))
		}
	}
	if !onlyGlobal {
		if !onlyZones {
			fmt.Println()
		}
		fmt.Println("Zone forwarders")
		if len(zoned) == 0 {
			fmt.Println("  none")
		}
		for _, r := range zoned {
			fmt.Printf("  %-24s %-34s %s\n", r.Zone, r.Address, tlsLabel(r.TLS))
		}
	}
}

func tlsLabel(on bool) string {
	if on {
		return "DNS-over-TLS"
	}
	return "plain DNS"
}

func scopeName(zone string) string {
	if zone == "" {
		return "global"
	}
	return zone
}

func scopeLabel(zone string) string {
	if zone == "." {
		return "(global)"
	}
	return zone
}

func dotIfEmpty(zone string) string {
	if zone == "" {
		return "."
	}
	return zone
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// connError marks a failure to reach a server (exit code 7).
type connError struct{ err error }

func (e connError) Error() string { return e.err.Error() }
func (e connError) Unwrap() error { return e.err }

type probeResult struct {
	forwarderRow
	OK     bool    `json:"ok"`
	Result string  `json:"result"` // ok | unreachable | refused | error
	Detail string  `json:"detail"`
	RTTms  float64 `json:"rtt_ms,omitempty"`
}

// probeForwarder sends one query straight to the forwarder: the zone's SOA
// for a zone forwarder, the root NS set for a global one.
func probeForwarder(r forwarderRow) probeResult {
	res := probeResult{forwarderRow: r}
	f, err := config.ParseForwarder(r.Address)
	if err != nil {
		res.Result, res.Detail = "error", err.Error()
		return res
	}
	m := new(dns.Msg)
	if r.Zone == "." {
		m.SetQuestion(".", dns.TypeNS)
	} else {
		m.SetQuestion(dns.Fqdn(r.Zone), dns.TypeSOA)
	}
	c := &dns.Client{Timeout: 4 * time.Second}
	port := f.Port
	if r.TLS {
		c.Net = "tcp-tls"
		c.TLSConfig = &tls.Config{ServerName: f.AuthName, InsecureSkipVerify: f.AuthName == ""}
		if port == 0 {
			port = 853
		}
	} else if port == 0 {
		port = 53
	}
	resp, rtt, err := c.Exchange(m, net.JoinHostPort(f.Addr.String(), strconv.Itoa(port)))
	if err != nil {
		res.Result, res.Detail = "unreachable", shortNetErr(err)
		return res
	}
	res.RTTms = float64(rtt.Microseconds()) / 1000
	rcode := dns.RcodeToString[resp.Rcode]
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		res.OK, res.Result = true, "ok"
		res.Detail = fmt.Sprintf("%s in %s", rcode, rtt.Round(100*time.Microsecond))
	case dns.RcodeRefused:
		res.Result, res.Detail = "refused", "the server is reachable but refuses queries from this host"
	default:
		res.Result, res.Detail = "error", "the server answered "+rcode
	}
	return res
}

func shortNetErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "no answer (timeout)"
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}
