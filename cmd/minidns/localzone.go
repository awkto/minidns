package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zones"
)

// ---- activation ----------------------------------------------------------

// activateZone makes unbound serve the zone file that was just saved and
// proves it did: the zone is hot-reloaded on its own (no daemon reload, the
// cache survives) and the SOA serial unbound answers with must be the one we
// wrote. If not, the previous file is restored and reloaded.
func activateZone(cfg *config.Config, z *zones.Zone) error {
	if z.Overlay {
		return activateOverlay(cfg, z)
	}
	if !unbound.Active() {
		note("note: unbound is not running — %s was written and will be served once it starts", z.Name)
		return nil
	}
	err := reloadAndVerify(cfg, z.Name, z.Serial)
	if err == nil {
		return nil
	}
	undoZone(cfg, z)
	return applyError{fmt.Errorf("unbound did not accept the change to %s (previous zone restored): %w", z.Name, err)}
}

func reloadAndVerify(cfg *config.Config, zone string, serial uint32) error {
	if _, err := unbound.Control("auth_zone_reload", dns.Fqdn(zone)); err != nil {
		return err
	}
	got, err := servedSerial(cfg, zone)
	if err != nil {
		return err
	}
	if got != serial {
		return fmt.Errorf("unbound serves serial %d, expected %d", got, serial)
	}
	return nil
}

// serverAddr is where the local unbound can be queried.
func serverAddr(cfg *config.Config) string {
	host := "127.0.0.1"
	if len(cfg.Listen) > 0 {
		first, _, _ := strings.Cut(cfg.Listen[0], "@")
		if a, err := netip.ParseAddr(first); err == nil && !a.IsUnspecified() {
			host = a.String()
		}
	}
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(cfg.Port)).String()
}

func servedSerial(cfg *config.Config, zone string) (uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	c := &dns.Client{Timeout: 3 * time.Second}
	var lastErr error
	for i := 0; i < 5; i++ {
		resp, _, err := c.Exchange(m, serverAddr(cfg))
		if err == nil {
			for _, rr := range resp.Answer {
				if soa, ok := rr.(*dns.SOA); ok {
					return soa.Serial, nil
				}
			}
			lastErr = fmt.Errorf("no SOA in the answer for %s (rcode %s)", zone, dns.RcodeToString[resp.Rcode])
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, lastErr
}

// ---- zone ----------------------------------------------------------------

type zoneSummary struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // forward | reverse
	Serial  uint32 `json:"serial"`
	Records int    `json:"records"`
}

func summarize(z *zones.Zone) zoneSummary {
	kind := "forward"
	if zones.IsReverse(z.Name) {
		kind = "reverse"
	}
	return zoneSummary{Name: z.Name, Kind: kind, Serial: z.Serial, Records: len(z.UserRecords())}
}

// createZone is shared by `zone add` and `reverse-zone add`.
func createZone(name, ns, email string) (*zones.Zone, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	name = zones.NormalizeZone(name)
	if cfg.FindZone(name) != nil {
		return nil, fmt.Errorf("%w: %s is a cloud replica on this host; remove it first (`minidns cloud zone remove %s`) if you want to own the zone locally", zones.ErrConflict, name, name)
	}
	if cfg.HasLocalZone(name) && zones.Exists(name) {
		return nil, fmt.Errorf("%w: zone %s already exists", zones.ErrConflict, name)
	}
	z, err := zones.Create(name, ns, email)
	if err != nil {
		return nil, err
	}
	if !cfg.HasLocalZone(name) {
		cfg.LocalZones = append(cfg.LocalZones, name)
		sort.Strings(cfg.LocalZones)
	}
	undo := func() {
		cfg.LocalZones = without(cfg.LocalZones, name)
		config.Save(cfg)
		cmdApplyQuiet()
		zones.Remove(name)
	}
	if err := config.Save(cfg); err != nil {
		zones.Remove(name)
		return nil, err
	}
	// a new zone needs a new auth-zone clause, i.e. a config reload
	if err := cmdApplyQuiet(); err != nil {
		undo()
		return nil, applyError{fmt.Errorf("unbound rejected the new zone (nothing was changed): %w", err)}
	}
	if unbound.Active() {
		if got, err := servedSerial(cfg, name); err != nil || got != z.Serial {
			undo()
			return nil, applyError{fmt.Errorf("unbound is not serving %s after the reload (zone removed again): %v", name, err)}
		}
	}
	return z, nil
}

func without(list []string, s string) []string {
	out := list[:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func zoneCmd() *cobra.Command {
	zone := &cobra.Command{Use: "zone", Short: "Local authoritative zones (owned and edited on this host)"}

	var ns, email, provider string
	add := &cobra.Command{
		Use: "add <zone>", Short: "Create a local authoritative zone", Args: cobra.ExactArgs(1),
		Example: "  minidns zone add home.arpa\n  minidns record add home.arpa nas A 10.20.0.10",
		RunE: func(cmd *cobra.Command, args []string) error {
			if provider != "" { // v0.1 spelling of `cloud zone add`
				deprecated("zone add --provider", "cloud zone add "+args[0]+" --provider "+provider)
				return cmdZone([]string{"add", args[0], "--provider", provider})
			}
			z, err := createZone(args[0], ns, email)
			if err != nil {
				return err
			}
			return emit(summarize(z), func() {
				fmt.Printf("Zone %q added (serial %d). Add records with: minidns record add %s <name> <type> <value>\n", z.Name, z.Serial, z.Name)
			})
		},
	}
	add.Flags().StringVar(&ns, "ns", "", "primary name server for the SOA/NS records (default: localhost.)")
	add.Flags().StringVar(&email, "email", "", "zone contact (default: hostmaster@<zone>)")
	add.Flags().StringVar(&provider, "provider", "", "")
	add.Flags().MarkHidden("provider")

	list := &cobra.Command{
		Use: "list", Short: "List local zones", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			out := []zoneSummary{}
			for _, name := range cfg.LocalZones {
				z, err := zones.Load(name)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: %v\n", err)
					continue
				}
				out = append(out, summarize(z))
			}
			return emit(out, func() {
				if len(out) == 0 {
					fmt.Println("no local zones — create one with `minidns zone add <zone>`")
					return
				}
				fmt.Printf("%-40s %-8s %-11s %s\n", "ZONE", "KIND", "SERIAL", "RECORDS")
				for _, s := range out {
					fmt.Printf("%-40s %-8s %-11d %d\n", s.Name, s.Kind, s.Serial, s.Records)
				}
			})
		},
	}

	show := &cobra.Command{
		Use: "show <zone>", Short: "Show a zone and its records", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, err := loadLocal(args[0])
			if err != nil {
				return err
			}
			return emit(z, func() {
				fmt.Printf("zone %s — serial %d, %d records\n\n", z.Name, z.Serial, len(z.UserRecords()))
				printRecords(z, z.Records)
			})
		},
	}

	var force bool
	remove := &cobra.Command{
		Use: "remove <zone>", Short: "Delete a local zone", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, err := loadLocal(args[0])
			if err != nil {
				return err
			}
			if n := userData(z); n > 0 && !force {
				return fmt.Errorf("%w: zone %s still holds %d record(s); re-run with --force to delete it and them", zones.ErrConflict, z.Name, n)
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.LocalZones = without(cfg.LocalZones, z.Name)
			if err := config.Save(cfg); err != nil {
				return err
			}
			// config first, file second: unbound exits if it reloads while
			// a zonefile it still references is gone
			if err := cmdApplyQuiet(); err != nil {
				return applyError{err}
			}
			if err := zones.Remove(z.Name); err != nil {
				return err
			}
			return emit(map[string]any{"removed": z.Name}, func() { fmt.Printf("Zone %q removed.\n", z.Name) })
		},
	}
	remove.Flags().BoolVar(&force, "force", false, "delete the zone even though it still has records")

	// v0.1 spelling of `cloud zone sync`; the systemd unit of an old install
	// may still call it during an upgrade
	sync := &cobra.Command{
		Use: "sync", Hidden: true, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			deprecated("zone sync", "cloud zone sync")
			return cmdZone(append([]string{"sync"}, args...))
		},
	}

	markReadOnly(list, show)
	zone.AddCommand(add, list, show, remove, sync)
	return zone
}

// userData counts the records an operator would miss: everything except the
// SOA and the apex NS that `zone add` created.
func userData(z *zones.Zone) int {
	n := 0
	for _, r := range z.UserRecords() {
		if !(r.Type == "NS" && r.Name == z.Origin()) {
			n++
		}
	}
	return n
}

func loadLocal(name string) (*zones.Zone, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	name = zones.NormalizeZone(name)
	if !cfg.HasLocalZone(name) {
		if cfg.FindZone(name) != nil {
			return nil, fmt.Errorf("%w: %s is a cloud replica, not a local zone (see `minidns cloud zone list`)", zones.ErrInvalid, name)
		}
		return nil, fmt.Errorf("%w: no local zone %s (see `minidns zone list`)", zones.ErrNotFound, name)
	}
	return zones.Load(name)
}

func readOnlyReplica(name string) error {
	return fmt.Errorf("%w: %s is a read-only cloud replica — change it at the provider, or allow local-only records on top of it with `minidns cloud zone overlay enable %s`", zones.ErrInvalid, name, name)
}

// loadEditable returns what `record` may change: a local zone, or the
// overlay of a replica that has one enabled.
func loadEditable(name string) (*zones.Zone, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	name = zones.NormalizeZone(name)
	if rz := cfg.FindZone(name); rz != nil {
		if !rz.Overlay {
			return nil, readOnlyReplica(name)
		}
		return zones.LoadOverlay(name)
	}
	return loadLocal(name)
}

// loadView returns a zone for reading: a local zone, or what a replica
// serves with every record marked by where it comes from.
func loadView(name string) (*zones.Zone, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if rz := cfg.FindZone(name); rz != nil {
		return replicaView(*rz)
	}
	return loadLocal(name)
}

func printRecords(z *zones.Zone, recs []zones.Record) {
	sourced := false
	for _, r := range recs {
		sourced = sourced || r.Source != ""
	}
	if sourced {
		fmt.Printf("%-36s %-6s %-6s %-13s %s\n", "NAME", "TTL", "TYPE", "SOURCE", "VALUE")
	} else {
		fmt.Printf("%-36s %-6s %-6s %s\n", "NAME", "TTL", "TYPE", "VALUE")
	}
	for _, r := range recs {
		value := r.Value
		if r.ManagedBy != "" {
			value += "   (managed by " + r.ManagedBy + ")"
		}
		if sourced {
			fmt.Printf("%-36s %-6d %-6s %-13s %s\n", r.Name, r.TTL, r.Type, r.Source, value)
		} else {
			fmt.Printf("%-36s %-6d %-6s %s\n", r.Name, r.TTL, r.Type, value)
		}
	}
}

// ---- record --------------------------------------------------------------

func recordCmd() *cobra.Command {
	record := &cobra.Command{Use: "record", Short: "Records in local zones, and local overlay records on cloud replicas"}

	var ttl uint32
	var managedBy string
	add := &cobra.Command{
		Use: "add <zone> <name> <type> <value>...", Short: "Add a record (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR)",
		Args: cobra.MinimumNArgs(4),
		Example: `  minidns record add home.arpa nas A 10.20.0.10
  minidns record add home.arpa git CNAME nas
  minidns record add home.arpa @ MX 10 mail.home.arpa.
  minidns record add home.arpa @ TXT "v=spf1 -all"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			z, err := loadEditable(args[0])
			if err != nil {
				return err
			}
			rec, added, err := z.Add(args[1], args[2], strings.Join(args[3:], " "), ttl, managedBy)
			if err != nil {
				return err
			}
			if added {
				if err := saveAndActivate(z); err != nil {
					return err
				}
			}
			out := map[string]any{"zone": z.Name, "serial": z.Serial, "changed": added, "record": rec}
			var hidden []zones.Record
			if z.Overlay {
				out["overlay"] = true
				if cfg, err := config.Load(); err == nil {
					if rz := cfg.FindZone(z.Name); rz != nil {
						hidden = overlayShadows(*rz, rec.Name)
					}
				}
				out["shadows"] = hidden
			}
			return emit(out, func() {
				if !added {
					fmt.Printf("Already present: %s %s %s (zone %s unchanged)\n", rec.Name, rec.Type, rec.Value, z.Name)
					return
				}
				if !z.Overlay {
					fmt.Printf("Added %s %d %s %s (zone %s, serial %d)\n", rec.Name, rec.TTL, rec.Type, rec.Value, z.Name, z.Serial)
					return
				}
				fmt.Printf("Added %s %d %s %s as a local overlay on replica %s (serial %d) — it exists only on this resolver\n", rec.Name, rec.TTL, rec.Type, rec.Value, z.Name, z.Serial)
				for _, h := range hidden {
					fmt.Printf("  hides the provider's record: %s %s %s\n", h.Name, h.Type, h.Value)
				}
			})
		},
	}
	add.Flags().Uint32Var(&ttl, "ttl", 0, fmt.Sprintf("time to live in seconds (default %d)", zones.DefaultTTL))
	add.Flags().StringVar(&managedBy, "managed-by", "", "tag the record as owned by another tool (e.g. minidhcp)")

	var filterManaged, filterType string
	var overlayOnly bool
	list := &cobra.Command{
		Use: "list <zone>", Short: "List the records of a zone", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, err := loadView(args[0])
			if err != nil {
				return err
			}
			recs := []zones.Record{}
			for _, r := range z.UserRecords() {
				if filterManaged != "" && r.ManagedBy != filterManaged {
					continue
				}
				if filterType != "" && !strings.EqualFold(r.Type, filterType) {
					continue
				}
				if overlayOnly && r.Source != zones.SourceOverlay {
					continue
				}
				recs = append(recs, r)
			}
			return emit(recs, func() {
				if len(recs) == 0 {
					fmt.Println("no matching records")
					return
				}
				printRecords(z, recs)
			})
		},
	}
	list.Flags().BoolVar(&overlayOnly, "overlay", false, "on a replica: only the local overlay records")
	list.Flags().StringVar(&filterManaged, "managed-by", "", "only records tagged with this owner")
	list.Flags().StringVar(&filterType, "type", "", "only records of this type")

	remove := &cobra.Command{
		Use: "remove <zone> <name> <type> [value...]", Short: "Remove records (all of that name and type, or just the given value)",
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, err := loadEditable(args[0])
			if err != nil {
				return err
			}
			removed, err := z.Remove(args[1], args[2], strings.Join(args[3:], " "))
			if err != nil {
				return err
			}
			if err := saveAndActivate(z); err != nil {
				return err
			}
			return emit(map[string]any{"zone": z.Name, "serial": z.Serial, "removed": removed}, func() {
				for _, r := range removed {
					fmt.Printf("Removed %s %s %s\n", r.Name, r.Type, r.Value)
				}
				fmt.Printf("(zone %s, serial %d)\n", z.Name, z.Serial)
			})
		},
	}

	markReadOnly(list)
	record.AddCommand(add, list, remove)
	return record
}

func saveAndActivate(z *zones.Zone) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := z.Save(); err != nil {
		return err
	}
	return activateZone(cfg, z)
}

// ---- reverse-zone --------------------------------------------------------

func reverseZoneCmd() *cobra.Command {
	rz := &cobra.Command{Use: "reverse-zone", Short: "Reverse-lookup (PTR) zones"}
	add := &cobra.Command{
		Use: "add <cidr>", Short: "Create the reverse zone for a network", Args: cobra.ExactArgs(1),
		Example: "  minidns reverse-zone add 10.20.0.0/24\n  minidns reverse-zone add fd00:1234::/32",
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix, err := netip.ParsePrefix(args[0])
			if err != nil {
				return fmt.Errorf("%w: %q is not a network in CIDR form (e.g. 10.20.0.0/24)", zones.ErrInvalid, args[0])
			}
			name, widened, err := zones.ReverseZoneFor(prefix)
			if err != nil {
				return err
			}
			if widened {
				note("note: reverse DNS is delegated on %s boundaries, so %s is served by the enclosing zone %s",
					map[bool]string{true: "octet", false: "nibble"}[prefix.Addr().Is4()], prefix.Masked(), name)
			}
			z, err := createZone(name, "", "")
			if err != nil {
				return err
			}
			return emit(summarize(z), func() {
				fmt.Printf("Reverse zone %q added for %s. `minidns host add` will now create PTR records in it.\n", z.Name, prefix.Masked())
			})
		},
	}
	rz.AddCommand(add)
	return rz
}

// ---- host ----------------------------------------------------------------

// hostChange records one thing a host command did, for the report.
type hostChange struct {
	Action string       `json:"action"` // added | removed | skipped
	Zone   string       `json:"zone,omitempty"`
	Record zones.Record `json:"record,omitempty"`
	Note   string       `json:"note,omitempty"`
}

// zoneSet loads zones lazily and saves/activates each touched zone once.
type zoneSet struct {
	cfg     *config.Config
	loaded  map[string]*zones.Zone
	touched map[string]bool
}

func newZoneSet() (*zoneSet, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return &zoneSet{cfg: cfg, loaded: map[string]*zones.Zone{}, touched: map[string]bool{}}, nil
}

func (s *zoneSet) get(name string) (*zones.Zone, error) {
	if z, ok := s.loaded[name]; ok {
		return z, nil
	}
	var z *zones.Zone
	var err error
	if rz := s.cfg.FindZone(name); rz != nil && rz.Overlay {
		z, err = zones.LoadOverlay(name)
	} else {
		z, err = zones.Load(name)
	}
	if err == nil {
		s.loaded[name] = z
	}
	return z, err
}

func (s *zoneSet) commit() error {
	names := make([]string, 0, len(s.touched))
	for n := range s.touched {
		names = append(names, n)
	}
	sort.Strings(names)
	var done []string
	for _, n := range names {
		z := s.loaded[n]
		err := z.Save()
		if err == nil {
			err = activateZone(s.cfg, z)
		}
		if err != nil {
			// undo the zones already activated so forward and reverse stay in step
			for _, d := range done {
				undoZone(s.cfg, s.loaded[d])
			}
			return err
		}
		done = append(done, n)
	}
	return nil
}

// forwardZoneFor resolves which local forward zone a host name belongs to.
func (s *zoneSet) forwardZoneFor(name, zoneFlag string) (string, error) {
	if zoneFlag != "" {
		z := zones.NormalizeZone(zoneFlag)
		if rz := s.cfg.FindZone(z); rz != nil && !rz.Overlay {
			return "", readOnlyReplica(z)
		}
		if !s.cfg.HasLocalZone(z) && s.cfg.FindZone(z) == nil {
			return "", fmt.Errorf("%w: no local zone %s", zones.ErrNotFound, z)
		}
		return z, nil
	}
	var forward []string
	best := ""
	fq := dns.Fqdn(strings.ToLower(name))
	candidates := append([]string(nil), s.cfg.LocalZones...)
	for _, rz := range s.cfg.CloudZones {
		if rz.Overlay {
			candidates = append(candidates, rz.Name)
		}
	}
	for _, z := range candidates {
		if zones.IsReverse(z) {
			continue
		}
		forward = append(forward, z)
		if strings.Contains(name, ".") && dns.IsSubDomain(dns.Fqdn(z), fq) && len(z) > len(best) {
			best = z
		}
	}
	switch {
	case best != "":
		return best, nil
	case len(forward) == 1:
		return forward[0], nil
	case len(forward) == 0:
		return "", fmt.Errorf("%w: there is no local zone yet — create one with `minidns zone add <zone>`", zones.ErrNotFound)
	}
	return "", usagef("several local zones exist (%s): say which with --zone", strings.Join(forward, ", "))
}

func hostCmd() *cobra.Command {
	host := &cobra.Command{Use: "host", Short: "Hosts: address records and their PTRs managed together"}

	var ips []string
	var zoneFlag, managedBy string
	var ttl uint32
	add := &cobra.Command{
		Use: "add <name> --ip <address> [--ip <address>...]", Short: "Add A/AAAA records and the matching PTRs", Args: cobra.ExactArgs(1),
		Example: "  minidns host add nas --ip 10.20.0.10 --zone home.arpa\n  minidns host add nas --ip 10.20.0.10 --ip fd00::10",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(ips) == 0 {
				return usagef("host add needs at least one --ip")
			}
			set, err := newZoneSet()
			if err != nil {
				return err
			}
			zoneName, err := set.forwardZoneFor(args[0], zoneFlag)
			if err != nil {
				return err
			}
			fwd, err := set.get(zoneName)
			if err != nil {
				return err
			}
			fqdn, err := fwd.Owner(args[0])
			if err != nil {
				return err
			}
			var changes []hostChange
			for _, raw := range ips {
				addr, err := netip.ParseAddr(raw)
				if err != nil {
					return fmt.Errorf("%w: %q is not an IP address", zones.ErrInvalid, raw)
				}
				addr = addr.Unmap()
				rrtype := "AAAA"
				if addr.Is4() {
					rrtype = "A"
				}
				rec, added, err := fwd.Add(fqdn, rrtype, addr.String(), ttl, managedBy)
				if err != nil {
					return err
				}
				changes = append(changes, change(added, fwd.Name, rec))
				set.touched[fwd.Name] = set.touched[fwd.Name] || added

				rev := zones.BestReverseZone(set.cfg.LocalZones, addr)
				if rev == "" {
					changes = append(changes, hostChange{Action: "skipped", Note: fmt.Sprintf("no local reverse zone covers %s — no PTR created (minidns reverse-zone add <cidr>)", addr)})
					continue
				}
				rz, err := set.get(rev)
				if err != nil {
					return err
				}
				ptr, added, err := rz.Add(zones.PTRName(addr), "PTR", fqdn, ttl, managedBy)
				if err != nil {
					return err
				}
				changes = append(changes, change(added, rz.Name, ptr))
				set.touched[rz.Name] = set.touched[rz.Name] || added
			}
			if err := set.commit(); err != nil {
				return err
			}
			return reportHost(fqdn, changes)
		},
	}
	add.Flags().StringArrayVar(&ips, "ip", nil, "IPv4 or IPv6 address (repeatable)")
	add.Flags().StringVar(&zoneFlag, "zone", "", "forward zone (optional when there is only one, or the name is fully qualified)")
	add.Flags().Uint32Var(&ttl, "ttl", 0, fmt.Sprintf("time to live in seconds (default %d)", zones.DefaultTTL))
	add.Flags().StringVar(&managedBy, "managed-by", "", "tag the records as owned by another tool (e.g. minidhcp)")

	var rmZone string
	remove := &cobra.Command{
		Use: "remove <name>", Short: "Remove a host's address records and PTRs", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := newZoneSet()
			if err != nil {
				return err
			}
			fqdn, changes, err := set.dropHost(args[0], rmZone)
			if err != nil {
				return err
			}
			if err := set.commit(); err != nil {
				return err
			}
			return reportHost(fqdn, changes)
		},
	}
	remove.Flags().StringVar(&rmZone, "zone", "", "forward zone (optional when unambiguous)")

	var mvZone string
	rename := &cobra.Command{
		Use: "rename <old> <new>", Short: "Rename a host, keeping its addresses and PTRs", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := newZoneSet()
			if err != nil {
				return err
			}
			zoneName, err := set.forwardZoneFor(args[0], mvZone)
			if err != nil {
				return err
			}
			fwd, err := set.get(zoneName)
			if err != nil {
				return err
			}
			newFQDN, err := fwd.Owner(args[1])
			if err != nil {
				return err
			}
			oldFQDN, err := fwd.Owner(args[0])
			if err != nil {
				return err
			}
			// remember addresses (with ttl/tag) before dropping the old name
			var addrs []zones.Record
			for _, r := range fwd.Records {
				if r.Name == oldFQDN && (r.Type == "A" || r.Type == "AAAA") {
					addrs = append(addrs, r)
				}
			}
			_, changes, err := set.dropHost(args[0], zoneName)
			if err != nil {
				return err
			}
			for _, r := range addrs {
				rec, added, err := fwd.Add(newFQDN, r.Type, r.Value, r.TTL, r.ManagedBy)
				if err != nil {
					return err
				}
				changes = append(changes, change(added, fwd.Name, rec))
				addr, _ := netip.ParseAddr(r.Value)
				if rev := zones.BestReverseZone(set.cfg.LocalZones, addr); rev != "" {
					rz, err := set.get(rev)
					if err != nil {
						return err
					}
					ptr, added, err := rz.Add(zones.PTRName(addr), "PTR", newFQDN, r.TTL, r.ManagedBy)
					if err != nil {
						return err
					}
					changes = append(changes, change(added, rz.Name, ptr))
					set.touched[rz.Name] = true
				}
			}
			for _, r := range fwd.Records {
				if r.Type == "CNAME" && r.Value == oldFQDN {
					changes = append(changes, hostChange{Action: "skipped", Zone: fwd.Name, Record: r, Note: "this CNAME still points at the old name — update it if you want it to follow"})
				}
			}
			if err := set.commit(); err != nil {
				return err
			}
			return reportHost(newFQDN, changes)
		},
	}
	rename.Flags().StringVar(&mvZone, "zone", "", "forward zone (optional when unambiguous)")

	host.AddCommand(add, remove, rename)
	return host
}

func change(added bool, zone string, rec zones.Record) hostChange {
	if added {
		return hostChange{Action: "added", Zone: zone, Record: rec}
	}
	return hostChange{Action: "skipped", Zone: zone, Record: rec, Note: "already present"}
}

// dropHost removes the A/AAAA records of a host and every PTR in a local
// reverse zone that points at it.
func (s *zoneSet) dropHost(name, zoneFlag string) (string, []hostChange, error) {
	zoneName, err := s.forwardZoneFor(name, zoneFlag)
	if err != nil {
		return "", nil, err
	}
	fwd, err := s.get(zoneName)
	if err != nil {
		return "", nil, err
	}
	fqdn, err := fwd.Owner(name)
	if err != nil {
		return "", nil, err
	}
	var changes []hostChange
	for _, t := range []string{"A", "AAAA"} {
		removed, err := fwd.Remove(fqdn, t, "")
		if errors.Is(err, zones.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		for _, r := range removed {
			changes = append(changes, hostChange{Action: "removed", Zone: fwd.Name, Record: r})
		}
		s.touched[fwd.Name] = true
	}
	if len(changes) == 0 {
		return "", nil, fmt.Errorf("%w: %s has no address records in zone %s", zones.ErrNotFound, fqdn, fwd.Name)
	}
	for _, zn := range s.cfg.LocalZones {
		if !zones.IsReverse(zn) {
			continue
		}
		rz, err := s.get(zn)
		if err != nil {
			continue
		}
		for _, r := range append([]zones.Record(nil), rz.Records...) {
			if r.Type == "PTR" && r.Value == fqdn {
				if _, err := rz.Remove(r.Name, "PTR", r.Value); err == nil {
					changes = append(changes, hostChange{Action: "removed", Zone: rz.Name, Record: r})
					s.touched[rz.Name] = true
				}
			}
		}
	}
	return fqdn, changes, nil
}

func reportHost(fqdn string, changes []hostChange) error {
	return emit(map[string]any{"host": fqdn, "changes": changes}, func() {
		fmt.Printf("Host %s\n", fqdn)
		for _, c := range changes {
			switch {
			case c.Record.Name == "":
				fmt.Printf("  %-8s %s\n", c.Action, c.Note)
			case c.Note != "":
				fmt.Printf("  %-8s %s %s %s  (%s)\n", c.Action, c.Record.Name, c.Record.Type, c.Record.Value, c.Note)
			default:
				fmt.Printf("  %-8s %s %s %s\n", c.Action, c.Record.Name, c.Record.Type, c.Record.Value)
			}
		}
	})
}
