package main

import (
	"fmt"
	"os"
	"sort"
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

// ---- explain -------------------------------------------------------------

// ruleMatch is one policy rule that covers a name.
type ruleMatch struct {
	Source string `json:"source"` // allowlist | manual | blocklist
	List   string `json:"list,omitempty"`
	Rule   string `json:"rule"`
	Action string `json:"action"` // allow | nxdomain
}

func (m ruleMatch) String() string {
	switch m.Source {
	case "allowlist":
		return fmt.Sprintf("allowlist rule %s", m.Rule)
	case "manual":
		return fmt.Sprintf("manual block %s", m.Rule)
	}
	return fmt.Sprintf("blocklist %q rule %s", m.List, m.Rule)
}

// explanation is the filtering verdict for one name, derived from the same
// files, in the same order, that unbound applies (first match wins).
type explanation struct {
	Name       string      `json:"name"`
	Blocked    bool        `json:"blocked"`
	Action     string      `json:"action"` // none | allow | nxdomain
	Effective  *ruleMatch  `json:"effective,omitempty"`
	Overridden []ruleMatch `json:"overridden,omitempty"` // matches that lost to the effective rule
	Inactive   []ruleMatch `json:"inactive,omitempty"`   // matches in switched-off rule sets
	ServedFrom string      `json:"served_from,omitempty"`
}

func explain(cfg *config.Config, name string) explanation {
	name = rpz.Normalize(name)
	ex := explanation{Name: name, Action: "none"}
	var matches []ruleMatch
	add := func(active bool, m ruleMatch) {
		if active {
			matches = append(matches, m)
		} else {
			ex.Inactive = append(ex.Inactive, m)
		}
	}
	if rule, ok := rpz.Contains(paths.AllowRPZ(), name); ok {
		add(true, ruleMatch{Source: "allowlist", Rule: rule, Action: "allow"})
	}
	if rule, ok := rpz.Contains(paths.BlockRPZ(), name); ok {
		add(cfg.Firewall.Enabled, ruleMatch{Source: "manual", Rule: rule, Action: "nxdomain"})
	}
	lists := append([]config.BlockList(nil), cfg.Adblock.Lists...)
	sort.Slice(lists, func(i, j int) bool { return lists[i].Name < lists[j].Name })
	for _, l := range lists {
		if rule, ok := rpz.Contains(paths.AdblockRPZ(l.Name), name); ok {
			add(cfg.Adblock.Enabled && !l.Disabled, ruleMatch{Source: "blocklist", List: l.Name, Rule: rule, Action: "nxdomain"})
		}
	}
	if len(matches) > 0 {
		ex.Effective, ex.Overridden = &matches[0], matches[1:]
		ex.Action = matches[0].Action
		ex.Blocked = ex.Action == "nxdomain"
	}
	for _, lz := range cfg.LocalZones {
		if name == lz || strings.HasSuffix(name, "."+lz) {
			ex.ServedFrom = "local zone " + lz
		}
	}
	if z := matchZone(cfg, name); z != nil {
		ex.ServedFrom = "local mirror of " + z.Name
	}
	return ex
}

// oneLine is the verdict as `minidns test` has always phrased it.
func (ex explanation) oneLine() string {
	v := "not blocked"
	if m := ex.Effective; m != nil {
		switch m.Source {
		case "allowlist":
			v = fmt.Sprintf("allowlisted (matches %s)", m.Rule)
		case "manual":
			v = fmt.Sprintf("blocked by firewall (matches %s)", m.Rule)
		default:
			v = fmt.Sprintf("blocked by adblock list %q (matches %s)", m.List, m.Rule)
		}
	}
	if ex.ServedFrom != "" {
		if ex.Effective == nil {
			return "served from " + ex.ServedFrom
		}
		return "served from " + ex.ServedFrom + "; " + v
	}
	return v
}

func (ex explanation) print() {
	switch {
	case ex.Blocked:
		fmt.Printf("%s is BLOCKED (answer: NXDOMAIN)\n", ex.Name)
	case ex.Effective != nil:
		fmt.Printf("%s is ALLOWED by an allowlist override\n", ex.Name)
	default:
		fmt.Printf("%s is not blocked\n", ex.Name)
	}
	if ex.Effective != nil {
		fmt.Printf("  matching rule   %s\n", ex.Effective.Rule)
		origin := map[string]string{"allowlist": "the allowlist (minidns allow)", "manual": "a manual block (minidns block)"}[ex.Effective.Source]
		if origin == "" {
			origin = fmt.Sprintf("subscribed blocklist %q", ex.Effective.List)
		}
		fmt.Printf("  comes from      %s\n", origin)
	}
	for _, m := range ex.Overridden {
		verb := "also matched by"
		if !ex.Blocked {
			verb = "overrides"
		}
		fmt.Printf("  %-15s %s\n", verb, m)
	}
	for _, m := range ex.Inactive {
		fmt.Printf("  switched off    %s (its rule set is disabled)\n", m)
	}
	if ex.ServedFrom != "" {
		fmt.Printf("  served from     %s\n", ex.ServedFrom)
	}
}

// ---- block / allow -------------------------------------------------------

type ruleSet struct {
	noun, path, action, zone, listHint string
}

var (
	blockRules = ruleSet{"block", "", rpz.ActionBlock, "block.rpz.minidns.", "manual blocks"}
	allowRules = ruleSet{"allow", "", rpz.ActionPassthru, "allow.rpz.minidns.", "allowlist entries"}
)

func (r ruleSet) file() string {
	if r.noun == "allow" {
		return paths.AllowRPZ()
	}
	return paths.BlockRPZ()
}

func checkDomains(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for _, a := range args {
		d := rpz.Normalize(a)
		if !rpz.ValidDomain(strings.TrimPrefix(d, "*.")) {
			return nil, fmt.Errorf("%w: %q doesn't look like a domain", zones.ErrInvalid, a)
		}
		out = append(out, d)
	}
	return out, nil
}

func (r ruleSet) addCmd(extra func(*cobra.Command)) *cobra.Command {
	c := &cobra.Command{
		Use: "add <domain>...", Short: "Add " + r.listHint + " (each covers its subdomains too)", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a, _ := cmd.Flags().GetString("action"); a != "" && !strings.EqualFold(a, "nxdomain") {
				return fmt.Errorf("%w: action %q is not implemented — blocked names answer NXDOMAIN", zones.ErrInvalid, a)
			}
			domains, err := checkDomains(args)
			if err != nil {
				return err
			}
			have, _ := rpz.ReadAll(r.file())
			var added []string
			for _, d := range domains {
				if _, ok := have[d]; !ok {
					added = append(added, d)
				}
			}
			if len(added) > 0 {
				if err := editRPZ(r.file(), r.action, r.zone, added, nil); err != nil {
					return applyError{err}
				}
			}
			return emit(map[string]any{"added": added, "changed": len(added) > 0}, func() {
				if len(added) == 0 {
					fmt.Printf("Already present: %s\n", strings.Join(domains, ", "))
					return
				}
				if r.noun == "allow" {
					fmt.Printf("Allowed: %s (overrides manual blocks and blocklists)\n", strings.Join(added, ", "))
				} else {
					fmt.Printf("Blocked: %s (and subdomains)\n", strings.Join(added, ", "))
				}
			})
		},
	}
	if extra != nil {
		extra(c)
	}
	return c
}

func (r ruleSet) removeCmd() *cobra.Command {
	return &cobra.Command{
		Use: "remove <domain>...", Short: "Remove " + r.listHint, Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domains, err := checkDomains(args)
			if err != nil {
				return err
			}
			current, err := rpz.ReadDomains(r.file())
			if err != nil {
				return err
			}
			for _, d := range domains {
				if !contains(current, d) {
					return fmt.Errorf("%w: %s is not in the %s list (see `minidns %s list`)", zones.ErrNotFound, d, r.noun, r.noun)
				}
			}
			if err := editRPZ(r.file(), r.action, r.zone, nil, domains); err != nil {
				return applyError{err}
			}
			return emit(map[string]any{"removed": domains}, func() {
				fmt.Printf("Removed from the %s list: %s\n", r.noun, strings.Join(domains, ", "))
			})
		},
	}
}

func (r ruleSet) listCmd() *cobra.Command {
	c := &cobra.Command{
		Use: "list", Short: "Show " + r.listHint, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			domains, err := rpz.ReadDomains(r.file())
			if err != nil {
				return err
			}
			if domains == nil {
				domains = []string{}
			}
			return emit(domains, func() {
				if len(domains) == 0 {
					fmt.Printf("no %s — add one with `minidns %s add <domain>`\n", r.listHint, r.noun)
				}
				for _, d := range domains {
					fmt.Println(d)
				}
			})
		},
	}
	markReadOnly(c)
	return c
}

// legacyVerb lets `minidns block example.com` (v0.1) keep working next to
// `minidns block add example.com`.
func legacyVerb(parent *cobra.Command, old string, add *cobra.Command) {
	parent.Args = cobra.ArbitraryArgs
	parent.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		deprecated(old+" <domain>", old+" add <domain>")
		return add.RunE(add, args)
	}
}

func blockCmd() *cobra.Command {
	block := &cobra.Command{Use: "block", Short: "Manual blocks (the DNS firewall)"}
	add := blockRules.addCmd(func(c *cobra.Command) {
		c.Flags().String("action", "", "what blocked names answer (only nxdomain is implemented)")
	})

	explainCmd := &cobra.Command{
		Use: "explain <name>", Short: "Say whether a name is blocked, by which rule, from which list", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if _, err := checkDomains(args); err != nil {
				return err
			}
			ex := explain(cfg, args[0])
			return emit(ex, ex.print)
		},
	}

	test := &cobra.Command{
		Use: "test <name>", Short: "Ask the running server and compare with what the rules say", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if _, err := checkDomains(args); err != nil {
				return err
			}
			ex := explain(cfg, args[0])
			resp, _, err := exchange(serverAddr(cfg), ex.Name, dns.TypeA, true)
			if err != nil {
				return connError{fmt.Errorf("no answer from the local server: %s (is unbound running? `minidns status`)", shortNetErr(err))}
			}
			rcode := dns.RcodeToString[resp.Rcode]
			// a blocked name must answer NXDOMAIN; an unblocked one may too,
			// when it simply does not exist
			consistent := !ex.Blocked || resp.Rcode == dns.RcodeNameError
			out := map[string]any{"explanation": ex, "rcode": rcode, "consistent": consistent}
			if err := emit(out, func() {
				ex.print()
				fmt.Printf("  server answers  %s\n", rcode)
			}); err != nil {
				return err
			}
			if !consistent {
				return applyError{fmt.Errorf("the rules say %s is blocked but the server answers %s — run `minidns apply`", ex.Name, rcode)}
			}
			return nil
		},
	}
	markReadOnly(explainCmd, test)
	block.AddCommand(add, blockRules.removeCmd(), blockRules.listCmd(), test, explainCmd)
	legacyVerb(block, "block", add)
	return block
}

func allowCmd() *cobra.Command {
	allow := &cobra.Command{Use: "allow", Short: "Allowlist: names that are never blocked"}
	add := allowRules.addCmd(nil)
	allow.AddCommand(add, allowRules.removeCmd(), allowRules.listCmd())
	legacyVerb(allow, "allow", add)
	return allow
}

// ---- blocklist -----------------------------------------------------------

type blocklistRow struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Format  string `json:"format"`
	Enabled bool   `json:"enabled"`
	adblock.ListState
	ActiveEntries int `json:"active_entries"`
}

func blocklistRows(cfg *config.Config, only string) []blocklistRow {
	state := adblock.LoadState()
	rows := []blocklistRow{}
	for _, l := range cfg.Adblock.Lists {
		if only != "" && l.Name != only {
			continue
		}
		row := blocklistRow{Name: l.Name, URL: adblock.RedactURL(l.URL), Format: l.Format,
			Enabled: cfg.Adblock.Enabled && !l.Disabled, ListState: state[l.Name]}
		if st, err := os.Stat(paths.AdblockRPZ(l.Name)); err == nil {
			row.ActiveEntries = rpz.CountEntries(paths.AdblockRPZ(l.Name))
			if row.LastSuccess.IsZero() { // refreshed by a version that kept no state
				row.LastSuccess = st.ModTime().UTC().Truncate(time.Second)
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// updateLists refreshes the named lists (all enabled ones when names is
// empty) and activates the result. If unbound does not come back with the
// new data, the replaced files are restored and loaded again.
func updateLists(cfg *config.Config, names []string, quiet, force bool) error {
	var targets []config.BlockList
	for _, l := range cfg.Adblock.Lists {
		if len(names) == 0 && !l.Disabled || contains(names, l.Name) {
			targets = append(targets, l)
		}
	}
	for _, n := range names {
		if cfg.FindList(n) == nil {
			return fmt.Errorf("%w: no blocklist named %q (see `minidns blocklist list`)", zones.ErrNotFound, n)
		}
	}
	if len(targets) == 0 {
		if len(cfg.Adblock.Lists) == 0 {
			return fmt.Errorf("%w: no blocklists configured — add one with `minidns blocklist add <name> --url <url>`", zones.ErrNotFound)
		}
		return nil
	}
	type outcome struct {
		Name    string `json:"name"`
		Entries int    `json:"entries"`
		Changed bool   `json:"changed"`
		Error   string `json:"error,omitempty"`
	}
	var results []outcome
	var changed []string
	var firstErr error
	for _, l := range targets {
		n, ch, err := adblock.Update(l, force)
		adblock.Record(l.Name, n, err)
		o := outcome{Name: l.Name, Entries: n, Changed: ch}
		if err != nil {
			o.Error = err.Error()
			fmt.Fprintln(os.Stderr, err)
			if firstErr == nil {
				firstErr = err
			}
		} else if ch {
			changed = append(changed, l.Name)
		}
		results = append(results, o)
	}
	if len(changed) > 0 {
		// new list files may need wiring into the unbound config
		err := cmdApply(false)
		if err == nil && unbound.Active() {
			err = unbound.Reload()
		}
		if err != nil {
			for _, n := range changed {
				if adblock.Restore(n) == nil {
					adblock.Record(n, 0, fmt.Errorf("activation failed, last known good copy restored: %v", err))
				}
			}
			if unbound.Active() {
				unbound.Reload()
			} else {
				unbound.Restart()
			}
			return applyError{fmt.Errorf("unbound did not accept the refreshed lists (previous copies restored): %w", err)}
		}
	}
	if jsonOut {
		emit(results, func() {})
	} else if !quiet {
		for _, o := range results {
			if o.Error == "" {
				fmt.Printf("%s: %d domains%s\n", o.Name, o.Entries, map[bool]string{true: " (changed)", false: " (unchanged)"}[o.Changed])
			}
		}
	}
	return firstErr
}

func addList(cfg *config.Config, name, url, format string) (int, error) {
	if !rpz.ValidListName(name) {
		return 0, fmt.Errorf("%w: invalid list name %q: use lowercase letters, digits, - and _", zones.ErrInvalid, name)
	}
	if format != "hosts" && format != "domains" && format != "rpz" {
		return 0, fmt.Errorf("%w: unknown format %q (hosts, domains or rpz)", zones.ErrInvalid, format)
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return 0, fmt.Errorf("%w: the list URL must start with https:// or http://", zones.ErrInvalid)
	}
	if cfg.FindList(name) != nil {
		return 0, fmt.Errorf("%w: a blocklist named %q already exists", zones.ErrConflict, name)
	}
	l := config.BlockList{Name: name, URL: url, Format: format}
	note("downloading %s...", name)
	count, _, err := adblock.Update(l, false)
	adblock.Record(name, count, err)
	if err != nil {
		adblock.Forget(name)
		return 0, err
	}
	if _, err := changeConfig(func(c *config.Config) error {
		c.Adblock.Lists = append(c.Adblock.Lists, l)
		return nil
	}); err != nil {
		os.Remove(paths.AdblockRPZ(name))
		adblock.Forget(name)
		return 0, err
	}
	return count, nil
}

func removeList(cfg *config.Config, name string) error {
	if cfg.FindList(name) == nil {
		return fmt.Errorf("%w: no blocklist named %q", zones.ErrNotFound, name)
	}
	// unbound must stop referencing the file before it disappears — a
	// daemon that reloads and finds it missing exits
	if _, err := changeConfig(func(c *config.Config) error {
		out := c.Adblock.Lists[:0]
		for _, l := range c.Adblock.Lists {
			if l.Name != name {
				out = append(out, l)
			}
		}
		c.Adblock.Lists = out
		return nil
	}); err != nil {
		return err
	}
	os.Remove(paths.AdblockRPZ(name))
	os.Remove(paths.AdblockRPZ(name) + ".prev")
	adblock.Forget(name)
	return nil
}

func setListEnabled(name string, on bool) error {
	_, err := changeConfig(func(cfg *config.Config) error {
		if name == "" {
			cfg.Adblock.Enabled = on
			return nil
		}
		l := cfg.FindList(name)
		if l == nil {
			return fmt.Errorf("%w: no blocklist named %q", zones.ErrNotFound, name)
		}
		l.Disabled = !on
		if on && !cfg.Adblock.Enabled {
			note("note: blocklists are switched off as a whole — `minidns blocklist enable` turns them on")
		}
		return nil
	})
	return err
}

func printBlocklists(cfg *config.Config, rows []blocklistRow, detail bool) {
	if !cfg.Adblock.Enabled {
		fmt.Println("Blocklists are switched OFF as a whole (`minidns blocklist enable` turns them on).")
	}
	if len(rows) == 0 {
		fmt.Println("no blocklists — add one with `minidns blocklist add <name> --url <url>`")
		return
	}
	if !detail {
		fmt.Printf("%-16s %-9s %-8s %-9s %-12s %s\n", "NAME", "STATE", "FORMAT", "ENTRIES", "REFRESHED", "LAST ERROR")
	}
	for _, r := range rows {
		state := "enabled"
		if !r.Enabled {
			state = "disabled"
		}
		refreshed := "never"
		if !r.LastSuccess.IsZero() {
			refreshed = ago(r.LastSuccess)
		}
		if !detail {
			fmt.Printf("%-16s %-9s %-8s %-9d %-12s %s\n", r.Name, state, r.Format, r.ActiveEntries, refreshed, r.Error)
			continue
		}
		fmt.Printf("%s (%s)\n  source        %s\n  format        %s\n  entries       %d active\n  last success  %s\n", r.Name, state, r.URL, r.Format, r.ActiveEntries, refreshed)
		if !r.LastAttempt.IsZero() {
			fmt.Printf("  last attempt  %s\n", ago(r.LastAttempt))
		}
		if r.Error != "" {
			fmt.Printf("  last error    %s\n  (the last good copy is still in use)\n", r.Error)
		}
	}
}

func blocklistCmd() *cobra.Command {
	bl := &cobra.Command{
		Use: "blocklist", Short: "Subscribed blocklists (refreshed daily by a timer)",
		Args: cobra.NoArgs,
		// v0.1: `minidns blocklist` printed the manual block and allow entries
		RunE: func(cmd *cobra.Command, args []string) error {
			deprecated("blocklist (without a subcommand)", "block list / allow list — `blocklist list` now shows subscribed lists")
			return cmdBlocklist(nil)
		},
	}

	var url, format string
	add := &cobra.Command{
		Use: "add <name> --url <url> [--format hosts|domains|rpz]", Short: "Subscribe to a blocklist", Args: cobra.ExactArgs(1),
		Example: "  minidns blocklist add hagezi --url https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt --format domains",
		RunE: func(cmd *cobra.Command, args []string) error {
			if url == "" {
				return usagef("blocklist add needs --url")
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			n, err := addList(cfg, args[0], url, format)
			if err != nil {
				return err
			}
			return emit(map[string]any{"name": args[0], "entries": n}, func() { fmt.Printf("Blocklist %q added (%d domains).\n", args[0], n) })
		},
	}
	add.Flags().StringVar(&url, "url", "", "where to download the list")
	add.Flags().StringVar(&format, "format", "hosts", "hosts (0.0.0.0 name), domains (one per line, subdomains included) or rpz")

	list := &cobra.Command{
		Use: "list", Short: "Show subscribed blocklists", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			rows := blocklistRows(cfg, "")
			return emit(rows, func() { printBlocklists(cfg, rows, false) })
		},
	}
	status := &cobra.Command{
		Use: "status [<name>]", Short: "Refresh state: last attempt, last success, entries, last error", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			only := ""
			if len(args) == 1 {
				if only = args[0]; cfg.FindList(only) == nil {
					return fmt.Errorf("%w: no blocklist named %q", zones.ErrNotFound, only)
				}
			}
			rows := blocklistRows(cfg, only)
			return emit(rows, func() { printBlocklists(cfg, rows, true) })
		},
	}

	var quiet, force bool
	update := &cobra.Command{
		Use: "update [<name>...]", Short: "Refresh now; a bad download never replaces the active copy",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			return updateLists(cfg, args, quiet, force)
		},
	}
	update.Flags().BoolVar(&quiet, "quiet", false, "only print errors")
	update.Flags().BoolVar(&force, "force", false, "accept a list that shrank by more than half")

	toggle := func(verb string, on bool) *cobra.Command {
		return &cobra.Command{
			Use: verb + " [<name>]", Short: map[bool]string{true: "Apply a blocklist again (no name: blocklists as a whole)", false: "Stop applying a blocklist, keeping the subscription (no name: all of them)"}[on],
			Args: cobra.MaximumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				name := ""
				if len(args) == 1 {
					name = args[0]
				}
				if err := setListEnabled(name, on); err != nil {
					return err
				}
				what := "blocklists"
				if name != "" {
					what = fmt.Sprintf("blocklist %q", name)
				}
				return emit(map[string]any{"name": name, "enabled": on}, func() { fmt.Printf("%s %sd.\n", strings.ToUpper(what[:1])+what[1:], verb) })
			},
		}
	}

	remove := &cobra.Command{
		Use: "remove <name>", Short: "Unsubscribe and delete the list", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if err := removeList(cfg, args[0]); err != nil {
				return err
			}
			return emit(map[string]any{"removed": args[0]}, func() { fmt.Printf("Blocklist %q removed.\n", args[0]) })
		},
	}

	markReadOnly(list, status)
	enable, disable := toggle("enable", true), toggle("disable", false)
	supportsDryRun(enable, disable)
	bl.AddCommand(add, list, status, update, enable, disable, remove)
	return bl
}
