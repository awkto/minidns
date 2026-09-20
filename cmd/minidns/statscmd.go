package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/store"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zones"
)

// queryFlags are the selectors shared by `stats …` and `query-log list`.
type queryFlags struct {
	tr              timeRange
	device, client  string
	domain          string
	exact           bool
	qtype, rcode    string
	blocked, passed bool
}

func (q *queryFlags) register(cmd *cobra.Command, withDomain bool) {
	f := cmd.Flags()
	f.StringVar(&q.tr.last, "last", "", "period ending now: 30m, 24h, 7d, 2w")
	f.StringVar(&q.tr.from, "from", "", `start of the period: 2026-09-20 or "2026-09-20 14:00"`)
	f.StringVar(&q.tr.to, "to", "", "end of the period (default: now)")
	f.StringVar(&q.device, "device", "", "only this device (all the addresses it has had)")
	f.StringVar(&q.client, "client", "", "only this client IP address")
	f.StringVar(&q.qtype, "type", "", "only this query type (A, AAAA, PTR, HTTPS, …)")
	f.StringVar(&q.rcode, "rcode", "", "only this response code (NOERROR, NXDOMAIN, SERVFAIL, …)")
	f.BoolVar(&q.blocked, "blocked", false, "only blocked queries")
	f.BoolVar(&q.passed, "allowed", false, "only queries that were not blocked")
	if withDomain {
		f.StringVar(&q.domain, "domain", "", "only this domain and its subdomains")
		f.BoolVar(&q.exact, "exact", false, "with --domain: that exact name only")
	}
}

func (q *queryFlags) filter(defaultLast time.Duration) (store.Filter, time.Time, time.Time, error) {
	from, to, err := q.tr.resolve(defaultLast)
	if err != nil {
		return store.Filter{}, from, to, err
	}
	if q.device != "" && q.client != "" {
		return store.Filter{}, from, to, usagef("--device and --client exclude each other")
	}
	if q.blocked && q.passed {
		return store.Filter{}, from, to, usagef("--blocked and --allowed exclude each other")
	}
	f := store.Filter{From: from.Unix(), To: to.Unix(), Device: q.device, Client: q.client,
		Domain: q.domain, Suffix: !q.exact, Qtype: q.qtype, Rcode: q.rcode}
	if q.blocked || q.passed {
		f.Blocked = &q.blocked
	}
	return f, from, to, nil
}

// rollupFilter widens the period to whole hours: statistics are counted per hour.
func rollupFilter(f store.Filter) store.Filter {
	f.From -= f.From % 3600
	return f
}

// withData opens the database, ingests what is new, and runs fn.
func withData(fn func(s *store.Store, cfg *config.Config) error) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	s, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	freshen(s, cfg)
	if !cfg.Logging.Queries {
		note("note: query logging is off, so nothing new is being recorded (`minidns query-log enable`)")
	}
	return fn(s, cfg)
}

func percent(part, whole int64) string {
	if whole == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(part)/float64(whole))
}

func printCounts(title, keyHeader string, rows []store.Count, total int64) {
	fmt.Println(title)
	if len(rows) == 0 {
		fmt.Println("  nothing recorded for this selection")
		return
	}
	fmt.Printf("  %-4s %-44s %9s %7s %9s\n", "#", keyHeader, "QUERIES", "SHARE", "BLOCKED")
	for i, r := range rows {
		key := r.Key
		if len(r.IPs) > 0 {
			key += " (" + strings.Join(r.IPs, ", ") + ")"
		}
		if len(key) > 44 {
			key = key[:41] + "..."
		}
		blocked := ""
		if r.Blocked > 0 {
			blocked = strconv.FormatInt(r.Blocked, 10)
		}
		fmt.Printf("  %-4d %-44s %9d %7s %9s\n", i+1, key, r.Queries, percent(r.Queries, total), blocked)
	}
}

func statsCmd() *cobra.Command {
	var q queryFlags
	stats := &cobra.Command{
		Use: "stats", Short: "Who asks for what: totals, top domains, top devices, blocked, reverse lookups",
		Long: "Statistics come from the query log, counted per hour in a local database (nothing\n" +
			"leaves this host). Every report takes the same selectors: a period (--last 24h, or\n" +
			"--from/--to), --device or --client, --type, --blocked/--allowed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withData(func(s *store.Store, cfg *config.Config) error {
				f, from, to, err := q.filter(24 * time.Hour)
				if err != nil {
					return err
				}
				f = rollupFilter(f)
				o, err := s.Overview(f)
				if err != nil {
					return storeErr(err)
				}
				domains, _ := s.TopDomains(f, false, 5)
				devices, _ := s.TopDevices(f, 5)
				cache := cacheStats()
				out := map[string]any{"from": from.Unix(), "to": to.Unix(), "overview": o, "top_domains": domains, "top_devices": devices, "resolver": cache}
				return emit(out, func() {
					fmt.Printf("Queries %s\n", describeRange(from, to))
					fmt.Printf("  total        %d from %d clients, %d different names\n", o.Queries, o.Clients, o.Names)
					fmt.Printf("  blocked      %d (%s)%s\n", o.Blocked, percent(o.Blocked, o.Queries), breakdown(o.ByPolicy, o.Blocked))
					fmt.Printf("  by type      %s\n", strings.TrimPrefix(breakdown(o.ByType, o.Queries), " — "))
					fmt.Printf("  by answer    %s\n", strings.TrimPrefix(breakdown(o.ByRcode, o.Queries), " — "))
					if len(cache) > 0 {
						fmt.Printf("  resolver     %s cache hits since unbound started %s ago, average recursion %sms\n", cache["cache_hit_percent"], cache["uptime"], cache["avg_recursion_ms"])
					}
					fmt.Println()
					printCounts("Top domains", "DOMAIN", domains, o.Queries)
					fmt.Println()
					printCounts("Top devices", "DEVICE", devices, o.Queries)
					fmt.Println("\nMore: minidns stats top-domains | top-devices | blocked | reverse | device <name>   (all take --last, --device, --json)")
				})
			})
		},
	}
	q.register(stats, true)

	var n int
	var groupBy string
	var pick bool
	ranking := func(use, short, title string, preset func(*store.Filter), example string) *cobra.Command {
		var rq queryFlags
		c := &cobra.Command{
			Use: use, Short: short, Args: cobra.NoArgs, Example: example,
			RunE: func(cmd *cobra.Command, args []string) error {
				if groupBy != "domain" && groupBy != "registered" {
					return usagef("--group-by takes domain or registered")
				}
				return withData(func(s *store.Store, cfg *config.Config) error {
					f, from, to, err := rq.filter(24 * time.Hour)
					if err != nil {
						return err
					}
					f = rollupFilter(f)
					if preset != nil {
						preset(&f)
					}
					o, err := s.Overview(f)
					if err != nil {
						return storeErr(err)
					}
					rows, err := s.TopDomains(f, groupBy == "registered", n)
					if err != nil {
						return storeErr(err)
					}
					if rows == nil {
						rows = []store.Count{}
					}
					if use == "reverse" {
						annotateReverse(s, rows, to.Unix())
					}
					out := map[string]any{"from": from.Unix(), "to": to.Unix(), "total": o.Queries, "rows": rows}
					if use == "blocked" {
						out["blocked_by"] = o.ByPolicy
					}
					if pick {
						return pickAndBlock(title+" "+describeRange(from, to), rows, o.Queries)
					}
					return emit(out, func() {
						who := ""
						if rq.device != "" {
							who = " — device " + rq.device
						} else if rq.client != "" {
							who = " — client " + rq.client
						}
						printCounts(fmt.Sprintf("%s %s%s", title, describeRange(from, to), who), "DOMAIN", rows, o.Queries)
						if use == "blocked" && len(o.ByPolicy) > 0 {
							fmt.Printf("\n  blocked by   %s\n", strings.TrimPrefix(breakdown(o.ByPolicy, o.Queries), " — "))
							fmt.Println("  (`minidns block explain <name>` says which rule; `minidns allow add <name>` lets one through)")
						}
					})
				})
			},
		}
		rq.register(c, true)
		c.Flags().IntVarP(&n, "limit", "n", 20, "how many rows")
		c.Flags().StringVar(&groupBy, "group-by", "domain", "domain = every name on its own; registered = subdomains counted under their domain (www.example.co.uk → example.co.uk)")
		return c
	}
	yes := true
	topDomains := ranking("top-domains", "Most queried names", "Top domains", nil,
		"  minidns stats top-domains --last 7d\n  minidns stats top-domains --device laptop --group-by registered\n  minidns stats top-domains --from 2026-09-01 --to 2026-09-08 --type AAAA")
	topDomains.Flags().BoolVar(&pick, "pick", false, "choose rows to block, interactively (in scripts: … --json | jq -r '.rows[].key' | sudo minidns block add -)")
	blocked := ranking("blocked", "Most blocked names, and which rule set blocked them", "Top blocked domains", func(f *store.Filter) { f.Blocked = &yes }, "")
	reverse := ranking("reverse", "Most looked-up addresses (PTR queries), with device names where known", "Top reverse lookups", func(f *store.Filter) { f.Qtype = "PTR" }, "")

	var dq queryFlags
	var dn int
	topDevices := &cobra.Command{
		Use: "top-devices", Short: "Busiest devices (clients without a name show as their IP address)", Args: cobra.NoArgs,
		Example: "  minidns stats top-devices --last 7d\n  minidns stats top-devices --domain netflix.com      who talks to Netflix",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withData(func(s *store.Store, cfg *config.Config) error {
				f, from, to, err := dq.filter(24 * time.Hour)
				if err != nil {
					return err
				}
				f = rollupFilter(f)
				o, err := s.Overview(f)
				if err != nil {
					return storeErr(err)
				}
				rows, err := s.TopDevices(f, dn)
				if err != nil {
					return storeErr(err)
				}
				if rows == nil {
					rows = []store.Count{}
				}
				return emit(map[string]any{"from": from.Unix(), "to": to.Unix(), "total": o.Queries, "rows": rows}, func() {
					printCounts("Top devices "+describeRange(from, to), "DEVICE", rows, o.Queries)
					unnamed := 0
					for _, r := range rows {
						if _, err := netip.ParseAddr(r.Key); err == nil {
							unnamed++
						}
					}
					if unnamed > 0 {
						fmt.Printf("\n  %d of these have no name yet: minidns device add <name> --ip <address>\n", unnamed)
					}
				})
			})
		},
	}
	dq.register(topDevices, true)
	topDevices.Flags().IntVarP(&dn, "limit", "n", 20, "how many rows")

	var oq queryFlags
	oneDevice := &cobra.Command{
		Use: "device <name>", Short: "One device: totals, what it asks for most, what gets blocked", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withData(func(s *store.Store, cfg *config.Config) error {
				oq.device = args[0]
				f, from, to, err := oq.filter(24 * time.Hour)
				if err != nil {
					return err
				}
				f = rollupFilter(f)
				o, err := s.Overview(f)
				if err != nil {
					return storeErr(err)
				}
				d, _ := s.Device(args[0])
				top, _ := s.TopDomains(f, false, 10)
				fb := f
				fb.Blocked = &yes
				topBlocked, _ := s.TopDomains(fb, false, 10)
				return emit(map[string]any{"device": d, "from": from.Unix(), "to": to.Unix(), "overview": o, "top_domains": top, "top_blocked": topBlocked}, func() {
					fmt.Printf("%s (%s) — %s\n", d.Name, joinAddresses(d.Addresses), describeRange(from, to))
					fmt.Printf("  queries      %d, %d different names\n", o.Queries, o.Names)
					fmt.Printf("  blocked      %d (%s)%s\n", o.Blocked, percent(o.Blocked, o.Queries), breakdown(o.ByPolicy, o.Blocked))
					fmt.Printf("  by type      %s\n\n", strings.TrimPrefix(breakdown(o.ByType, o.Queries), " — "))
					printCounts("Top domains", "DOMAIN", top, o.Queries)
					if len(topBlocked) > 0 {
						fmt.Println()
						printCounts("Top blocked", "DOMAIN", topBlocked, o.Queries)
					}
				})
			})
		},
	}
	oq.register(oneDevice, true)

	all := []*cobra.Command{stats, topDomains, topDevices, blocked, reverse, oneDevice}
	markReadOnly(all...)
	stats.AddCommand(all[1:]...)
	return stats
}

// pickAndBlock shows a ranking and blocks the rows the operator names.
func pickAndBlock(title string, rows []store.Count, total int64) error {
	if jsonOut {
		return usagef("--pick is interactive; in scripts pipe names into `minidns block add -`")
	}
	if !isTerminal(os.Stdin) {
		return usagef("--pick needs a terminal; in scripts: minidns stats top-domains --json | jq -r '.rows[].key' | sudo minidns block add -")
	}
	printCounts(title, "DOMAIN", rows, total)
	if len(rows) == 0 {
		return nil
	}
	fmt.Print("\nBlock which? Row numbers separated by spaces (Enter = none): ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	var chosen []string
	for _, f := range strings.Fields(strings.ReplaceAll(line, ",", " ")) {
		i, err := strconv.Atoi(f)
		if err != nil || i < 1 || i > len(rows) {
			return fmt.Errorf("%w: %q is not a row number between 1 and %d — nothing was blocked", zones.ErrInvalid, f, len(rows))
		}
		chosen = append(chosen, rows[i-1].Key)
	}
	if len(chosen) == 0 {
		fmt.Println("Nothing blocked.")
		return nil
	}
	if err := lockState(); err != nil {
		return err
	}
	if err := editRPZ(blockRules.file(), blockRules.action, blockRules.zone, chosen, nil); err != nil {
		return applyError{err}
	}
	fmt.Printf("Blocked: %s (and subdomains). Undo with `minidns block remove <name>`.\n", strings.Join(chosen, ", "))
	return nil
}

// breakdown renders "— A 61%, AAAA 30%, …" largest first.
func breakdown(m map[string]int64, total int64) string {
	type kv struct {
		k string
		n int64
	}
	var list []kv
	for k, n := range m {
		list = append(list, kv{k, n})
	}
	if len(list) == 0 {
		return ""
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].k < list[j].k
	})
	var parts []string
	for i, e := range list {
		if i == 6 {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", e.k, percent(e.n, total)))
	}
	return " — " + strings.Join(parts, ", ")
}

// annotateReverse turns 5.0.20.10.in-addr.arpa into "10.20.0.5 (laptop)".
func annotateReverse(s *store.Store, rows []store.Count, at int64) {
	for i, r := range rows {
		addr, ok := zones.AddrFromPTR(r.Key)
		if !ok {
			continue
		}
		rows[i].Key = addr.String()
		if name := s.DeviceAt(addr.String(), at); name != "" {
			rows[i].Key += " (" + name + ")"
		}
	}
}

// cacheStats are the resolver-side numbers only unbound knows.
func cacheStats() map[string]string {
	st, err := unbound.Stats()
	if err != nil {
		return map[string]string{}
	}
	get := func(k string) float64 { v, _ := strconv.ParseFloat(st[k], 64); return v }
	out := map[string]string{
		"uptime":           (time.Duration(get("time.up")) * time.Second).String(),
		"queries":          st["total.num.queries"],
		"cache_hits":       st["total.num.cachehits"],
		"avg_recursion_ms": fmt.Sprintf("%.1f", get("total.recursion.time.avg")*1000),
	}
	if total := get("total.num.queries"); total > 0 {
		out["cache_hit_percent"] = fmt.Sprintf("%.1f%%", 100*get("total.num.cachehits")/total)
	} else {
		out["cache_hit_percent"] = "0%"
	}
	return out
}
