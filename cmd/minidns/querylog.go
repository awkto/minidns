package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/ingest"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/qlog"
	"github.com/awkto/minidns/internal/store"
	"github.com/awkto/minidns/internal/zones"
)

const privacyNotice = `Query logging records every DNS lookup with the IP address that made it. That is
personal data about the people on your network: tell them. It stays on this host
(the log under /var/log/minidns, 30 days; the statistics database, see
"minidns query-log status") and is readable by root only.`

func printLogged(q store.LoggedQuery) {
	who := q.Client
	if q.Device != "" {
		who = q.Device
	}
	if len(who) > 24 {
		who = who[:21] + "..."
	}
	verdict := q.Rcode
	if q.Blocked {
		verdict = "BLOCKED [" + q.Policy + "]"
	}
	cache := ""
	if q.Cached && !q.Blocked {
		cache = " (cache)"
	}
	fmt.Printf("%s  %-24s %-6s %-26s %s%s\n", time.Unix(q.Time, 0).Format("2006-01-02 15:04:05"), who, q.Type, verdict, q.Name, cache)
}

func queryLogCmd() *cobra.Command {
	ql := &cobra.Command{Use: "query-log", Short: "The query log: search it, follow it, switch it on or off, set how long it is kept"}

	var q queryFlags
	var n int
	list := &cobra.Command{
		Use: "list", Short: "Recent queries, newest last", Args: cobra.NoArgs,
		Example: "  minidns query-log list --device laptop --last 1h\n  minidns query-log list --blocked -n 100\n  minidns query-log list --domain netflix.com --type AAAA\n  minidns query-log list --rcode SERVFAIL --last 7d",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withData(func(s *store.Store, cfg *config.Config) error {
				f, from, to, err := q.filter(24 * time.Hour)
				if err != nil {
					return err
				}
				rows, err := s.Events(f, n)
				if err != nil {
					return storeErr(err)
				}
				if rows == nil {
					rows = []store.LoggedQuery{}
				}
				return emit(rows, func() {
					for _, r := range rows {
						printLogged(r)
					}
					if len(rows) == 0 {
						fmt.Printf("no matching queries %s\n", describeRange(from, to))
						if keep := retention(cfg).Events; time.Since(from) > keep {
							fmt.Printf("(individual queries are kept for %s; older periods only have counts — see `minidns stats`)\n", roundSpan(keep))
						}
					} else if len(rows) == n {
						fmt.Fprintf(os.Stderr, "(showing the newest %d; -n raises the limit)\n", n)
					}
				})
			})
		},
	}
	q.register(list, true)
	list.Flags().IntVarP(&n, "limit", "n", 50, "how many queries")

	var tailDevice, tailClient string
	var tailBlocked bool
	tail := &cobra.Command{
		Use: "tail", Short: "Follow queries live (Ctrl-C stops)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOut {
				return usagef("`query-log tail` streams for people; use `query-log list --json` in scripts")
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			if tailDevice != "" {
				if _, err := s.Device(tailDevice); err != nil {
					return storeErr(err)
				}
			}
			pending := map[string]string{}
			return qlog.Follow(func(e qlog.Entry) {
				key := e.Client + "|" + e.Qname + "|" + e.Qtype
				switch e.Kind {
				case qlog.RPZ:
					pending[key] = e.RPZTag
				case qlog.Reply:
					lq := store.LoggedQuery{Time: e.Time.Unix(), Client: e.Client, Name: e.Qname, Type: e.Qtype, Rcode: e.Rcode,
						Cached: e.Cached, Policy: pending[key], Device: s.DeviceAt(e.Client, e.Time.Unix())}
					delete(pending, key)
					lq.Blocked = lq.Policy != "" && lq.Policy != "allow"
					if (tailDevice != "" && !sameName(lq.Device, tailDevice)) || (tailClient != "" && lq.Client != tailClient) || (tailBlocked && !lq.Blocked) {
						return
					}
					printLogged(lq)
				}
			})
		},
	}
	tail.Flags().StringVar(&tailDevice, "device", "", "only this device")
	tail.Flags().StringVar(&tailClient, "client", "", "only this client IP address")
	tail.Flags().BoolVar(&tailBlocked, "blocked", false, "only blocked queries")

	toggle := func(verb string, on bool) *cobra.Command {
		c := &cobra.Command{
			Use: verb, Short: map[bool]string{true: "Record queries (with a privacy notice)", false: "Stop recording queries (what was recorded stays until it expires, or `query-log purge`)"}[on], Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				changed := false
				if _, err := changeConfig(func(c *config.Config) error {
					changed = c.Logging.Queries != on
					c.Logging.Queries = on
					return nil
				}); err != nil {
					return err
				}
				return emit(map[string]any{"query_logging": on, "changed": changed}, func() {
					fmt.Printf("Query logging is %s.\n", map[bool]string{true: "ON", false: "OFF"}[on])
					if on {
						fmt.Println()
						fmt.Println(privacyNotice)
					}
				})
			},
		}
		supportsDryRun(c)
		return c
	}

	status := &cobra.Command{
		Use: "status", Short: "Is logging on, how much is stored, how far back, how current", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			fp := s.Footprint()
			r := retention(cfg)
			var dbBytes, logBytes int64
			for _, suffix := range []string{"", "-wal"} {
				if st, err := os.Stat(store.File() + suffix); err == nil {
					dbBytes += st.Size()
				}
			}
			for _, f := range qlog.Files() {
				if st, err := os.Stat(f); err == nil {
					logBytes += st.Size()
				}
			}
			applied, latest := s.SchemaVersion()
			out := map[string]any{"query_logging": cfg.Logging.Queries, "stored": fp, "database_bytes": dbBytes, "log_bytes": logBytes,
				"keep_events_days": int(r.Events.Hours() / 24), "keep_hourly_days": int(r.Hourly.Hours() / 24), "keep_daily_days": int(r.Daily.Hours() / 24),
				"schema": applied, "schema_latest": latest, "database": store.File()}
			return emit(out, func() {
				fmt.Printf("query logging   %s\n", map[bool]string{true: "on", false: "OFF — nothing new is recorded (`minidns query-log enable`)"}[cfg.Logging.Queries])
				fmt.Printf("database        %s, %.1f MB (schema %d)\n", store.File(), float64(dbBytes)/1e6, applied)
				fmt.Printf("log files       %s, %.1f MB\n", paths.LogDir(), float64(logBytes)/1e6)
				fmt.Printf("queries         %d individual queries", fp.Events)
				if fp.OldestEvent > 0 {
					fmt.Printf(", oldest %s, newest %s", ago(time.Unix(fp.OldestEvent, 0)), ago(time.Unix(fp.NewestEvent, 0)))
				}
				fmt.Printf("\ncounts          %d rows", fp.RollupRows)
				if fp.OldestCount > 0 {
					fmt.Printf(" going back to %s", time.Unix(fp.OldestCount, 0).Format("2006-01-02"))
				}
				fmt.Printf("; %d names, %d clients\n", fp.Names, fp.Clients)
				fmt.Printf("kept for        queries %d days, hourly counts %d days, daily counts %d days  (`minidns query-log retention`)\n",
					int(r.Events.Hours()/24), int(r.Hourly.Hours()/24), int(r.Daily.Hours()/24))
			})
		},
	}

	var keepEvents, keepHourly, keepDaily string
	retentionCmd := &cobra.Command{
		Use: "retention [--events 7d] [--hourly 35d] [--daily 400d]", Short: "How long queries and counts are kept", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			days := func(v string) (int, error) {
				d, err := parseSpan(v)
				if err != nil {
					return 0, err
				}
				if d < 24*time.Hour {
					return 0, fmt.Errorf("%w: retention is set in whole days (at least 1d)", zones.ErrInvalid)
				}
				return int(d.Hours() / 24), nil
			}
			cfg, err := changeConfig(func(c *config.Config) error {
				for _, set := range []struct {
					v    string
					into *int
				}{{keepEvents, &c.Logging.EventsDays}, {keepHourly, &c.Logging.HourlyDays}, {keepDaily, &c.Logging.DailyDays}} {
					if set.v != "" {
						n, err := days(set.v)
						if err != nil {
							return err
						}
						*set.into = n
					}
				}
				r := retention(c)
				if r.Hourly > r.Daily {
					return fmt.Errorf("%w: daily counts must be kept at least as long as hourly ones", zones.ErrInvalid)
				}
				return nil
			})
			if err != nil {
				return err
			}
			r := retention(cfg)
			return emit(map[string]any{"events_days": int(r.Events.Hours() / 24), "hourly_days": int(r.Hourly.Hours() / 24), "daily_days": int(r.Daily.Hours() / 24)}, func() {
				fmt.Printf("Kept: individual queries %d days, hourly counts %d days (then folded into days), daily counts %d days.\n",
					int(r.Events.Hours()/24), int(r.Hourly.Hours()/24), int(r.Daily.Hours()/24))
				fmt.Println("Shorter periods take effect at the next daily clean-up, or now with `minidns query-log purge --expired`.")
			})
		},
	}
	retentionCmd.Flags().StringVar(&keepEvents, "events", "", "individual queries (default 7d)")
	retentionCmd.Flags().StringVar(&keepHourly, "hourly", "", "per-hour counts (default 35d)")
	retentionCmd.Flags().StringVar(&keepDaily, "daily", "", "per-day counts (default 400d)")

	var expired, everything bool
	purge := &cobra.Command{
		Use: "purge --expired | --all", Short: "Delete stored queries: what is past its retention, or everything", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if expired == everything {
				return usagef("say which: --expired (apply the retention now) or --all (delete every stored query and count; devices stay)")
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			if everything {
				if err := s.PurgeAll(); err != nil {
					return err
				}
				return emit(map[string]any{"purged": "all"}, func() {
					fmt.Println("All stored queries and counts are deleted; devices are untouched. The log files under " + paths.LogDir() + " are separate (logrotate removes them after 30 days).")
				})
			}
			res, err := s.Prune(retention(cfg), time.Now())
			if err != nil {
				return err
			}
			return emit(res, func() {
				fmt.Printf("Deleted %d expired queries and %d expired daily counts; folded %d hourly counts into days.\n", res.Events, res.Rollups, res.Folded)
			})
		},
	}
	purge.Flags().BoolVar(&expired, "expired", false, "apply the retention now")
	purge.Flags().BoolVar(&everything, "all", false, "delete every stored query and count")

	var quiet bool
	ingestCmd := &cobra.Command{
		Use: "ingest", Short: "Move new log lines into the database (a timer does this every 5 minutes)", Args: cobra.NoArgs, Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			res, err := ingest.Run(s, retention(cfg).Events)
			if err != nil {
				return err
			}
			today := time.Now().UTC().Format("2006-01-02")
			if !res.Skipped && s.Meta("last_prune") != today {
				if _, err := s.Prune(retention(cfg), time.Now()); err == nil {
					s.SetMeta("last_prune", today)
				}
			}
			if quiet {
				return nil
			}
			return emit(res, func() {
				if res.Skipped {
					fmt.Println("another ingest is running")
					return
				}
				fmt.Printf("ingested %d queries from %d file(s) in %s\n", res.Events, res.Files, res.Took.Round(time.Millisecond))
			})
		},
	}
	ingestCmd.Flags().BoolVar(&quiet, "quiet", false, "only print errors")

	markReadOnly(list, tail, status)
	markNoLock(purge, ingestCmd)
	ql.AddCommand(list, tail, toggle("enable", true), toggle("disable", false), status, retentionCmd, purge, ingestCmd)
	return ql
}

func sameName(a, b string) bool { return strings.EqualFold(a, b) }
