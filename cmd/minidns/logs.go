package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/exporter"
	"github.com/awkto/minidns/internal/qlog"
)

func printEntry(e qlog.Entry) {
	ts := e.Time.Format("2006-01-02 15:04:05")
	switch e.Kind {
	case qlog.Reply:
		cache := ""
		if e.Cached {
			cache = " (cache)"
		}
		fmt.Printf("%s  %-15s %-6s %-8s %6.1fms%s  %s\n",
			ts, e.Client, e.Qtype, e.Rcode, e.Latency*1000, cache, e.Qname)
	case qlog.RPZ:
		fmt.Printf("%s  %-15s BLOCKED [%s] %s\n", ts, e.Client, e.RPZTag, e.Qname)
	default:
		fmt.Printf("%s  %-15s %-6s query    %s\n", ts, e.Client, e.Qtype, e.Qname)
	}
}

func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	n := fs.Int("n", 50, "number of recent entries to show")
	follow := fs.Bool("f", false, "follow the live log")
	client := fs.String("client", "", "only entries from this client IP")
	blocked := fs.Bool("blocked", false, "only RPZ-blocked queries")
	since := fs.Duration("since", 0, "look back this far (e.g. 24h); default: last entries")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	match := func(e qlog.Entry) bool {
		if *client != "" && e.Client != *client {
			return false
		}
		if *blocked && e.Kind != qlog.RPZ {
			return false
		}
		// without filters, show replies + blocks (queries would be duplicates)
		if !*blocked && e.Kind == qlog.Query {
			return false
		}
		return true
	}

	if !*follow || *n > 0 {
		var cutoff time.Time
		if *since > 0 {
			cutoff = time.Now().Add(-*since)
		}
		ring := make([]qlog.Entry, 0, *n)
		err := qlog.Scan(cutoff, func(e qlog.Entry) {
			if !match(e) {
				return
			}
			if len(ring) == *n {
				ring = append(ring[1:], e)
			} else {
				ring = append(ring, e)
			}
		})
		if err != nil {
			return err
		}
		if len(ring) == 0 && !*follow {
			fmt.Println("no matching log entries (is logging.queries enabled and unbound running?)")
			return nil
		}
		for _, e := range ring {
			printEntry(e)
		}
	}
	if *follow {
		return qlog.Follow(func(e qlog.Entry) {
			if match(e) {
				printEntry(e)
			}
		})
	}
	return nil
}

func cmdTop(args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	n := fs.Int("n", 25, "number of rows")
	clients := fs.Bool("clients", false, "rank clients instead of domains")
	client := fs.String("client", "", "only queries from this client IP")
	blocked := fs.Bool("blocked", false, "only RPZ-blocked queries")
	since := fs.Duration("since", 24*time.Hour, "look back this far (0 = everything)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	var cutoff time.Time
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}
	counts := make(map[string]int)
	total := 0
	err := qlog.Scan(cutoff, func(e qlog.Entry) {
		if *blocked {
			if e.Kind != qlog.RPZ {
				return
			}
		} else if e.Kind != qlog.Query {
			return
		}
		if *client != "" && e.Client != *client {
			return
		}
		key := e.Qname
		if *clients {
			key = e.Client
		}
		counts[key]++
		total++
	})
	if err != nil {
		return err
	}
	if total == 0 {
		fmt.Println("no queries in that window")
		return nil
	}

	type row struct {
		key string
		n   int
	}
	rows := make([]row, 0, len(counts))
	for k, c := range counts {
		rows = append(rows, row{k, c})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].key < rows[j].key
	})
	if len(rows) > *n {
		rows = rows[:*n]
	}

	what := "domains"
	if *clients {
		what = "clients"
	}
	window := "all time"
	if *since > 0 {
		window = "last " + since.String()
	}
	fmt.Printf("top %s (%s, %d queries, %d unique)\n", what, window, total, len(counts))
	for _, r := range rows {
		fmt.Printf("%8d  %s\n", r.n, r.key)
	}
	return nil
}

func cmdExporter(args []string) error {
	fs := flag.NewFlagSet("exporter", flag.ContinueOnError)
	listen := fs.String("listen", "", "listen address (default: exporter.listen from config)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		if !os.IsPermission(err) {
			return err
		}
		// the exporter runs unprivileged, and config.yaml is private while a
		// blocklist URL carries credentials: fall back to the default address
		fmt.Fprintln(os.Stderr, "warning: config.yaml is not readable by this user; listening on the default address (override with --listen)")
		cfg = config.Default()
	}
	addr := cfg.Exporter.Listen
	if *listen != "" {
		addr = *listen
	}
	if addr == "" {
		addr = "0.0.0.0:9153"
	}
	fmt.Println("exporter listening on", addr, "— scrape /metrics")
	return exporter.Serve(addr, version)
}
