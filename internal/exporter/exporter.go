// Package exporter serves unbound statistics in Prometheus text format so
// an external Prometheus/Grafana stack can scrape the resolver.
package exporter

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/awkto/minidns/internal/unbound"
)

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// Serve blocks, listening on addr and answering /metrics.
func Serve(addr, version string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metrics(version))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "minidns exporter — scrape /metrics")
	})
	return http.ListenAndServe(addr, mux)
}

func metrics(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := unbound.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP minidns_up 1 if unbound-control stats succeeded\n# TYPE minidns_up gauge\nminidns_up %d\n", boolToInt(err == nil))
		fmt.Fprintf(w, "# HELP minidns_build_info minidns version\n# TYPE minidns_build_info gauge\nminidns_build_info{version=%q} 1\n", version)
		if err != nil {
			return
		}
		derived(w, stats)
		keys := make([]string, 0, len(stats))
		for k := range stats {
			// per-thread counters just duplicate the totals — skip them
			if strings.HasPrefix(k, "thread") {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, err := strconv.ParseFloat(stats[k], 64)
			if err != nil {
				continue
			}
			name := "unbound_" + sanitizeRe.ReplaceAllString(k, "_")
			fmt.Fprintf(w, "# TYPE %s untyped\n%s %g\n", name, name, v)
		}
	}
}

// derived writes the handful of named metrics dashboards actually want, so
// nobody has to know unbound's counter names. Labels are bounded sets only —
// never a domain name or a client address.
func derived(w http.ResponseWriter, stats map[string]string) {
	get := func(k string) float64 { v, _ := strconv.ParseFloat(stats[k], 64); return v }
	metric := func(name, typ, help string, value float64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %g\n", name, help, name, typ, name, value)
	}
	queries, hits := get("total.num.queries"), get("total.num.cachehits")
	metric("minidns_queries_total", "counter", "Queries answered since unbound started", queries)
	metric("minidns_cache_hits_total", "counter", "Queries answered from cache since unbound started", hits)
	ratio := 0.0
	if queries > 0 {
		ratio = hits / queries
	}
	metric("minidns_cache_hit_ratio", "gauge", "Share of queries answered from cache since unbound started (0-1)", ratio)
	if up := get("time.up"); up > 0 {
		metric("minidns_queries_per_second", "gauge", "Average query rate since unbound started", queries/up)
	}
	metric("minidns_blocked_total", "counter", "Queries answered by a block rule (RPZ NXDOMAIN) since unbound started", get("num.rpz.action.nxdomain"))
	metric("minidns_recursion_time_avg_seconds", "gauge", "Average time to resolve a cache miss", get("total.recursion.time.avg"))
	metric("minidns_uptime_seconds", "gauge", "unbound uptime", get("time.up"))

	fmt.Fprintf(w, "# HELP minidns_answers_total Answers by response code since unbound started\n# TYPE minidns_answers_total counter\n")
	var rcodes []string
	for k := range stats {
		if strings.HasPrefix(k, "num.answer.rcode.") {
			rcodes = append(rcodes, k)
		}
	}
	sort.Strings(rcodes)
	for _, k := range rcodes {
		fmt.Fprintf(w, "minidns_answers_total{rcode=%q} %g\n", strings.TrimPrefix(k, "num.answer.rcode."), get(k))
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
