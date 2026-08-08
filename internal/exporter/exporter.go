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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
