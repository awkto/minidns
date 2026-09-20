package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/ingest"
	"github.com/awkto/minidns/internal/store"
	"github.com/awkto/minidns/internal/zones"
)

// openStore opens the statistics database. It is private to root: it holds
// who looked up what.
func openStore() (*store.Store, error) {
	if os.Geteuid() != 0 && os.Getenv("MINIDNS_PREFIX") == "" {
		return nil, fmt.Errorf("%w: devices and query data are private to root — run this with sudo", os.ErrPermission)
	}
	s, err := store.Open()
	if err != nil {
		return nil, fmt.Errorf("the statistics database is unavailable (DNS service is not affected): %w", err)
	}
	return s, nil
}

// storeErr maps the store's errors onto the CLI's exit codes.
func storeErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %s", zones.ErrNotFound, strings.TrimPrefix(err.Error(), "not found: "))
	case errors.Is(err, store.ErrConflict):
		return fmt.Errorf("%w: %s", zones.ErrConflict, strings.TrimPrefix(err.Error(), "conflict: "))
	case errors.Is(err, store.ErrInvalid):
		return fmt.Errorf("%w: %s", zones.ErrInvalid, strings.TrimPrefix(err.Error(), "invalid: "))
	}
	return err
}

func retention(cfg *config.Config) store.Retention {
	r := store.DefaultRetention
	day := 24 * time.Hour
	if d := cfg.Logging.EventsDays; d > 0 {
		r.Events = time.Duration(d) * day
	}
	if d := cfg.Logging.HourlyDays; d > 0 {
		r.Hourly = time.Duration(d) * day
	}
	if d := cfg.Logging.DailyDays; d > 0 {
		r.Daily = time.Duration(d) * day
	}
	return r
}

// freshen ingests what unbound logged since the last run, so that a report
// includes the last few minutes, and applies the retention once a day.
// Failures are reported but never stop the command that wanted the data.
func freshen(s *store.Store, cfg *config.Config) ingest.Result {
	r := retention(cfg)
	res, err := ingest.Run(s, r.Events)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not ingest the query log:", err)
		return res
	}
	if res.FirstRun && res.Events > 0 {
		note("(first run: imported %d queries from the existing logs in %s)", res.Events, res.Took.Round(time.Millisecond))
	}
	today := time.Now().UTC().Format("2006-01-02")
	if !res.Skipped && s.Meta("last_prune") != today {
		if _, err := s.Prune(r, time.Now()); err == nil {
			s.SetMeta("last_prune", today)
		}
	}
	return res
}

// parseSpan reads durations people type: 90m, 24h, 7d, 2w.
func parseSpan(v string) (time.Duration, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if n, err := strconv.ParseFloat(strings.TrimRight(v, "dw"), 64); err == nil && n > 0 {
		switch {
		case strings.HasSuffix(v, "d"):
			return time.Duration(n * 24 * float64(time.Hour)), nil
		case strings.HasSuffix(v, "w"):
			return time.Duration(n * 7 * 24 * float64(time.Hour)), nil
		}
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%w: %q is not a time span (examples: 30m, 24h, 7d, 2w)", zones.ErrInvalid, v)
	}
	return d, nil
}

// parseWhen reads a point in time: RFC 3339, "2026-09-20 14:00", "2026-09-20".
func parseWhen(v string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, strings.TrimSpace(v), time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: %q is not a date or time (examples: 2026-09-20, \"2026-09-20 14:00\")", zones.ErrInvalid, v)
}

// timeRange is the --last / --from / --to trio shared by stats and query-log.
type timeRange struct{ last, from, to string }

func (tr timeRange) resolve(defaultLast time.Duration) (from, to time.Time, err error) {
	to = time.Now()
	if tr.to != "" {
		if to, err = parseWhen(tr.to); err != nil {
			return
		}
	}
	switch {
	case tr.from != "" && tr.last != "":
		err = usagef("--last and --from exclude each other")
	case tr.from != "":
		from, err = parseWhen(tr.from)
	case tr.last != "":
		var d time.Duration
		if d, err = parseSpan(tr.last); err == nil {
			from = to.Add(-d)
		}
	default:
		from = to.Add(-defaultLast)
	}
	if err == nil && !from.Before(to) {
		err = fmt.Errorf("%w: the period ends before it starts", zones.ErrInvalid)
	}
	return
}

func describeRange(from, to time.Time) string {
	layout := "2006-01-02 15:04"
	if time.Since(to) < time.Minute {
		return fmt.Sprintf("since %s (%s)", from.Format(layout), roundSpan(to.Sub(from)))
	}
	return fmt.Sprintf("%s → %s", from.Format(layout), to.Format(layout))
}

func roundSpan(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	}
	return d.Round(time.Minute).String()
}
