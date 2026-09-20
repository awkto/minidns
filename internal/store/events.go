package store

import (
	"database/sql"
	"time"
)

// Event is one answered query.
type Event struct {
	TS        int64
	Client    string
	Qname     string
	Qtype     string
	Rcode     string
	Policy    string // "", allow, block, adblock-<list>
	Cached    bool
	LatencyUS int64
}

// Cursor is how far a log file has been ingested.
type Cursor struct {
	Path   string
	Inode  uint64
	Offset int64
	Head   string // the file's first line, to recognise a truncated-and-refilled log
}

func (s *Store) CursorFor(path string) (Cursor, bool) {
	c := Cursor{Path: path}
	err := s.db.QueryRow(`SELECT inode, offset, head FROM ingest_state WHERE path = ?`, path).Scan(&c.Inode, &c.Offset, &c.Head)
	return c, err == nil
}

// Retention is how long each level of detail is kept.
type Retention struct {
	Events time.Duration // individual queries
	Hourly time.Duration // per-hour counts; older ones are folded into days
	Daily  time.Duration // per-day counts
}

var DefaultRetention = Retention{Events: 7 * 24 * time.Hour, Hourly: 35 * 24 * time.Hour, Daily: 400 * 24 * time.Hour}

type rollupKey struct {
	bucket           int64
	client, name     int64
	qtype, rcode, pl string
}

// AddBatch stores events, adds them to the hourly rollups and moves the
// cursor — all in one transaction, so a crash or a second run can neither
// lose nor double-count a line. Events older than eventsAfter only count in
// the rollups (importing old logs must not bloat the event table).
func (s *Store) AddBatch(events []Event, cursor *Cursor, eventsAfter int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	ids := map[string]int64{}
	lookup := func(table, col, value string) (int64, error) {
		key := table + "\x00" + value
		if id, ok := ids[key]; ok {
			return id, nil
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO `+table+`(`+col+`) VALUES (?)`, value); err != nil {
			return 0, err
		}
		var id int64
		if err := tx.QueryRow(`SELECT id FROM `+table+` WHERE `+col+` = ?`, value).Scan(&id); err != nil {
			return 0, err
		}
		ids[key] = id
		return id, nil
	}

	var insert *sql.Stmt
	if insert, err = tx.Prepare(`INSERT INTO query_events(ts, client_id, name_id, qtype, rcode, policy, cached, latency_us) VALUES (?,?,?,?,?,?,?,?)`); err != nil {
		return err
	}
	defer insert.Close()

	rollups := map[rollupKey]int64{}
	for _, e := range events {
		cid, err := lookup("clients", "ip", e.Client)
		if err != nil {
			return err
		}
		nid, err := lookup("names", "name", e.Qname)
		if err != nil {
			return err
		}
		if e.TS >= eventsAfter {
			if _, err := insert.Exec(e.TS, cid, nid, e.Qtype, e.Rcode, e.Policy, e.Cached, e.LatencyUS); err != nil {
				return err
			}
		}
		rollups[rollupKey{e.TS - e.TS%3600, cid, nid, e.Qtype, e.Rcode, e.Policy}]++
	}
	if len(rollups) > 0 {
		up, err := tx.Prepare(`INSERT INTO query_rollups(bucket, span, client_id, name_id, qtype, rcode, policy, count) VALUES (?,'h',?,?,?,?,?,?)
			ON CONFLICT DO UPDATE SET count = count + excluded.count`)
		if err != nil {
			return err
		}
		defer up.Close()
		for k, n := range rollups {
			if _, err := up.Exec(k.bucket, k.client, k.name, k.qtype, k.rcode, k.pl, n); err != nil {
				return err
			}
		}
	}
	if cursor != nil {
		if _, err := tx.Exec(`INSERT INTO ingest_state(path, inode, offset, head) VALUES (?,?,?,?)
			ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset, head = excluded.head`, cursor.Path, int64(cursor.Inode), cursor.Offset, cursor.Head); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneResult says what Prune removed.
type PruneResult struct {
	Events  int64 `json:"events_deleted"`
	Folded  int64 `json:"hourly_rows_folded_into_days"`
	Rollups int64 `json:"daily_rows_deleted"`
}

// Prune applies the retention: old events go, old hourly counts are folded
// into daily counts (UTC days), very old daily counts go, and names and
// clients nothing refers to any more are dropped.
func (s *Store) Prune(r Retention, now time.Time) (PruneResult, error) {
	var res PruneResult
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	affected := func(out *int64, query string, args ...any) error {
		r, err := tx.Exec(query, args...)
		if err == nil {
			*out, _ = r.RowsAffected()
		}
		return err
	}
	if err := affected(&res.Events, `DELETE FROM query_events WHERE ts < ?`, now.Add(-r.Events).Unix()); err != nil {
		return res, err
	}
	// fold whole UTC days only, so a day is never split between spans
	foldBefore := now.Add(-r.Hourly).Unix()
	foldBefore -= foldBefore % 86400
	if _, err := tx.Exec(`INSERT INTO query_rollups(bucket, span, client_id, name_id, qtype, rcode, policy, count)
		SELECT bucket - bucket % 86400, 'd', client_id, name_id, qtype, rcode, policy, SUM(count)
		FROM query_rollups WHERE span = 'h' AND bucket < ? GROUP BY 1, 3, 4, 5, 6, 7
		ON CONFLICT DO UPDATE SET count = count + excluded.count`, foldBefore); err != nil {
		return res, err
	}
	if err := affected(&res.Folded, `DELETE FROM query_rollups WHERE span = 'h' AND bucket < ?`, foldBefore); err != nil {
		return res, err
	}
	if err := affected(&res.Rollups, `DELETE FROM query_rollups WHERE span = 'd' AND bucket < ?`, now.Add(-r.Daily).Unix()); err != nil {
		return res, err
	}
	if res.Rollups > 0 {
		var n int64
		affected(&n, `DELETE FROM names WHERE id NOT IN (SELECT name_id FROM query_rollups) AND id NOT IN (SELECT name_id FROM query_events)`)
		affected(&n, `DELETE FROM clients WHERE id NOT IN (SELECT client_id FROM query_rollups) AND id NOT IN (SELECT client_id FROM query_events)`)
	}
	return res, tx.Commit()
}

// PurgeAll deletes every stored query (devices stay).
func (s *Store) PurgeAll() error {
	for _, q := range []string{`DELETE FROM query_events`, `DELETE FROM query_rollups`, `DELETE FROM names`, `DELETE FROM clients`} {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`VACUUM`)
	return err
}

// Footprint describes what is stored.
type Footprint struct {
	Events      int64 `json:"events"`
	RollupRows  int64 `json:"rollup_rows"`
	Names       int64 `json:"names"`
	Clients     int64 `json:"clients"`
	OldestEvent int64 `json:"oldest_event,omitempty"`
	OldestCount int64 `json:"oldest_count,omitempty"`
	NewestEvent int64 `json:"newest_event,omitempty"`
}

func (s *Store) Footprint() Footprint {
	var f Footprint
	s.db.QueryRow(`SELECT COUNT(*), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0) FROM query_events`).Scan(&f.Events, &f.OldestEvent, &f.NewestEvent)
	s.db.QueryRow(`SELECT COUNT(*), COALESCE(MIN(bucket),0) FROM query_rollups`).Scan(&f.RollupRows, &f.OldestCount)
	s.db.QueryRow(`SELECT COUNT(*) FROM names`).Scan(&f.Names)
	s.db.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&f.Clients)
	return f
}
