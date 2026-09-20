// Package store is the SQLite database for the things that are not
// canonical in files: devices, query events, query rollups and ingestion
// state. Zones, records, block rules and config.yaml never live here, and
// nothing on the DNS serving path depends on it — a broken or missing
// database costs statistics, not resolution.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // pure Go: the static, CGO-free build stays

	"github.com/awkto/minidns/internal/paths"
)

// File is the database path.
func File() string { return filepath.Join(paths.StateDir(), "minidns.db") }

type Store struct{ db *sql.DB }

// migrations are applied in order, once each, inside a transaction. Never
// edit a released entry — append a new one.
var migrations = []string{
	// 1 — v0.3.0
	`CREATE TABLE devices (
		id          INTEGER PRIMARY KEY,
		name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
		description TEXT NOT NULL DEFAULT '',
		tags        TEXT NOT NULL DEFAULT '',
		created_at  INTEGER NOT NULL
	);
	-- an address belongs to a device for a period: [valid_from, valid_to),
	-- valid_to NULL = still current. Manual entries are open-ended; a DHCP
	-- lease feed (minidhcp) can add bounded ones later.
	CREATE TABLE device_addresses (
		id         INTEGER PRIMARY KEY,
		device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		ip         TEXT NOT NULL,
		mac        TEXT NOT NULL DEFAULT '',
		valid_from INTEGER NOT NULL DEFAULT 0,
		valid_to   INTEGER,
		source     TEXT NOT NULL DEFAULT 'manual'
	);
	CREATE INDEX device_addresses_ip ON device_addresses(ip);

	-- dictionaries keep the big tables narrow
	CREATE TABLE names   (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
	CREATE TABLE clients (id INTEGER PRIMARY KEY, ip   TEXT NOT NULL UNIQUE);

	-- one row per answered query, kept for days
	CREATE TABLE query_events (
		ts         INTEGER NOT NULL,
		client_id  INTEGER NOT NULL,
		name_id    INTEGER NOT NULL,
		qtype      TEXT NOT NULL,
		rcode      TEXT NOT NULL,
		policy     TEXT NOT NULL DEFAULT '',   -- '', allow, block, adblock-<list>
		cached     INTEGER NOT NULL DEFAULT 0,
		latency_us INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX query_events_ts ON query_events(ts);

	-- counts per period, kept for months. span 'h' = hour, 'd' = day
	-- (hours are folded into days once they are old).
	CREATE TABLE query_rollups (
		bucket    INTEGER NOT NULL,
		span      TEXT NOT NULL,
		client_id INTEGER NOT NULL,
		name_id   INTEGER NOT NULL,
		qtype     TEXT NOT NULL,
		rcode     TEXT NOT NULL,
		policy    TEXT NOT NULL,
		count     INTEGER NOT NULL,
		PRIMARY KEY (bucket, span, client_id, name_id, qtype, rcode, policy)
	) WITHOUT ROWID;

	CREATE TABLE ingest_state (
		path   TEXT PRIMARY KEY,
		inode  INTEGER NOT NULL,
		offset INTEGER NOT NULL,
		head   TEXT NOT NULL DEFAULT ''   -- first line of the file: changes when it is truncated and refilled
	);
	CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
}

// Open opens (creating and migrating if needed) the database. The file is
// private to root: it records who looked up what.
func Open() (*Store, error) {
	if err := os.MkdirAll(paths.StateDir(), 0o755); err != nil {
		return nil, err
	}
	if f, err := os.OpenFile(File(), os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		f.Close()
		os.Chmod(File(), 0o600)
	} else {
		return nil, err
	}
	dsn := "file:" + File() + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; also keeps the pragmas on the one connection
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database %s: %w", File(), err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// SchemaVersion returns the applied and the newest known schema version.
func (s *Store) SchemaVersion() (applied, latest int) {
	s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&applied)
	return applied, len(migrations)
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	applied, latest := s.SchemaVersion()
	if applied > latest {
		return fmt.Errorf("schema version %d is newer than this minidns understands (%d) — upgrade minidns", applied, latest)
	}
	for v := applied + 1; v <= latest; v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v-1]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, strftime('%s','now'))`, v); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Meta reads a stored setting ("" if unset).
func (s *Store) Meta(key string) string {
	var v string
	s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v
}

func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Snapshot writes a consistent copy of the database to dest. Without
// withEvents the individual queries are left out: a backup is for devices
// and counts, and should not quietly become a second copy of everybody's
// browsing.
func Snapshot(dest string, withEvents bool) error {
	s, err := Open()
	if err != nil {
		return err
	}
	os.Remove(dest)
	_, err = s.db.Exec(`VACUUM INTO ?`, dest)
	s.Close()
	if err != nil {
		return err
	}
	os.Chmod(dest, 0o600)
	if withEvents {
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+dest)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM query_events`); err != nil {
		return err
	}
	_, err = db.Exec(`VACUUM`)
	return err
}
