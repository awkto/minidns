// Package ingest moves the unbound query log into the database,
// incrementally: each run continues where the previous one stopped.
package ingest

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/qlog"
	"github.com/awkto/minidns/internal/store"
)

const (
	batchSize = 20000
	// an RPZ line and the reply it explains are written back to back; after
	// this long an unanswered one is given up on
	pairWindow = 5
)

type Result struct {
	Files    int           `json:"files"`
	Events   int64         `json:"events"`
	FirstRun bool          `json:"first_run"`
	Skipped  bool          `json:"skipped,omitempty"` // another ingest was running
	Took     time.Duration `json:"-"`
	TookMS   int64         `json:"took_ms"`
}

// ErrBusy means another process is ingesting right now.
var ErrBusy = errors.New("another ingest is running")

func lock() (*os.File, error) {
	if err := os.MkdirAll(paths.StateDir(), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(paths.StateDir(), ".ingest.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrBusy
	}
	return f, nil
}

// Run ingests everything new. The very first run also imports the rotated
// logs, so history starts with whatever logrotate has kept.
func Run(s *store.Store, keepEvents time.Duration) (Result, error) {
	start := time.Now()
	var res Result
	l, err := lock()
	if err == ErrBusy {
		res.Skipped = true
		return res, nil
	}
	if err != nil {
		return res, err
	}
	defer l.Close()

	live := paths.QueryLog()
	st, err := os.Stat(live)
	if err != nil {
		return res, nil // logging is off, or nothing was logged yet
	}
	inode, head := inodeOf(st), firstLine(live)
	eventsAfter := start.Add(-keepEvents).Unix()
	in := &ingester{s: s, eventsAfter: eventsAfter, pending: map[string]pendingRPZ{}}

	cur, seen := s.CursorFor(live)
	switch {
	case !seen:
		res.FirstRun = true
		for _, f := range qlog.Files() { // oldest first; the live file is last
			if f == live {
				continue
			}
			if err := in.file(f, 0, nil); err != nil {
				return res, err
			}
			res.Files++
		}
		cur = store.Cursor{Path: live, Inode: inode}
	case cur.Inode != inode || st.Size() < cur.Offset || (cur.Head != "" && cur.Head != head):
		// rotated (copytruncate) since the last run: what was appended
		// after our offset now sits in the newest rotated copy
		// (or, with rename-style rotation, the rotated file *is* the old log)
		if rst, err := os.Stat(live + ".1"); err == nil && rst.Size() > cur.Offset && (cur.Inode == inode || inodeOf(rst) == cur.Inode) {
			if err := in.file(live+".1", cur.Offset, nil); err != nil {
				return res, err
			}
			res.Files++
		}
		cur = store.Cursor{Path: live, Inode: inode}
	}
	if err := in.file(live, cur.Offset, &store.Cursor{Path: live, Inode: inode, Head: head}); err != nil {
		return res, err
	}
	res.Files++
	res.Events = in.total
	res.Took = time.Since(start)
	res.TookMS = res.Took.Milliseconds()
	return res, nil
}

type pendingRPZ struct {
	tag    string
	ts     int64
	offset int64 // where its line starts
}

type timedEvent struct {
	store.Event
	offset int64 // where its line starts
}

type ingester struct {
	s           *store.Store
	eventsAfter int64
	pending     map[string]pendingRPZ
	batch       []timedEvent
	total       int64
}

// file reads path from offset. With cursor set (the live log), progress is
// recorded; without (a rotated copy) the file is read once, to its end.
func (in *ingester) file(path string, offset int64, cursor *store.Cursor) error {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil // half-written rotation; the next first-run would get it
		}
		defer gz.Close()
		r = gz
	} else if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return err
		}
	}
	br := bufio.NewReaderSize(r, 1<<20)
	pos := offset
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break // EOF; a line without its newline is still being written
		}
		lineStart := pos
		pos += int64(len(line))
		in.line(strings.TrimRight(line, "\r\n"), lineStart)
		if len(in.batch) >= batchSize && len(in.pending) == 0 {
			if err := in.flush(cursor, pos); err != nil {
				return err
			}
		}
	}
	// An RPZ line whose reply has not been written yet: stop just before it,
	// and leave everything from there on for the next run.
	end := pos
	for _, p := range in.pending {
		if cursor != nil && p.offset < end {
			end = p.offset
		}
	}
	if end < pos {
		kept := in.batch[:0]
		for _, e := range in.batch {
			if e.offset < end {
				kept = append(kept, e)
			}
		}
		in.batch = kept
	}
	in.pending = map[string]pendingRPZ{}
	return in.flush(cursor, end)
}

func (in *ingester) line(text string, offset int64) {
	e, ok := qlog.ParseLine(text)
	if !ok {
		return
	}
	ts := e.Time.Unix()
	key := e.Client + "|" + e.Qname + "|" + e.Qtype
	switch e.Kind {
	case qlog.RPZ:
		in.pending[key] = pendingRPZ{e.RPZTag, ts, offset}
	case qlog.Reply:
		ev := store.Event{TS: ts, Client: e.Client, Qname: e.Qname, Qtype: e.Qtype, Rcode: e.Rcode,
			Cached: e.Cached, LatencyUS: int64(e.Latency * 1e6)}
		if p, ok := in.pending[key]; ok {
			if ts-p.ts <= pairWindow {
				ev.Policy = p.tag
			}
			delete(in.pending, key)
		}
		for k, p := range in.pending { // replies that never came
			if ts-p.ts > pairWindow {
				delete(in.pending, k)
			}
		}
		in.batch = append(in.batch, timedEvent{ev, offset})
	}
}

func (in *ingester) flush(cursor *store.Cursor, offset int64) error {
	if len(in.batch) == 0 && cursor == nil {
		return nil
	}
	events := make([]store.Event, len(in.batch))
	for i, e := range in.batch {
		events[i] = e.Event
	}
	var c *store.Cursor
	if cursor != nil {
		c = &store.Cursor{Path: cursor.Path, Inode: cursor.Inode, Offset: offset, Head: cursor.Head}
	}
	if err := in.s.AddBatch(events, c, in.eventsAfter); err != nil {
		return err
	}
	in.total += int64(len(events))
	in.batch = in.batch[:0]
	return nil
}

// firstLine returns the first complete line of a file ("" if there is none
// yet). Appending never changes it; copytruncate rotation does.
func firstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	line, err := bufio.NewReaderSize(f, 4096).ReadString('\n')
	if err != nil {
		return ""
	}
	return line
}

func inodeOf(st os.FileInfo) uint64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	return 0
}
