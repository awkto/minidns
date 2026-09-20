package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/store"
)

var now = time.Now().Unix()

func reply(ts int64, client, name, qtype, rcode string) string {
	return fmt.Sprintf("[%d] unbound[1:0] query: %s %s. %s IN\n[%d] unbound[1:0] reply: %s %s. %s IN %s 0.012000 0 44\n", ts, client, name, qtype, ts, client, name, qtype, rcode)
}

func blocked(ts int64, client, name, rule, tag string) string {
	return fmt.Sprintf("[%d] unbound[1:0] query: %s %s. A IN\n[%d] unbound[1:0] info: rpz: applied [%s] %s. rpz-nxdomain %s@4242 %s. A IN\n[%d] unbound[1:0] reply: %s %s. A IN NXDOMAIN 0.000000 1 40\n",
		ts, client, name, ts, tag, rule, client, name, ts, client, name)
}

func setup(t *testing.T) *store.Store {
	t.Helper()
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	os.MkdirAll(paths.LogDir(), 0o755)
	s, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func appendLog(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(text)
	f.Close()
}

func total(t *testing.T, s *store.Store) (queries, blockedCount int64) {
	t.Helper()
	o, err := s.Overview(store.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	return o.Queries, o.Blocked
}

func TestIncrementalNoDuplicatesNoLoss(t *testing.T) {
	s := setup(t)
	live := paths.QueryLog()
	appendLog(t, live, reply(now-10, "10.0.0.5", "example.org", "A", "NOERROR")+blocked(now-9, "10.0.0.5", "www.ads.example", "*.ads.example", "block"))
	r, err := Run(s, time.Hour)
	if err != nil || !r.FirstRun || r.Events != 2 {
		t.Fatalf("first run: %+v %v", r, err)
	}
	// nothing new → nothing counted twice
	if r, _ = Run(s, time.Hour); r.Events != 0 {
		t.Fatalf("idle run ingested %d events", r.Events)
	}
	// a line still being written is left for the next run
	appendLog(t, live, reply(now-8, "10.0.0.6", "example.net", "AAAA", "NOERROR")+fmt.Sprintf("[%d] unbound[1:0] reply: 10.0.0.6 half.exam", now-7))
	if r, _ = Run(s, time.Hour); r.Events != 1 {
		t.Fatalf("partial line: ingested %d events, want 1", r.Events)
	}
	appendLog(t, live, "ple. A IN NOERROR 0.001000 0 44\n")
	if r, _ = Run(s, time.Hour); r.Events != 1 {
		t.Fatalf("completed line: ingested %d events, want 1", r.Events)
	}
	q, b := total(t, s)
	if q != 4 || b != 1 {
		t.Fatalf("totals: %d queries, %d blocked; want 4 and 1", q, b)
	}
	ev, _ := s.Events(store.Filter{Domain: "www.ads.example"}, 10)
	if len(ev) != 1 || ev[0].Policy != "block" || !ev[0].Blocked || ev[0].Rcode != "NXDOMAIN" {
		t.Fatalf("blocked event: %+v", ev)
	}
}

func TestRPZLineWithoutItsReplyYetIsNotLostOrDoubled(t *testing.T) {
	s := setup(t)
	live := paths.QueryLog()
	rpz := fmt.Sprintf("[%d] unbound[1:0] info: rpz: applied [adblock-x] ads.example. rpz-nxdomain 10.0.0.5@1 ads.example. A IN\n", now-5)
	after := reply(now-5, "10.0.0.9", "later.example", "A", "NOERROR") // written after the rpz line, before its reply
	appendLog(t, live, reply(now-6, "10.0.0.5", "a.example", "A", "NOERROR")+rpz+after)
	if r, _ := Run(s, time.Hour); r.Events != 1 {
		t.Fatalf("run 1 ingested %d, want only what precedes the open rpz line", r.Events)
	}
	appendLog(t, live, fmt.Sprintf("[%d] unbound[1:0] reply: 10.0.0.5 ads.example. A IN NXDOMAIN 0.000000 1 40\n", now-5))
	if r, _ := Run(s, time.Hour); r.Events != 2 {
		t.Fatalf("run 2 ingested %d, want 2", r.Events)
	}
	q, b := total(t, s)
	if q != 3 || b != 1 {
		t.Fatalf("totals: %d queries, %d blocked; want 3 and 1", q, b)
	}
}

func TestCopytruncateRotation(t *testing.T) {
	s := setup(t)
	live := paths.QueryLog()
	appendLog(t, live, reply(now-100, "10.0.0.5", "one.example", "A", "NOERROR"))
	Run(s, time.Hour)
	// more lines arrive, then logrotate copies the file and truncates it
	appendLog(t, live, reply(now-90, "10.0.0.5", "two.example", "A", "NOERROR"))
	old, _ := os.ReadFile(live)
	os.WriteFile(live+".1", old, 0o644)
	os.Truncate(live, 0)
	appendLog(t, live, reply(now-80, "10.0.0.5", "three.example", "A", "NOERROR"))
	r, err := Run(s, time.Hour)
	if err != nil || r.Events != 2 {
		t.Fatalf("after rotation: %+v %v (want the tail of .1 and the new file)", r, err)
	}
	if q, _ := total(t, s); q != 3 {
		t.Fatalf("total %d, want 3", q)
	}
}

func TestFirstRunImportsRotatedLogsButKeepsOldEventsOutOfTheEventTable(t *testing.T) {
	s := setup(t)
	live := paths.QueryLog()
	old := now - 40*86400
	appendLog(t, live+".2", reply(old, "10.0.0.5", "ancient.example", "A", "NOERROR"))
	os.Chtimes(live+".2", time.Unix(old, 0), time.Unix(old, 0))
	appendLog(t, live, reply(now-5, "10.0.0.5", "fresh.example", "A", "NOERROR"))
	if r, _ := Run(s, 7*24*time.Hour); r.Events != 2 || r.Files != 2 {
		t.Fatalf("first run: %+v", r)
	}
	if f := s.Footprint(); f.Events != 1 || f.RollupRows != 2 {
		t.Fatalf("footprint %+v: want 1 event (the fresh one) and 2 rollup rows", f)
	}
	// a garbage line and an unknown format never stop ingestion
	appendLog(t, live, "complete nonsense\n[abc] unbound[1:0] reply: x\n"+reply(now-1, "10.0.0.5", "fresh.example", "A", "NOERROR"))
	if r, err := Run(s, time.Hour); err != nil || r.Events != 1 {
		t.Fatalf("malformed lines: %+v %v", r, err)
	}
	_ = filepath.Base
}
