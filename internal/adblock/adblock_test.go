package adblock

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/rpz"
)

func serve(t *testing.T, body *string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, *body) }))
	t.Cleanup(srv.Close)
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	os.MkdirAll(paths.RPZDir(), 0o755)
	return srv.URL
}

func TestUpdateRPZFeedIsReducedToBlocks(t *testing.T) {
	body := `$TTL 300
@ SOA localhost. root.localhost. 1 1 1 1 1
 NS localhost.
ads.example.com CNAME .
*.ads.example.com CNAME .
tracker.example.net 300 IN CNAME . ; comment
good.example.org CNAME rpz-passthru.
evil.example.org A 10.0.0.1
../../etc/passwd CNAME .
`
	url := serve(t, &body)
	n, changed, err := Update(config.BlockList{Name: "feed", URL: url, Format: "rpz"}, false)
	if err != nil || !changed || n != 3 {
		t.Fatalf("n=%d changed=%v err=%v", n, changed, err)
	}
	got, _ := os.ReadFile(paths.AdblockRPZ("feed"))
	for _, bad := range []string{"passthru", "10.0.0.1", "passwd"} {
		if strings.Contains(string(got), bad) {
			t.Errorf("%q leaked into the active file:\n%s", bad, got)
		}
	}
	// a second identical download changes nothing (no reload for nothing)
	if _, changed, _ = Update(config.BlockList{Name: "feed", URL: url, Format: "rpz"}, false); changed {
		t.Error("identical refresh reported as changed")
	}
}

func TestUpdateKeepsLastKnownGood(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&b, "0.0.0.0 ads%d.example.com\n", i)
	}
	body := b.String()
	url := serve(t, &body)
	l := config.BlockList{Name: "big", URL: url, Format: "hosts"}
	if n, _, err := Update(l, false); err != nil || n != 1200 {
		t.Fatalf("first update: n=%d err=%v", n, err)
	}

	for name, bad := range map[string]string{"empty": "", "html error page": "<html><body>rate limited</body></html>"} {
		body = bad
		if _, _, err := Update(l, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if rpz.CountEntries(paths.AdblockRPZ("big")) != 1200 {
			t.Fatalf("%s: active list was damaged", name)
		}
	}

	body = "0.0.0.0 only.example.com\n0.0.0.0 two.example.com\n"
	_, _, err := Update(l, false)
	if !errors.Is(err, ErrShrunk) || rpz.CountEntries(paths.AdblockRPZ("big")) != 1200 {
		t.Fatalf("implausible shrink: err=%v", err)
	}
	if n, changed, err := Update(l, true); err != nil || !changed || n != 2 {
		t.Fatalf("forced: n=%d changed=%v err=%v", n, changed, err)
	}
	// and the replaced copy can be put back
	if err := Restore("big"); err != nil || rpz.CountEntries(paths.AdblockRPZ("big")) != 1200 {
		t.Fatalf("restore: %v", err)
	}
}

func TestRedactURL(t *testing.T) {
	got := RedactURL("https://user:s3cret@lists.example.com/x.txt?token=abc123")
	if strings.Contains(got, "s3cret") || strings.Contains(got, "abc123") || !strings.Contains(got, "lists.example.com/x.txt") {
		t.Errorf("RedactURL = %s", got)
	}
}

func TestStateRecordsAttempts(t *testing.T) {
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	os.MkdirAll(paths.StateDir(), 0o755)
	Record("x", 10, nil)
	Record("x", 0, errors.New("boom"))
	st := LoadState()["x"]
	if st.Entries != 10 || st.Error != "boom" || st.LastSuccess.IsZero() {
		t.Errorf("state = %+v", st)
	}
	Forget("x")
	if _, ok := LoadState()["x"]; ok {
		t.Error("not forgotten")
	}
}
