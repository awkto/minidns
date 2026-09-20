package zones

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/awkto/minidns/internal/paths"
)

func newZone(t *testing.T, name string) *Zone {
	t.Helper()
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	z, err := Create(name, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestCreateLoadRoundTrip(t *testing.T) {
	z := newZone(t, "Home.Example.")
	if z.Name != "home.example" || z.Serial == 0 {
		t.Fatalf("unexpected zone %+v", z)
	}
	got, err := Load("home.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != z.Serial || len(got.Records) != 2 {
		t.Fatalf("round trip: %+v", got)
	}
	if _, err := Create("home.example", "", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate create: want ErrConflict, got %v", err)
	}
	if _, err := Load("nope.example"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing zone: want ErrNotFound, got %v", err)
	}
	for _, bad := range []string{"", "a b.example", "../../etc", "x/y", "semi;colon.example"} {
		if _, err := Create(bad, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("zone name %q: want ErrInvalid, got %v", bad, err)
		}
	}
}

func TestAddEveryCommonType(t *testing.T) {
	z := newZone(t, "home.example")
	cases := []struct{ name, typ, val, wantName, wantVal string }{
		{"nas", "a", "10.20.0.10", "nas.home.example.", "10.20.0.10"},
		{"nas", "AAAA", "fd00::10", "nas.home.example.", "fd00::10"},
		{"git", "CNAME", "nas", "git.home.example.", "nas.home.example."},
		{"www.home.example", "CNAME", "nas.home.example.", "www.home.example.", "nas.home.example."},
		{"@", "MX", "10 mail.home.example.", "home.example.", "10 mail.home.example."},
		{"@", "TXT", "v=spf1 -all", "home.example.", `"v=spf1 -all"`},
		{"quoted", "TXT", `"already quoted" "two strings"`, "quoted.home.example.", `"already quoted" "two strings"`},
		{"_https._tcp", "SRV", "0 5 443 nas", "_https._tcp.home.example.", "0 5 443 nas.home.example."},
		{"@", "CAA", `0 issue "letsencrypt.org"`, "home.example.", `0 issue "letsencrypt.org"`},
		{"sub", "NS", "ns1.other.example.", "sub.home.example.", "ns1.other.example."},
	}
	for _, c := range cases {
		rec, added, err := z.Add(c.name, c.typ, c.val, 0, "")
		if err != nil || !added {
			t.Fatalf("add %v: added=%v err=%v", c, added, err)
		}
		if rec.Name != c.wantName || rec.Value != c.wantVal || rec.TTL != DefaultTTL {
			t.Errorf("add %v: got %+v", c, rec)
		}
	}
	// everything must survive a reload from disk
	if err := z.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load("home.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.UserRecords()) != len(cases)+1 { // + the default NS
		t.Errorf("want %d records on disk, got %d:\n%s", len(cases)+1, len(got.UserRecords()), got.Render(got.Serial))
	}
}

func TestAddRejectsBadInput(t *testing.T) {
	z := newZone(t, "home.example")
	bad := []struct{ name, typ, val string }{
		{"nas", "A", "not-an-ip"},
		{"nas", "A", "fd00::1"},
		{"nas", "AAAA", "10.0.0.1"},
		{"nas", "MX", "mail.home.example."},
		{"nas", "SRV", "443 nas"},
		{"nas", "BOGUS", "x"},
		{"nas", "SOA", "a. b. 1 2 3 4 5"},
		{"nas", "A", ""},
		{"nas", "A", "10.0.0.1\nevil 300 IN A 6.6.6.6"},
		{"host.other.org.", "A", "10.0.0.1"},
		{"bad name", "A", "10.0.0.1"},
		{"nas", "DNSKEY", "256 3 8 AwEAAc"},
	}
	for _, c := range bad {
		if _, _, err := z.Add(c.name, c.typ, c.val, 0, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("add %v: want ErrInvalid, got %v", c, err)
		}
	}
	if _, _, err := z.Add("nas", "A", "10.0.0.1", 0, "bad tag"); !errors.Is(err, ErrInvalid) {
		t.Error("managed-by with spaces must be rejected")
	}
}

func TestIdempotentAddAndCNAMERules(t *testing.T) {
	z := newZone(t, "home.example")
	if _, added, _ := z.Add("nas", "A", "10.20.0.10", 0, ""); !added {
		t.Fatal("first add should add")
	}
	if _, added, err := z.Add("nas", "A", "10.20.0.10", 0, ""); added || err != nil {
		t.Errorf("identical add must be a no-op: added=%v err=%v", added, err)
	}
	if _, added, _ := z.Add("nas", "A", "10.20.0.10", 600, ""); !added {
		t.Error("same data with a new TTL is an update")
	}
	if _, _, err := z.Add("nas", "CNAME", "other", 0, ""); !errors.Is(err, ErrConflict) {
		t.Errorf("CNAME next to A: want ErrConflict, got %v", err)
	}
	z.Add("alias", "CNAME", "nas", 0, "")
	if _, _, err := z.Add("alias", "A", "10.0.0.1", 0, ""); !errors.Is(err, ErrConflict) {
		t.Errorf("A next to CNAME: want ErrConflict, got %v", err)
	}
	if _, _, err := z.Add("@", "CNAME", "nas", 0, ""); !errors.Is(err, ErrConflict) {
		t.Errorf("apex CNAME: want ErrConflict, got %v", err)
	}
}

func TestRemove(t *testing.T) {
	z := newZone(t, "home.example")
	z.Add("nas", "A", "10.20.0.10", 0, "")
	z.Add("nas", "A", "10.20.0.11", 0, "")
	z.Add("nas", "AAAA", "fd00::10", 0, "")
	if removed, err := z.Remove("nas", "A", "10.20.0.11"); err != nil || len(removed) != 1 {
		t.Fatalf("remove one: %v %v", removed, err)
	}
	if removed, err := z.Remove("nas", "a", ""); err != nil || len(removed) != 1 {
		t.Fatalf("remove rest: %v %v", removed, err)
	}
	if _, err := z.Remove("nas", "A", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if _, err := z.Remove("@", "NS", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("removing the last apex NS: want ErrConflict, got %v", err)
	}
	if _, err := z.Remove("@", "SOA", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("removing the SOA: want ErrInvalid, got %v", err)
	}
	if err := z.Save(); err != nil {
		t.Fatal(err)
	}
	got, _ := Load("home.example")
	if len(got.UserRecords()) != 2 { // NS + AAAA
		t.Errorf("unexpected records left: %+v", got.UserRecords())
	}
}

func TestManagedByAndLongTXTSurviveDisk(t *testing.T) {
	z := newZone(t, "home.example")
	z.Add("laptop", "A", "10.20.0.5", 0, "minidhcp")
	long := strings.Repeat("k", 600)
	z.Add("dkim._domainkey", "TXT", long, 0, "")
	if err := z.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load("home.example")
	if err != nil {
		t.Fatal(err)
	}
	var tagged, txt *Record
	for i, r := range got.Records {
		if r.Type == "A" {
			tagged = &got.Records[i]
		}
		if r.Type == "TXT" {
			txt = &got.Records[i]
		}
	}
	if tagged == nil || tagged.ManagedBy != "minidhcp" {
		t.Errorf("managed-by lost: %+v", tagged)
	}
	if txt == nil || strings.Count(txt.Value, `"`) != 6 || len(strings.ReplaceAll(strings.ReplaceAll(txt.Value, `"`, ""), " ", "")) != 600 {
		t.Errorf("long TXT not split into 3 strings: %+v", txt)
	}
}

func TestRenderIsDeterministicAndSorted(t *testing.T) {
	z := newZone(t, "home.example")
	for _, n := range []string{"zeta", "alpha", "a.alpha", "@"} {
		z.Add(n, "A", "10.0.0.1", 0, "")
	}
	out := z.Render(7)
	if out != z.Render(7) {
		t.Error("render not deterministic")
	}
	idx := func(s string) int { return strings.Index(out, s) }
	if !(idx("\tSOA\t") < idx("\tNS\t") && idx("\tNS\t") < idx("home.example.\t300\tIN\tA") &&
		idx("alpha.home.example.") < idx("a.alpha.home.example.") && idx("a.alpha.home.example.") < idx("zeta.home.example.")) {
		t.Errorf("unexpected order:\n%s", out)
	}
	if !strings.Contains(out, " 7 3600 600 604800 300") {
		t.Errorf("serial not rendered:\n%s", out)
	}
}

func TestSerial(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	if got := nextSerial(0, now); got != 2026092000 {
		t.Errorf("fresh: %d", got)
	}
	if got := nextSerial(2026092000, now); got != 2026092001 {
		t.Errorf("same day: %d", got)
	}
	if got := nextSerial(2026092099, now); got != 2026092100 {
		t.Errorf("overflow must keep increasing: %d", got)
	}
	if got := nextSerial(2030010100, now); got != 2030010101 {
		t.Errorf("never go backwards: %d", got)
	}
}

func TestRollback(t *testing.T) {
	z := newZone(t, "home.example")
	z.Add("nas", "A", "10.20.0.10", 0, "")
	z.Save()
	before, _ := os.ReadFile(paths.LocalZoneFile("home.example"))
	z.Add("bad", "A", "10.20.0.66", 0, "")
	z.Add("worse", "A", "10.20.0.67", 0, "")
	z.Save() // two changes, one write, one rollback
	if err := Rollback("home.example"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(paths.LocalZoneFile("home.example"))
	if string(before) != string(after) {
		t.Error("rollback did not restore the previous file")
	}
}

func TestReverseZoneFor(t *testing.T) {
	cases := []struct {
		cidr, zone string
		widened    bool
	}{
		{"10.20.0.0/24", "0.20.10.in-addr.arpa", false},
		{"10.20.0.0/16", "20.10.in-addr.arpa", false},
		{"10.0.0.0/8", "10.in-addr.arpa", false},
		{"192.168.1.128/25", "1.168.192.in-addr.arpa", true},
		{"10.20.16.0/20", "20.10.in-addr.arpa", true},
		{"fd00:1234::/32", "4.3.2.1.0.0.d.f.ip6.arpa", false},
		{"fd00:1234:5678:9a00::/56", "a.9.8.7.6.5.4.3.2.1.0.0.d.f.ip6.arpa", false},
		{"fd00::/30", "0.0.0.0.0.d.f.ip6.arpa", true}, // 30 bits = 7 whole nibbles
	}
	for _, c := range cases {
		zone, widened, err := ReverseZoneFor(netip.MustParsePrefix(c.cidr))
		if err != nil || zone != c.zone || widened != c.widened {
			t.Errorf("%s: got %q widened=%v err=%v, want %q %v", c.cidr, zone, widened, err, c.zone, c.widened)
		}
	}
	if _, _, err := ReverseZoneFor(netip.MustParsePrefix("0.0.0.0/0")); err == nil {
		t.Error("/0 must be rejected")
	}
}

func TestBestReverseZoneAndPTR(t *testing.T) {
	local := []string{"home.example", "10.in-addr.arpa", "0.20.10.in-addr.arpa", "0.0.d.f.ip6.arpa"}
	if got := BestReverseZone(local, netip.MustParseAddr("10.20.0.10")); got != "0.20.10.in-addr.arpa" {
		t.Errorf("longest match: %q", got)
	}
	if got := BestReverseZone(local, netip.MustParseAddr("10.99.0.1")); got != "10.in-addr.arpa" {
		t.Errorf("fallback to /8: %q", got)
	}
	if got := BestReverseZone(local, netip.MustParseAddr("192.168.1.1")); got != "" {
		t.Errorf("no zone: %q", got)
	}
	if got := PTRName(netip.MustParseAddr("10.20.0.10")); got != "10.0.20.10.in-addr.arpa." {
		t.Errorf("ptr name: %q", got)
	}
	if got := BestReverseZone(local, netip.MustParseAddr("fd00::10")); got != "0.0.d.f.ip6.arpa" {
		t.Errorf("v6: %q", got)
	}
}
