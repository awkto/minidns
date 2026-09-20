package store

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/awkto/minidns/internal/paths"
)

func open(t *testing.T) *Store {
	t.Helper()
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	s, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenIsPrivateAndMigratesOnce(t *testing.T) {
	s := open(t)
	if st, _ := os.Stat(File()); st.Mode().Perm() != 0o600 {
		t.Errorf("database mode %o, want 600 — it records who looked up what", st.Mode().Perm())
	}
	if a, l := s.SchemaVersion(); a != l || a == 0 {
		t.Fatalf("schema %d of %d", a, l)
	}
	s.Close()
	s2, err := Open() // reopening must not re-run migrations
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
	_ = paths.StateDir
}

func TestDevicesAndAddressHistory(t *testing.T) {
	s := open(t)
	if err := s.AddDevice("Altan's Laptop", "work machine", []string{"work"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDevice("altan's laptop", "", nil); !errors.Is(err, ErrConflict) {
		t.Errorf("names must be unique regardless of case: %v", err)
	}
	if err := s.AddDevice("10.0.0.5", "", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("an IP address is not a device name: %v", err)
	}
	a, err := s.AddAddress("Altan's Laptop", "10.0.0.5", "AA-BB-CC-00-11-22", "")
	if err != nil || a.ValidFrom != 0 || a.MAC != "aa:bb:cc:00:11:22" {
		t.Fatalf("first holder of an address owns its history: %+v %v", a, err)
	}
	s.AddDevice("phone", "", nil)
	if _, err := s.AddAddress("phone", "10.0.0.5", "", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("an address can be current for one device only: %v", err)
	}
	if _, err := s.AddAddress("phone", "not-an-ip", "", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad ip: %v", err)
	}
	if _, err := s.AddAddress("nobody", "10.0.0.9", "", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown device: %v", err)
	}

	// the laptop moves to .9; .5 is later handed to the phone
	before := time.Now().Unix() - 10
	s.AddAddress("Altan's Laptop", "10.0.0.9", "", "")
	if err := s.RemoveAddress("Altan's Laptop", "10.0.0.5", false); err != nil {
		t.Fatal(err)
	}
	p, err := s.AddAddress("phone", "10.0.0.5", "", "")
	if err != nil || p.ValidFrom == 0 {
		t.Fatalf("second holder starts now, not at the beginning of time: %+v %v", p, err)
	}
	if got := s.DeviceAt("10.0.0.5", before); got != "Altan's Laptop" {
		t.Errorf("history of .5 belongs to the laptop, got %q", got)
	}
	if got := s.DeviceAt("10.0.0.5", time.Now().Unix()+5); got != "phone" {
		t.Errorf(".5 now belongs to the phone, got %q", got)
	}
	if err := s.RenameDevice("phone", "Pixel 9"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Device("pixel 9")
	if d == nil || len(d.Addresses) != 1 || !d.Addresses[0].Current() {
		t.Fatalf("renamed device: %+v", d)
	}
	if err := s.RemoveDevice("Pixel 9"); err != nil {
		t.Fatal(err)
	}
	if got := s.DeviceAt("10.0.0.5", time.Now().Unix()+5); got != "" {
		t.Errorf("a removed device must not attribute anything, got %q", got)
	}
}

func seed(t *testing.T, s *Store, now int64) {
	t.Helper()
	ev := func(ago int64, client, name, qtype, rcode, policy string) Event {
		return Event{TS: now - ago, Client: client, Qname: name, Qtype: qtype, Rcode: rcode, Policy: policy}
	}
	events := []Event{
		ev(60, "10.0.0.5", "www.example.co.uk", "A", "NOERROR", ""),
		ev(61, "10.0.0.5", "api.example.co.uk", "A", "NOERROR", ""),
		ev(62, "10.0.0.5", "api.example.co.uk", "AAAA", "NOERROR", ""),
		ev(63, "10.0.0.5", "ads.tracker.net", "A", "NXDOMAIN", "adblock-stevenblack"),
		ev(64, "10.0.0.6", "ads.tracker.net", "A", "NXDOMAIN", "block"),
		ev(65, "10.0.0.6", "5.0.0.10.in-addr.arpa", "PTR", "NOERROR", ""),
		ev(66, "10.0.0.6", "allowed.tracker.net", "A", "NOERROR", "allow"),
		ev(67, "fd00::7", "nas.home.arpa", "A", "NOERROR", ""),
	}
	if err := s.AddBatch(events, nil, 0); err != nil {
		t.Fatal(err)
	}
}

func TestRankingsFiltersAndAttribution(t *testing.T) {
	s := open(t)
	now := time.Now().Unix()
	seed(t, s, now)
	s.AddDevice("laptop", "", nil)
	s.AddAddress("laptop", "10.0.0.5", "", "")

	top, err := s.TopDomains(Filter{}, false, 10)
	if err != nil || len(top) != 6 || top[0].Queries != 2 {
		t.Fatalf("top domains: %+v %v", top, err)
	}
	reg, _ := s.TopDomains(Filter{}, true, 10)
	if reg[0].Key != "example.co.uk" || reg[0].Queries != 3 || reg[1].Key != "tracker.net" || reg[1].Blocked != 2 {
		t.Fatalf("grouped by registrable domain: %+v", reg)
	}
	mine, _ := s.TopDomains(Filter{Device: "laptop"}, false, 10)
	if len(mine) != 3 {
		t.Fatalf("top domains of one device: %+v", mine)
	}
	yes := true
	bl, _ := s.TopDomains(Filter{Blocked: &yes}, false, 10)
	if len(bl) != 1 || bl[0].Key != "ads.tracker.net" || bl[0].Queries != 2 {
		t.Fatalf("top blocked (an allowlisted hit is not a block): %+v", bl)
	}
	ptr, _ := s.TopDomains(Filter{Qtype: "ptr"}, false, 10)
	if len(ptr) != 1 || ptr[0].Key != "5.0.0.10.in-addr.arpa" {
		t.Fatalf("top reverse lookups: %+v", ptr)
	}
	sub, _ := s.TopDomains(Filter{Domain: "tracker.net", Suffix: true}, false, 10)
	if len(sub) != 2 {
		t.Fatalf("suffix filter: %+v", sub)
	}

	dev, _ := s.TopDevices(Filter{}, 10)
	if len(dev) != 3 || dev[0].Key != "laptop" || dev[0].Queries != 4 || dev[1].Key != "10.0.0.6" {
		t.Fatalf("top devices (unknown clients stay visible as IPs): %+v", dev)
	}
	// naming a device later renames its history too
	s.RenameDevice("laptop", "Altan's MacBook")
	dev, _ = s.TopDevices(Filter{}, 10)
	if dev[0].Key != "Altan's MacBook" {
		t.Fatalf("attribution happens at read time: %+v", dev)
	}

	o, _ := s.Overview(Filter{})
	if o.Queries != 8 || o.Blocked != 2 || o.Clients != 3 || o.ByType["PTR"] != 1 || o.ByRcode["NXDOMAIN"] != 2 || o.ByPolicy["block"] != 1 {
		t.Fatalf("overview: %+v", o)
	}
	ev, _ := s.Events(Filter{Device: "Altan's MacBook"}, 2)
	if len(ev) != 2 || ev[1].Name != "www.example.co.uk" || ev[1].Device != "Altan's MacBook" {
		t.Fatalf("newest events, oldest first, with the device name: %+v", ev)
	}
	if _, err := s.TopDomains(Filter{Device: "ghost"}, false, 10); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown device: %v", err)
	}
}

func TestPruneFoldsHoursIntoDaysWithoutLosingCounts(t *testing.T) {
	s := open(t)
	now := time.Now()
	old := now.Add(-50 * 24 * time.Hour).Unix()
	var events []Event
	for i := int64(0); i < 5; i++ { // five different hours of one old day…
		events = append(events, Event{TS: old - old%86400 + i*3600 + 10, Client: "10.0.0.5", Qname: "old.example", Qtype: "A", Rcode: "NOERROR"})
	}
	events = append(events, Event{TS: now.Unix() - 30, Client: "10.0.0.5", Qname: "new.example", Qtype: "A", Rcode: "NOERROR"})
	if err := s.AddBatch(events, nil, 0); err != nil {
		t.Fatal(err)
	}
	res, err := s.Prune(DefaultRetention, now)
	if err != nil || res.Events != 5 || res.Folded != 5 {
		t.Fatalf("prune: %+v %v", res, err)
	}
	f := s.Footprint()
	if f.Events != 1 || f.RollupRows != 2 {
		t.Fatalf("after prune: %+v (want the recent event, one daily row and one hourly row)", f)
	}
	top, _ := s.TopDomains(Filter{}, false, 10)
	if top[0].Key != "old.example" || top[0].Queries != 5 {
		t.Fatalf("counts must survive folding: %+v", top)
	}
	// running it again changes nothing
	if res, _ = s.Prune(DefaultRetention, now); res.Events+res.Folded+res.Rollups != 0 {
		t.Fatalf("second prune: %+v", res)
	}
	// beyond the daily retention the counts go, and so do orphaned names
	if _, err := s.Prune(Retention{Events: time.Hour, Hourly: 24 * time.Hour, Daily: 40 * 24 * time.Hour}, now); err != nil {
		t.Fatal(err)
	}
	if f = s.Footprint(); f.Names != 1 {
		t.Fatalf("orphaned names should be dropped: %+v", f)
	}
}
