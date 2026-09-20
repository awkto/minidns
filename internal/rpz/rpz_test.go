package rpz

import (
	"path/filepath"
	"testing"
)

func TestWriteReadContains(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test.rpz")
	n, err := Write(p, []string{"Ads.Example.COM.", "tracker.net", "ads.example.com", "not a domain"}, ActionBlock, true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("want 2 unique domains, got %d", n)
	}
	domains, err := ReadDomains(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0] != "ads.example.com" {
		t.Fatalf("unexpected domains: %v", domains)
	}
	if _, ok := Contains(p, "sub.deep.ads.example.com"); !ok {
		t.Error("wildcard should match subdomain")
	}
	if _, ok := Contains(p, "example.com"); ok {
		t.Error("parent domain should not match")
	}
	if got := CountEntries(p); got != 4 {
		t.Errorf("want 4 CNAME entries (2 + 2 wildcards), got %d", got)
	}
}

func TestValidDomain(t *testing.T) {
	for _, good := range []string{"a.com", "sub.domain-x.co.uk", "xn--nxasmq6b.example", "_dmarc.example.com"} {
		if !ValidDomain(good) {
			t.Errorf("%q should be valid", good)
		}
	}
	for _, bad := range []string{"", "com", "-bad.com", "ex ample.com", "1.2.3.4"} {
		if ValidDomain(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestExplicitWildcardRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "block.rpz")
	if _, err := Write(p, []string{"*.foo.com", "bar.com"}, ActionBlock, true); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDomains(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "*.foo.com" || got[1] != "bar.com" {
		t.Fatalf("explicit wildcard lost on read-back: %v", got)
	}
	// a rewrite (what block/unblock does) must keep it
	if _, err := Write(p, append(got, "baz.com"), ActionBlock, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := Contains(p, "x.foo.com"); !ok {
		t.Error("*.foo.com dropped by rewrite")
	}
	if _, ok := Contains(p, "foo.com"); ok {
		t.Error("explicit wildcard must not block the apex")
	}
}

func TestValidListName(t *testing.T) {
	for _, good := range []string{"stevenblack", "oisd-big", "list_2"} {
		if !ValidListName(good) {
			t.Errorf("%q should be valid", good)
		}
	}
	for _, bad := range []string{"", "../../evil", "a b", "Upper", "-x", "x\ny", "a/b", "x.rpz"} {
		if ValidListName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
