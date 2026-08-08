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
