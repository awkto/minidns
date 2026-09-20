package qlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLine(t *testing.T) {
	e, ok := ParseLine("[1691577600] unbound[1234:0] query: 192.168.1.10 example.com. A IN")
	if !ok || e.Kind != Query || e.Client != "192.168.1.10" || e.Qname != "example.com" || e.Qtype != "A" {
		t.Fatalf("query parse failed: %+v ok=%v", e, ok)
	}

	e, ok = ParseLine("[1691577600] unbound[1234:0] reply: 192.168.1.10 example.com. A IN NOERROR 0.012000 0 44")
	if !ok || e.Kind != Reply || e.Rcode != "NOERROR" || e.Latency != 0.012 || e.Cached {
		t.Fatalf("reply parse failed: %+v ok=%v", e, ok)
	}

	e, ok = ParseLine("[1691577600] unbound[1234:0] reply: 10.0.0.2 ads.foo.net. AAAA IN NXDOMAIN 0.000000 1 100")
	if !ok || !e.Cached || e.Rcode != "NXDOMAIN" {
		t.Fatalf("cached reply parse failed: %+v ok=%v", e, ok)
	}

	e, ok = ParseLine("[1691577600] unbound[1234:0] info: rpz: applied [adblock-stevenblack] ads.foo.net. rpz-nxdomain 10.0.0.2@40405 ads.foo.net. A IN")
	if !ok || e.Kind != RPZ || e.RPZTag != "adblock-stevenblack" || e.Qname != "ads.foo.net" || e.Client != "10.0.0.2" {
		t.Fatalf("rpz parse failed: %+v ok=%v", e, ok)
	}

	if _, ok := ParseLine("[1691577600] unbound[1234:0] info: start of service (unbound 1.19.2)."); ok {
		t.Error("noise line should not parse")
	}
}

func TestReadFromKeepsPartialLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "unbound.log")
	full := "[1691577600] unbound[1:0] query: 10.0.0.2 a.example. A IN\n"
	half := "[1691577601] unbound[1:0] query: 10.0.0.2 b.exam"
	if err := os.WriteFile(p, []byte(full+half), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	off := readFrom(p, 0, func(e Entry) { got = append(got, e.Qname) })
	if off != int64(len(full)) || len(got) != 1 || got[0] != "a.example" {
		t.Fatalf("offset=%d got=%v", off, got)
	}
	// unbound finishes the line; the next read must deliver it whole
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("ple. A IN\n")
	f.Close()
	readFrom(p, off, func(e Entry) { got = append(got, e.Qname) })
	if len(got) != 2 || got[1] != "b.example" {
		t.Fatalf("partial line lost: %v", got)
	}
}
