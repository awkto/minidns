package zonefile

import "testing"

const good = `$ORIGIN example.com.
$TTL 1800
example.com. IN SOA ns1.digitalocean.com. hostmaster.example.com. 1723100000 10800 3600 604800 1800
example.com. 1800 IN NS ns1.digitalocean.com.
www.example.com. 300 IN A 192.0.2.10
example.com. 300 IN TXT "v=spf1 -all"
`

func TestValidate(t *testing.T) {
	info, err := Validate("Example.COM", good)
	if err != nil {
		t.Fatal(err)
	}
	if info.Serial != 1723100000 || info.Records != 4 {
		t.Fatalf("unexpected info: %+v", info)
	}
	bad := map[string]string{
		"empty":        "",
		"html error":   "<html><body>502 Bad Gateway</body></html>",
		"no soa":       "$ORIGIN example.com.\nwww 300 IN A 192.0.2.1\n",
		"soa only":     "example.com. 300 IN SOA ns1.x. h.x. 1 2 3 4 5\n",
		"out of zone":  good + "evil.other.org. 300 IN A 192.0.2.66\n",
		"include":      good + "$INCLUDE /etc/passwd\n",
		"truncated rr": good + "broken 300 IN A\n",
		"wrong zone":   "$ORIGIN other.org.\nother.org. 300 IN SOA ns1.x. h.x. 1 2 3 4 5\nother.org. 300 IN NS ns1.x.\n",
	}
	for name, data := range bad {
		if _, err := Validate("example.com", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
