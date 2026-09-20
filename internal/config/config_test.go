package config

import "testing"

func TestValidate(t *testing.T) {
	c := Default()
	c.Zones = []Zone{{Name: "dnsif.ca", Provider: "digitalocean"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults should validate: %v", err)
	}
	for _, bad := range []string{"../../etc/passwd", "a b", "x\"\n  include: /etc/shadow", ""} {
		c := Default()
		c.Adblock.Lists = []BlockList{{Name: bad}}
		if c.Validate() == nil {
			t.Errorf("list name %q should be rejected", bad)
		}
		c = Default()
		c.Zones = []Zone{{Name: bad}}
		if c.Validate() == nil {
			t.Errorf("zone name %q should be rejected", bad)
		}
	}
}

func TestListNameFromURL(t *testing.T) {
	if got := ListNameFromURL("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"); got != "githubusercontent-com" {
		t.Errorf("got %q", got)
	}
}
