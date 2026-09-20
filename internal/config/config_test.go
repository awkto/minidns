package config

import (
	"os"
	"strings"
	"testing"

	"github.com/awkto/minidns/internal/paths"
)

func TestValidate(t *testing.T) {
	c := Default()
	c.CloudZones = []Zone{{Name: "dnsif.ca", Provider: "digitalocean"}}
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
		c.CloudZones = []Zone{{Name: bad}}
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

// v0.1 stored cloud replicas under "zones:"; v0.2 gives that word to local
// authoritative zones.
func TestLoadMigratesLegacyZonesKey(t *testing.T) {
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	os.MkdirAll(paths.ConfigDir(), 0o755)
	v01 := "upstreams: [1.1.1.1]\nzones:\n  - name: dnsif.ca\n    provider: digitalocean\nproviders:\n  digitalocean:\n    token_file: /etc/minidns/do.token\n"
	if err := os.WriteFile(paths.ConfigFile(), []byte(v01), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.Migrated || c.FindZone("dnsif.ca") == nil || len(c.LocalZones) != 0 {
		t.Fatalf("legacy zones not folded into cloud_zones: %+v", c)
	}
	if c.Providers.DigitalOcean.TokenFile != "/etc/minidns/do.token" {
		t.Error("unrelated settings must survive")
	}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(paths.ConfigFile())
	if !strings.Contains(string(b), "cloud_zones:") || strings.Contains(string(b), "\nzones:") {
		t.Errorf("saved config still uses the old key:\n%s", b)
	}
	c2, _ := Load()
	if c2.Migrated || c2.FindZone("dnsif.ca") == nil {
		t.Error("second load should be clean and keep the replica")
	}
}

func TestLocalZoneCannotShadowReplica(t *testing.T) {
	c := Default()
	c.CloudZones = []Zone{{Name: "dnsif.ca"}}
	c.LocalZones = []string{"dnsif.ca"}
	if c.Validate() == nil {
		t.Error("the same name as local zone and replica must be rejected")
	}
	c.LocalZones = []string{"lan", "home.arpa", "0.20.10.in-addr.arpa"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid local zones rejected: %v", err)
	}
}
