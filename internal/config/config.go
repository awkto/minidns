// Package config loads and saves /etc/minidns/config.yaml — the single
// source of truth the unbound config is generated from.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/awkto/minidns/internal/paths"
)

type BlockList struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Format string `yaml:"format"` // hosts | domains | rpz
}

type Zone struct {
	Name     string `yaml:"name"`
	Provider string `yaml:"provider"` // digitalocean (roadmap: route53, azure, cloudflare)
}

type Config struct {
	Listen        []string `yaml:"listen"`         // unbound interface: lines
	Port          int      `yaml:"port"`           //
	AllowNetworks []string `yaml:"allow_networks"` // access-control allow

	Upstreams   []string `yaml:"upstreams"`    // forward-addr targets; ip[@port][#authname]
	UpstreamTLS bool     `yaml:"upstream_tls"` // DNS-over-TLS to upstreams
	Recursion   bool     `yaml:"recursion"`    // true = full recursion, no forwarding

	Threads      int `yaml:"threads"`        // 0 = one per CPU
	MsgCacheMB   int `yaml:"msg_cache_mb"`   //
	RRsetCacheMB int `yaml:"rrset_cache_mb"` //

	Firewall struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"firewall"`

	Adblock struct {
		Enabled bool        `yaml:"enabled"`
		Lists   []BlockList `yaml:"lists"`
	} `yaml:"adblock"`

	// LocalZones are authoritative zones owned by this host; their records
	// live in zone files under paths.LocalZoneDir().
	LocalZones []string `yaml:"local_zones"`

	// CloudZones are read-only replicas of zones hosted at a cloud provider.
	// v0.1 called this key "zones"; Load folds the old key in and the next
	// Save writes the new one.
	CloudZones  []Zone `yaml:"cloud_zones"`
	LegacyZones []Zone `yaml:"zones,omitempty"`

	Providers struct {
		DigitalOcean struct {
			Token     string `yaml:"token"`
			TokenFile string `yaml:"token_file"`
		} `yaml:"digitalocean"`
	} `yaml:"providers"`

	Logging struct {
		Queries bool `yaml:"queries"`
	} `yaml:"logging"`

	Exporter struct {
		Enabled bool   `yaml:"enabled"`
		Listen  string `yaml:"listen"`
	} `yaml:"exporter"`

	// Migrated is set by Load when the file used keys from an older version;
	// callers that are allowed to write should Save to persist the new form.
	Migrated bool `yaml:"-"`
}

func Default() *Config {
	c := &Config{
		Listen:        []string{"0.0.0.0"},
		Port:          53,
		AllowNetworks: []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		Upstreams:     []string{"1.1.1.1", "1.0.0.1", "8.8.8.8"},
		MsgCacheMB:    64,
		RRsetCacheMB:  128,
	}
	c.Firewall.Enabled = true
	c.Adblock.Enabled = true
	c.Adblock.Lists = []BlockList{{
		Name:   "stevenblack",
		URL:    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Format: "hosts",
	}}
	c.Logging.Queries = true
	c.Exporter.Listen = "0.0.0.0:9153"
	return c
}

// Load reads the config file, or returns defaults if it doesn't exist yet.
func Load() (*Config, error) {
	b, err := os.ReadFile(paths.ConfigFile())
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", paths.ConfigFile(), err)
	}
	if len(c.LegacyZones) > 0 {
		for _, z := range c.LegacyZones {
			if c.FindZone(z.Name) == nil {
				c.CloudZones = append(c.CloudZones, z)
			}
		}
		c.LegacyZones = nil
		c.Migrated = true
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", paths.ConfigFile(), err)
	}
	return c, nil
}

var (
	listNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	zoneNameRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]*[a-z0-9_])?\.)*[a-z][a-z0-9-]*$`)
)

// Validate rejects names that would be unsafe in the file paths and unbound
// config lines generated from them (a hand-edited config is the only way to
// get them past the CLI, but the renderer must not trust it).
func (c *Config) Validate() error {
	for _, l := range c.Adblock.Lists {
		if !listNameRe.MatchString(l.Name) {
			return fmt.Errorf("adblock list name %q is invalid (lowercase letters, digits, - and _)", l.Name)
		}
	}
	for _, z := range c.CloudZones {
		if len(z.Name) > 253 || !zoneNameRe.MatchString(z.Name) {
			return fmt.Errorf("cloud zone name %q is invalid", z.Name)
		}
	}
	for _, z := range c.LocalZones {
		if len(z) > 253 || !zoneNameRe.MatchString(z) {
			return fmt.Errorf("local zone name %q is invalid", z)
		}
		if c.FindZone(z) != nil {
			return fmt.Errorf("%q is configured both as a local zone and as a cloud replica", z)
		}
	}
	return nil
}

// Save writes the config with 0600 perms (it may hold provider tokens).
func Save(c *Config) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.ConfigDir(), 0o755); err != nil {
		return err
	}
	tmp := paths.ConfigFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, paths.ConfigFile())
}

// DOToken resolves the DigitalOcean API token from config, token_file,
// or the DIGITALOCEAN_TOKEN environment variable.
func (c *Config) DOToken() (string, error) {
	if t := strings.TrimSpace(c.Providers.DigitalOcean.Token); t != "" {
		return t, nil
	}
	if f := c.Providers.DigitalOcean.TokenFile; f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read digitalocean token_file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := os.Getenv("DIGITALOCEAN_TOKEN"); t != "" {
		return strings.TrimSpace(t), nil
	}
	return "", fmt.Errorf("no DigitalOcean token: set providers.digitalocean.token in %s (or token_file / DIGITALOCEAN_TOKEN)", paths.ConfigFile())
}

// FindZone returns the cloud replica entry for name, if any.
func (c *Config) FindZone(name string) *Zone {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for i := range c.CloudZones {
		if c.CloudZones[i].Name == name {
			return &c.CloudZones[i]
		}
	}
	return nil
}

// HasLocalZone reports whether name is one of the local authoritative zones.
func (c *Config) HasLocalZone(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, z := range c.LocalZones {
		if z == name {
			return true
		}
	}
	return false
}

// FindList returns the adblock list with the given name, if any.
func (c *Config) FindList(name string) *BlockList {
	for i := range c.Adblock.Lists {
		if c.Adblock.Lists[i].Name == name {
			return &c.Adblock.Lists[i]
		}
	}
	return nil
}

// ListNameFromURL derives a short list name from a URL host.
func ListNameFromURL(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "www.")
	s = strings.TrimPrefix(s, "raw.")
	s = strings.ReplaceAll(s, ".", "-")
	return filepath.Clean(strings.ToLower(s))
}
