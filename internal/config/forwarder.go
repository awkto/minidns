package config

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Forwarder is one upstream server: ip, optional port, optional TLS
// authentication name. Its text form is unbound's: ip[@port][#authname].
type Forwarder struct {
	Addr     netip.Addr
	Port     int    // 0 = default (53, or 853 with TLS)
	AuthName string // certificate name to expect with DNS-over-TLS
}

// ParseForwarder validates and normalizes a forwarder address.
func ParseForwarder(s string) (Forwarder, error) {
	var f Forwarder
	rest := strings.TrimSpace(s)
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		f.AuthName = strings.TrimSuffix(strings.ToLower(rest[i+1:]), ".")
		rest = rest[:i]
		if f.AuthName == "" || !zoneNameRe.MatchString(f.AuthName) {
			return f, fmt.Errorf("%q: the part after # must be the server's TLS host name", s)
		}
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		p, err := strconv.Atoi(rest[i+1:])
		if err != nil || p < 1 || p > 65535 {
			return f, fmt.Errorf("%q: the part after @ must be a port number", s)
		}
		f.Port = p
		rest = rest[:i]
	}
	addr, err := netip.ParseAddr(strings.Trim(rest, "[]"))
	if err != nil || addr.Zone() != "" {
		return f, fmt.Errorf("%q is not an IP address (use ip, ip@port, or ip@port#tlsname)", s)
	}
	f.Addr = addr.Unmap()
	return f, nil
}

// String is the canonical form stored in the config and given to unbound.
func (f Forwarder) String() string {
	s := f.Addr.String()
	if f.Port != 0 {
		s += "@" + strconv.Itoa(f.Port)
	}
	if f.AuthName != "" {
		s += "#" + f.AuthName
	}
	return s
}

// ZoneForwarder sends the queries for one suffix (or reverse zone) to its
// own servers instead of the global forwarders or the roots.
type ZoneForwarder struct {
	Zone    string   `yaml:"zone"`
	Servers []string `yaml:"servers"`
	TLS     bool     `yaml:"tls,omitempty"`
}

// FindZoneForwarder returns the entry for zone, if any.
func (c *Config) FindZoneForwarder(zone string) *ZoneForwarder {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	for i := range c.ZoneForwarders {
		if c.ZoneForwarders[i].Zone == zone {
			return &c.ZoneForwarders[i]
		}
	}
	return nil
}
