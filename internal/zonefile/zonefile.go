// Package zonefile validates master-format zone data before minidns hands
// it to unbound.
package zonefile

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Info summarizes a validated zone.
type Info struct {
	Serial  uint32
	Records int
}

// Validate parses data as the zone named origin and checks it is something
// unbound can serve: it parses, has exactly one SOA at the apex, at least
// one other record, and nothing outside the zone. $INCLUDE is refused —
// zone data comes from the network.
func Validate(origin, data string) (Info, error) {
	origin = dns.Fqdn(strings.ToLower(origin))
	zp := dns.NewZoneParser(strings.NewReader(data), origin, "")
	zp.SetIncludeAllowed(false)

	var info Info
	soas := 0
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		name := strings.ToLower(rr.Header().Name)
		if !dns.IsSubDomain(origin, name) {
			return info, fmt.Errorf("record %s is outside zone %s", name, origin)
		}
		// the parser tolerates records with no data (dynamic-update syntax);
		// a served zone must not contain them
		if dns.Len(rr) <= dns.Len(&dns.ANY{Hdr: *rr.Header()}) {
			return info, fmt.Errorf("record %s %s has no data", name, dns.TypeToString[rr.Header().Rrtype])
		}
		if soa, isSOA := rr.(*dns.SOA); isSOA {
			if name != origin {
				return info, fmt.Errorf("SOA at %s, expected the zone apex %s", name, origin)
			}
			soas++
			info.Serial = soa.Serial
		}
		info.Records++
	}
	if err := zp.Err(); err != nil {
		return info, fmt.Errorf("zone data does not parse: %w", err)
	}
	if soas != 1 {
		return info, fmt.Errorf("expected exactly one SOA record, found %d", soas)
	}
	if info.Records < 2 {
		return info, fmt.Errorf("zone has no records besides the SOA")
	}
	return info, nil
}
