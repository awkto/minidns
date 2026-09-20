// Package zones manages the local authoritative zones minidns owns.
//
// The zone file on disk is the single copy of the data: unbound serves it
// as an auth-zone and `minidns record` edits it. Every write re-renders the
// whole file deterministically (sorted, absolute names, one record per
// line), bumps the SOA serial and validates the result before it replaces
// the previous file, so a zone can never be left half-written.
package zones

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/zonefile"
)

// Sentinel errors so the CLI can map failures to stable exit codes.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
)

const (
	DefaultTTL = 300
	header     = "; Managed by minidns — change records with `minidns record`, not by hand.\n"
	managedTag = "managed-by="
)

// Record is one resource record in a local zone.
type Record struct {
	Name      string `json:"name"`  // absolute owner name, lower case, trailing dot
	TTL       uint32 `json:"ttl"`   //
	Type      string `json:"type"`  //
	Value     string `json:"value"` // rdata in presentation format
	ManagedBy string `json:"managed_by,omitempty"`
}

// Zone is a parsed local zone.
type Zone struct {
	Name    string   `json:"name"` // no trailing dot
	Serial  uint32   `json:"serial"`
	Records []Record `json:"records"`
}

// Origin returns the zone name as an FQDN.
func (z *Zone) Origin() string { return dns.Fqdn(z.Name) }

// NormalizeZone lower-cases and strips the trailing dot.
func NormalizeZone(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// ValidZoneName reports whether s can be a local zone: a syntactically valid
// domain name, single-label names ("lan") included.
func ValidZoneName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if _, ok := dns.IsDomainName(s); !ok {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || strings.ContainsAny(label, " \t\"\\/;()@$*") {
			return false
		}
	}
	return true
}

// Create writes a new zone containing only SOA and NS.
func Create(name, primaryNS, email string) (*Zone, error) {
	name = NormalizeZone(name)
	if !ValidZoneName(name) {
		return nil, fmt.Errorf("%w: %q is not a valid zone name", ErrInvalid, name)
	}
	if Exists(name) {
		return nil, fmt.Errorf("%w: zone %s already exists", ErrConflict, name)
	}
	if primaryNS == "" {
		primaryNS = "localhost."
	}
	if email == "" {
		email = "hostmaster." + dns.Fqdn(name)
	}
	primaryNS, email = dns.Fqdn(strings.ToLower(primaryNS)), dns.Fqdn(strings.ToLower(strings.Replace(email, "@", ".", 1)))
	origin := dns.Fqdn(name)
	z := &Zone{Name: name, Records: []Record{
		{Name: origin, TTL: DefaultTTL, Type: "SOA", Value: fmt.Sprintf("%s %s 0 3600 600 604800 %d", primaryNS, email, DefaultTTL)},
		{Name: origin, TTL: DefaultTTL, Type: "NS", Value: primaryNS},
	}}
	return z, z.Save()
}

// Exists reports whether a local zone file is present.
func Exists(name string) bool {
	st, err := os.Stat(paths.LocalZoneFile(NormalizeZone(name)))
	return err == nil && !st.IsDir()
}

// Remove deletes the zone file. The caller must have stopped unbound from
// referencing it first (a reload that finds the file missing is fatal).
func Remove(name string) error {
	err := os.Remove(paths.LocalZoneFile(NormalizeZone(name)))
	if os.IsNotExist(err) {
		return fmt.Errorf("%w: no local zone %s", ErrNotFound, name)
	}
	return err
}

// Load parses a local zone from disk.
func Load(name string) (*Zone, error) {
	name = NormalizeZone(name)
	b, err := os.ReadFile(paths.LocalZoneFile(name))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: no local zone %s (create it with `minidns zone add %s`)", ErrNotFound, name, name)
	}
	if err != nil {
		return nil, err
	}
	return parse(name, string(b))
}

func parse(name, data string) (*Zone, error) {
	z := &Zone{Name: name}
	zp := dns.NewZoneParser(strings.NewReader(data), dns.Fqdn(name), "")
	zp.SetIncludeAllowed(false)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rec := fromRR(rr)
		if c := zp.Comment(); strings.Contains(c, managedTag) {
			if f := strings.Fields(c[strings.Index(c, managedTag)+len(managedTag):]); len(f) > 0 {
				rec.ManagedBy = f[0]
			}
		}
		if soa, ok := rr.(*dns.SOA); ok {
			z.Serial = soa.Serial
		}
		z.Records = append(z.Records, rec)
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("zone %s does not parse: %w", name, err)
	}
	return z, nil
}

func fromRR(rr dns.RR) Record {
	h := rr.Header()
	full := rr.String()
	// rr.String() is "<header fields>\t<rdata>"; the header has 4 tabs
	parts := strings.SplitN(full, "\t", 5)
	value := ""
	if len(parts) == 5 {
		value = parts[4]
	}
	return Record{Name: strings.ToLower(h.Name), TTL: h.Ttl, Type: dns.TypeToString[h.Rrtype], Value: value}
}

// Owner turns a user-supplied record name into the absolute owner name:
// "@" or "" is the apex, a name with a trailing dot is taken as-is, a name
// already ending in the zone is completed with a dot, anything else is
// relative to the zone.
func (z *Zone) Owner(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	origin := z.Origin()
	var fq string
	switch {
	case name == "" || name == "@":
		fq = origin
	case strings.HasSuffix(name, "."):
		fq = name
	case name == z.Name || strings.HasSuffix(name, "."+z.Name):
		fq = name + "."
	default:
		fq = name + "." + origin
	}
	if _, ok := dns.IsDomainName(fq); !ok {
		return "", fmt.Errorf("%w: %q is not a valid record name", ErrInvalid, name)
	}
	if !dns.IsSubDomain(origin, fq) {
		return "", fmt.Errorf("%w: %s is outside zone %s", ErrInvalid, fq, z.Name)
	}
	return fq, nil
}

// build validates type and value by parsing them the way a name server would
// and returns the record in canonical form.
func (z *Zone) build(name, rrtype, value string, ttl uint32, managedBy string) (Record, error) {
	owner, err := z.Owner(name)
	if err != nil {
		return Record{}, err
	}
	rrtype = strings.ToUpper(strings.TrimSpace(rrtype))
	t, ok := dns.StringToType[rrtype]
	if !ok {
		return Record{}, fmt.Errorf("%w: unknown record type %q", ErrInvalid, rrtype)
	}
	switch t {
	case dns.TypeSOA:
		return Record{}, fmt.Errorf("%w: the SOA record is managed by minidns", ErrInvalid)
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSRV, dns.TypeCAA, dns.TypePTR:
	default:
		return Record{}, fmt.Errorf("%w: record type %s is not supported (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR)", ErrInvalid, rrtype)
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return Record{}, fmt.Errorf("%w: %s record needs a value", ErrInvalid, rrtype)
	}
	if t == dns.TypeTXT {
		value = quoteTXT(value)
	}
	if strings.ContainsAny(value, "\n\r") || strings.ContainsAny(managedBy, " \t\n\r;") {
		return Record{}, fmt.Errorf("%w: control characters are not allowed", ErrInvalid)
	}
	rr, err := dns.NewRR(fmt.Sprintf("$ORIGIN %s\n%s %d IN %s %s", z.Origin(), owner, ttl, rrtype, value))
	if err != nil || rr == nil {
		return Record{}, fmt.Errorf("%w: %q is not a valid %s value (%v)", ErrInvalid, value, rrtype, cleanErr(err))
	}
	if dns.Len(rr) <= dns.Len(&dns.ANY{Hdr: *rr.Header()}) {
		return Record{}, fmt.Errorf("%w: %q is not a valid %s value", ErrInvalid, value, rrtype)
	}
	rec := fromRR(rr)
	rec.ManagedBy = managedBy
	return rec, nil
}

func cleanErr(err error) string {
	if err == nil {
		return "empty record"
	}
	return strings.TrimPrefix(err.Error(), "dns: ")
}

// quoteTXT wraps an unquoted TXT value in quotes (escaping as needed) and
// splits it into 255-byte strings; already-quoted input is left alone.
func quoteTXT(v string) string {
	if strings.HasPrefix(v, `"`) {
		return v
	}
	v = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v)
	var parts []string
	for len(v) > 255 {
		cut := 255
		for cut > 0 && v[cut-1] == '\\' { // don't split an escape
			cut--
		}
		parts = append(parts, `"`+v[:cut]+`"`)
		v = v[cut:]
	}
	parts = append(parts, `"`+v+`"`)
	return strings.Join(parts, " ")
}

// Add inserts a record in memory (call Save to persist). It returns
// added=false when an identical record is already present — adding is
// idempotent.
func (z *Zone) Add(name, rrtype, value string, ttl uint32, managedBy string) (rec Record, added bool, err error) {
	rec, err = z.build(name, rrtype, value, ttl, managedBy)
	if err != nil {
		return rec, false, err
	}
	for i, r := range z.Records {
		if r.Name != rec.Name {
			continue
		}
		if r.Type == rec.Type && r.Value == rec.Value {
			if r.TTL == rec.TTL && r.ManagedBy == rec.ManagedBy {
				return r, false, nil
			}
			z.Records[i] = rec // same data, new ttl/owner tag
			return rec, true, nil
		}
		// RFC 1034 §3.6.2: a CNAME owns its name alone
		if rec.Type == "CNAME" {
			return rec, false, fmt.Errorf("%w: %s already has a %s record; a CNAME cannot share a name with other records", ErrConflict, rec.Name, r.Type)
		}
		if r.Type == "CNAME" {
			return rec, false, fmt.Errorf("%w: %s is a CNAME; remove it before adding a %s record", ErrConflict, rec.Name, rec.Type)
		}
	}
	if rec.Type == "CNAME" && rec.Name == z.Origin() {
		return rec, false, fmt.Errorf("%w: the zone apex cannot be a CNAME", ErrConflict)
	}
	z.Records = append(z.Records, rec)
	return rec, true, nil
}

// Remove deletes, in memory, the records at name of the given type — all of
// them, or only the one matching value when value is non-empty — and returns
// what was removed.
func (z *Zone) Remove(name, rrtype, value string) ([]Record, error) {
	owner, err := z.Owner(name)
	if err != nil {
		return nil, err
	}
	rrtype = strings.ToUpper(strings.TrimSpace(rrtype))
	if rrtype == "SOA" {
		return nil, fmt.Errorf("%w: the SOA record is managed by minidns", ErrInvalid)
	}
	want := ""
	if value != "" {
		probe, err := z.build(name, rrtype, value, 0, "")
		if err != nil {
			return nil, err
		}
		want = probe.Value
	}
	var kept, removed []Record
	for _, r := range z.Records {
		if r.Name == owner && r.Type == rrtype && (want == "" || r.Value == want) {
			removed = append(removed, r)
		} else {
			kept = append(kept, r)
		}
	}
	if len(removed) == 0 {
		return nil, fmt.Errorf("%w: no %s record at %s", ErrNotFound, rrtype, owner)
	}
	if rrtype == "NS" && owner == z.Origin() && countApexNS(kept, owner) == 0 {
		return nil, fmt.Errorf("%w: a zone needs at least one NS record at its apex", ErrConflict)
	}
	z.Records = kept
	return removed, nil
}

func countApexNS(recs []Record, origin string) int {
	n := 0
	for _, r := range recs {
		if r.Type == "NS" && r.Name == origin {
			n++
		}
	}
	return n
}

// UserRecords returns the records without the SOA, in canonical order.
func (z *Zone) UserRecords() []Record {
	var out []Record
	for _, r := range z.sorted() {
		if r.Type != "SOA" {
			out = append(out, r)
		}
	}
	return out
}

// nextSerial follows the YYYYMMDDnn convention and never goes backwards.
func nextSerial(old uint32, now time.Time) uint32 {
	today, _ := strconv.ParseUint(now.Format("20060102")+"00", 10, 32)
	if uint32(today) > old {
		return uint32(today)
	}
	return old + 1
}

func (z *Zone) sorted() []Record {
	recs := append([]Record(nil), z.Records...)
	origin := z.Origin()
	rank := func(r Record) int {
		switch {
		case r.Name == origin && r.Type == "SOA":
			return 0
		case r.Name == origin && r.Type == "NS":
			return 1
		case r.Name == origin:
			return 2
		}
		return 3
	}
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.Name != b.Name {
			return reverseLabels(a.Name) < reverseLabels(b.Name)
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Value < b.Value
	})
	return recs
}

// reverseLabels makes names sort by hierarchy (com.example.www), so a host
// and its subdomains end up next to each other.
func reverseLabels(name string) string {
	labels := dns.SplitDomainName(name)
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// Render produces the canonical zone file with the given serial.
func (z *Zone) Render(serial uint32) string {
	var b strings.Builder
	b.WriteString(header)
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL %d\n", z.Origin(), DefaultTTL)
	for _, r := range z.sorted() {
		value := r.Value
		if r.Type == "SOA" {
			f := strings.Fields(value)
			if len(f) == 7 {
				f[2] = strconv.FormatUint(uint64(serial), 10)
				value = strings.Join(f, " ")
			}
		}
		fmt.Fprintf(&b, "%s\t%d\tIN\t%s\t%s", r.Name, r.TTL, r.Type, value)
		if r.ManagedBy != "" {
			fmt.Fprintf(&b, " ; %s%s", managedTag, r.ManagedBy)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Save bumps the serial, validates the rendered zone and atomically replaces
// the file. Add and Remove only change the zone in memory, so a command that
// touches several records is written — and can be rolled back — as one
// change. The previous file is kept as <file>.prev for Rollback.
func (z *Zone) Save() error {
	serial := nextSerial(z.Serial, time.Now())
	data := z.Render(serial)
	if _, err := zonefile.Validate(z.Name, data); err != nil {
		return fmt.Errorf("refusing to write zone %s: %w", z.Name, err)
	}
	target := paths.LocalZoneFile(z.Name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if old, err := os.ReadFile(target); err == nil {
		if err := os.WriteFile(target+".prev", old, 0o644); err != nil {
			return err
		}
	} else {
		os.Remove(target + ".prev")
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	z.Serial = serial
	return nil
}

// Rollback restores the file that was active before the last save (or
// removes the zone file if that save created it).
func Rollback(name string) error {
	target := paths.LocalZoneFile(NormalizeZone(name))
	if _, err := os.Stat(target + ".prev"); err != nil {
		return os.Remove(target)
	}
	return os.Rename(target+".prev", target)
}

// ReverseZoneFor returns the reverse zone name enclosing prefix, rounded
// down to the octet (IPv4) or nibble (IPv6) boundary DNS delegation uses,
// and whether that zone is wider than the prefix asked for.
func ReverseZoneFor(prefix netip.Prefix) (zone string, widened bool, err error) {
	prefix = prefix.Masked()
	addr := prefix.Addr()
	if addr.Is4() {
		if prefix.Bits() < 8 {
			return "", false, fmt.Errorf("%w: reverse zones wider than /8 are not supported", ErrInvalid)
		}
		octets := prefix.Bits() / 8
		if octets > 3 {
			octets = 3 // a /25../32 lives in its /24 zone
		}
		b := addr.As4()
		labels := make([]string, 0, octets)
		for i := octets - 1; i >= 0; i-- {
			labels = append(labels, strconv.Itoa(int(b[i])))
		}
		return strings.Join(labels, ".") + ".in-addr.arpa", prefix.Bits() != octets*8, nil
	}
	if prefix.Bits() < 4 {
		return "", false, fmt.Errorf("%w: reverse zones wider than /4 are not supported", ErrInvalid)
	}
	nibbles := prefix.Bits() / 4
	b := addr.As16()
	labels := make([]string, 0, nibbles)
	for i := nibbles - 1; i >= 0; i-- {
		n := b[i/2]
		if i%2 == 0 {
			n >>= 4
		}
		labels = append(labels, strconv.FormatUint(uint64(n&0xf), 16))
	}
	return strings.Join(labels, ".") + ".ip6.arpa", prefix.Bits() != nibbles*4, nil
}

// PTRName returns the reverse-lookup owner name for an address.
func PTRName(addr netip.Addr) string {
	name, _ := dns.ReverseAddr(addr.Unmap().String())
	return name
}

// IsReverse reports whether a zone name is a reverse-lookup zone.
func IsReverse(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa")
}

// BestReverseZone picks, from the given local zones, the most specific
// reverse zone that contains addr's PTR name ("" if none does).
func BestReverseZone(localZones []string, addr netip.Addr) string {
	ptr := PTRName(addr)
	best := ""
	for _, z := range localZones {
		if IsReverse(z) && dns.IsSubDomain(dns.Fqdn(z), ptr) && len(z) > len(best) {
			best = z
		}
	}
	return best
}
