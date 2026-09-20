// Package rpz reads and writes the RPZ zone files minidns feeds to unbound.
//
// Manual firewall blocks resolve to NXDOMAIN via "CNAME .", the allowlist
// uses "CNAME rpz-passthru." (and is configured first, so it always wins).
package rpz

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ActionBlock    = "."             // rpz NXDOMAIN
	ActionPassthru = "rpz-passthru." // rpz allow
)

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9_]([a-z0-9_-]*[a-z0-9_])?\.)+[a-z][a-z0-9-]*$`)

// ValidDomain reports whether s looks like a blockable domain name.
func ValidDomain(s string) bool {
	return len(s) <= 253 && domainRe.MatchString(s)
}

var listNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidListName reports whether s is safe to use as a blocklist name: it
// ends up in a file name and in the generated unbound config.
func ValidListName(s string) bool { return listNameRe.MatchString(s) }

// Normalize lowercases and strips a trailing dot.
func Normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// Write emits an RPZ zone file for the given domains and action. When
// wildcard is true each domain also gets a *.domain entry so subdomains
// match. Returns the number of domains written.
func Write(path string, domains []string, action string, wildcard bool) (int, error) {
	uniq := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = Normalize(d)
		if ValidDomain(strings.TrimPrefix(d, "*.")) {
			uniq[d] = struct{}{}
		}
	}
	sorted := make([]string, 0, len(uniq))
	for d := range uniq {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)

	var body bytes.Buffer
	for _, d := range sorted {
		fmt.Fprintf(&body, "%s CNAME %s\n", d, action)
		if wildcard && !strings.HasPrefix(d, "*.") {
			fmt.Fprintf(&body, "*.%s CNAME %s\n", d, action)
		}
	}
	// The SOA serial is a timestamp, so two writes of the same entries never
	// produce identical files. Leave the file alone when only the serial
	// would differ, so callers comparing file hashes see "unchanged" and
	// don't reload unbound for nothing.
	if old, err := os.ReadFile(path); err == nil {
		if _, oldBody, ok := bytes.Cut(old, []byte(headerEnd)); ok && bytes.Equal(oldBody, body.Bytes()) {
			return len(sorted), nil
		}
	}

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	fmt.Fprintf(w, "$TTL 300\n@ IN SOA localhost. root.localhost. (%d 43200 3600 86400 300)\n%s", time.Now().Unix(), headerEnd)
	w.Write(body.Bytes())
	if err := w.Flush(); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return 0, err
	}
	return len(sorted), os.Rename(tmp, path)
}

// headerEnd is the last header line of a generated RPZ file; everything
// after it is policy records.
const headerEnd = "@ IN NS localhost.\n"

// ReadDomains returns the entries of an RPZ file previously written by
// Write, as the user entered them: "example.com" stands for the domain and
// the *.example.com companion Write generated for it, while a wildcard with
// no bare companion ("*.example.com" on its own) was entered explicitly and
// is returned as such.
func ReadDomains(path string) ([]string, error) {
	all, err := ReadAll(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(all))
	for d := range all {
		if bare, ok := strings.CutPrefix(d, "*."); ok {
			if _, companion := all[bare]; companion {
				continue
			}
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// CountEntries counts CNAME policy records in an RPZ file (wildcards
// included) without loading it into memory.
func CountEntries(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.Contains(sc.Text(), " CNAME ") {
			n++
		}
	}
	return n
}

// Contains reports whether domain (or a wildcard covering it) is present in
// the RPZ file, returning the matching entry.
func Contains(path, domain string) (string, bool) {
	domains, err := ReadAll(path)
	if err != nil {
		return "", false
	}
	domain = Normalize(domain)
	if _, ok := domains[domain]; ok {
		return domain, true
	}
	// walk up labels checking wildcard entries
	rest := domain
	for {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return "", false
		}
		rest = rest[i+1:]
		if _, ok := domains["*."+rest]; ok {
			return "*." + rest, true
		}
	}
}

// ReadAll returns every owner name in the file (wildcards included) as a set.
func ReadAll(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[1] == "CNAME" &&
			!strings.HasPrefix(fields[0], "@") && !strings.HasPrefix(fields[0], "$") {
			set[fields[0]] = struct{}{}
		}
	}
	return set, sc.Err()
}
