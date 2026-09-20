// Package adblock downloads subscription blocklists and converts them to
// RPZ zone files.
package adblock

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/rpz"
)

var httpClient = &http.Client{Timeout: 120 * time.Second}

// hostnames that appear in hosts-format lists but are not blockable domains
var hostsNoise = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// Limits for one download. The largest public lists are ~30 MB.
const (
	MaxListBytes = 200 << 20
	// a refresh that loses more than this share of the active list's entries
	// looks like a truncated or wrong download, and is refused unless forced
	maxShrink = 0.5
	shrinkMin = 1000 // …once the active list is at least this big
)

// ErrShrunk marks a refresh refused because the list shrank implausibly.
var ErrShrunk = fmt.Errorf("list shrank implausibly")

// Update fetches one list and rewrites its RPZ file. Returns the number of
// entries and whether the file content changed.
//
// The active file is only ever replaced by a complete, parsed and
// de-duplicated result: the download is size-limited, every format —
// native RPZ feeds included — is reduced to validated domain names and
// re-rendered, an empty or implausibly smaller result is refused (force
// overrides the latter), and the replaced file is kept as <file>.prev so a
// failed activation can be undone with Restore.
func Update(l config.BlockList, force bool) (entries int, changed bool, err error) {
	resp, err := httpClient.Get(l.URL)
	if err != nil {
		return 0, false, fmt.Errorf("fetch %s: %s", RedactURL(l.URL), redactErr(err, l.URL))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("fetch %s: HTTP %d", RedactURL(l.URL), resp.StatusCode)
	}
	body := &io.LimitedReader{R: resp.Body, N: MaxListBytes + 1}

	var domains []string
	wildcard := false
	switch l.Format {
	case "rpz":
		domains, err = parseRPZ(body)
	case "hosts", "domains", "":
		domains, err = parse(body, l.Format)
		// domain-level lists imply subdomains; hosts lists are exact entries
		wildcard = l.Format == "domains"
	default:
		return 0, false, fmt.Errorf("list %s: unknown format %q (want hosts|domains|rpz)", l.Name, l.Format)
	}
	if err != nil {
		return 0, false, fmt.Errorf("list %s: %w", l.Name, err)
	}
	if body.N <= 0 {
		return 0, false, fmt.Errorf("list %s: download exceeds %d MB — refusing it", l.Name, MaxListBytes>>20)
	}
	if len(domains) == 0 {
		return 0, false, fmt.Errorf("list %s: parsed 0 domains — wrong format, or not a blocklist?", l.Name)
	}

	target := paths.AdblockRPZ(l.Name)
	before := fileHash(target)
	if active := rpz.CountEntries(target); !force && active >= shrinkMin && float64(len(domains)) < float64(active)*maxShrink {
		return 0, false, fmt.Errorf("list %s: %w — the download has %d entries, the active copy %d; keeping the active copy (use --force to accept)", l.Name, ErrShrunk, len(domains), active)
	}
	old, _ := os.ReadFile(target)
	entries, err = rpz.Write(target, domains, rpz.ActionBlock, wildcard)
	if err != nil {
		return 0, false, err
	}
	changed = fileHash(target) != before
	if changed && len(old) > 0 {
		os.WriteFile(target+".prev", old, 0o644)
	}
	return entries, changed, nil
}

// Restore puts back the file Update replaced (last known good).
func Restore(name string) error {
	target := paths.AdblockRPZ(name)
	if _, err := os.Stat(target + ".prev"); err != nil {
		return err
	}
	return os.Rename(target+".prev", target)
}

// RedactURL hides credentials a private list URL may carry (userinfo and
// query string) so they never reach logs, errors or status output.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable url)"
	}
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	if u.RawQuery != "" {
		u.RawQuery = "REDACTED"
	}
	return u.String()
}

func redactErr(err error, raw string) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return strings.ReplaceAll(err.Error(), raw, RedactURL(raw))
}

// parseRPZ reduces a native RPZ feed to the owner names it blocks with
// NXDOMAIN ("name CNAME ."). Other policy actions and records (SOA, NS,
// passthru, local data) are not taken over: a subscribed list may only ever
// add blocks.
func parseRPZ(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		// name [ttl] [IN] CNAME .
		if len(f) < 3 || f[len(f)-1] != "." || !strings.EqualFold(f[len(f)-2], "CNAME") {
			continue
		}
		d := rpz.Normalize(f[0])
		if rpz.ValidDomain(strings.TrimPrefix(d, "*.")) {
			out = append(out, d)
		}
	}
	return out, sc.Err()
}

// parse extracts domains from a hosts-format or plain-domains list.
func parse(r io.Reader, format string) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		var candidates []string
		if format == "hosts" || (len(fields) > 1 && isIP(fields[0])) {
			if len(fields) < 2 || !isIP(fields[0]) {
				continue
			}
			candidates = fields[1:]
		} else {
			candidates = fields[:1]
		}
		for _, d := range candidates {
			d = rpz.Normalize(d)
			if !hostsNoise[d] && rpz.ValidDomain(strings.TrimPrefix(d, "*.")) {
				out = append(out, d)
			}
		}
	}
	return out, sc.Err()
}

func isIP(s string) bool {
	return s == "0.0.0.0" || s == "127.0.0.1" || s == "::" || s == "::1" || s == "0"
}

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return fmt.Sprintf("%x", h.Sum(nil))
}
