// Package adblock downloads subscription blocklists and converts them to
// RPZ zone files.
package adblock

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
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

// Update fetches one list and rewrites its RPZ file. Returns the number of
// entries and whether the file content changed.
func Update(l config.BlockList) (entries int, changed bool, err error) {
	resp, err := httpClient.Get(l.URL)
	if err != nil {
		return 0, false, fmt.Errorf("fetch %s: %w", l.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("fetch %s: HTTP %d", l.URL, resp.StatusCode)
	}

	target := paths.AdblockRPZ(l.Name)
	before := fileHash(target)

	switch l.Format {
	case "rpz":
		// native RPZ feed — store verbatim
		tmp := target + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			return 0, false, err
		}
		if _, err := io.Copy(f, resp.Body); err != nil {
			f.Close()
			return 0, false, err
		}
		if err := f.Close(); err != nil {
			return 0, false, err
		}
		os.Chmod(tmp, 0o644)
		if err := os.Rename(tmp, target); err != nil {
			return 0, false, err
		}
		entries = rpz.CountEntries(target)
	case "hosts", "domains", "":
		domains, err := parse(resp.Body, l.Format)
		if err != nil {
			return 0, false, err
		}
		if len(domains) == 0 {
			return 0, false, fmt.Errorf("list %s: parsed 0 domains — wrong format?", l.Name)
		}
		// domain-level lists imply subdomains; hosts lists are exact entries
		wildcard := l.Format == "domains"
		entries, err = rpz.Write(target, domains, rpz.ActionBlock, wildcard)
		if err != nil {
			return 0, false, err
		}
	default:
		return 0, false, fmt.Errorf("list %s: unknown format %q (want hosts|domains|rpz)", l.Name, l.Format)
	}

	return entries, fileHash(target) != before, nil
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
