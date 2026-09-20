// Package qlog parses the unbound query log minidns configures
// (epoch timestamps, log-queries/log-replies/log-tag-queryreply, rpz-log).
package qlog

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/awkto/minidns/internal/paths"
)

type Kind int

const (
	Query Kind = iota
	Reply
	RPZ
)

type Entry struct {
	Time    time.Time
	Kind    Kind
	Client  string
	Qname   string
	Qtype   string
	Rcode   string  // replies only
	Latency float64 // seconds, replies only
	Cached  bool    // replies only
	RPZTag  string  // rpz hits only: allow, block, adblock-<list>
	Action  string  // rpz hits only
}

// [1691577600] unbound[1234:0] query: 192.168.1.10 example.com. A IN
// [1691577600] unbound[1234:0] reply: 192.168.1.10 example.com. A IN NOERROR 0.012 0 44
var lineRe = regexp.MustCompile(`^\[(\d+)\] unbound\[[^\]]*\] (query|reply): (\S+) (\S+)\. (\S+) \S+(?: (\S+) ([\d.]+) ([01]) \d+)?`)

// [1691577600] unbound[1234:0] info: rpz: applied [block] example.com. rpz-nxdomain 192.168.1.10@40405 ...
var rpzRe = regexp.MustCompile(`^\[(\d+)\] unbound\[[^\]]*\] info: rpz: applied \[([^\]]+)\] (\S+?)\.? (\S+) (\S+?)@\d+`)

// ParseLine decodes one log line; ok is false for lines that aren't
// query/reply/rpz records.
func ParseLine(line string) (Entry, bool) {
	if m := lineRe.FindStringSubmatch(line); m != nil {
		ts, _ := strconv.ParseInt(m[1], 10, 64)
		e := Entry{
			Time:   time.Unix(ts, 0),
			Client: m[3],
			Qname:  strings.ToLower(m[4]),
			Qtype:  m[5],
		}
		if m[2] == "reply" {
			e.Kind = Reply
			e.Rcode = m[6]
			e.Latency, _ = strconv.ParseFloat(m[7], 64)
			e.Cached = m[8] == "1"
		}
		return e, true
	}
	if m := rpzRe.FindStringSubmatch(line); m != nil {
		ts, _ := strconv.ParseInt(m[1], 10, 64)
		return Entry{
			Time:   time.Unix(ts, 0),
			Kind:   RPZ,
			RPZTag: m[2],
			Qname:  strings.ToLower(m[3]),
			Action: m[4],
			Client: m[5],
		}, true
	}
	return Entry{}, false
}

// Files returns the query log plus rotated copies, oldest first.
func Files() []string {
	base := paths.QueryLog()
	matches, _ := filepath.Glob(base + "*")
	sort.Slice(matches, func(i, j int) bool {
		si, _ := os.Stat(matches[i])
		sj, _ := os.Stat(matches[j])
		if si == nil || sj == nil {
			return matches[i] > matches[j]
		}
		return si.ModTime().Before(sj.ModTime())
	})
	return matches
}

// Scan streams every entry with Time >= since (zero = all) through fn,
// reading rotated and gzipped logs transparently.
func Scan(since time.Time, fn func(Entry)) error {
	for _, path := range Files() {
		// skip rotated files older than the window entirely
		if !since.IsZero() {
			if st, err := os.Stat(path); err == nil && path != paths.QueryLog() && st.ModTime().Before(since) {
				continue
			}
		}
		if err := scanFile(path, since, fn); err != nil {
			return err
		}
	}
	return nil
}

func scanFile(path string, since time.Time, fn func(Entry)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil // partially-written rotation; skip
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if e, ok := ParseLine(sc.Text()); ok {
			if since.IsZero() || !e.Time.Before(since) {
				fn(e)
			}
		}
	}
	return sc.Err()
}

// Follow tails the live log, emitting new entries as they are written.
// Handles logrotate copytruncate by reopening when the file shrinks.
func Follow(fn func(Entry)) error {
	path := paths.QueryLog()
	var offset int64
	if st, err := os.Stat(path); err == nil {
		offset = st.Size()
	}
	for {
		if st, err := os.Stat(path); err == nil {
			if st.Size() < offset {
				offset = 0 // truncated by rotation
			}
			if st.Size() > offset {
				offset = readFrom(path, offset, fn)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// readFrom parses the complete lines found after offset and returns the
// offset just past the last one. A trailing line unbound is still writing
// (no newline yet) is left for the next call rather than parsed half-done
// and lost.
func readFrom(path string, offset int64, fn func(Entry)) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}
	r := bufio.NewReaderSize(f, 1<<16)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return offset // partial line (or EOF): don't consume it
		}
		offset += int64(len(line))
		if e, ok := ParseLine(strings.TrimRight(line, "\r\n")); ok {
			fn(e)
		}
	}
}
