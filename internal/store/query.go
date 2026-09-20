package store

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Filter selects queries. Zero values mean "any".
type Filter struct {
	From, To int64  // unix seconds; To 0 = now
	Device   string // device name
	Client   string // IP address
	Domain   string // exact name…
	Suffix   bool   // …or the name and everything under it
	Qtype    string
	Rcode    string
	Blocked  *bool
}

// blockedExpr is true for queries answered by a block rule.
const blockedExpr = `(%s.policy <> '' AND %s.policy <> 'allow')`

// where builds the SQL conditions for table alias t whose time column is
// col; the query must join clients as c and names as n.
func (s *Store) where(f Filter, t, col string) (string, []any, error) {
	w, args, _, _, err := s.whereJoins(f, t, col)
	return w, args, err
}

// whereJoins also reports which dictionary tables the conditions refer to,
// so that a query over millions of rows only joins what it needs.
func (s *Store) whereJoins(f Filter, t, col string) (where string, args []any, needClients, needNames bool, err error) {
	w, a, err := s.whereRaw(f, t, col)
	return w, a, f.Client != "" || f.Device != "", f.Domain != "", err
}

func (s *Store) whereRaw(f Filter, t, col string) (string, []any, error) {
	var cond []string
	var args []any
	add := func(c string, a ...any) { cond, args = append(cond, c), append(args, a...) }
	if f.From > 0 {
		add(t+"."+col+" >= ?", f.From)
	}
	if f.To > 0 {
		add(t+"."+col+" < ?", f.To)
	}
	if f.Client != "" {
		ip, err := CleanIP(f.Client)
		if err != nil {
			return "", nil, err
		}
		add("c.ip = ?", ip)
	}
	if f.Device != "" {
		d, err := s.Device(f.Device)
		if err != nil {
			return "", nil, err
		}
		if len(d.Addresses) == 0 {
			return "", nil, fmt.Errorf("%w: device %q has no addresses, so no queries can be attributed to it (`minidns device address add`)", ErrNotFound, d.Name)
		}
		var periods []string
		for _, a := range d.Addresses {
			p := "(c.ip = ? AND " + t + "." + col + " >= ?"
			args = append(args, a.IP, a.ValidFrom)
			if a.ValidTo > 0 {
				p += " AND " + t + "." + col + " < ?"
				args = append(args, a.ValidTo)
			}
			periods = append(periods, p+")")
		}
		cond = append(cond, "("+strings.Join(periods, " OR ")+")")
	}
	if f.Domain != "" {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f.Domain)), ".")
		if f.Suffix {
			add("(n.name = ? OR n.name LIKE ? ESCAPE '\\')", name, "%."+likeEscape(name))
		} else {
			add("n.name = ?", name)
		}
	}
	if f.Qtype != "" {
		add(t+".qtype = ?", strings.ToUpper(f.Qtype))
	}
	if f.Rcode != "" {
		add(t+".rcode = ?", strings.ToUpper(f.Rcode))
	}
	if f.Blocked != nil {
		expr := fmt.Sprintf(blockedExpr, t, t)
		if !*f.Blocked {
			expr = "NOT " + expr
		}
		cond = append(cond, expr)
	}
	if len(cond) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(cond, " AND "), args, nil
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Count is one line of a ranking.
type Count struct {
	Key     string `json:"key"`
	Queries int64  `json:"queries"`
	Blocked int64  `json:"blocked"`
	// for device rankings
	IPs []string `json:"ips,omitempty"`
}

const rollupFrom = ` FROM query_rollups r JOIN clients c ON c.id = r.client_id JOIN names n ON n.id = r.name_id`

// TopDomains ranks queried names. With registered set, names are grouped
// under their registrable domain (www.example.co.uk → example.co.uk).
func (s *Store) TopDomains(f Filter, registered bool, limit int) ([]Count, error) {
	where, args, needClients, needNames, err := s.whereJoins(f, "r", "bucket")
	if err != nil {
		return nil, err
	}
	// aggregate on the narrow ids first, look the names up afterwards
	inner := `SELECT r.name_id AS name_id, SUM(r.count) AS q, SUM(CASE WHEN ` + fmt.Sprintf(blockedExpr, "r", "r") + ` THEN r.count ELSE 0 END) AS b FROM query_rollups r`
	if needClients {
		inner += ` JOIN clients c ON c.id = r.client_id`
	}
	if needNames {
		inner += ` JOIN names n ON n.id = r.name_id`
	}
	inner += where + ` GROUP BY r.name_id`
	if !registered {
		inner += fmt.Sprintf(` ORDER BY q DESC LIMIT %d`, limit)
	}
	rows, err := s.db.Query(`SELECT nn.name, t.q, t.b FROM (`+inner+`) t JOIN names nn ON nn.id = t.name_id ORDER BY t.q DESC, nn.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	grouped := map[string]*Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Queries, &c.Blocked); err != nil {
			return nil, err
		}
		if !registered {
			out = append(out, c)
			continue
		}
		key := RegisteredDomain(c.Key)
		if g, ok := grouped[key]; ok {
			g.Queries, g.Blocked = g.Queries+c.Queries, g.Blocked+c.Blocked
		} else {
			c.Key = key
			grouped[key] = &c
		}
	}
	if registered {
		for _, g := range grouped {
			out = append(out, *g)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Queries != out[j].Queries {
				return out[i].Queries > out[j].Queries
			}
			return out[i].Key < out[j].Key
		})
		if len(out) > limit {
			out = out[:limit]
		}
	}
	return out, rows.Err()
}

// RegisteredDomain is the registrable domain of name; names without one
// (single labels, reverse names, private suffixes like home.arpa) group
// under their last two labels, reverse lookups under their zone.
func RegisteredDomain(name string) string {
	if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		return "(reverse lookups)"
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return d
	}
	labels := strings.Split(name, ".")
	if len(labels) > 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return name
}

// TopDevices ranks clients, under their device name where the address
// belonged to a known device at the time of the query.
func (s *Store) TopDevices(f Filter, limit int) ([]Count, error) {
	where, args, err := s.where(f, "r", "bucket")
	if err != nil {
		return nil, err
	}
	q := `SELECT COALESCE(d.name, c.ip), SUM(r.count), SUM(CASE WHEN ` + fmt.Sprintf(blockedExpr, "r", "r") + ` THEN r.count ELSE 0 END), GROUP_CONCAT(DISTINCT c.ip)` +
		rollupFrom + `
		LEFT JOIN device_addresses a ON a.ip = c.ip AND a.valid_from <= r.bucket AND (a.valid_to IS NULL OR r.bucket < a.valid_to)
		LEFT JOIN devices d ON d.id = a.device_id` + where +
		fmt.Sprintf(` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT %d`, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		var ips string
		if err := rows.Scan(&c.Key, &c.Queries, &c.Blocked, &ips); err != nil {
			return nil, err
		}
		if ips != c.Key {
			c.IPs = strings.Split(ips, ",")
			sort.Strings(c.IPs)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Overview is the summary of a period.
type Overview struct {
	Queries       int64            `json:"queries"`
	Blocked       int64            `json:"blocked"`
	Clients       int64            `json:"clients"`
	Names         int64            `json:"names"`
	ByType        map[string]int64 `json:"by_type"`
	ByRcode       map[string]int64 `json:"by_rcode"`
	ByPolicy      map[string]int64 `json:"blocked_by"`
	FirstRecorded int64            `json:"first_recorded,omitempty"`
}

func (s *Store) Overview(f Filter) (*Overview, error) {
	where, args, needClients, needNames, err := s.whereJoins(f, "r", "bucket")
	if err != nil {
		return nil, err
	}
	from := ` FROM query_rollups r`
	if needClients {
		from += ` JOIN clients c ON c.id = r.client_id`
	}
	if needNames {
		from += ` JOIN names n ON n.id = r.name_id`
	}
	o := &Overview{ByType: map[string]int64{}, ByRcode: map[string]int64{}, ByPolicy: map[string]int64{}}
	err = s.db.QueryRow(`SELECT COALESCE(SUM(r.count),0), COALESCE(SUM(CASE WHEN `+fmt.Sprintf(blockedExpr, "r", "r")+` THEN r.count ELSE 0 END),0),
		COUNT(DISTINCT r.client_id), COUNT(DISTINCT r.name_id), COALESCE(MIN(r.bucket),0)`+from+where, args...).
		Scan(&o.Queries, &o.Blocked, &o.Clients, &o.Names, &o.FirstRecorded)
	if err != nil {
		return nil, err
	}
	// one pass for the three breakdowns
	rows, err := s.db.Query(`SELECT r.qtype, r.rcode, r.policy, SUM(r.count)`+from+where+` GROUP BY 1, 2, 3`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var qtype, rcode, policy string
		var n int64
		if err := rows.Scan(&qtype, &rcode, &policy, &n); err != nil {
			return nil, err
		}
		o.ByType[qtype] += n
		o.ByRcode[rcode] += n
		if policy != "" && policy != "allow" {
			o.ByPolicy[policy] += n
		}
	}
	return o, rows.Err()
}

// LoggedQuery is one stored event, attributed to a device where possible.
type LoggedQuery struct {
	Time      int64   `json:"time"`
	Client    string  `json:"client"`
	Device    string  `json:"device,omitempty"`
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Rcode     string  `json:"rcode"`
	Policy    string  `json:"policy,omitempty"`
	Blocked   bool    `json:"blocked"`
	Cached    bool    `json:"cached"`
	LatencyMS float64 `json:"latency_ms"`
}

// Events returns the newest matching queries, oldest first.
func (s *Store) Events(f Filter, limit int) ([]LoggedQuery, error) {
	where, args, err := s.where(f, "e", "ts")
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT e.ts, c.ip, COALESCE(d.name, ''), n.name, e.qtype, e.rcode, e.policy, e.cached, e.latency_us
		FROM query_events e JOIN clients c ON c.id = e.client_id JOIN names n ON n.id = e.name_id
		LEFT JOIN device_addresses a ON a.ip = c.ip AND a.valid_from <= e.ts AND (a.valid_to IS NULL OR e.ts < a.valid_to)
		LEFT JOIN devices d ON d.id = a.device_id`+where+fmt.Sprintf(` ORDER BY e.ts DESC, e.rowid DESC LIMIT %d`, limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoggedQuery
	for rows.Next() {
		var q LoggedQuery
		var us int64
		if err := rows.Scan(&q.Time, &q.Client, &q.Device, &q.Name, &q.Type, &q.Rcode, &q.Policy, &q.Cached, &us); err != nil {
			return nil, err
		}
		q.LatencyMS = float64(us) / 1000
		q.Blocked = q.Policy != "" && q.Policy != "allow"
		out = append(out, q)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}
