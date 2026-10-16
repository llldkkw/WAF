package store

import (
	"context"
	"encoding/json"
	"strings"
)

// Event actions.
const (
	ActBlocked     = "blocked"      // WAF rule interrupted the request
	ActDetected    = "detected"     // detect-only mode, would have been blocked
	ActRateLimited = "rate_limited" // rate limit exceeded
	ActIPDenied    = "ip_denied"    // IP deny list / auto-ban
	ActGeoDenied   = "geo_denied"   // country blocked
	ActPathDenied  = "path_denied"  // path ACL
)

type Match struct {
	RuleID   int    `json:"rule_id"`
	Message  string `json:"message"`
	Data     string `json:"data"`
	Severity string `json:"severity"`
	Variable string `json:"variable"`
}

type Event struct {
	ID        int64   `json:"id"`
	TS        int64   `json:"ts"`
	SiteID    int64   `json:"site_id"`
	ClientIP  string  `json:"client_ip"`
	Country   string  `json:"country"`
	Method    string  `json:"method"`
	Host      string  `json:"host"`
	URI       string  `json:"uri"`
	UserAgent string  `json:"user_agent"`
	Action    string  `json:"action"`
	Status    int     `json:"status"`
	RuleID    int     `json:"rule_id"`
	Message   string  `json:"message"`
	Category  string  `json:"category"`
	Severity  string  `json:"severity"`
	Matches   []Match `json:"matches"`
}

func (s *Store) InsertEvents(ctx context.Context, evs []*Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events(ts, site_id, client_ip, country, method, host, uri, user_agent, action, status, rule_id, message, category, severity, matches)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range evs {
		m, _ := json.Marshal(e.Matches)
		res, err := stmt.ExecContext(ctx, e.TS, e.SiteID, e.ClientIP, e.Country, e.Method, e.Host, e.URI, e.UserAgent, e.Action, e.Status, e.RuleID, e.Message, e.Category, e.Severity, string(m))
		if err != nil {
			return err
		}
		e.ID, _ = res.LastInsertId()
	}
	return tx.Commit()
}

type EventFilter struct {
	From, To int64
	SiteID   int64
	IP       string
	Action   string
	Category string
	Query    string
	Limit    int
	Offset   int
}

func (f EventFilter) where() (string, []any) {
	var (
		conds = []string{"1=1"}
		args  []any
	)
	if f.From > 0 {
		conds, args = append(conds, "ts >= ?"), append(args, f.From)
	}
	if f.To > 0 {
		conds, args = append(conds, "ts <= ?"), append(args, f.To)
	}
	if f.SiteID > 0 {
		conds, args = append(conds, "site_id = ?"), append(args, f.SiteID)
	}
	if f.IP != "" {
		conds, args = append(conds, "client_ip = ?"), append(args, f.IP)
	}
	if f.Action != "" {
		conds, args = append(conds, "action = ?"), append(args, f.Action)
	}
	if f.Category != "" {
		conds, args = append(conds, "category = ?"), append(args, f.Category)
	}
	if f.Query != "" {
		q := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(f.Query) + "%"
		conds = append(conds, `(uri LIKE ? ESCAPE '\' OR message LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\')`)
		args = append(args, q, q, q)
	}
	return strings.Join(conds, " AND "), args
}

func (s *Store) QueryEvents(ctx context.Context, f EventFilter) ([]Event, int, error) {
	where, args := f.where()
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, site_id, client_ip, country, method, host, uri, user_agent, action, status, rule_id, message, category, severity, matches
		FROM events WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var (
			e Event
			m string
		)
		if err := rows.Scan(&e.ID, &e.TS, &e.SiteID, &e.ClientIP, &e.Country, &e.Method, &e.Host, &e.URI, &e.UserAgent, &e.Action, &e.Status, &e.RuleID, &e.Message, &e.Category, &e.Severity, &m); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal([]byte(m), &e.Matches)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// AddStats accumulates per-minute request counters.
func (s *Store) AddStats(ctx context.Context, ts int64, perSite map[int64][2]int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for site, c := range perSite {
		if _, err := tx.ExecContext(ctx, `INSERT INTO stats_minute(ts, site_id, requests, blocked) VALUES(?,?,?,?)
			ON CONFLICT(ts, site_id) DO UPDATE SET requests = requests + excluded.requests, blocked = blocked + excluded.blocked`,
			ts, site, c[0], c[1]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type Point struct {
	TS       int64 `json:"ts"`
	Requests int64 `json:"requests"`
	Blocked  int64 `json:"blocked"`
}

type Count struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type Overview struct {
	Requests   int64   `json:"requests"`
	Blocked    int64   `json:"blocked"`
	Attackers  int64   `json:"attackers"`
	Series     []Point `json:"series"`
	TopIPs     []Count `json:"top_ips"`
	Categories []Count `json:"categories"`
	Actions    []Count `json:"actions"`
	TopURIs    []Count `json:"top_uris"`
	TopRules   []Count `json:"top_rules"`
	Countries  []Count `json:"countries"`
}

// Overview aggregates the dashboard data since `from`, bucketing the time
// series by `bucket` seconds.
func (s *Store) Overview(ctx context.Context, from, bucket int64, siteID int64) (*Overview, error) {
	ov := &Overview{}
	siteCond, siteArgs := "", []any{}
	if siteID > 0 {
		siteCond, siteArgs = " AND site_id = ?", []any{siteID}
	}
	args := append([]any{from}, siteArgs...)

	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(requests),0), COALESCE(SUM(blocked),0) FROM stats_minute WHERE ts >= ?`+siteCond, args...).
		Scan(&ov.Requests, &ov.Blocked); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT client_ip) FROM events WHERE ts >= ?`+siteCond, args...).Scan(&ov.Attackers); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, `SELECT (ts / ?) * ? AS b, SUM(requests), SUM(blocked) FROM stats_minute WHERE ts >= ?`+siteCond+` GROUP BY b ORDER BY b`,
		append([]any{bucket, bucket}, args...)...)
	if err != nil {
		return nil, err
	}
	ov.Series = []Point{}
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.TS, &p.Requests, &p.Blocked); err != nil {
			rows.Close()
			return nil, err
		}
		ov.Series = append(ov.Series, p)
	}
	rows.Close()

	top := func(expr string, extra string, n int) ([]Count, error) {
		rows, err := s.db.QueryContext(ctx, `SELECT `+expr+` AS k, COUNT(*) AS c FROM events WHERE ts >= ?`+siteCond+extra+` GROUP BY k ORDER BY c DESC LIMIT ?`,
			append(args, n)...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []Count{}
		for rows.Next() {
			var c Count
			if err := rows.Scan(&c.Key, &c.Count); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
	if ov.TopIPs, err = top("client_ip", "", 10); err != nil {
		return nil, err
	}
	if ov.Categories, err = top("category", " AND category != ''", 10); err != nil {
		return nil, err
	}
	if ov.Actions, err = top("action", "", 10); err != nil {
		return nil, err
	}
	if ov.TopURIs, err = top("CASE WHEN instr(uri, '?') > 0 THEN substr(uri, 1, instr(uri, '?') - 1) ELSE uri END", "", 10); err != nil {
		return nil, err
	}
	if ov.TopRules, err = top("CAST(rule_id AS TEXT) || ' ' || message", " AND rule_id > 0", 10); err != nil {
		return nil, err
	}
	if ov.Countries, err = top("country", " AND country != ''", 200); err != nil {
		return nil, err
	}
	return ov, nil
}
