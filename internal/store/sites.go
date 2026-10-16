package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/config"
)

const (
	ModeBlock  = "block"
	ModeDetect = "detect"
	ModeOff    = "off"
)

// Site is one protected application: a set of hostnames proxied to upstreams.
type Site struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`

	Hosts     []string `json:"hosts"`
	Upstreams []string `json:"upstreams"`
	// PreserveHost forwards the original Host header instead of the upstream's.
	PreserveHost bool `json:"preserve_host"`

	// Mode: block (enforce), detect (log only) or off (plain proxy).
	Mode string `json:"mode"`
	// ParanoiaLevel is the OWASP CRS paranoia level (1-4).
	ParanoiaLevel int `json:"paranoia_level"`
	// AnomalyThreshold is the CRS inbound anomaly score that triggers a block.
	AnomalyThreshold int `json:"anomaly_threshold"`

	// UpstreamInsecure skips TLS verification for https:// upstreams
	// (internal servers with self-signed certificates).
	UpstreamInsecure bool `json:"upstream_insecure"`

	HTTPS      bool `json:"https"`
	ForceHTTPS bool `json:"force_https"`

	RateLimit RateLimit `json:"rate_limit"`
	AttackBan AttackBan `json:"attack_ban"`
	Geo       GeoPolicy `json:"geo"`
	Challenge Challenge `json:"challenge"`
	// BlockCountries is the pre-GeoPolicy format, migrated on Normalize.
	BlockCountries []string        `json:"block_countries,omitempty"`
	RuleExclusions []RuleExclusion `json:"rule_exclusions"`
	PathRules      []PathRule      `json:"path_rules"`
	HealthCheck    HealthCheck     `json:"health_check"`
}

type RateLimit struct {
	Enabled bool    `json:"enabled"`
	RPS     float64 `json:"rps"`
	Burst   int     `json:"burst"`
	// BanThreshold auto-bans an IP after this many rate-limited requests
	// within one minute (0 disables auto-ban).
	BanThreshold int `json:"ban_threshold"`
	BanMinutes   int `json:"ban_minutes"`
}

// GeoPolicy blocks or exclusively allows visitors by location. Rules are
// "CN" (country), "CN-GD" (province, ISO 3166-2) or "CN/深圳", "CN-GD/Shenzhen"
// (city). Regions and cities need a GeoLite2-City database.
type GeoPolicy struct {
	Mode  string   `json:"mode"` // off, block, allow
	Rules []string `json:"rules"`
	// AllowUnknown lets through public IPs the database cannot place when
	// mode is allow. Private/VPN addresses are always allowed.
	AllowUnknown bool `json:"allow_unknown"`
}

// Challenge serves a JavaScript proof-of-work page before letting a visitor
// through, which stops most bots and scripted floods.
type Challenge struct {
	Mode string `json:"mode"` // off, always, suspicious
	// TTLHours is how long a solved challenge stays valid.
	TTLHours int `json:"ttl_hours"`
	// Difficulty in leading zero bits of the proof of work (12-22).
	Difficulty  int      `json:"difficulty"`
	ExemptPaths []string `json:"exempt_paths"`
}

// AttackBan bans IPs that trigger many WAF blocks in a short time (scanners).
type AttackBan struct {
	Enabled bool `json:"enabled"`
	// Threshold blocked requests within 5 minutes.
	Threshold int `json:"threshold"`
	Minutes   int `json:"minutes"`
}

// RuleExclusion disables a CRS rule, optionally only below a path prefix.
// This is how false positives are handled.
type RuleExclusion struct {
	RuleID int    `json:"rule_id"`
	Path   string `json:"path"`
	Note   string `json:"note"`
}

// PathRule restricts a path prefix: "deny" blocks it for everyone, "allow"
// only admits the listed CIDRs (e.g. /admin only from the VPN).
type PathRule struct {
	Path   string   `json:"path"`
	Action string   `json:"action"`
	CIDRs  []string `json:"cidrs"`
}

type HealthCheck struct {
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path"`
	IntervalSec int    `json:"interval_sec"`
}

var (
	hostRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// Paths end up inside SecLang directives, so keep them strictly literal.
	pathRe    = regexp.MustCompile(`^/[A-Za-z0-9._~\-/%]*$`)
	countryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	regionRe  = regexp.MustCompile(`^[A-Z]{2}-[A-Z0-9]{1,3}$`)
)

// Normalize fills defaults and validates the site.
func (s *Site) Normalize() error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return errors.New("名称不能为空")
	}
	if len(s.Hosts) == 0 {
		return errors.New("至少需要一个域名")
	}
	for i, h := range s.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if !hostRe.MatchString(h) {
			return fmt.Errorf("域名无效: %q", h)
		}
		s.Hosts[i] = h
	}
	if len(s.Upstreams) == 0 {
		return errors.New("至少需要一个后端地址")
	}
	for i, u := range s.Upstreams {
		u = strings.TrimSpace(u)
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			return fmt.Errorf("后端地址无效: %q (示例 http://10.0.0.2:8080)", u)
		}
		s.Upstreams[i] = strings.TrimRight(u, "/")
	}
	switch s.Mode {
	case ModeBlock, ModeDetect, ModeOff:
	case "":
		s.Mode = ModeBlock
	default:
		return fmt.Errorf("模式无效: %q", s.Mode)
	}
	if s.ParanoiaLevel < 1 || s.ParanoiaLevel > 4 {
		s.ParanoiaLevel = 1
	}
	if s.AnomalyThreshold <= 0 {
		s.AnomalyThreshold = 5
	}
	if s.ForceHTTPS && !s.HTTPS {
		return errors.New("强制 HTTPS 需要先开启 HTTPS")
	}
	rl := &s.RateLimit
	if rl.Enabled {
		if rl.RPS <= 0 {
			return errors.New("限流速率必须大于 0")
		}
		if rl.Burst <= 0 {
			rl.Burst = int(rl.RPS * 2)
			if rl.Burst < 1 {
				rl.Burst = 1
			}
		}
		if rl.BanThreshold > 0 && rl.BanMinutes <= 0 {
			rl.BanMinutes = 30
		}
	}
	if ab := &s.AttackBan; ab.Enabled {
		if ab.Threshold <= 0 {
			ab.Threshold = 20
		}
		if ab.Minutes <= 0 {
			ab.Minutes = 60
		}
	}
	if len(s.BlockCountries) > 0 && s.Geo.Mode == "" {
		s.Geo = GeoPolicy{Mode: "block", Rules: s.BlockCountries}
	}
	s.BlockCountries = nil
	if err := s.Geo.normalize(); err != nil {
		return err
	}
	if err := s.Challenge.normalize(); err != nil {
		return err
	}
	for _, ex := range s.RuleExclusions {
		if ex.RuleID <= 0 {
			return errors.New("排除规则 ID 无效")
		}
		if ex.Path != "" && !pathRe.MatchString(ex.Path) {
			return fmt.Errorf("排除路径无效: %q", ex.Path)
		}
	}
	for i, pr := range s.PathRules {
		if !pathRe.MatchString(pr.Path) {
			return fmt.Errorf("路径无效: %q", pr.Path)
		}
		switch pr.Action {
		case "deny":
		case "allow":
			if len(pr.CIDRs) == 0 {
				return fmt.Errorf("路径 %s 的白名单不能为空", pr.Path)
			}
		default:
			return fmt.Errorf("路径动作无效: %q", pr.Action)
		}
		for j, c := range pr.CIDRs {
			p, err := config.ParsePrefixOrAddr(c)
			if err != nil {
				return fmt.Errorf("IP/网段无效: %q", c)
			}
			s.PathRules[i].CIDRs[j] = p.String()
		}
	}
	hc := &s.HealthCheck
	if hc.Enabled {
		if hc.Path == "" {
			hc.Path = "/"
		}
		if !pathRe.MatchString(hc.Path) {
			return fmt.Errorf("健康检查路径无效: %q", hc.Path)
		}
		if hc.IntervalSec < 5 {
			hc.IntervalSec = 10
		}
	}
	if s.RuleExclusions == nil {
		s.RuleExclusions = []RuleExclusion{}
	}
	if s.PathRules == nil {
		s.PathRules = []PathRule{}
	}
	return nil
}

func (s *Store) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, data, enabled, created_at, updated_at FROM sites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		st, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *st)
	}
	return out, rows.Err()
}

func (s *Store) GetSite(ctx context.Context, id int64) (*Site, error) {
	return scanSite(s.db.QueryRowContext(ctx, `SELECT id, name, data, enabled, created_at, updated_at FROM sites WHERE id = ?`, id))
}

func scanSite(sc interface{ Scan(...any) error }) (*Site, error) {
	var (
		st   Site
		data string
		id   int64
		en   bool
		name string
		c, u int64
	)
	if err := sc.Scan(&id, &name, &data, &en, &c, &u); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(data), &st); err != nil {
		return nil, err
	}
	st.ID, st.Name, st.Enabled, st.CreatedAt, st.UpdatedAt = id, name, en, c, u
	st.applyDefaults()
	return &st, nil
}

func (s *Store) SaveSite(ctx context.Context, st *Site) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	st.UpdatedAt = now
	if st.ID == 0 {
		st.CreatedAt = now
		res, err := s.db.ExecContext(ctx, `INSERT INTO sites(name, data, enabled, created_at, updated_at) VALUES(?,?,?,?,?)`,
			st.Name, string(data), st.Enabled, now, now)
		if err != nil {
			return err
		}
		st.ID, err = res.LastInsertId()
		if err != nil {
			return err
		}
	} else {
		res, err := s.db.ExecContext(ctx, `UPDATE sites SET name = ?, data = ?, enabled = ?, updated_at = ? WHERE id = ?`,
			st.Name, string(data), st.Enabled, now, st.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	return s.BumpConfigVersion(ctx)
}

func (s *Store) DeleteSite(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sites WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM ip_rules WHERE site_id = ?`, id); err != nil {
		return err
	}
	return s.BumpConfigVersion(ctx)
}

// applyDefaults upgrades sites stored by older versions so readers never see
// missing fields.
func (s *Site) applyDefaults() {
	if s.Geo.Mode == "" {
		s.Geo = GeoPolicy{Mode: "off"}
		if len(s.BlockCountries) > 0 {
			s.Geo = GeoPolicy{Mode: "block", Rules: s.BlockCountries}
		}
	}
	s.BlockCountries = nil
	if s.Geo.Rules == nil {
		s.Geo.Rules = []string{}
	}
	if s.Challenge.Mode == "" {
		s.Challenge = Challenge{Mode: "off", TTLHours: 24, Difficulty: 16}
	}
	if s.Challenge.ExemptPaths == nil {
		s.Challenge.ExemptPaths = []string{}
	}
	if s.RuleExclusions == nil {
		s.RuleExclusions = []RuleExclusion{}
	}
	if s.PathRules == nil {
		s.PathRules = []PathRule{}
	}
}

func (g *GeoPolicy) normalize() error {
	switch g.Mode {
	case "", "off":
		g.Mode = "off"
	case "block", "allow":
	default:
		return fmt.Errorf("地区策略无效: %q", g.Mode)
	}
	out := []string{}
	for _, r := range g.Rules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		area, city, hasCity := strings.Cut(r, "/")
		area = strings.ToUpper(area)
		if !countryRe.MatchString(area) && !regionRe.MatchString(area) {
			return fmt.Errorf("地区规则无效: %q（示例：CN、CN-GD、CN/深圳）", r)
		}
		if hasCity {
			city = strings.TrimSpace(city)
			if city == "" || strings.ContainsAny(city, "/\n") {
				return fmt.Errorf("城市名无效: %q", r)
			}
			area += "/" + city
		}
		out = append(out, area)
	}
	g.Rules = out
	if g.Mode == "allow" && len(g.Rules) == 0 {
		return errors.New("「仅允许」模式至少需要一个地区")
	}
	return nil
}

func (c *Challenge) normalize() error {
	switch c.Mode {
	case "", "off":
		c.Mode = "off"
	case "always", "suspicious":
	default:
		return fmt.Errorf("人机验证模式无效: %q", c.Mode)
	}
	if c.TTLHours <= 0 {
		c.TTLHours = 24
	}
	if c.Difficulty == 0 {
		c.Difficulty = 16
	}
	if c.Difficulty < 12 || c.Difficulty > 22 {
		return errors.New("人机验证难度需在 12-22 之间")
	}
	out := []string{}
	for _, p := range c.ExemptPaths {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !pathRe.MatchString(p) {
			return fmt.Errorf("免验证路径无效: %q", p)
		}
		out = append(out, p)
	}
	c.ExemptPaths = out
	return nil
}
