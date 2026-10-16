package store

import (
	"context"
	"errors"
	"time"

	"github.com/llldkkw/waf/internal/config"
)

const (
	IPAllow = "allow"
	IPDeny  = "deny"
)

// IPRule is a global (SiteID 0) or per-site allow/deny entry.
type IPRule struct {
	ID        int64  `json:"id"`
	CIDR      string `json:"cidr"`
	Action    string `json:"action"`
	SiteID    int64  `json:"site_id"`
	Note      string `json:"note"`
	Source    string `json:"source"` // manual, auto-ban, cli
	ExpiresAt int64  `json:"expires_at"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
}

func (r *IPRule) Normalize() error {
	p, err := config.ParsePrefixOrAddr(r.CIDR)
	if err != nil {
		return errors.New("IP/网段格式无效")
	}
	r.CIDR = p.String()
	if r.Action != IPAllow && r.Action != IPDeny {
		return errors.New("动作必须是 allow 或 deny")
	}
	if r.Source == "" {
		r.Source = "manual"
	}
	return nil
}

func (s *Store) ListIPRules(ctx context.Context) ([]IPRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, cidr, action, site_id, note, source, expires_at, created_by, created_at
		FROM ip_rules WHERE expires_at = 0 OR expires_at > ? ORDER BY id DESC`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPRule{}
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.CIDR, &r.Action, &r.SiteID, &r.Note, &r.Source, &r.ExpiresAt, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddIPRule(ctx context.Context, r *IPRule) error {
	r.CreatedAt = time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO ip_rules(cidr, action, site_id, note, source, expires_at, created_by, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		r.CIDR, r.Action, r.SiteID, r.Note, r.Source, r.ExpiresAt, r.CreatedBy, r.CreatedAt)
	if err != nil {
		return err
	}
	if r.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	return s.BumpConfigVersion(ctx)
}

func (s *Store) DeleteIPRule(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM ip_rules WHERE id = ?`, id); err != nil {
		return err
	}
	return s.BumpConfigVersion(ctx)
}

// DeleteIPRulesByCIDR removes every rule for an exact CIDR (used by the CLI).
func (s *Store) DeleteIPRulesByCIDR(ctx context.Context, cidr string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ip_rules WHERE cidr = ?`, cidr)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, s.BumpConfigVersion(ctx)
}
