package store

import (
	"context"
	"time"
)

type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	Username string `json:"username"`
	IP       string `json:"ip"`
	Action   string `json:"action"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
}

func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if e.TS == 0 {
		e.TS = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit(ts, username, ip, action, target, detail) VALUES(?,?,?,?,?,?)`,
		e.TS, e.Username, e.IP, e.Action, e.Target, e.Detail)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit, offset int) ([]AuditEntry, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, username, ip, action, target, detail FROM audit ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Username, &e.IP, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Channel is a notification destination. Config holds secrets (bot tokens,
// webhook URLs) and is stored encrypted.
type Channel struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Config    map[string]string `json:"config"`
	MinLevel  string            `json:"min_level"`
	Enabled   bool              `json:"enabled"`
	CreatedAt int64             `json:"created_at"`
	ConfigEnc string            `json:"-"`
}

func (s *Store) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, type, config_enc, min_level, enabled, created_at FROM channels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &c.ConfigEnc, &c.MinLevel, &c.Enabled, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) SaveChannel(ctx context.Context, c *Channel) error {
	if c.ID == 0 {
		c.CreatedAt = time.Now().Unix()
		res, err := s.db.ExecContext(ctx, `INSERT INTO channels(name, type, config_enc, min_level, enabled, created_at) VALUES(?,?,?,?,?,?)`,
			c.Name, c.Type, c.ConfigEnc, c.MinLevel, c.Enabled, c.CreatedAt)
		if err != nil {
			return err
		}
		c.ID, err = res.LastInsertId()
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE channels SET name = ?, type = ?, config_enc = ?, min_level = ?, enabled = ? WHERE id = ?`,
		c.Name, c.Type, c.ConfigEnc, c.MinLevel, c.Enabled, c.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM channels WHERE id = ?`, id)
	return err
}
