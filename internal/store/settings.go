package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const settingsSchema = `
CREATE TABLE IF NOT EXISTS action_uses (
	nonce   TEXT PRIMARY KEY,
	used_at INTEGER NOT NULL
);`

// GetJSON reads a JSON value stored in the meta table into v. A missing key
// leaves v unchanged.
func (s *Store) GetJSON(ctx context.Context, key string, v any) error {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), v)
}

func (s *Store) SetJSON(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, string(b))
	return err
}

// UseActionNonce records a one-click link as used; false means it was used before.
func (s *Store) UseActionNonce(ctx context.Context, nonce string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO action_uses(nonce, used_at) VALUES(?, ?)`, nonce, time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) ActionNonceUsed(ctx context.Context, nonce string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM action_uses WHERE nonce = ?`, nonce).Scan(&n)
	return n > 0, err
}

// DeleteDenyRules lifts every deny rule for an exact address or network.
func (s *Store) DeleteDenyRules(ctx context.Context, cidr string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ip_rules WHERE cidr = ? AND action = ?`, cidr, IPDeny)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, s.BumpConfigVersion(ctx)
}
