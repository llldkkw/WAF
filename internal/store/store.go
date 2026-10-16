// Package store persists runtime configuration and logs in SQLite.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	totp_enc      TEXT NOT NULL,
	role          TEXT NOT NULL DEFAULT 'viewer',
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	last_login_at INTEGER NOT NULL DEFAULT 0,
	last_login_ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	ip         TEXT NOT NULL,
	user_agent TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	data       TEXT NOT NULL,
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_rules (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	cidr       TEXT NOT NULL,
	action     TEXT NOT NULL,
	site_id    INTEGER NOT NULL DEFAULT 0,
	note       TEXT NOT NULL DEFAULT '',
	source     TEXT NOT NULL DEFAULT 'manual',
	expires_at INTEGER NOT NULL DEFAULT 0,
	created_by TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         INTEGER NOT NULL,
	site_id    INTEGER NOT NULL,
	client_ip  TEXT NOT NULL,
	country    TEXT NOT NULL DEFAULT '',
	method     TEXT NOT NULL,
	host       TEXT NOT NULL,
	uri        TEXT NOT NULL,
	user_agent TEXT NOT NULL,
	action     TEXT NOT NULL,
	status     INTEGER NOT NULL,
	rule_id    INTEGER NOT NULL DEFAULT 0,
	message    TEXT NOT NULL DEFAULT '',
	category   TEXT NOT NULL DEFAULT '',
	severity   TEXT NOT NULL DEFAULT '',
	matches    TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(client_ip, ts);

CREATE TABLE IF NOT EXISTS stats_minute (
	ts       INTEGER NOT NULL,
	site_id  INTEGER NOT NULL,
	requests INTEGER NOT NULL,
	blocked  INTEGER NOT NULL,
	PRIMARY KEY (ts, site_id)
);

CREATE TABLE IF NOT EXISTS audit (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	ts       INTEGER NOT NULL,
	username TEXT NOT NULL,
	ip       TEXT NOT NULL,
	action   TEXT NOT NULL,
	target   TEXT NOT NULL DEFAULT '',
	detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);

CREATE TABLE IF NOT EXISTS channels (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	type       TEXT NOT NULL,
	config_enc TEXT NOT NULL,
	min_level  TEXT NOT NULL DEFAULT 'warning',
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL
);
`

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "waf.db")
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ConfigVersion is bumped on every change that the proxy must pick up. The
// proxy polls it, which also lets the CLI (a separate process) apply changes
// such as an emergency allow-list entry to a running server.
func (s *Store) ConfigVersion(ctx context.Context) (int64, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='config_version'`).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

func (s *Store) BumpConfigVersion(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES('config_version', '1')
		ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1`)
	return err
}

// Prune drops events, stats and expired IP rules older than the retention.
func (s *Store) Prune(ctx context.Context, retention time.Duration) error {
	cut := time.Now().Add(-retention).Unix()
	now := time.Now().Unix()
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM events WHERE ts < ?`, []any{cut}},
		{`DELETE FROM stats_minute WHERE ts < ?`, []any{cut}},
		{`DELETE FROM audit WHERE ts < ?`, []any{time.Now().Add(-365 * 24 * time.Hour).Unix()}},
		{`DELETE FROM sessions WHERE expires_at < ?`, []any{now}},
		{`DELETE FROM ip_rules WHERE expires_at > 0 AND expires_at < ?`, []any{now}},
	}
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.q, st.args...); err != nil {
			return err
		}
	}
	return nil
}
