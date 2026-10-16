package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	TOTPEnc      string `json:"-"`
	Role         string `json:"role"`
	Disabled     bool   `json:"disabled"`
	CreatedAt    int64  `json:"created_at"`
	LastLoginAt  int64  `json:"last_login_at"`
	LastLoginIP  string `json:"last_login_ip"`
}

const userCols = `id, username, password_hash, totp_enc, role, disabled, created_at, last_login_at, last_login_ip`

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPEnc, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt, &u.LastLoginIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Store) CreateUser(ctx context.Context, u *User) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username, password_hash, totp_enc, role, created_at) VALUES(?,?,?,?,?)`,
		u.Username, u.PasswordHash, u.TOTPEnc, u.Role, time.Now().Unix())
	if err != nil {
		return err
	}
	u.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ? AND disabled = 0`, RoleAdmin).Scan(&n)
	return n, err
}

func (s *Store) UpdateUserPassword(ctx context.Context, id int64, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

func (s *Store) UpdateUserTOTP(ctx context.Context, id int64, enc string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_enc = ? WHERE id = ?`, enc, id)
	return err
}

func (s *Store) UpdateUserRole(ctx context.Context, id int64, role string, disabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ? WHERE id = ?`, role, disabled, id)
	return err
}

func (s *Store) TouchLogin(ctx context.Context, id int64, ip string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?`, time.Now().Unix(), ip, id)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// HasLoggedInFrom reports whether a user ever had a session from ip; used to
// alert on logins from new addresses.
func (s *Store) HasLoggedInFrom(ctx context.Context, userID int64, ip string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit a JOIN users u ON u.username = a.username
		WHERE u.id = ? AND a.action = 'login' AND a.ip = ?`, userID, ip).Scan(&n)
	return n > 0, err
}

type Session struct {
	TokenHash string
	UserID    int64
	IP        string
	UserAgent string
	CreatedAt int64
	LastSeen  int64
	ExpiresAt int64
}

func (s *Store) CreateSession(ctx context.Context, se *Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, ip, user_agent, created_at, last_seen, expires_at) VALUES(?,?,?,?,?,?,?)`,
		se.TokenHash, se.UserID, se.IP, se.UserAgent, se.CreatedAt, se.LastSeen, se.ExpiresAt)
	return err
}

func (s *Store) SessionByHash(ctx context.Context, h string) (*Session, error) {
	var se Session
	err := s.db.QueryRowContext(ctx, `SELECT token_hash, user_id, ip, user_agent, created_at, last_seen, expires_at FROM sessions WHERE token_hash = ?`, h).
		Scan(&se.TokenHash, &se.UserID, &se.IP, &se.UserAgent, &se.CreatedAt, &se.LastSeen, &se.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &se, err
}

func (s *Store) TouchSession(ctx context.Context, h string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, now, h)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, h string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, h)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}
