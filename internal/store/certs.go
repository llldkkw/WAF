package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Certificate is an uploaded TLS certificate (including wildcard ones). The
// private key is stored encrypted.
type Certificate struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Issuer    string   `json:"issuer"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	CreatedAt int64    `json:"created_at"`
	CertPEM   string   `json:"-"`
	KeyEnc    string   `json:"-"`
}

const certSchema = `
CREATE TABLE IF NOT EXISTS certs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	domains    TEXT NOT NULL,
	issuer     TEXT NOT NULL,
	not_before INTEGER NOT NULL,
	not_after  INTEGER NOT NULL,
	cert_pem   TEXT NOT NULL,
	key_enc    TEXT NOT NULL,
	created_at INTEGER NOT NULL
);`

// ParseCertificate validates a PEM certificate chain and key and returns the
// metadata. It rejects mismatched keys and expired certificates.
func ParseCertificate(certPEM, keyPEM string) (*Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("证书或私钥无效（需要 PEM 格式，且私钥与证书匹配）: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, errors.New("证书已过期")
	}
	domains := append([]string{}, leaf.DNSNames...)
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = []string{leaf.Subject.CommonName}
	}
	for i, d := range domains {
		domains[i] = strings.ToLower(d)
	}
	if len(domains) == 0 {
		return nil, errors.New("证书中没有域名")
	}
	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	return &Certificate{
		Domains: domains, Issuer: issuer, CertPEM: certPEM,
		NotBefore: leaf.NotBefore.Unix(), NotAfter: leaf.NotAfter.Unix(),
	}, nil
}

func (s *Store) ListCerts(ctx context.Context) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, domains, issuer, not_before, not_after, cert_pem, key_enc, created_at FROM certs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Certificate{}
	for rows.Next() {
		var (
			c Certificate
			d string
		)
		if err := rows.Scan(&c.ID, &c.Name, &d, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.CertPEM, &c.KeyEnc, &c.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(d), &c.Domains)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) SaveCert(ctx context.Context, c *Certificate) error {
	d, _ := json.Marshal(c.Domains)
	if c.ID == 0 {
		c.CreatedAt = time.Now().Unix()
		res, err := s.db.ExecContext(ctx, `INSERT INTO certs(name, domains, issuer, not_before, not_after, cert_pem, key_enc, created_at) VALUES(?,?,?,?,?,?,?,?)`,
			c.Name, string(d), c.Issuer, c.NotBefore, c.NotAfter, c.CertPEM, c.KeyEnc, c.CreatedAt)
		if err != nil {
			return err
		}
		if c.ID, err = res.LastInsertId(); err != nil {
			return err
		}
	} else {
		res, err := s.db.ExecContext(ctx, `UPDATE certs SET name = ?, domains = ?, issuer = ?, not_before = ?, not_after = ?, cert_pem = ?, key_enc = ? WHERE id = ?`,
			c.Name, string(d), c.Issuer, c.NotBefore, c.NotAfter, c.CertPEM, c.KeyEnc, c.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	return s.BumpConfigVersion(ctx)
}

func (s *Store) DeleteCert(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM certs WHERE id = ?`, id); err != nil {
		return err
	}
	return s.BumpConfigVersion(ctx)
}
