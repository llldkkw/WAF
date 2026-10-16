package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/llldkkw/waf/internal/store"
)

func selfSignedPEM(t *testing.T, notAfter time.Time, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, Issuer: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: names}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestUploadedCertificates(t *testing.T) {
	be := backend(t)
	p, st := setup(t, store.Site{Name: "app", Enabled: true, Hosts: []string{"*.example.com", "example.com"}, Upstreams: []string{be.URL}, Mode: store.ModeOff, HTTPS: true}, "")
	ctx := context.Background()

	certPEM, keyPEM := selfSignedPEM(t, time.Now().Add(90*24*time.Hour), "*.example.com", "example.com")
	c, err := store.ParseCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Domains) != 2 || c.Domains[0] != "*.example.com" {
		t.Fatalf("domains: %v", c.Domains)
	}
	// Mismatched key is rejected.
	_, otherKey := selfSignedPEM(t, time.Now().Add(time.Hour), "x.test")
	if _, err := store.ParseCertificate(certPEM, otherKey); err == nil {
		t.Fatal("mismatched key accepted")
	}
	// Expired certificate is rejected.
	expired, expKey := selfSignedPEM(t, time.Now().Add(-time.Minute), "old.test")
	if _, err := store.ParseCertificate(expired, expKey); err == nil {
		t.Fatal("expired certificate accepted")
	}

	c.Name = "wildcard"
	c.KeyEnc, _ = p.box.Seal([]byte(keyPEM))
	if err := st.SaveCert(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"www.example.com", "api.example.com", "example.com"} {
		got, err := p.getCertificate(&tls.ClientHelloInfo{ServerName: host})
		if err != nil || got == nil {
			t.Fatalf("%s: no certificate (%v)", host, err)
		}
	}
	if _, err := p.getCertificate(&tls.ClientHelloInfo{ServerName: "a.b.example.com"}); err == nil {
		t.Fatal("wildcard must only cover one label")
	}
	if _, err := p.getCertificate(&tls.ClientHelloInfo{ServerName: "other.test"}); err == nil {
		t.Fatal("unknown host got a certificate")
	}
}
