// Package admin serves the management API and the web panel. It must only be
// reachable from a private network (WireGuard / LAN).
package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/config"
	"github.com/llldkkw/waf/internal/events"
	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/proxy"
	"github.com/llldkkw/waf/internal/report"
	"github.com/llldkkw/waf/internal/secure"
	"github.com/llldkkw/waf/internal/store"
)

type Server struct {
	cfg      *config.Config
	st       *store.Store
	box      *secure.Box
	nt       *notify.Notifier
	hub      *events.Hub
	px       *proxy.Proxy
	web      fs.FS
	tls      bool
	started  time.Time
	version  string
	throttle *throttle
	totpUsed totpGuard
	rep      *report.Reporter
	geo      *events.Geo
}

type Deps struct {
	Config   *config.Config
	Store    *store.Store
	Box      *secure.Box
	Notifier *notify.Notifier
	Hub      *events.Hub
	Proxy    *proxy.Proxy
	Web      fs.FS
	Version  string
	Reporter *report.Reporter
	Geo      *events.Geo
}

func New(d Deps) *Server {
	return &Server{
		cfg: d.Config, st: d.Store, box: d.Box, nt: d.Notifier, hub: d.Hub, px: d.Proxy, web: d.Web,
		tls: d.Config.Admin.TLS != "off", started: time.Now(), version: d.Version, throttle: newThrottle(),
		rep: d.Reporter, geo: d.Geo,
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	auth, admin := s.requireAuth, s.requireAdmin

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", auth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]any{"user": userFrom(r)}) }))
	mux.HandleFunc("POST /api/me/password", auth(s.handleChangePassword))

	mux.HandleFunc("GET /api/overview", auth(s.handleOverview))
	mux.HandleFunc("GET /api/status", auth(s.handleStatus))
	mux.HandleFunc("GET /api/ws", auth(s.handleWS))

	mux.HandleFunc("GET /api/sites", auth(s.handleListSites))
	mux.HandleFunc("POST /api/sites", admin(s.handleSaveSite))
	mux.HandleFunc("GET /api/sites/{id}", auth(s.handleGetSite))
	mux.HandleFunc("PUT /api/sites/{id}", admin(s.handleSaveSite))
	mux.HandleFunc("DELETE /api/sites/{id}", admin(s.handleDeleteSite))
	mux.HandleFunc("POST /api/sites/{id}/exclusions", admin(s.handleAddExclusion))

	mux.HandleFunc("GET /api/ip-rules", auth(s.handleListIPRules))
	mux.HandleFunc("POST /api/ip-rules", admin(s.handleAddIPRule))
	mux.HandleFunc("DELETE /api/ip-rules/{id}", admin(s.handleDeleteIPRule))

	mux.HandleFunc("GET /api/events", auth(s.handleEvents))
	mux.HandleFunc("GET /api/audit", admin(s.handleAudit))

	mux.HandleFunc("GET /api/channel-types", auth(s.handleChannelTypes))
	mux.HandleFunc("GET /api/channels", admin(s.handleListChannels))
	mux.HandleFunc("POST /api/channels", admin(s.handleSaveChannel))
	mux.HandleFunc("PUT /api/channels/{id}", admin(s.handleSaveChannel))
	mux.HandleFunc("DELETE /api/channels/{id}", admin(s.handleDeleteChannel))
	mux.HandleFunc("POST /api/channels/{id}/test", admin(s.handleTestChannel))

	mux.HandleFunc("GET /api/users", admin(s.handleListUsers))
	mux.HandleFunc("POST /api/users", admin(s.handleCreateUser))
	mux.HandleFunc("PUT /api/users/{id}", admin(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", admin(s.handleDeleteUser))
	mux.HandleFunc("POST /api/users/{id}/reset", admin(s.handleResetUser))

	mux.HandleFunc("GET /api/certs", admin(s.handleListCerts))
	mux.HandleFunc("POST /api/certs", admin(s.handleSaveCert))
	mux.HandleFunc("PUT /api/certs/{id}", admin(s.handleSaveCert))
	mux.HandleFunc("DELETE /api/certs/{id}", admin(s.handleDeleteCert))

	mux.HandleFunc("GET /api/actions", admin(s.handleInspectAction))
	mux.HandleFunc("POST /api/actions", admin(s.handleExecuteAction))

	mux.HandleFunc("GET /api/settings/reports", admin(s.handleGetReportSettings))
	mux.HandleFunc("PUT /api/settings/reports", admin(s.handleSaveReportSettings))
	mux.HandleFunc("POST /api/reports/send", admin(s.handleSendReport))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, errors.New("not found"))
	})
	mux.Handle("/", s.static())
	return s.guard(mux)
}

// guard applies network restrictions, CSRF protection and security headers.
func (s *Server) guard(next http.Handler) http.Handler {
	allowed := s.cfg.Admin.Allowed()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(remoteIP(r))
		if err != nil || (len(allowed) > 0 && !config.ContainsAddr(allowed, ip)) {
			// Look like nothing is here.
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if s.tls {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
			// CSRF: state-changing requests must carry a custom header, which a
			// cross-site form or image cannot set, and a same-origin Origin.
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if r.Header.Get("X-Requested-With") != "waf" || !sameOrigin(r) {
					writeErr(w, http.StatusForbidden, errors.New("CSRF check failed"))
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true // non-browser clients; the custom header still applies
	}
	o = strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://")
	return o == r.Host
}

// static serves the embedded single page app.
func (s *Server) static() http.Handler {
	fileServer := http.FileServer(http.FS(s.web))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.web, p); err != nil {
			// SPA route: serve index.html.
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			p = "index.html"
			r = r2
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// Serve runs the admin listener until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Admin.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	if host, _, err := net.SplitHostPort(srv.Addr); err == nil {
		if a, err := netip.ParseAddr(host); err != nil || a.IsUnspecified() || isPublic(a) {
			slog.Warn("admin: panel is not bound to a private address; restrict it to the VPN/LAN", "listen", srv.Addr)
		}
	}
	var err error
	switch s.cfg.Admin.TLS {
	case "self-signed":
		var cert tls.Certificate
		cert, err = selfSigned(filepath.Join(s.cfg.DataDir, "admin-tls"))
		if err != nil {
			return err
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	case "file":
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(s.cfg.Admin.CertFile, s.cfg.Admin.KeyFile)
		if err != nil {
			return err
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go s.janitor(ctx)
	slog.Info("admin: listening", "addr", srv.Addr, "tls", s.cfg.Admin.TLS)
	if srv.TLSConfig != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if err := s.st.Prune(ctx, time.Duration(s.cfg.LogRetentionDays)*24*time.Hour); err != nil && ctx.Err() == nil {
			slog.Error("admin: prune failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func isPublic(a netip.Addr) bool {
	return !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast())
}

// selfSigned loads or creates a long-lived self-signed certificate for the panel.
func selfSigned(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "WAF Admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "waf.local"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.8.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// --- helpers ---

func remoteIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	msg := err.Error()
	if status >= 500 {
		slog.Error("admin: request failed", "err", err)
		msg = "服务器内部错误"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误: "+err.Error()))
		return false
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	u := userFrom(r)
	name := ""
	if u != nil {
		name = u.Username
	}
	if err := s.st.Audit(r.Context(), store.AuditEntry{Username: name, IP: remoteIP(r), Action: action, Target: target, Detail: truncate(detail, 4000)}); err != nil {
		slog.Error("admin: audit failed", "err", err)
	}
}
