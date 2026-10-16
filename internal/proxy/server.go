package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/store"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Serve runs the HTTP and HTTPS listeners until ctx is cancelled. HTTPS
// serves uploaded certificates first and falls back to Let's Encrypt.
func (p *Proxy) Serve(ctx context.Context) error {
	var handler http.Handler = p
	httpHandler := handler

	if p.cfg.ACME.Enabled {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(filepath.Join(p.cfg.DataDir, "certs")),
			HostPolicy: p.HostAllowed,
			Email:      p.cfg.ACME.Email,
		}
		if p.cfg.ACME.DirectoryURL != "" {
			m.Client = &acme.Client{DirectoryURL: p.cfg.ACME.DirectoryURL}
		}
		p.acme = m
		httpHandler = m.HTTPHandler(handler)
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: p.getCertificate,
	}
	if p.acme != nil {
		tlsCfg.NextProtos = append(tlsCfg.NextProtos, acme.ALPNProto)
	}

	errc := make(chan error, 2)
	servers := []*http.Server{newServer(p.cfg.Proxy.HTTPListen, httpHandler, nil)}
	if p.cfg.Proxy.HTTPSListen != "" {
		servers = append(servers, newServer(p.cfg.Proxy.HTTPSListen, handler, tlsCfg))
	}
	for _, s := range servers {
		go func(s *http.Server) {
			slog.Info("proxy: listening", "addr", s.Addr, "tls", s.TLSConfig != nil)
			var err error
			if s.TLSConfig != nil {
				err = s.ListenAndServeTLS("", "")
			} else {
				err = s.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(s)
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return nil
}

func (p *Proxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, proto := range hello.SupportedProtos {
		if proto == acme.ALPNProto && p.acme != nil {
			return p.acme.GetCertificate(hello)
		}
	}
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if c := p.tbl.Load().certs.lookup(name); c != nil {
		return c, nil
	}
	if p.acme != nil && name != "" {
		return p.acme.GetCertificate(hello)
	}
	return nil, fmt.Errorf("no certificate for %q", name)
}

// certIndex maps hostnames to uploaded certificates.
type certIndex struct {
	exact    map[string]*tls.Certificate
	wildcard map[string]*tls.Certificate // "example.com" for "*.example.com"
}

func (ci *certIndex) lookup(name string) *tls.Certificate {
	if ci == nil {
		return nil
	}
	if c, ok := ci.exact[name]; ok {
		return c
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		return ci.wildcard[name[i+1:]]
	}
	return nil
}

func (p *Proxy) buildCerts(list []store.Certificate) *certIndex {
	ci := &certIndex{exact: map[string]*tls.Certificate{}, wildcard: map[string]*tls.Certificate{}}
	// Newer uploads win when domains overlap (list is ordered by id).
	for _, c := range list {
		key, err := p.box.Open(c.KeyEnc)
		if err != nil {
			slog.Error("proxy: cannot decrypt certificate key", "cert", c.Name, "err", err)
			continue
		}
		pair, err := tls.X509KeyPair([]byte(c.CertPEM), key)
		if err != nil {
			slog.Error("proxy: invalid certificate", "cert", c.Name, "err", err)
			continue
		}
		for _, d := range c.Domains {
			if w, ok := strings.CutPrefix(d, "*."); ok {
				ci.wildcard[w] = &pair
			} else {
				ci.exact[d] = &pair
			}
		}
	}
	return ci
}

// HasCertificate reports whether an uploaded certificate covers host.
func (p *Proxy) HasCertificate(host string) bool {
	return p.tbl.Load().certs.lookup(host) != nil
}

func newServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
}

var blockTmpl = template.Must(template.New("block").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Status}} {{.Title}}</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#0f172a;--muted:#64748b;--accent:#0891b2;--line:#e2e8f0}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f14;--card:#121821;--fg:#e2e8f0;--muted:#94a3b8;--accent:#22d3ee;--line:#1e293b}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;padding:16px}
.card{max-width:440px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px}
.code{font:600 13px ui-monospace,monospace;color:var(--accent);letter-spacing:.08em}
h1{font-size:22px;margin:8px 0 6px}p{color:var(--muted);margin:0 0 20px}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:0;padding-top:16px;border-top:1px solid var(--line);font-size:13px}
dt{color:var(--muted)}dd{margin:0;font-family:ui-monospace,monospace;word-break:break-all}
</style></head><body><div class="card">
<div class="code">HTTP {{.Status}}</div><h1>{{.Title}}</h1><p>{{.Message}}</p>
<dl><dt>时间</dt><dd>{{.Time}}</dd>{{if .IP}}<dt>IP</dt><dd>{{.IP}}</dd>{{end}}</dl>
</div></body></html>`))

func writeBlockPage(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	if status == 0 {
		status = http.StatusForbidden
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = blockTmpl.Execute(w, map[string]any{
		"Status": status, "Title": title, "Message": msg,
		"Time": time.Now().Format("2006-01-02 15:04:05"), "IP": clientIPFrom(r.Context()),
	})
}
