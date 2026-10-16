package proxy

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/llldkkw/waf/internal/config"
	"github.com/llldkkw/waf/internal/events"
	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/secure"
	"github.com/llldkkw/waf/internal/store"
)

func setup(t *testing.T, site store.Site, yamlExtra string) (*Proxy, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "waf.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"+yamlExtra), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secure.LoadOrCreateKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	nt := notify.New(st, box)
	geo, err := events.OpenGeo(cfg.GeoIPDB)
	if err != nil {
		t.Fatal(err)
	}
	rec := events.NewRecorder(st, events.NewHub(), nt, geo)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go rec.Run(ctx)

	if err := site.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSite(ctx, &site); err != nil {
		t.Fatal(err)
	}
	p := New(cfg, st, rec, nt, box)
	if err := p.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	return p, st
}

func backend(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "secret-backend/1.0")
		io.WriteString(w, "ok:"+r.Header.Get("X-Real-IP"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func do(p *Proxy, method, target, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remote
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "text/html")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestProxyFlow(t *testing.T) {
	be := backend(t)
	p, st := setup(t, store.Site{
		Name: "app", Enabled: true, Hosts: []string{"app.test", "*.wild.test"}, Upstreams: []string{be.URL},
		Mode:      store.ModeBlock,
		PathRules: []store.PathRule{{Path: "/admin", Action: "allow", CIDRs: []string{"10.8.0.0/24"}}},
	}, "")

	if w := do(p, "GET", "http://app.test/hello", "198.51.100.1:1234", nil); w.Code != 200 || w.Body.String() != "ok:198.51.100.1" {
		t.Fatalf("normal request: %d %q", w.Code, w.Body.String())
	} else if w.Header().Get("Server") != "" {
		t.Error("backend Server header leaked")
	}
	if w := do(p, "GET", "http://x.wild.test/", "198.51.100.1:1234", nil); w.Code != 200 {
		t.Fatalf("wildcard host: %d", w.Code)
	}
	if w := do(p, "GET", "http://unknown.test/", "198.51.100.1:1234", nil); w.Code != 404 {
		t.Fatalf("unknown host: %d", w.Code)
	}
	if w := do(p, "GET", "http://app.test/?id=1'%20OR%20'1'='1'%20--", "198.51.100.1:1234", nil); w.Code != 403 {
		t.Fatalf("sqli: %d", w.Code)
	}
	if w := do(p, "GET", "http://app.test/admin/", "198.51.100.1:1234", nil); w.Code != 403 {
		t.Fatalf("path acl from outside: %d", w.Code)
	}
	if w := do(p, "GET", "http://app.test/admin/", "10.8.0.2:1234", nil); w.Code != 200 {
		t.Fatalf("path acl from vpn: %d", w.Code)
	}

	// Deny then allow: allow wins.
	ctx := context.Background()
	_ = st.AddIPRule(ctx, &store.IPRule{CIDR: "203.0.113.0/24", Action: store.IPDeny})
	_ = p.Reload(ctx)
	if w := do(p, "GET", "http://app.test/", "203.0.113.9:1", nil); w.Code != 403 {
		t.Fatalf("deny list: %d", w.Code)
	}
	_ = st.AddIPRule(ctx, &store.IPRule{CIDR: "203.0.113.9/32", Action: store.IPAllow})
	_ = p.Reload(ctx)
	if w := do(p, "GET", "http://app.test/?id=1'%20OR%20'1'='1'%20--", "203.0.113.9:1", nil); w.Code != 200 {
		t.Fatalf("allow list should bypass everything: %d", w.Code)
	}
}

func TestRateLimitAutoBan(t *testing.T) {
	be := backend(t)
	p, st := setup(t, store.Site{
		Name: "app", Enabled: true, Hosts: []string{"app.test"}, Upstreams: []string{be.URL}, Mode: store.ModeOff,
		RateLimit: store.RateLimit{Enabled: true, RPS: 1, Burst: 2, BanThreshold: 3, BanMinutes: 5},
	}, "")
	codes := []int{}
	for i := 0; i < 7; i++ {
		codes = append(codes, do(p, "GET", "http://app.test/", "198.51.100.7:1", nil).Code)
	}
	want := []int{200, 200, 429, 429, 429, 403, 403}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("codes = %v, want %v", codes, want)
		}
	}
	// The ban is persisted with an expiry.
	time.Sleep(200 * time.Millisecond)
	rules, _ := st.ListIPRules(context.Background())
	if len(rules) != 1 || rules[0].Source != "auto-ban" || rules[0].ExpiresAt == 0 {
		t.Fatalf("expected one persisted auto-ban, got %+v", rules)
	}
	// Other clients are unaffected.
	if w := do(p, "GET", "http://app.test/", "198.51.100.8:1", nil); w.Code != 200 {
		t.Fatalf("other client: %d", w.Code)
	}
}

func TestTrustedProxy(t *testing.T) {
	be := backend(t)
	p, _ := setup(t, store.Site{Name: "app", Enabled: true, Hosts: []string{"app.test"}, Upstreams: []string{be.URL}, Mode: store.ModeOff},
		"proxy:\n  trusted_proxies: [\"10.0.0.0/8\"]\n")

	// Untrusted peer: X-Forwarded-For is ignored.
	xff := map[string]string{"X-Forwarded-For": "1.2.3.4, 10.1.1.1"}
	if w := do(p, "GET", "http://app.test/", "198.51.100.1:1", xff); w.Body.String() != "ok:198.51.100.1" {
		t.Fatalf("spoofed XFF accepted: %q", w.Body.String())
	}
	// Trusted peer: rightmost untrusted hop is the client.
	if w := do(p, "GET", "http://app.test/", "10.0.0.5:1", xff); w.Body.String() != "ok:1.2.3.4" {
		t.Fatalf("trusted XFF not honoured: %q", w.Body.String())
	}
}

func TestChallenge(t *testing.T) {
	be := backend(t)
	p, _ := setup(t, store.Site{
		Name: "app", Enabled: true, Hosts: []string{"app.test"}, Upstreams: []string{be.URL}, Mode: store.ModeOff,
		Challenge: store.Challenge{Mode: "always", Difficulty: 12, ExemptPaths: []string{"/webhook"}},
	}, "")
	const ip = "198.51.100.20:1"

	w := do(p, "GET", "http://app.test/page?x=1", ip, nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "安全验证") {
		t.Fatalf("expected challenge page, got %d", w.Code)
	}
	if w := do(p, "GET", "http://app.test/webhook/x", ip, nil); w.Code != 200 {
		t.Fatalf("exempt path challenged: %d", w.Code)
	}
	if w := do(p, "POST", "http://app.test/api", ip, map[string]string{"Accept": "application/json"}); w.Code != 403 || !strings.Contains(w.Body.String(), "challenge_required") {
		t.Fatalf("api request: %d %s", w.Code, w.Body.String())
	}

	tok := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if tok == nil {
		tok = regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(do(p, "GET", "http://app.test/", ip, nil).Body.String())
	}
	token := html.UnescapeString(tok[1])
	counter := ""
	for i := 0; ; i++ {
		if powOK(token, strconv.Itoa(i), 12) {
			counter = strconv.Itoa(i)
			break
		}
	}

	submit := func(tok, ctr, remote string) *httptest.ResponseRecorder {
		form := url.Values{"token": {tok}, "counter": {ctr}, "return": {"/page?x=1"}}
		r := httptest.NewRequest("POST", "http://app.test"+challengePath, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, r)
		return rec
	}
	if w := submit(token, "nope", ip); w.Code == 303 {
		t.Fatal("wrong proof accepted")
	}
	if w := submit(token, counter, "203.0.113.50:1"); w.Code == 303 {
		t.Fatal("token accepted from another network")
	}
	w = submit(token, counter, ip)
	if w.Code != 303 || w.Header().Get("Location") != "/page?x=1" {
		t.Fatalf("submit: %d %s", w.Code, w.Header().Get("Location"))
	}
	cookie := w.Result().Cookies()[0]

	withCookie := func(ua string) int {
		r := httptest.NewRequest("GET", "http://app.test/page", nil)
		r.RemoteAddr = "198.51.100.77:1" // same /24
		r.Header.Set("User-Agent", ua)
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, r)
		return rec.Code
	}
	if c := withCookie("Mozilla/5.0"); c != 200 {
		t.Fatalf("cleared request: %d", c)
	}
	if c := withCookie("curl/8"); c != 403 {
		t.Fatalf("cookie reused with another UA: %d", c)
	}
}
