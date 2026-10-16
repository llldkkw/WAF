package proxy

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/llldkkw/waf/internal/store"
)

// fakeVerifier mimics a siteverify endpoint: response "good" succeeds,
// anything else fails. score/host are returned as given.
func fakeVerifier(t *testing.T, score float64, host, action string) (*httptest.Server, *[]url.Values) {
	var calls []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		calls = append(calls, r.PostForm)
		ok := r.PostForm.Get("response") == "good" && r.PostForm.Get("secret") == "sec"
		_ = json.NewEncoder(w).Encode(map[string]any{"success": ok, "hostname": host, "score": score, "action": action})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func captchaSubmit(p *Proxy, page, response, remote string) *httptest.ResponseRecorder {
	tok := html.UnescapeString(regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(page)[1])
	form := url.Values{"token": {tok}, "captcha": {response}, "return": {"/after"}}
	r := httptest.NewRequest("POST", "http://app.test"+challengePath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestTurnstile(t *testing.T) {
	be := backend(t)
	p, st := setup(t, store.Site{Name: "app", Enabled: true, Hosts: []string{"app.test"}, Upstreams: []string{be.URL}, Mode: store.ModeOff,
		Challenge: store.Challenge{Mode: "always", Provider: "turnstile"}}, "")
	const ip = "198.51.100.9:1"

	// No keys configured yet: falls back to the built-in proof of work.
	if body := do(p, "GET", "http://app.test/", ip, nil).Body.String(); !strings.Contains(body, "正在进行安全验证") {
		t.Fatal("expected built-in challenge when Turnstile has no keys")
	}

	srv, calls := fakeVerifier(t, 0, "app.test", "")
	old := turnstileVerifyURL
	turnstileVerifyURL = srv.URL
	defer func() { turnstileVerifyURL = old }()
	ctx := context.Background()
	caps := &store.CaptchaProviders{Turnstile: store.TurnstileConfig{SiteKey: "0x4AAA-site", Secret: "sec"}}
	_ = caps.Normalize()
	if err := st.SaveCaptchaProviders(ctx, p.box, caps); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	w := do(p, "GET", "http://app.test/", ip, nil)
	page := w.Body.String()
	if !strings.Contains(page, "cf-turnstile") || !strings.Contains(page, "0x4AAA-site") {
		t.Fatalf("turnstile widget missing: %s", page)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "https://challenges.cloudflare.com") {
		t.Fatalf("csp: %s", csp)
	}
	if w := captchaSubmit(p, page, "bad", ip); w.Code == 303 {
		t.Fatal("failed captcha accepted")
	}
	w = captchaSubmit(p, page, "good", ip)
	if w.Code != 303 || w.Header().Get("Location") != "/after" {
		t.Fatalf("good captcha: %d %s", w.Code, w.Header().Get("Location"))
	}
	if got := (*calls)[len(*calls)-1].Get("remoteip"); got != "198.51.100.9" {
		t.Errorf("remoteip sent to provider = %q", got)
	}
}

func TestRecaptcha(t *testing.T) {
	be := backend(t)
	const ip = "198.51.100.9:1"
	for _, c := range []struct {
		name    string
		version string
		score   float64
		host    string
		action  string
		want    bool
	}{
		{"v2 ok", "v2", 0, "app.test", "", true},
		{"v2 wrong host", "v2", 0, "evil.test", "", false},
		{"v3 high score", "v3", 0.9, "app.test", recaptchaAction, true},
		{"v3 low score", "v3", 0.1, "app.test", recaptchaAction, false},
		{"v3 wrong action", "v3", 0.9, "app.test", "login", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, st := setup(t, store.Site{Name: "app", Enabled: true, Hosts: []string{"app.test"}, Upstreams: []string{be.URL}, Mode: store.ModeOff,
				Challenge: store.Challenge{Mode: "always", Provider: "recaptcha"}}, "")
			srv, _ := fakeVerifier(t, c.score, c.host, c.action)
			old := recaptchaVerifyURL
			recaptchaVerifyURL = func(string) string { return srv.URL }
			defer func() { recaptchaVerifyURL = old }()
			caps := &store.CaptchaProviders{Recaptcha: store.RecaptchaConfig{SiteKey: "6Lc-site", Secret: "sec", Version: c.version}}
			_ = caps.Normalize()
			_ = st.SaveCaptchaProviders(context.Background(), p.box, caps)
			_ = p.Reload(context.Background())

			page := do(p, "GET", "http://app.test/", ip, nil).Body.String()
			if !strings.Contains(page, "https://www.recaptcha.net/recaptcha/api.js") {
				t.Fatalf("recaptcha script missing: %s", page)
			}
			if got := captchaSubmit(p, page, "good", ip).Code == 303; got != c.want {
				t.Fatalf("accepted=%v want %v", got, c.want)
			}
		})
	}
}
