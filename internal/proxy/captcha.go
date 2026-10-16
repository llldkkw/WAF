package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/store"
)

// Third-party human verification (Cloudflare Turnstile, Google reCAPTCHA).
// The page still carries our signed token, so a captcha answer is bound to
// the site, the client network and a 5 minute window just like the built-in
// proof of work; the provider's verdict is checked server side.

var (
	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	recaptchaVerifyURL = func(domain string) string { return "https://" + domain + "/recaptcha/api/siteverify" }
	captchaClient      = &http.Client{Timeout: 8 * time.Second}
)

const recaptchaAction = "waf_challenge"

type siteverifyResp struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Score      *float64 `json:"score"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

func siteverify(ctx context.Context, endpoint, secret, response, ip string) (*siteverifyResp, error) {
	form := url.Values{"secret": {secret}, "response": {response}, "remoteip": {ip}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := captchaClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("siteverify HTTP %d", resp.StatusCode)
	}
	var out siteverifyResp
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// effectiveProvider falls back to the built-in proof of work when the chosen
// provider has no keys configured, so a misconfiguration never locks
// visitors out.
func effectiveProvider(s *store.Site, c *store.CaptchaProviders) string {
	switch s.Challenge.Provider {
	case "turnstile":
		if c != nil && c.Turnstile.Ready() {
			return "turnstile"
		}
	case "recaptcha":
		if c != nil && c.Recaptcha.Ready() {
			return "recaptcha"
		}
	}
	return "pow"
}

// verifyCaptcha checks a provider response. It fails closed: if the provider
// cannot be reached the visitor sees the challenge again.
func verifyCaptcha(ctx context.Context, provider string, c *store.CaptchaProviders, response, ip, host string) bool {
	if response == "" || len(response) > 4096 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	switch provider {
	case "turnstile":
		v, err := siteverify(ctx, turnstileVerifyURL, c.Turnstile.Secret, response, ip)
		if err != nil || !v.Success {
			return false
		}
		return v.Hostname == "" || strings.EqualFold(v.Hostname, host)
	case "recaptcha":
		rc := c.Recaptcha
		v, err := siteverify(ctx, recaptchaVerifyURL(rc.Domain), rc.Secret, response, ip)
		if err != nil || !v.Success {
			return false
		}
		if v.Hostname != "" && !strings.EqualFold(v.Hostname, host) {
			return false
		}
		if rc.Version == "v3" {
			return v.Score != nil && *v.Score >= rc.MinScore && v.Action == recaptchaAction
		}
		return true
	}
	return false
}

func captchaCSP(provider, nonce, recaptchaDomain string) string {
	switch provider {
	case "turnstile":
		return "default-src 'none'; script-src 'nonce-" + nonce + "' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; " +
			"connect-src https://challenges.cloudflare.com; style-src 'unsafe-inline'; img-src https: data:; form-action 'self'; base-uri 'none'"
	case "recaptcha":
		srcs := "https://" + recaptchaDomain + " https://www.gstatic.com https://www.gstatic.cn"
		return "default-src 'none'; script-src 'nonce-" + nonce + "' " + srcs + "; frame-src " + srcs + "; connect-src " + srcs +
			"; style-src 'unsafe-inline' " + srcs + "; img-src https: data:; form-action 'self'; base-uri 'none'"
	}
	return ""
}

var captchaTmpl = template.Must(template.New("captcha").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>安全验证</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#0f172a;--muted:#64748b;--line:#e2e8f0}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f14;--card:#121821;--fg:#e2e8f0;--muted:#94a3b8;--line:#1e293b}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;padding:16px}
.card{max-width:420px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px;text-align:center}
h1{font-size:20px;margin:0 0 6px}p{color:var(--muted);margin:0 0 20px}.w{display:flex;justify-content:center;min-height:78px}
</style>
{{if eq .Provider "turnstile"}}<script nonce="{{.Nonce}}" src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
{{else if eq .Version "v3"}}<script nonce="{{.Nonce}}" src="https://{{.Domain}}/recaptcha/api.js?render={{.SiteKey}}"></script>
{{else}}<script nonce="{{.Nonce}}" src="https://{{.Domain}}/recaptcha/api.js" async defer></script>{{end}}
</head><body><div class="card">
<h1>请完成安全验证</h1><p>{{if eq .Version "v3"}}正在自动验证，请稍候…{{else}}确认您是真人访问后即可继续。{{end}}</p>
<form id="f" method="post" action="{{.Action}}">
<input type="hidden" name="token" value="{{.Token}}"><input type="hidden" name="return" value="{{.Return}}">
<input type="hidden" name="captcha" id="cap">
<div class="w">{{if eq .Provider "turnstile"}}<div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="wafDone" data-language="zh-cn"></div>
{{else if ne .Version "v3"}}<div class="g-recaptcha" data-sitekey="{{.SiteKey}}" data-callback="wafDone"></div>{{end}}</div>
</form>
<noscript><p>请启用 JavaScript 后刷新页面。</p></noscript>
</div>
<script nonce="{{.Nonce}}">
window.wafDone=function(t){document.getElementById('cap').value=t;document.getElementById('f').submit();};
{{if and (eq .Provider "recaptcha") (eq .Version "v3")}}
(function w(){if(!window.grecaptcha||!grecaptcha.ready){return setTimeout(w,100);}grecaptcha.ready(function(){grecaptcha.execute({{.SiteKey}},{action:{{.ActionName}}}).then(window.wafDone);});})();
{{end}}
</script></body></html>`))
