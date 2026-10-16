package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"math/bits"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/secure"
	"github.com/llldkkw/waf/internal/store"
)

// JS challenge: the visitor's browser must find a counter such that
// sha256(token ":" counter) starts with N zero bits. Real browsers solve it in
// well under a second; scripted floods and most bots never run it. A solved
// challenge grants a signed clearance cookie bound to the site, the client's
// network (/24 or /64) and its User-Agent.

const (
	challengePath   = "/.waf/challenge"
	clearanceCookie = "__waf_clr"
	tokenTTL        = 5 * time.Minute
)

type challengeToken struct {
	Site int64  `json:"s"`
	Net  string `json:"n"`
	Exp  int64  `json:"e"`
	Diff int    `json:"d"`
	Salt string `json:"r"`
}

// clientNet coarsens an address so mobile clients hopping within their
// carrier's range keep their clearance.
func clientNet(a netip.Addr) string {
	bits := 24
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits)
	return p.String()
}

func uaHash(r *http.Request) string {
	h := sha256.Sum256([]byte(r.UserAgent()))
	return base64.RawURLEncoding.EncodeToString(h[:8])
}

func (p *Proxy) sign(purpose string, msg []byte) string {
	return base64.RawURLEncoding.EncodeToString(p.box.MAC(purpose, msg))
}

func (p *Proxy) verifySig(purpose string, msg []byte, sig string) bool {
	want, err := base64.RawURLEncoding.DecodeString(sig)
	return err == nil && hmac.Equal(want, p.box.MAC(purpose, msg))
}

func (p *Proxy) newToken(site *store.Site, a netip.Addr) string {
	t := challengeToken{Site: site.ID, Net: clientNet(a), Exp: time.Now().Add(tokenTTL).Unix(), Diff: site.Challenge.Difficulty, Salt: secure.Token(8)}
	b, _ := json.Marshal(t)
	payload := base64.RawURLEncoding.EncodeToString(b)
	return payload + "." + p.sign("challenge", []byte(payload))
}

func (p *Proxy) parseToken(tok string) (*challengeToken, bool) {
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok || !p.verifySig("challenge", []byte(payload), sig) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	var t challengeToken
	if json.Unmarshal(b, &t) != nil || t.Exp < time.Now().Unix() {
		return nil, false
	}
	return &t, true
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(x)
	}
	return n
}

func powOK(tok, counter string, diff int) bool {
	if len(counter) == 0 || len(counter) > 16 {
		return false
	}
	h := sha256.Sum256([]byte(tok + ":" + counter))
	return leadingZeroBits(h[:]) >= diff
}

func (p *Proxy) clearanceValue(site *store.Site, a netip.Addr, r *http.Request, exp int64) string {
	msg := strconv.FormatInt(site.ID, 10) + "|" + clientNet(a) + "|" + uaHash(r) + "|" + strconv.FormatInt(exp, 10)
	return strconv.FormatInt(exp, 10) + "." + p.sign("clearance", []byte(msg))
}

func (p *Proxy) hasClearance(site *store.Site, a netip.Addr, r *http.Request) bool {
	c, err := r.Cookie(clearanceCookie)
	if err != nil {
		return false
	}
	expS, sig, ok := strings.Cut(c.Value, ".")
	exp, err := strconv.ParseInt(expS, 10, 64)
	if !ok || err != nil || exp < time.Now().Unix() {
		return false
	}
	msg := strconv.FormatInt(site.ID, 10) + "|" + clientNet(a) + "|" + uaHash(r) + "|" + expS
	return p.verifySig("clearance", []byte(msg), sig)
}

// suspicious flags clients that recently misbehaved or do not look like a
// browser at all.
func (p *Proxy) suspicious(siteID int64, a netip.Addr, r *http.Request) bool {
	if p.rlHits.count(siteID, a, 10*time.Minute) > 0 || p.atkHits.count(siteID, a, 10*time.Minute) > 0 {
		return true
	}
	ua := r.UserAgent()
	return !strings.Contains(ua, "Mozilla/") || r.Header.Get("Accept-Language") == ""
}

func exempt(paths []string, path string) bool {
	for _, p := range paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// needsChallenge reports whether the request must solve a challenge first.
func (p *Proxy) needsChallenge(s *store.Site, a netip.Addr, r *http.Request) bool {
	c := &s.Challenge
	if c.Mode == "off" || c.Mode == "" || exempt(c.ExemptPaths, r.URL.Path) || p.hasClearance(s, a, r) {
		return false
	}
	return c.Mode == "always" || p.suspicious(s.ID, a, r)
}

func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	acc := r.Header.Get("Accept")
	return acc == "" || strings.Contains(acc, "text/html") || strings.Contains(acc, "*/*")
}

// serveChallenge answers with the challenge page, or a plain 403 for
// requests that cannot run JavaScript (API calls, assets).
func (p *Proxy) serveChallenge(w http.ResponseWriter, r *http.Request, s *store.Site, a netip.Addr) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if !wantsHTML(r) {
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"challenge_required","message":"请在浏览器中打开本站完成人机验证"}`))
		return
	}
	nonce := secure.Token(12)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return
	}
	_ = challengeTmpl.Execute(w, map[string]any{
		"Nonce": nonce, "Token": p.newToken(s, a), "Diff": s.Challenge.Difficulty,
		"Return": r.URL.RequestURI(), "Action": challengePath,
	})
}

// handleChallengeSubmit verifies a solution and issues the clearance cookie.
func (p *Proxy) handleChallengeSubmit(w http.ResponseWriter, r *http.Request, s *store.Site, a netip.Addr) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, counter, ret := r.PostForm.Get("token"), r.PostForm.Get("counter"), r.PostForm.Get("return")
	t, ok := p.parseToken(tok)
	if !ok || t.Site != s.ID || t.Net != clientNet(a) || !powOK(tok, counter, t.Diff) {
		p.serveChallenge(w, r, s, a)
		return
	}
	exp := time.Now().Add(time.Duration(s.Challenge.TTLHours) * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name: clearanceCookie, Value: p.clearanceValue(s, a, r, exp.Unix()), Path: "/",
		Expires: exp, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	// Only redirect within this site.
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || strings.HasPrefix(ret, "/\\") {
		ret = "/"
	}
	http.Redirect(w, r, ret, http.StatusSeeOther)
}

var challengeTmpl = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>安全验证</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#0f172a;--muted:#64748b;--accent:#0891b2;--line:#e2e8f0}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f14;--card:#121821;--fg:#e2e8f0;--muted:#94a3b8;--accent:#22d3ee;--line:#1e293b}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;padding:16px}
.card{max-width:420px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px;text-align:center}
h1{font-size:20px;margin:16px 0 6px}p{color:var(--muted);margin:0}
.spin{width:36px;height:36px;margin:0 auto;border:3px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
.bar{height:4px;background:var(--line);border-radius:4px;margin-top:20px;overflow:hidden}.bar i{display:block;height:100%;width:0;background:var(--accent);transition:width .2s}
</style></head><body><div class="card">
<div class="spin"></div><h1>正在进行安全验证</h1><p id="msg">请稍候，这通常不到一秒…</p><div class="bar"><i id="bar"></i></div>
<noscript><p style="margin-top:16px">请启用 JavaScript 后刷新页面。</p></noscript>
<form id="f" method="post" action="{{.Action}}"><input type="hidden" name="token" value="{{.Token}}"><input type="hidden" name="counter" id="c"><input type="hidden" name="return" value="{{.Return}}"></form>
</div>
<script nonce="{{.Nonce}}">
(function(){
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
var W=new Int32Array(64);
function sha(s){ // returns first 32-bit word of SHA-256 (ASCII input)
 var n=s.length,l=((n+9+63)>>6)<<4,m=new Int32Array(l),i;
 for(i=0;i<n;i++)m[i>>2]|=s.charCodeAt(i)<<(24-(i&3)*8);
 m[n>>2]|=0x80<<(24-(n&3)*8);m[l-1]=n*8;
 var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
 for(var o=0;o<l;o+=16){
  var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7,j,t1,t2,x,y;
  for(j=0;j<64;j++){
   if(j<16)W[j]=m[o+j];else{x=W[j-15];y=W[j-2];
    W[j]=(((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3))+W[j-7]+(((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10))+W[j-16]|0;}
   t1=h+(((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)))+((e&f)^(~e&g))+K[j]+W[j]|0;
   t2=(((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)))+((a&b)^(a&c)^(b&c))|0;
   h=g;g=f;f=e;e=d+t1|0;d=c;c=b;b=a;a=t1+t2|0;}
  h0=h0+a|0;h1=h1+b|0;h2=h2+c|0;h3=h3+d|0;h4=h4+e|0;h5=h5+f|0;h6=h6+g|0;h7=h7+h|0;}
 return [h0,h1];
}
function lz(w){var h=w[0];if(h!==0)return Math.clz32(h);return 32+Math.clz32(w[1]);}
var tok=document.querySelector('input[name=token]').value,diff={{.Diff}},i=0,exp=Math.pow(2,diff),bar=document.getElementById('bar');
function step(){
 var end=i+20000;
 for(;i<end;i++){if(lz(sha(tok+":"+i))>=diff){document.getElementById('c').value=i;bar.style.width='100%';document.getElementById('f').submit();return;}}
 bar.style.width=Math.min(95,i/exp*60)+'%';
 setTimeout(step,0);
}
setTimeout(step,50);
})();
</script></body></html>`))
