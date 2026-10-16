// Package proxy is the data plane: a reverse proxy that applies IP rules,
// geo blocking, path ACLs, rate limits and the WAF engine to every request.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"

	"github.com/llldkkw/waf/internal/config"
	"github.com/llldkkw/waf/internal/engine"
	"github.com/llldkkw/waf/internal/events"
	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/store"
)

type pathRule struct {
	prefix string
	deny   bool
	allow  []netip.Prefix
}

type siteRuntime struct {
	site      store.Site
	waf       coraza.WAF
	pool      *pool
	pathRules []pathRule
	countries map[string]bool
}

type table struct {
	exact    map[string]*siteRuntime
	wildcard map[string]*siteRuntime // key: "example.com" for "*.example.com"
	ips      *ipList
	version  int64
	httpsSet map[string]bool
	wildTLS  map[string]bool
}

func (t *table) lookup(host string) *siteRuntime {
	if s, ok := t.exact[host]; ok {
		return s
	}
	for h := host; ; {
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return nil
		}
		h = h[i+1:]
		if s, ok := t.wildcard[h]; ok {
			return s
		}
	}
}

type Proxy struct {
	cfg  *config.Config
	st   *store.Store
	rec  *events.Recorder
	nt   *notify.Notifier
	wafs *engine.Cache

	tbl     atomic.Pointer[table]
	bans    *banList
	lims    *limiters
	rlHits  *strikes
	atkHits *strikes
	hc      *healthChecker
}

func New(cfg *config.Config, st *store.Store, rec *events.Recorder, nt *notify.Notifier) *Proxy {
	p := &Proxy{
		cfg: cfg, st: st, rec: rec, nt: nt,
		wafs:    engine.NewCache(cfg.Proxy.MaxBodyBytes),
		bans:    newBanList(),
		lims:    newLimiters(),
		rlHits:  newStrikes(),
		atkHits: newStrikes(),
		hc:      newHealthChecker(nt),
	}
	p.tbl.Store(&table{exact: map[string]*siteRuntime{}, wildcard: map[string]*siteRuntime{}, ips: buildIPList(nil), httpsSet: map[string]bool{}, wildTLS: map[string]bool{}})
	return p
}

// Reload rebuilds the routing table from the database. On error the previous
// table stays active, so a bad change never takes the gateway down.
func (p *Proxy) Reload(ctx context.Context) error {
	ver, err := p.st.ConfigVersion(ctx)
	if err != nil {
		return err
	}
	sites, err := p.st.ListSites(ctx)
	if err != nil {
		return err
	}
	rules, err := p.st.ListIPRules(ctx)
	if err != nil {
		return err
	}
	t := &table{
		exact: map[string]*siteRuntime{}, wildcard: map[string]*siteRuntime{},
		ips: buildIPList(rules), version: ver,
		httpsSet: map[string]bool{}, wildTLS: map[string]bool{},
	}
	var targets []hcTarget
	var active []store.Site
	for i := range sites {
		s := sites[i]
		if !s.Enabled {
			continue
		}
		active = append(active, s)
		w, err := p.wafs.Get(&s)
		if err != nil {
			return err
		}
		pl, err := newPool(s.Upstreams, s.PreserveHost, s.UpstreamInsecure)
		if err != nil {
			return fmt.Errorf("site %q: %w", s.Name, err)
		}
		rt := &siteRuntime{site: s, waf: w, pool: pl, countries: map[string]bool{}}
		for _, c := range s.BlockCountries {
			rt.countries[c] = true
		}
		for _, pr := range s.PathRules {
			r := pathRule{prefix: pr.Path, deny: pr.Action == "deny"}
			for _, c := range pr.CIDRs {
				if pf, err := netip.ParsePrefix(c); err == nil {
					r.allow = append(r.allow, pf)
				}
			}
			rt.pathRules = append(rt.pathRules, r)
		}
		for _, h := range s.Hosts {
			if w, ok := strings.CutPrefix(h, "*."); ok {
				t.wildcard[w] = rt
				if s.HTTPS {
					t.wildTLS[w] = true
				}
			} else {
				t.exact[h] = rt
				if s.HTTPS {
					t.httpsSet[h] = true
				}
			}
		}
		if s.HealthCheck.Enabled {
			targets = append(targets, hcTarget{
				site: s.Name, path: s.HealthCheck.Path, insecure: s.UpstreamInsecure,
				interval: time.Duration(s.HealthCheck.IntervalSec) * time.Second, pool: pl,
			})
		}
	}
	p.tbl.Store(t)
	p.wafs.Retain(active)
	p.hc.restart(ctx, targets)
	slog.Info("proxy: config loaded", "version", ver, "sites", len(active), "ip_rules", len(rules))
	return nil
}

// Watch reloads whenever the config version changes (admin panel or CLI).
func (p *Proxy) Watch(ctx context.Context) {
	if err := p.Reload(ctx); err != nil {
		slog.Error("proxy: initial load failed", "err", err)
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	gc := time.NewTicker(time.Minute)
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			v, err := p.st.ConfigVersion(ctx)
			if err == nil && v != p.tbl.Load().version {
				if err := p.Reload(ctx); err != nil {
					slog.Error("proxy: reload failed, keeping previous config", "err", err)
					p.nt.Notify(notify.Message{Level: notify.Critical, Kind: "config", Key: "reload-failed",
						Title: "配置加载失败", Body: "新配置未生效，网关继续使用旧配置运行。\n错误: " + err.Error()})
				}
			}
		case <-gc.C:
			p.lims.prune(10 * time.Minute)
			p.rlHits.prune(time.Minute)
			p.atkHits.prune(5 * time.Minute)
			p.bans.prune()
		}
	}
}

// HostAllowed tells autocert which hostnames may get certificates, so random
// SNI values cannot exhaust Let's Encrypt rate limits.
func (p *Proxy) HostAllowed(_ context.Context, host string) error {
	t := p.tbl.Load()
	host = strings.ToLower(host)
	if t.httpsSet[host] {
		return nil
	}
	if i := strings.IndexByte(host, '.'); i > 0 && t.wildTLS[host[i+1:]] {
		return nil
	}
	return fmt.Errorf("host %q not configured for HTTPS", host)
}

type ctxKey struct{}

func clientIPFrom(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKey{}).(string); ok {
		return s
	}
	return ""
}

// clientAddr returns the real client address, honouring X-Forwarded-For only
// when the direct peer is a trusted proxy.
func (p *Proxy) clientAddr(r *http.Request) (netip.Addr, int) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, 0
	}
	addr, port := ap.Addr().Unmap(), int(ap.Port())
	trusted := p.cfg.Proxy.Trusted()
	if len(trusted) == 0 || !config.ContainsAddr(trusted, addr) {
		return addr, port
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !config.ContainsAddr(trusted, a) {
			return a, 0
		}
	}
	return addr, port
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := p.tbl.Load()
	host := hostOnly(r.Host)
	rt := t.lookup(host)
	if rt == nil {
		// Unknown host: do not reveal anything about what is behind the gateway.
		writeBlockPage(w, r, http.StatusNotFound, "站点不存在", "该域名未在网关中配置。")
		return
	}
	s := &rt.site
	if s.ForceHTTPS && r.TLS == nil {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
		return
	}

	addr, port := p.clientAddr(r)
	ip := addr.String()
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, ip))
	ev := func(action string, status int) *store.Event {
		return &store.Event{
			SiteID: s.ID, ClientIP: ip, Method: r.Method, Host: host,
			URI: truncate(r.URL.RequestURI(), 2048), UserAgent: truncate(r.UserAgent(), 512),
			Action: action, Status: status,
		}
	}
	block := func(e *store.Event, title, msg string) {
		p.rec.Count(s.ID, true)
		p.rec.Record(e)
		writeBlockPage(w, r, e.Status, title, msg)
	}

	// 1. IP allow/deny lists. Allow-listed addresses bypass every check.
	switch t.ips.verdict(s.ID, addr) {
	case 1:
		p.rec.Count(s.ID, false)
		rt.pool.pick().proxy.ServeHTTP(w, r)
		return
	case -1:
		e := ev(store.ActIPDenied, http.StatusForbidden)
		e.Message = "IP 在黑名单中"
		block(e, "访问被拒绝", "您的 IP 地址已被禁止访问。")
		return
	}
	if p.bans.has(addr) {
		e := ev(store.ActIPDenied, http.StatusForbidden)
		e.Message = "IP 已被自动封禁"
		block(e, "访问被拒绝", "您的 IP 地址已被临时封禁。")
		return
	}

	// 2. Country blocking.
	if len(rt.countries) > 0 {
		if c := p.rec.Geo().Country(ip); c != "" && rt.countries[c] {
			e := ev(store.ActGeoDenied, http.StatusForbidden)
			e.Country, e.Message = c, "地区封禁: "+c
			block(e, "访问被拒绝", "您所在的地区无法访问此站点。")
			return
		}
	}

	// 3. Path ACLs.
	for _, pr := range rt.pathRules {
		if !strings.HasPrefix(r.URL.Path, pr.prefix) {
			continue
		}
		if pr.deny || !config.ContainsAddr(pr.allow, addr) {
			e := ev(store.ActPathDenied, http.StatusForbidden)
			e.Message = "路径访问控制: " + pr.prefix
			block(e, "访问被拒绝", "您无权访问该路径。")
			return
		}
	}

	// 4. Rate limiting with optional auto-ban.
	if rl := s.RateLimit; rl.Enabled && !p.lims.allow(s.ID, addr, rl.RPS, rl.Burst) {
		e := ev(store.ActRateLimited, http.StatusTooManyRequests)
		e.Message = fmt.Sprintf("超过限流 %.1f 次/秒", rl.RPS)
		if rl.BanThreshold > 0 && p.rlHits.hit(s.ID, addr, time.Minute) >= rl.BanThreshold {
			p.rlHits.reset(s.ID, addr)
			p.ban(addr, s, rl.BanMinutes, fmt.Sprintf("1 分钟内触发限流 %d 次", rl.BanThreshold))
		}
		w.Header().Set("Retry-After", "1")
		block(e, "请求过于频繁", "请稍后再试。")
		return
	}

	// 5. WAF engine.
	if rt.waf != nil {
		v, done, err := engine.Inspect(rt.waf, s.Mode == store.ModeDetect, r, ip, port)
		defer done()
		if err != nil {
			slog.Error("proxy: waf error", "site", s.Name, "err", err)
			if !p.cfg.Proxy.FailOpen {
				p.rec.Count(s.ID, true)
				writeBlockPage(w, r, http.StatusServiceUnavailable, "请求无法处理", "安全检查失败，请稍后再试。")
				return
			}
		} else if v.Interrupted || v.Detected {
			action, status := store.ActBlocked, v.Status
			if !v.Interrupted {
				action, status = store.ActDetected, 0
			}
			e := ev(action, status)
			e.RuleID, e.Message, e.Category, e.Severity, e.Matches = v.RuleID, v.Message, v.Category, v.Severity, v.Matches
			if v.Interrupted {
				if ab := s.AttackBan; ab.Enabled && p.atkHits.hit(s.ID, addr, 5*time.Minute) >= ab.Threshold {
					p.atkHits.reset(s.ID, addr)
					p.ban(addr, s, ab.Minutes, fmt.Sprintf("5 分钟内触发 WAF 拦截 %d 次", ab.Threshold))
				}
				block(e, "请求已被拦截", "您的请求包含可疑内容，已被安全网关拦截。")
				return
			}
			p.rec.Record(e)
		}
	}

	p.rec.Count(s.ID, false)
	rt.pool.pick().proxy.ServeHTTP(w, r)
}

func (p *Proxy) ban(addr netip.Addr, s *store.Site, minutes int, reason string) {
	until := time.Now().Add(time.Duration(minutes) * time.Minute)
	p.bans.add(addr, until.Unix())
	rule := &store.IPRule{
		CIDR: netip.PrefixFrom(addr, addr.BitLen()).String(), Action: store.IPDeny,
		Note: s.Name + ": " + reason, Source: "auto-ban", ExpiresAt: until.Unix(), CreatedBy: "system",
	}
	go func() {
		if err := p.st.AddIPRule(context.Background(), rule); err != nil {
			slog.Error("proxy: persist ban failed", "err", err)
		}
	}()
	country := p.rec.Geo().Country(addr.String())
	if country != "" {
		country = " (" + country + ")"
	}
	p.nt.Notify(notify.Message{
		Level: notify.Warning, Kind: "ban", Key: "ban:" + addr.String(),
		Title: "IP 已自动封禁: " + addr.String(),
		Body:  fmt.Sprintf("IP: %s%s\n站点: %s\n原因: %s\n封禁时长: %d 分钟（至 %s）", addr, country, s.Name, reason, minutes, until.Format("01-02 15:04")),
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Status returns a summary for the dashboard.
type Status struct {
	Sites   int            `json:"sites"`
	Version int64          `json:"version"`
	Health  []UpstreamInfo `json:"upstreams"`
}

type UpstreamInfo struct {
	SiteID  int64  `json:"site_id"`
	Site    string `json:"site"`
	URL     string `json:"url"`
	Healthy bool   `json:"healthy"`
	Checked bool   `json:"checked"`
}

func (p *Proxy) Status() Status {
	t := p.tbl.Load()
	seen := map[int64]bool{}
	st := Status{Version: t.version, Health: []UpstreamInfo{}}
	add := func(rt *siteRuntime) {
		if seen[rt.site.ID] {
			return
		}
		seen[rt.site.ID] = true
		for _, u := range rt.pool.ups {
			st.Health = append(st.Health, UpstreamInfo{
				SiteID: rt.site.ID, Site: rt.site.Name, URL: u.url.String(),
				Healthy: u.healthy.Load(), Checked: rt.site.HealthCheck.Enabled,
			})
		}
	}
	for _, rt := range t.exact {
		add(rt)
	}
	for _, rt := range t.wildcard {
		add(rt)
	}
	st.Sites = len(seen)
	sort.Slice(st.Health, func(i, j int) bool {
		if st.Health[i].SiteID != st.Health[j].SiteID {
			return st.Health[i].SiteID < st.Health[j].SiteID
		}
		return st.Health[i].URL < st.Health[j].URL
	})
	return st
}
