package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/llldkkw/waf/internal/notify"
)

type upstream struct {
	url     *url.URL
	proxy   *httputil.ReverseProxy
	healthy atomic.Bool
}

type pool struct {
	ups  []*upstream
	next atomic.Uint64
}

// pick returns the next healthy upstream (round robin). If every upstream is
// marked down, it still tries one: a stale health check should not turn into
// a full outage.
func (p *pool) pick() *upstream {
	n := len(p.ups)
	start := p.next.Add(1)
	for i := 0; i < n; i++ {
		u := p.ups[(int(start)+i)%n]
		if u.healthy.Load() {
			return u
		}
	}
	return p.ups[int(start)%n]
}

func newTransport(insecure bool) *http.Transport {
	return &http.Transport{
		Proxy: nil, // never route backend traffic through an env proxy
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}, //nolint:gosec // opt-in per site
	}
}

func newPool(rawURLs []string, preserveHost, insecure bool) (*pool, error) {
	tr := newTransport(insecure)
	p := &pool{}
	for _, raw := range rawURLs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		up := &upstream{url: u}
		up.healthy.Store(true)
		target := u
		up.proxy = &httputil.ReverseProxy{
			Transport: tr,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				if preserveHost {
					pr.Out.Host = pr.In.Host
				}
				ci := clientIPFrom(pr.In.Context())
				pr.Out.Header.Set("X-Forwarded-For", ci)
				pr.Out.Header.Set("X-Real-IP", ci)
				pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
				if pr.In.TLS != nil {
					pr.Out.Header.Set("X-Forwarded-Proto", "https")
				} else {
					pr.Out.Header.Set("X-Forwarded-Proto", "http")
				}
			},
			ModifyResponse: func(r *http.Response) error {
				// Hide backend fingerprints.
				r.Header.Del("Server")
				r.Header.Del("X-Powered-By")
				r.Header.Del("X-AspNet-Version")
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				slog.Warn("proxy: upstream error", "upstream", target.Host, "err", err)
				writeBlockPage(w, r, http.StatusBadGateway, "后端服务暂时不可用", "网关无法连接到后端服务器，请稍后再试。")
			},
		}
		p.ups = append(p.ups, up)
	}
	return p, nil
}

// healthChecker probes upstreams of sites with health checks enabled.
type healthChecker struct {
	nt *notify.Notifier

	mu     sync.Mutex
	cancel context.CancelFunc
}

func newHealthChecker(nt *notify.Notifier) *healthChecker {
	return &healthChecker{nt: nt}
}

type hcTarget struct {
	site     string
	path     string
	interval time.Duration
	insecure bool
	pool     *pool
}

// restart stops previous probes and starts probing the new targets.
func (h *healthChecker) restart(parent context.Context, targets []hcTarget) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cancel != nil {
		h.cancel()
	}
	ctx, cancel := context.WithCancel(parent)
	h.cancel = cancel
	for _, t := range targets {
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: newTransport(t.insecure),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		for _, u := range t.pool.ups {
			go h.probeLoop(ctx, client, t, u)
		}
	}
}

func (h *healthChecker) probeLoop(ctx context.Context, client *http.Client, t hcTarget, u *upstream) {
	tick := time.NewTicker(t.interval)
	defer tick.Stop()
	fails := 0
	for {
		err := probe(ctx, client, u.url.String()+t.path)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			fails = 0
			if !u.healthy.Swap(true) {
				h.nt.Notify(notify.Message{
					Level: notify.Info, Kind: "upstream",
					Title: "后端恢复: " + t.site,
					Body:  fmt.Sprintf("后端 %s 已恢复正常。", u.url.Host),
				})
			}
		} else {
			fails++
			// Require consecutive failures to avoid flapping on a single blip.
			if fails == 3 && u.healthy.Swap(false) {
				h.nt.Notify(notify.Message{
					Level: notify.Critical, Kind: "upstream", Key: "upstream:" + u.url.Host,
					Title: "后端宕机: " + t.site,
					Body:  fmt.Sprintf("后端 %s 连续 3 次健康检查失败: %v", u.url.Host, err),
				})
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func probe(ctx context.Context, c *http.Client, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "waf-healthcheck/1.0")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
