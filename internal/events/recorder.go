// Package events records security events and traffic counters, persists them,
// streams them to the dashboard and raises notifications.
package events

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/store"
)

type Recorder struct {
	st  *store.Store
	hub *Hub
	nt  *notify.Notifier
	geo *Geo

	in chan *store.Event

	mu      sync.Mutex
	minute  map[int64][2]int64 // site -> {requests, blocked}
	secReq  atomic.Int64
	secBlk  atomic.Int64
	dropped atomic.Int64

	baseline float64 // EWMA of blocked requests per minute
}

func NewRecorder(st *store.Store, hub *Hub, nt *notify.Notifier, geo *Geo) *Recorder {
	return &Recorder{st: st, hub: hub, nt: nt, geo: geo, in: make(chan *store.Event, 4096), minute: map[int64][2]int64{}}
}

func (r *Recorder) Geo() *Geo { return r.geo }

// Count tracks one proxied request.
func (r *Recorder) Count(siteID int64, blocked bool) {
	r.secReq.Add(1)
	var b int64
	if blocked {
		r.secBlk.Add(1)
		b = 1
	}
	r.mu.Lock()
	c := r.minute[siteID]
	c[0]++
	c[1] += b
	r.minute[siteID] = c
	r.mu.Unlock()
}

// Record queues a security event. It never blocks the request path.
func (r *Recorder) Record(e *store.Event) {
	if e.TS == 0 {
		e.TS = time.Now().Unix()
	}
	select {
	case r.in <- e:
	default:
		r.dropped.Add(1)
	}
}

func (r *Recorder) Run(ctx context.Context) {
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	var (
		batch   []*store.Event
		lastMin = time.Now().Unix() / 60
	)
	save := func() {
		if len(batch) == 0 {
			return
		}
		for _, e := range batch {
			if e.Country == "" {
				e.Country = r.geo.Country(e.ClientIP)
			}
		}
		if err := r.st.InsertEvents(ctx, batch); err != nil {
			slog.Error("events: insert failed", "err", err, "n", len(batch))
		}
		for _, e := range batch {
			r.hub.Publish("event", e)
			r.alert(e)
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			save()
			r.flushMinute(context.Background(), lastMin*60)
			return
		case e := <-r.in:
			batch = append(batch, e)
			if len(batch) >= 200 {
				save()
			}
		case now := <-flush.C:
			save()
			r.hub.Publish("tick", map[string]int64{
				"ts": now.Unix(), "requests": r.secReq.Swap(0), "blocked": r.secBlk.Swap(0),
			})
			if m := now.Unix() / 60; m != lastMin {
				r.flushMinute(ctx, lastMin*60)
				lastMin = m
			}
			if d := r.dropped.Swap(0); d > 0 {
				slog.Warn("events: queue full, dropped events", "n", d)
			}
		}
	}
}

func (r *Recorder) flushMinute(ctx context.Context, ts int64) {
	r.mu.Lock()
	m := r.minute
	r.minute = map[int64][2]int64{}
	r.mu.Unlock()
	if len(m) == 0 {
		r.baseline *= 0.9
		return
	}
	if err := r.st.AddStats(ctx, ts, m); err != nil {
		slog.Error("events: stats failed", "err", err)
	}
	var blocked float64
	for _, c := range m {
		blocked += float64(c[1])
	}
	// Spike: well above the recent baseline and above a floor that ignores
	// background scanner noise.
	if blocked >= 100 && blocked > 5*r.baseline {
		r.nt.Notify(notify.Message{
			Level: notify.Warning, Kind: "spike", Key: "spike",
			Title: "攻击量突增",
			Body:  fmt.Sprintf("过去 1 分钟拦截 %d 次请求，平时约 %.0f 次/分钟。", int(blocked), r.baseline),
		})
	}
	r.baseline = 0.8*r.baseline + 0.2*blocked
}

var highRisk = map[string]bool{"rce": true, "java": true, "php": true, "rfi": true}

func (r *Recorder) alert(e *store.Event) {
	if e.Action != store.ActBlocked && e.Action != store.ActDetected {
		return
	}
	lv := notify.Info
	switch {
	case highRisk[e.Category]:
		lv = notify.Critical
	case e.Severity == "critical":
		lv = notify.Warning
	}
	where := ""
	if e.Country != "" {
		where = " (" + e.Country + ")"
	}
	verb := "已拦截"
	if e.Action == store.ActDetected {
		verb = "检测到（观察模式，未拦截）"
	}
	r.nt.Notify(notify.Message{
		Level: lv, Kind: "attack", Key: "attack:" + e.ClientIP,
		Title: fmt.Sprintf("%s %s 攻击", verb, categoryLabel(e.Category)),
		Body: fmt.Sprintf("来源: %s%s\n站点: %s\n请求: %s %s\n规则: %d %s",
			e.ClientIP, where, e.Host, e.Method, truncate(e.URI, 200), e.RuleID, e.Message),
	})
}

func categoryLabel(c string) string {
	if l, ok := map[string]string{
		"sqli": "SQL 注入", "xss": "XSS", "rce": "命令执行", "lfi": "本地文件包含", "rfi": "远程文件包含",
		"php": "PHP 注入", "java": "Java 攻击", "protocol": "协议违规", "scanner": "扫描器",
		"generic": "通用攻击", "injection": "注入", "fixation": "会话固定", "multipart-header": "畸形上传",
	}[c]; ok {
		return l
	}
	if c == "" {
		return "可疑"
	}
	return c
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
