// Package notify fans alerts out to push channels (Telegram, WeCom, DingTalk,
// Feishu, Bark, email, webhooks) with de-duplication and aggregation so an
// attack burst produces one message, not thousands.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/llldkkw/waf/internal/secure"
	"github.com/llldkkw/waf/internal/store"
)

type Level int

const (
	Info Level = iota
	Warning
	Critical
)

func (l Level) String() string {
	switch l {
	case Critical:
		return "critical"
	case Warning:
		return "warning"
	}
	return "info"
}

func (l Level) Label() string {
	switch l {
	case Critical:
		return "严重"
	case Warning:
		return "警告"
	}
	return "通知"
}

func (l Level) Emoji() string {
	switch l {
	case Critical:
		return "🔴"
	case Warning:
		return "🟠"
	}
	return "🔵"
}

func ParseLevel(s string) (Level, error) {
	switch s {
	case "info":
		return Info, nil
	case "warning", "":
		return Warning, nil
	case "critical":
		return Critical, nil
	}
	return Info, fmt.Errorf("invalid level %q", s)
}

// Message is one alert. Messages sharing a Key within the aggregation window
// are folded into a single follow-up summary.
type Message struct {
	Level Level
	Kind  string // attack, ban, upstream, login, config, test, report
	Key   string
	Title string
	Body  string
	// Actions are links rendered as buttons where the channel supports it
	// (one-click ban / allow, opened in the admin panel).
	Actions []Action
}

type Action struct {
	Label  string `json:"label"`
	URL    string `json:"url"`
	Danger bool   `json:"danger,omitempty"`
}

type channel struct {
	store.Channel
	level Level
	quiet [2]int // minutes of day; equal values mean no quiet hours
}

type agg struct {
	first time.Time
	count int
	last  Message
}

type Notifier struct {
	st     *store.Store
	box    *secure.Box
	window time.Duration

	mu       sync.Mutex
	channels []channel
	pending  map[string]*agg

	queue chan Message
	loc   *time.Location
}

// KindReport marks scheduled security reports.
const KindReport = "report"

// SetLocation sets the timezone used for quiet hours.
func (n *Notifier) SetLocation(loc *time.Location) { n.loc = loc }

func (n *Notifier) location() *time.Location {
	if n.loc == nil {
		return time.Local
	}
	return n.loc
}

// Send delivers a message synchronously to one channel config (used for
// tests and previews).
func (n *Notifier) Send(ctx context.Context, typ string, cfg map[string]string, m Message) error {
	return send(ctx, typ, cfg, m)
}

func New(st *store.Store, box *secure.Box) *Notifier {
	return &Notifier{
		st:      st,
		box:     box,
		window:  5 * time.Minute,
		pending: map[string]*agg{},
		queue:   make(chan Message, 256),
	}
}

// Reload re-reads channels from the database.
func (n *Notifier) Reload(ctx context.Context) error {
	list, err := n.st.ListChannels(ctx)
	if err != nil {
		return err
	}
	chs := make([]channel, 0, len(list))
	for _, c := range list {
		if !c.Enabled {
			continue
		}
		cfg, err := n.DecryptConfig(c.ConfigEnc)
		if err != nil {
			slog.Error("notify: cannot decrypt channel", "id", c.ID, "err", err)
			continue
		}
		c.Config = cfg
		lv, _ := ParseLevel(c.MinLevel)
		chs = append(chs, channel{Channel: c, level: lv, quiet: parseQuiet(cfg["quiet_hours"])})
	}
	n.mu.Lock()
	n.channels = chs
	n.mu.Unlock()
	return nil
}

func (n *Notifier) EncryptConfig(cfg map[string]string) (string, error) {
	b, _ := json.Marshal(cfg)
	return n.box.Seal(b)
}

func (n *Notifier) DecryptConfig(enc string) (map[string]string, error) {
	b, err := n.box.Open(enc)
	if err != nil {
		return nil, err
	}
	cfg := map[string]string{}
	if len(b) > 0 {
		err = json.Unmarshal(b, &cfg)
	}
	return cfg, err
}

// ValidateConfig checks required fields for a channel type.
func ValidateConfig(typ string, cfg map[string]string) error {
	ct := channelType(typ)
	if ct == nil {
		return fmt.Errorf("不支持的通知类型 %q", typ)
	}
	for _, f := range ct.Fields {
		if f.Required && strings.TrimSpace(cfg[f.Key]) == "" {
			return fmt.Errorf("%s 不能为空", f.Label)
		}
	}
	if q := cfg["quiet_hours"]; q != "" && parseQuiet(q) == [2]int{} {
		return errors.New("免打扰时段格式应为 23:00-07:00")
	}
	return nil
}

// SecretKeys lists config keys that must not be sent back to the browser.
func SecretKeys(typ string) map[string]bool {
	out := map[string]bool{}
	if ct := channelType(typ); ct != nil {
		for _, f := range ct.Fields {
			if f.Secret {
				out[f.Key] = true
			}
		}
	}
	return out
}

// Notify enqueues a message; it never blocks the caller.
func (n *Notifier) Notify(m Message) {
	select {
	case n.queue <- m:
	default:
		slog.Warn("notify: queue full, dropping", "title", m.Title)
	}
}

// Test sends a message to one channel synchronously, bypassing filters.
func (n *Notifier) Test(ctx context.Context, typ string, cfg map[string]string) error {
	return send(ctx, typ, cfg, Message{Level: Info, Kind: "test", Title: "测试通知", Body: "这是一条来自 WAF 控制台的测试消息，收到说明通知渠道配置正确。\n时间: " + time.Now().Format("2006-01-02 15:04:05")})
}

func (n *Notifier) Run(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-n.queue:
			n.handle(ctx, m)
		case now := <-tick.C:
			n.flush(ctx, now)
		}
	}
}

func (n *Notifier) handle(ctx context.Context, m Message) {
	if m.Key == "" {
		n.dispatch(ctx, m)
		return
	}
	n.mu.Lock()
	a, ok := n.pending[m.Key]
	if ok {
		a.count++
		a.last = m
		n.mu.Unlock()
		return
	}
	n.pending[m.Key] = &agg{first: time.Now(), last: m}
	n.mu.Unlock()
	n.dispatch(ctx, m)
}

func (n *Notifier) flush(ctx context.Context, now time.Time) {
	var out []Message
	n.mu.Lock()
	for k, a := range n.pending {
		if now.Sub(a.first) < n.window {
			continue
		}
		delete(n.pending, k)
		if a.count > 0 {
			m := a.last
			m.Title = m.Title + fmt.Sprintf("（%d 分钟内又发生 %d 次）", int(n.window.Minutes()), a.count)
			out = append(out, m)
		}
	}
	n.mu.Unlock()
	for _, m := range out {
		n.dispatch(ctx, m)
	}
}

func (n *Notifier) dispatch(ctx context.Context, m Message) {
	n.mu.Lock()
	chs := append([]channel(nil), n.channels...)
	n.mu.Unlock()
	now := time.Now().In(n.location())
	mod := now.Hour()*60 + now.Minute()
	for _, c := range chs {
		if m.Kind == KindReport {
			// Reports go only to channels subscribed to them, at any level.
			if c.Config["reports"] != "1" {
				continue
			}
		} else {
			if m.Level < c.level {
				continue
			}
			if m.Level < Critical && inQuiet(c.quiet, mod) {
				continue
			}
		}
		go func(c channel) {
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if err := send(cctx, c.Type, c.Config, m); err != nil {
				slog.Warn("notify: send failed", "channel", c.Name, "type", c.Type, "err", err)
			}
		}(c)
	}
}

func parseQuiet(s string) [2]int {
	var h1, m1, h2, m2 int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d:%d-%d:%d", &h1, &m1, &h2, &m2); err != nil {
		return [2]int{}
	}
	if h1 < 0 || h1 > 23 || h2 < 0 || h2 > 23 || m1 < 0 || m1 > 59 || m2 < 0 || m2 > 59 {
		return [2]int{}
	}
	return [2]int{h1*60 + m1, h2*60 + m2}
}

func inQuiet(q [2]int, mod int) bool {
	switch {
	case q[0] == q[1]:
		return false
	case q[0] < q[1]:
		return mod >= q[0] && mod < q[1]
	default: // wraps midnight
		return mod >= q[0] || mod < q[1]
	}
}
