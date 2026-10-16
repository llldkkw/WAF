// Package report builds and schedules daily / weekly security reports.
package report

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/events"
	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/store"
)

const settingsKey = "report_settings"

type Settings struct {
	Daily      bool   `json:"daily"`
	DailyTime  string `json:"daily_time"` // "09:00"
	Weekly     bool   `json:"weekly"`
	WeeklyDay  int    `json:"weekly_day"` // 1 = Monday ... 7 = Sunday
	WeeklyTime string `json:"weekly_time"`
}

func DefaultSettings() Settings {
	return Settings{Daily: true, DailyTime: "09:00", Weekly: true, WeeklyDay: 1, WeeklyTime: "09:00"}
}

func (s *Settings) Validate() error {
	for _, t := range []string{s.DailyTime, s.WeeklyTime} {
		if _, err := time.Parse("15:04", t); err != nil {
			return fmt.Errorf("时间格式应为 HH:MM: %q", t)
		}
	}
	if s.WeeklyDay < 1 || s.WeeklyDay > 7 {
		return fmt.Errorf("周报日期无效")
	}
	return nil
}

type Reporter struct {
	st  *store.Store
	nt  *notify.Notifier
	geo *events.Geo
	loc *time.Location
}

func New(st *store.Store, nt *notify.Notifier, geo *events.Geo, loc *time.Location) *Reporter {
	return &Reporter{st: st, nt: nt, geo: geo, loc: loc}
}

func (r *Reporter) Settings(ctx context.Context) (Settings, error) {
	s := DefaultSettings()
	err := r.st.GetJSON(ctx, settingsKey, &s)
	return s, err
}

func (r *Reporter) SaveSettings(ctx context.Context, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	return r.st.SetJSON(ctx, settingsKey, s)
}

// Run checks once a minute whether a report is due. The last sent period is
// stored, so restarts neither skip nor duplicate reports.
func (r *Reporter) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := r.tick(ctx, now.In(r.loc)); err != nil && ctx.Err() == nil {
				slog.Error("report: failed", "err", err)
			}
		}
	}
}

func atTime(day time.Time, hhmm string) time.Time {
	t, _ := time.Parse("15:04", hhmm)
	return time.Date(day.Year(), day.Month(), day.Day(), t.Hour(), t.Minute(), 0, 0, day.Location())
}

func midnight(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func (r *Reporter) tick(ctx context.Context, now time.Time) error {
	s, err := r.Settings(ctx)
	if err != nil {
		return err
	}
	today := midnight(now)
	if s.Daily && !now.Before(atTime(now, s.DailyTime)) {
		if err := r.once(ctx, "report_last_daily", today.Format("2006-01-02"), func() error {
			return r.Send(ctx, today.AddDate(0, 0, -1), today, "每日安全报告")
		}); err != nil {
			return err
		}
	}
	wd := int(now.Weekday())
	if wd == 0 {
		wd = 7
	}
	if s.Weekly && wd == s.WeeklyDay && !now.Before(atTime(now, s.WeeklyTime)) {
		return r.once(ctx, "report_last_weekly", today.Format("2006-01-02"), func() error {
			return r.Send(ctx, today.AddDate(0, 0, -7), today, "每周安全报告")
		})
	}
	return nil
}

func (r *Reporter) once(ctx context.Context, key, period string, fn func() error) error {
	var last string
	if err := r.st.GetJSON(ctx, key, &last); err != nil {
		return err
	}
	if last == period {
		return nil
	}
	if err := r.st.SetJSON(ctx, key, period); err != nil {
		return err
	}
	return fn()
}

// Send builds the report for [from, to) and queues it to subscribed channels.
func (r *Reporter) Send(ctx context.Context, from, to time.Time, title string) error {
	m, err := r.Build(ctx, from, to, title)
	if err != nil {
		return err
	}
	r.nt.Notify(*m)
	return nil
}

// Build renders the report, comparing against the preceding period.
func (r *Reporter) Build(ctx context.Context, from, to time.Time, title string) (*notify.Message, error) {
	span := to.Sub(from)
	cur, err := r.st.OverviewRange(ctx, from.Unix(), to.Unix(), 3600, 0)
	if err != nil {
		return nil, err
	}
	prev, err := r.st.OverviewRange(ctx, from.Add(-span).Unix(), from.Unix(), 3600, 0)
	if err != nil {
		return nil, err
	}
	bans, err := r.st.CountAutoBans(ctx, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	layout, end := "2006-01-02 15:04", to
	if from.Equal(midnight(from)) && to.Equal(midnight(to)) {
		layout, end = "2006-01-02", to.Add(-time.Second) // whole days: show inclusive end date
	}
	fmt.Fprintf(&b, "统计区间: %s ~ %s\n\n", from.Format(layout), end.Format(layout))
	fmt.Fprintf(&b, "总请求: %s%s\n", num(cur.Requests), delta(cur.Requests, prev.Requests))
	fmt.Fprintf(&b, "已拦截: %s（拦截率 %s）%s\n", num(cur.Blocked), pct(cur.Blocked, cur.Requests), delta(cur.Blocked, prev.Blocked))
	fmt.Fprintf(&b, "攻击来源 IP: %s%s\n", num(cur.Attackers), delta(cur.Attackers, prev.Attackers))
	fmt.Fprintf(&b, "新增自动封禁: %d\n", bans)

	if len(cur.Categories) > 0 {
		b.WriteString("\n主要攻击类型:\n")
		for _, c := range top(cur.Categories, 5) {
			fmt.Fprintf(&b, "  · %s  %s 次\n", category(c.Key), num(c.Count))
		}
	}
	if len(cur.TopIPs) > 0 {
		b.WriteString("\nTop 攻击 IP:\n")
		for _, c := range top(cur.TopIPs, 5) {
			loc := r.geo.Lookup(c.Key).String()
			if loc != "" {
				loc = " (" + loc + ")"
			}
			fmt.Fprintf(&b, "  · %s%s  %s 次\n", c.Key, loc, num(c.Count))
		}
	}
	if len(cur.Countries) > 0 {
		b.WriteString("\n攻击来源地区:\n")
		for _, c := range top(cur.Countries, 5) {
			fmt.Fprintf(&b, "  · %s  %s 次\n", c.Key, num(c.Count))
		}
	}
	if len(cur.TopURIs) > 0 {
		b.WriteString("\nTop 被攻击路径:\n")
		for _, c := range top(cur.TopURIs, 5) {
			fmt.Fprintf(&b, "  · %s  %s 次\n", c.Key, num(c.Count))
		}
	}
	if cur.Blocked == 0 && cur.Attackers == 0 {
		b.WriteString("\n本期没有拦截记录，一切正常。\n")
	}
	return &notify.Message{Level: notify.Info, Kind: notify.KindReport, Title: title, Body: strings.TrimRight(b.String(), "\n")}, nil
}

func top(cs []store.Count, n int) []store.Count {
	if len(cs) > n {
		return cs[:n]
	}
	return cs
}

func num(n int64) string {
	s := fmt.Sprint(n)
	var out []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return string(out)
}

func pct(a, b int64) string {
	if b == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", float64(a)*100/float64(b))
}

func delta(cur, prev int64) string {
	if prev == 0 {
		if cur == 0 {
			return ""
		}
		return "（上期无数据）"
	}
	d := float64(cur-prev) * 100 / float64(prev)
	arrow := "↑"
	if d < 0 {
		arrow = "↓"
		d = -d
	}
	return fmt.Sprintf("（较上期 %s%.0f%%）", arrow, d)
}

var categories = map[string]string{
	"sqli": "SQL 注入", "xss": "XSS", "rce": "命令执行", "lfi": "本地文件包含", "rfi": "远程文件包含",
	"php": "PHP 注入", "java": "Java 攻击", "protocol": "协议违规", "scanner": "扫描器",
	"generic": "通用攻击", "injection": "注入", "fixation": "会话固定", "multipart-header": "畸形上传",
}

func category(c string) string {
	if l, ok := categories[c]; ok {
		return l
	}
	return c
}
