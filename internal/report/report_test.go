package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/secure"
	"github.com/llldkkw/waf/internal/store"
)

func TestReport(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secure.LoadOrCreateKey(filepath.Join(dir, "k"))
	ctx := context.Background()
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(loc)
	today := midnight(now)
	y := today.Add(-12 * time.Hour).Unix()

	_ = st.AddStats(ctx, y, map[int64][2]int64{1: {1000, 120}})
	_ = st.AddStats(ctx, today.Add(-36*time.Hour).Unix(), map[int64][2]int64{1: {500, 60}})
	_ = st.InsertEvents(ctx, []*store.Event{
		{TS: y, SiteID: 1, ClientIP: "203.0.113.9", Method: "GET", Host: "a", URI: "/login?x=1", Action: store.ActBlocked, Category: "sqli"},
		{TS: y, SiteID: 1, ClientIP: "203.0.113.9", Method: "GET", Host: "a", URI: "/login", Action: store.ActBlocked, Category: "xss"},
	})

	r := New(st, notify.New(st, box), nil, loc)
	m, err := r.Build(ctx, today.AddDate(0, 0, -1), today, "每日安全报告")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"总请求: 1,000（较上期 ↑100%）", "已拦截: 120（拦截率 12.0%）", "SQL 注入", "203.0.113.9", "/login  2 次"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("report missing %q:\n%s", want, m.Body)
		}
	}
	if m.Kind != notify.KindReport {
		t.Error("report kind not set")
	}

	// Scheduling: due once per period, never twice.
	s := DefaultSettings()
	s.DailyTime = "00:00"
	s.Weekly = false
	if err := r.SaveSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := r.tick(ctx, now); err != nil {
		t.Fatal(err)
	}
	var last string
	_ = st.GetJSON(ctx, "report_last_daily", &last)
	if last != today.Format("2006-01-02") {
		t.Fatalf("daily report not marked as sent: %q", last)
	}
	if bad := (Settings{DailyTime: "9am", WeeklyTime: "09:00", WeeklyDay: 1}); bad.Validate() == nil {
		t.Error("invalid time accepted")
	}
}
