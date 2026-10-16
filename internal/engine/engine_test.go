package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/llldkkw/waf/internal/store"
)

func site(mode string) *store.Site {
	s := &store.Site{Name: "t", Hosts: []string{"example.com"}, Upstreams: []string{"http://127.0.0.1:1"}, Mode: mode}
	if err := s.Normalize(); err != nil {
		panic(err)
	}
	return s
}

func TestInspect(t *testing.T) {
	c := NewCache(1 << 20)
	w, err := c.Get(site(store.ModeBlock))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		method   string
		target   string
		body     string
		blocked  bool
		category string
	}{
		{"normal", "GET", "/products?id=42&sort=price", "", false, ""},
		{"sqli", "GET", "/products?id=1'%20OR%20'1'='1'%20--", "", true, "sqli"},
		{"xss", "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "", true, "xss"},
		{"lfi", "GET", "/download?file=../../../../etc/passwd", "", true, "lfi"},
		{"rce-body", "POST", "/run", "cmd=;cat%20/etc/passwd", true, ""},
		{"normal-body", "POST", "/login", "username=alice&password=hunter2", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://example.com"+tc.target, strings.NewReader(tc.body))
			r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
			r.Header.Set("Accept", "text/html")
			if tc.body != "" {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			v, done, err := Inspect(w, false, r, "203.0.113.9", 5555)
			defer done()
			if err != nil {
				t.Fatal(err)
			}
			if v.Interrupted != tc.blocked {
				t.Fatalf("blocked=%v want %v (rule %d %s)", v.Interrupted, tc.blocked, v.RuleID, v.Message)
			}
			if tc.category != "" && v.Category != tc.category {
				t.Errorf("category=%q want %q", v.Category, tc.category)
			}
			if !tc.blocked && tc.body != "" {
				got, _ := io.ReadAll(r.Body)
				if string(got) != tc.body {
					t.Errorf("body not preserved: %q", got)
				}
			}
		})
	}
}

func TestDetectOnly(t *testing.T) {
	c := NewCache(1 << 20)
	w, err := c.Get(site(store.ModeDetect))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://example.com/?id=1'%20OR%20'1'='1'%20--", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	v, done, err := Inspect(w, true, r, "203.0.113.9", 5555)
	defer done()
	if err != nil {
		t.Fatal(err)
	}
	if v.Interrupted || !v.Detected {
		t.Fatalf("want detected without interruption, got %+v", v)
	}
}

func TestExclusion(t *testing.T) {
	s := site(store.ModeBlock)
	c := NewCache(1 << 20)
	r := func() *http.Request {
		return newReq("GET", "http://example.com/api/q?id=1'%20OR%20'1'='1'%20--")
	}
	w, _ := c.Get(s)
	v, done, _ := Inspect(w, false, r(), "203.0.113.9", 1)
	done()
	if !v.Interrupted {
		t.Fatal("expected block before exclusion")
	}
	// Exclude every matched attack rule under /api/ and expect a pass.
	for _, m := range v.Matches {
		if !isScoringRule(m.RuleID) {
			s.RuleExclusions = append(s.RuleExclusions, store.RuleExclusion{RuleID: m.RuleID, Path: "/api/"})
		}
	}
	w2, err := c.Get(s)
	if err != nil {
		t.Fatal(err)
	}
	v2, done2, _ := Inspect(w2, false, r(), "203.0.113.9", 1)
	done2()
	if v2.Interrupted {
		t.Fatalf("still blocked after exclusion: %d %s", v2.RuleID, v2.Message)
	}
	v3, done3, _ := Inspect(w2, false, newReq("GET", "http://example.com/other?id=1'%20OR%20'1'='1'%20--"), "203.0.113.9", 1)
	done3()
	if !v3.Interrupted {
		t.Fatal("exclusion leaked outside its path")
	}
}

func newReq(method, url string) *http.Request {
	r := httptest.NewRequest(method, url, nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	return r
}
