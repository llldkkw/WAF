package proxy

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type limiterKey struct {
	site int64
	ip   netip.Addr
}

type limiterEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// limiters keeps one token bucket per (site, client IP).
type limiters struct {
	mu sync.Mutex
	m  map[limiterKey]*limiterEntry
}

func newLimiters() *limiters { return &limiters{m: map[limiterKey]*limiterEntry{}} }

func (l *limiters) allow(site int64, ip netip.Addr, rps float64, burst int) bool {
	k := limiterKey{site, ip}
	now := time.Now()
	l.mu.Lock()
	e, ok := l.m[k]
	if !ok || e.lim.Limit() != rate.Limit(rps) || e.lim.Burst() != burst {
		e = &limiterEntry{lim: rate.NewLimiter(rate.Limit(rps), burst)}
		l.m[k] = e
	}
	e.lastSeen = now
	l.mu.Unlock()
	return e.lim.AllowN(now, 1)
}

func (l *limiters) prune(idle time.Duration) {
	cut := time.Now().Add(-idle)
	l.mu.Lock()
	for k, e := range l.m {
		if e.lastSeen.Before(cut) {
			delete(l.m, k)
		}
	}
	l.mu.Unlock()
}

// strikes counts offences per (site, IP) in a sliding window, used to decide
// automatic bans.
type strikes struct {
	mu sync.Mutex
	m  map[limiterKey][]int64
}

func newStrikes() *strikes { return &strikes{m: map[limiterKey][]int64{}} }

// hit records an offence and returns how many fall within the window.
func (s *strikes) hit(site int64, ip netip.Addr, window time.Duration) int {
	k := limiterKey{site, ip}
	now := time.Now().Unix()
	cut := now - int64(window.Seconds())
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.m[k]
	i := 0
	for i < len(ts) && ts[i] < cut {
		i++
	}
	ts = append(ts[i:], now)
	s.m[k] = ts
	return len(ts)
}

// count returns offences within the window without recording one.
func (s *strikes) count(site int64, ip netip.Addr, window time.Duration) int {
	cut := time.Now().Add(-window).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.m[limiterKey{site, ip}] {
		if t >= cut {
			n++
		}
	}
	return n
}

func (s *strikes) reset(site int64, ip netip.Addr) {
	s.mu.Lock()
	delete(s.m, limiterKey{site, ip})
	s.mu.Unlock()
}

func (s *strikes) prune(window time.Duration) {
	cut := time.Now().Add(-window).Unix()
	s.mu.Lock()
	for k, ts := range s.m {
		if len(ts) == 0 || ts[len(ts)-1] < cut {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}
