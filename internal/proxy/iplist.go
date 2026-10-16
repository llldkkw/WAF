package proxy

import (
	"net/netip"
	"sync"
	"time"

	"github.com/llldkkw/waf/internal/store"
)

type ipEntry struct {
	prefix  netip.Prefix
	expires int64
}

// ipList is an immutable snapshot of allow/deny rules, keyed by site (0 = global).
type ipList struct {
	allow map[int64][]ipEntry
	deny  map[int64][]ipEntry
}

func buildIPList(rules []store.IPRule) *ipList {
	l := &ipList{allow: map[int64][]ipEntry{}, deny: map[int64][]ipEntry{}}
	for _, r := range rules {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			continue
		}
		e := ipEntry{prefix: p, expires: r.ExpiresAt}
		if r.Action == store.IPAllow {
			l.allow[r.SiteID] = append(l.allow[r.SiteID], e)
		} else {
			l.deny[r.SiteID] = append(l.deny[r.SiteID], e)
		}
	}
	return l
}

func match(es []ipEntry, a netip.Addr, now int64) bool {
	for _, e := range es {
		if (e.expires == 0 || e.expires > now) && e.prefix.Contains(a) {
			return true
		}
	}
	return false
}

// verdict returns +1 for allow-listed (skips all checks), -1 for denied, 0 otherwise.
// Allow beats deny so an operator can never lock out an allow-listed address.
func (l *ipList) verdict(siteID int64, a netip.Addr) int {
	now := time.Now().Unix()
	if match(l.allow[0], a, now) || match(l.allow[siteID], a, now) {
		return 1
	}
	if match(l.deny[0], a, now) || match(l.deny[siteID], a, now) {
		return -1
	}
	return 0
}

// banList holds bans made by this process so they apply immediately, before
// the next config reload picks them up from the database.
type banList struct {
	mu   sync.RWMutex
	bans map[netip.Addr]int64
}

func newBanList() *banList { return &banList{bans: map[netip.Addr]int64{}} }

func (b *banList) add(a netip.Addr, until int64) {
	b.mu.Lock()
	b.bans[a] = until
	b.mu.Unlock()
}

func (b *banList) has(a netip.Addr) bool {
	b.mu.RLock()
	until, ok := b.bans[a]
	b.mu.RUnlock()
	return ok && until > time.Now().Unix()
}

func (b *banList) prune() {
	now := time.Now().Unix()
	b.mu.Lock()
	for a, until := range b.bans {
		if until <= now {
			delete(b.bans, a)
		}
	}
	b.mu.Unlock()
}
