package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type regResult int

const (
	regCreated regResult = iota
	regRefreshed
	regOverwritten
	regConflict
	regPerIPLimit
	regFull
)

type record struct {
	IP      string
	Owner   netip.Addr
	Created time.Time
	Updated time.Time
	Updates uint64
}

// registry is the DNS table: domain -> IP of the host that registered it.
type registry struct {
	mu       sync.RWMutex
	m        map[string]*record
	perIP    map[netip.Addr]int
	max      int
	maxPerIP int
	strict   bool // first-writer-wins: another host cannot take over a live name
	ttl      time.Duration
	ver      atomic.Uint64
	dirty    atomic.Bool
}

func newRegistry(max, maxPerIP int, strict bool, ttl time.Duration) *registry {
	return &registry{m: make(map[string]*record, 64), perIP: map[netip.Addr]int{},
		max: max, maxPerIP: maxPerIP, strict: strict, ttl: ttl}
}

func (g *registry) lookup(d string, now time.Time) (string, bool) {
	g.mu.RLock()
	r, ok := g.m[d]
	if !ok {
		g.mu.RUnlock()
		return "", false
	}
	ip, up := r.IP, r.Updated
	g.mu.RUnlock()
	if g.ttl > 0 && now.Sub(up) > g.ttl {
		return "", false
	}
	return ip, true
}

func (g *registry) register(d string, owner netip.Addr, now time.Time) (regResult, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r, ok := g.m[d]; ok {
		if r.Owner == owner {
			r.Updated = now
			r.Updates++
			return regRefreshed, ""
		}
		expired := g.ttl > 0 && now.Sub(r.Updated) > g.ttl
		if g.strict && !expired {
			return regConflict, r.IP
		}
		if g.perIP[owner] >= g.maxPerIP {
			return regPerIPLimit, ""
		}
		prev := r.IP
		g.dec(r.Owner)
		r.IP, r.Owner, r.Updated = owner.String(), owner, now
		r.Updates++
		g.perIP[owner]++
		g.bump()
		return regOverwritten, prev
	}
	if len(g.m) >= g.max {
		return regFull, ""
	}
	if g.perIP[owner] >= g.maxPerIP {
		return regPerIPLimit, ""
	}
	g.m[d] = &record{IP: owner.String(), Owner: owner, Created: now, Updated: now, Updates: 1}
	g.perIP[owner]++
	g.bump()
	return regCreated, ""
}

func (g *registry) release(d string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.m[d]
	if !ok {
		return false
	}
	g.dec(r.Owner)
	delete(g.m, d)
	g.bump()
	return true
}

func (g *registry) dec(a netip.Addr) {
	if g.perIP[a] <= 1 {
		delete(g.perIP, a)
	} else {
		g.perIP[a]--
	}
}

func (g *registry) bump() { g.ver.Add(1); g.dirty.Store(true) }

func (g *registry) count() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.m)
}

// expire removes stale records when a TTL is configured.
func (g *registry) expire(now time.Time) {
	if g.ttl <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for d, r := range g.m {
		if now.Sub(r.Updated) > g.ttl {
			g.dec(r.Owner)
			delete(g.m, d)
			g.bump()
		}
	}
}

type recordView struct {
	Domain  string `json:"domain"`
	IP      string `json:"ip"`
	Created int64  `json:"created"`
	Updated int64  `json:"updated"`
	Updates uint64 `json:"updates"`
}

func (g *registry) snapshot() []recordView {
	g.mu.RLock()
	out := make([]recordView, 0, len(g.m))
	for d, r := range g.m {
		out = append(out, recordView{d, r.IP, r.Created.UnixMilli(), r.Updated.UnixMilli(), r.Updates})
	}
	g.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// ---- optional crash-safe persistence (atomic write, 0600) ----

type persisted struct {
	Domain  string    `json:"domain"`
	IP      string    `json:"ip"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

func (g *registry) save(path string) error {
	g.mu.RLock()
	out := make([]persisted, 0, len(g.m))
	for d, r := range g.m {
		out = append(out, persisted{d, r.IP, r.Created, r.Updated})
	}
	g.mu.RUnlock()
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (g *registry) load(path string) (int, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var in []persisted
	if err := json.Unmarshal(b, &in); err != nil {
		return 0, err
	}
	n := 0
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range in {
		d, ok := normalizeDomain(p.Domain)
		a, err := netip.ParseAddr(p.IP)
		if !ok || err != nil || len(g.m) >= g.max {
			continue
		}
		a = a.Unmap()
		g.m[d] = &record{IP: a.String(), Owner: a, Created: p.Created, Updated: p.Updated, Updates: 1}
		g.perIP[a]++
		n++
	}
	g.ver.Add(1)
	return n, nil
}

// normalizeDomain lower-cases and validates a name: labels of [a-z0-9_-],
// 1..63 chars, no leading/trailing hyphen, total <= 253. One trailing dot allowed.
func normalizeDomain(s string) (string, bool) {
	if n := len(s); n > 0 && s[n-1] == '.' {
		s = s[:n-1]
	}
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	out := []byte(s)
	label := 0
	for i, ch := range out {
		switch {
		case ch >= 'A' && ch <= 'Z':
			out[i] = ch + 32
			label++
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '_':
			label++
		case ch == '-':
			if label == 0 {
				return "", false
			}
			label++
		case ch == '.':
			if label == 0 || out[i-1] == '-' {
				return "", false
			}
			label = 0
		default:
			return "", false
		}
		if label > 63 {
			return "", false
		}
	}
	if label == 0 || out[len(out)-1] == '-' {
		return "", false
	}
	return string(out), true
}
