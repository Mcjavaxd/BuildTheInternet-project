package main

import (
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// guard.go: per-client token-bucket rate limiting, enumeration/brute-force
// detection with escalating bans, and a per-IP connection cap (anti-slowloris).

const shardCount = 64

type verdict int

const (
	vOK verdict = iota
	vRate
	vBanned
)

type client struct {
	tokens            float64
	last              time.Time
	banUntil, lastBan time.Time
	level             int
	strikes           int
	strikeStart       time.Time
	faults            int
	faultStart        time.Time
	reqs, blocked     uint64
	lastSeen, lastLog time.Time
	suppressed        int
	banReason         string
}

type shard struct {
	mu sync.Mutex
	m  map[netip.Addr]*client
}

type limitCfg struct {
	rate, burst     float64
	faultLimit      int // bad lookups/requests per minute before a ban
	strikeLimit     int // rate-limit rejections per minute before a ban
	banBase, banMax time.Duration
	trusted         []netip.Prefix
	maxClients      int64
}

type limiter struct {
	shards [shardCount]shard
	cfg    limitCfg
	count  atomic.Int64
	onBan  func(key netip.Addr, d time.Duration, reason string)
}

func newLimiter(c limitCfg, onBan func(netip.Addr, time.Duration, string)) *limiter {
	l := &limiter{cfg: c, onBan: onBan}
	for i := range l.shards {
		l.shards[i].m = make(map[netip.Addr]*client)
	}
	return l
}

// limitKey groups IPv6 clients by /64 so rotating addresses cannot dodge limits.
func limitKey(a netip.Addr) netip.Addr {
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return a
}

func (l *limiter) shardFor(a netip.Addr) *shard {
	b := a.As16()
	h := uint32(2166136261)
	for _, x := range b {
		h ^= uint32(x)
		h *= 16777619
	}
	return &l.shards[h%shardCount]
}

func (l *limiter) isTrusted(a netip.Addr) bool {
	for _, p := range l.cfg.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type decision struct {
	v          verdict
	retry      time.Duration
	logIt      bool
	suppressed int
}

func (l *limiter) getLocked(sh *shard, key netip.Addr, now time.Time) *client {
	c := sh.m[key]
	if c == nil {
		if l.count.Load() >= l.cfg.maxClients {
			return nil
		}
		c = &client{tokens: l.cfg.burst, last: now, strikeStart: now, faultStart: now}
		sh.m[key] = c
		l.count.Add(1)
	}
	return c
}

// admit decides whether a request from ip may proceed.
func (l *limiter) admit(ip netip.Addr, now time.Time) decision {
	if l.isTrusted(ip) {
		return decision{}
	}
	key := limitKey(ip)
	sh := l.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := l.getLocked(sh, key, now)
	if c == nil { // client table full: fail closed
		return decision{v: vRate, retry: 5 * time.Second}
	}
	c.lastSeen = now
	c.reqs++
	if now.Before(c.banUntil) {
		return l.denied(c, vBanned, c.banUntil.Sub(now), now)
	}
	c.tokens += now.Sub(c.last).Seconds() * l.cfg.rate
	c.last = now
	if c.tokens > l.cfg.burst {
		c.tokens = l.cfg.burst
	}
	if c.tokens < 1 {
		if now.Sub(c.strikeStart) > time.Minute {
			c.strikes, c.strikeStart = 0, now
		}
		c.strikes++
		if c.strikes >= l.cfg.strikeLimit {
			l.banLocked(key, c, now, "request flood")
			return l.denied(c, vBanned, c.banUntil.Sub(now), now)
		}
		wait := time.Duration((1 - c.tokens) / l.cfg.rate * float64(time.Second))
		return l.denied(c, vRate, wait, now)
	}
	c.tokens--
	return decision{}
}

func (l *limiter) denied(c *client, v verdict, retry time.Duration, now time.Time) decision {
	c.blocked++
	d := decision{v: v, retry: retry}
	if now.Sub(c.lastLog) >= time.Second { // log at most 1 block event / second / client
		d.logIt, d.suppressed = true, c.suppressed
		c.lastLog, c.suppressed = now, 0
	} else {
		c.suppressed++
	}
	return d
}

// fault records a suspicious request (unknown name, malformed input, hijack attempt).
// Too many inside a minute earns a ban with exponential back-off.
func (l *limiter) fault(ip netip.Addr, now time.Time, weight int, reason string) {
	if l.isTrusted(ip) {
		return
	}
	key := limitKey(ip)
	sh := l.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.m[key]
	if c == nil {
		return
	}
	if now.Sub(c.faultStart) > time.Minute {
		c.faults, c.faultStart = 0, now
	}
	c.faults += weight
	if c.faults > l.cfg.faultLimit && !now.Before(c.banUntil) {
		l.banLocked(key, c, now, reason)
	}
}

func (l *limiter) banLocked(key netip.Addr, c *client, now time.Time, reason string) {
	if now.Sub(c.lastBan) > 10*time.Minute {
		c.level = 0
	}
	d := l.cfg.banBase << uint(c.level)
	if d <= 0 || d > l.cfg.banMax {
		d = l.cfg.banMax
	}
	if c.level < 20 {
		c.level++
	}
	c.lastBan, c.banUntil, c.banReason = now, now.Add(d), reason
	c.faults, c.strikes, c.tokens = 0, 0, 0
	if l.onBan != nil {
		l.onBan(key, d, reason)
	}
}

func (l *limiter) unban(ip netip.Addr) bool {
	key := limitKey(ip)
	sh := l.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.m[key]
	if c == nil || !time.Now().Before(c.banUntil) {
		return false
	}
	c.banUntil, c.level, c.faults, c.strikes = time.Time{}, 0, 0, 0
	c.tokens = l.cfg.burst
	return true
}

type banView struct {
	IP     string `json:"ip"`
	Until  int64  `json:"until"`
	Reason string `json:"reason"`
	Level  int    `json:"level"`
}

type clientView struct {
	IP       string `json:"ip"`
	Reqs     uint64 `json:"reqs"`
	Blocked  uint64 `json:"blocked"`
	LastSeen int64  `json:"last"`
}

func (l *limiter) views(now time.Time, top int) ([]banView, []clientView) {
	bans := []banView{}
	cs := []clientView{}
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, c := range sh.m {
			if now.Before(c.banUntil) {
				bans = append(bans, banView{k.String(), c.banUntil.UnixMilli(), c.banReason, c.level})
			}
			cs = append(cs, clientView{k.String(), c.reqs, c.blocked, c.lastSeen.UnixMilli()})
		}
		sh.mu.Unlock()
	}
	sort.Slice(bans, func(i, j int) bool { return bans[i].Until > bans[j].Until })
	sort.Slice(cs, func(i, j int) bool { return cs[i].Reqs > cs[j].Reqs })
	if len(cs) > top {
		cs = cs[:top]
	}
	return bans, cs
}

func (l *limiter) prune(now time.Time) {
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, c := range sh.m {
			if !now.Before(c.banUntil) && now.Sub(c.lastSeen) > 10*time.Minute {
				delete(sh.m, k)
				l.count.Add(-1)
			}
		}
		sh.mu.Unlock()
	}
}

// ---- per-IP connection cap: blunts slowloris / socket exhaustion ----

type connGuard struct {
	mu      sync.Mutex
	m       map[netip.Addr]int
	max     int
	trusted []netip.Prefix
}

func connIP(c net.Conn) netip.Addr {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (g *connGuard) hook(c net.Conn, st http.ConnState) {
	switch st {
	case http.StateNew:
		ip := connIP(c)
		for _, p := range g.trusted {
			if p.Contains(ip) {
				return
			}
		}
		g.mu.Lock()
		g.m[ip]++
		over := g.m[ip] > g.max
		g.mu.Unlock()
		if over {
			c.Close()
		}
	case http.StateClosed, http.StateHijacked:
		ip := connIP(c)
		g.mu.Lock()
		if g.m[ip] > 0 {
			g.m[ip]--
			if g.m[ip] == 0 {
				delete(g.m, ip)
			}
		}
		g.mu.Unlock()
	}
}
