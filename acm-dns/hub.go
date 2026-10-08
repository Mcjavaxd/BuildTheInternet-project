package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// hub.go: in-memory event ring buffer, counters and a 60 s time series that feed
// the dashboard. Fixed size, so a request flood can never exhaust memory.

const (
	ringSize  = 2048
	seriesLen = 60
)

type Event struct {
	ID     uint64 `json:"id"`
	T      int64  `json:"t"`
	Kind   string `json:"kind"` // lookup | register | block | ban | admin
	Method string `json:"m,omitempty"`
	Path   string `json:"p,omitempty"`
	Domain string `json:"d,omitempty"`
	IP     string `json:"ip"`
	Status int    `json:"s,omitempty"`
	Result string `json:"r"`
	Dest   string `json:"dest,omitempty"`
	US     int64  `json:"us,omitempty"`
	Note   string `json:"n,omitempty"`
}

type bucket struct {
	ts                           int64
	hit, miss, reg, blocked, bad uint32
}

type point struct {
	T       int64  `json:"t"`
	Hit     uint32 `json:"hit"`
	Miss    uint32 `json:"miss"`
	Reg     uint32 `json:"reg"`
	Blocked uint32 `json:"blocked"`
	Bad     uint32 `json:"bad"`
}

type statsView struct {
	Total      uint64  `json:"total"`
	Resolved   uint64  `json:"resolved"`
	NotFound   uint64  `json:"notFound"`
	Registered uint64  `json:"registered"`
	Blocked    uint64  `json:"blocked"`
	Invalid    uint64  `json:"invalid"`
	AvgUS      float64 `json:"avgUs"`
	Uptime     int64   `json:"uptime"`
}

type hub struct {
	mu      sync.Mutex
	ring    [ringSize]Event
	last    uint64
	buckets [seriesLen]bucket
	c       statsView
	latSum  uint64
	latN    uint64
	start   time.Time
	logCh   chan Event
	bv      atomic.Uint64 // bumps whenever the ban list changes
	color   bool
}

func newHub(color bool) *hub {
	h := &hub{start: time.Now(), logCh: make(chan Event, 2048), color: color}
	go h.printer()
	return h
}

func category(result string) string {
	switch result {
	case "resolved":
		return "hit"
	case "not-found":
		return "miss"
	case "registered", "refreshed", "overwritten":
		return "reg"
	case "bad-request":
		return "bad"
	case "conflict", "limit", "full", "rate-limited", "banned":
		return "blocked"
	}
	return ""
}

// push records an event. store=false only updates counters (used to keep the
// feed readable while a flood is being rejected).
func (h *hub) push(e Event, store bool) {
	now := time.Now()
	e.T = now.UnixMilli()
	cat := category(e.Result)
	h.mu.Lock()
	if cat != "" {
		sec := now.Unix()
		b := &h.buckets[sec%seriesLen]
		if b.ts != sec {
			*b = bucket{ts: sec}
		}
		h.c.Total++
		switch cat {
		case "hit":
			b.hit++
			h.c.Resolved++
		case "miss":
			b.miss++
			h.c.NotFound++
		case "reg":
			b.reg++
			h.c.Registered++
		case "bad":
			b.bad++
			h.c.Invalid++
		case "blocked":
			b.blocked++
			h.c.Blocked++
		}
		if e.US > 0 && cat != "blocked" {
			h.latSum += uint64(e.US)
			h.latN++
		}
	}
	if store {
		h.last++
		e.ID = h.last
		h.ring[e.ID%ringSize] = e
	}
	h.mu.Unlock()
	if store {
		select {
		case h.logCh <- e:
		default: // terminal too slow: drop the log line, never block a request
		}
	}
}

func (h *hub) since(after uint64, max int) ([]Event, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	last := h.last
	if after > last {
		after = last
	}
	if last > ringSize && after < last-ringSize {
		after = last - ringSize
	}
	if int(last-after) > max {
		after = last - uint64(max)
	}
	out := make([]Event, 0, last-after)
	for id := after + 1; id <= last; id++ {
		out = append(out, h.ring[id%ringSize])
	}
	return out, last
}

func (h *hub) snapshot(now time.Time) (statsView, []point) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.c
	if h.latN > 0 {
		s.AvgUS = float64(h.latSum) / float64(h.latN)
	}
	s.Uptime = int64(now.Sub(h.start).Seconds())
	pts := make([]point, seriesLen)
	sec := now.Unix()
	for i := 0; i < seriesLen; i++ {
		t := sec - int64(seriesLen-1-i)
		b := h.buckets[t%seriesLen]
		pts[i] = point{T: t}
		if b.ts == t {
			pts[i] = point{t, b.hit, b.miss, b.reg, b.blocked, b.bad}
		}
	}
	return s, pts
}

// printer writes a colourised access log to the terminal (handy on a projector).
func (h *hub) printer() {
	for e := range h.logCh {
		col, reset := "", ""
		if h.color {
			reset = "\x1b[0m"
			switch category(e.Result) {
			case "hit":
				col = "\x1b[36m"
			case "reg":
				col = "\x1b[32m"
			case "miss", "bad":
				col = "\x1b[33m"
			case "blocked":
				col = "\x1b[31m"
			default:
				col = "\x1b[35m"
			}
		}
		what := e.Domain
		if e.Dest != "" {
			what += " -> " + e.Dest
		}
		if e.Note != "" {
			what = strings.TrimSpace(what + "  (" + e.Note + ")")
		}
		fmt.Fprintf(os.Stdout, "%s%s  %-8s %-15s %-12s %-s%s\n", col,
			time.UnixMilli(e.T).Format("15:04:05"), strings.ToUpper(e.Kind), e.IP, e.Result, what, reset)
	}
}
