package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web/*
var webFS embed.FS

type dashboard struct {
	s        *server
	tokenSum [32]byte
	lim      *limiter // protects the dashboard and its login from brute force
	secure   bool
	mu       sync.Mutex
	sessions map[string]time.Time
	sse      atomic.Int32
	static   map[string]asset
	listen   string
}

type asset struct {
	body []byte
	ct   string
}

const sessionTTL = 8 * time.Hour

func newDashboard(s *server, token, addr string, conns *connGuard) *http.Server {
	d := &dashboard{s: s, tokenSum: sha256.Sum256([]byte(token)), secure: s.cfg.tlsCert != "",
		sessions: map[string]time.Time{}, listen: addr, static: map[string]asset{}}
	// Login/API abuse: 5 bad logins a minute earns a ban that doubles every time.
	d.lim = newLimiter(limitCfg{rate: 40, burst: 80, faultLimit: 5, strikeLimit: 30,
		banBase: 30 * time.Second, banMax: time.Hour, maxClients: 10000},
		func(k netip.Addr, dur time.Duration, reason string) {
			s.hub.push(Event{Kind: "ban", IP: k.String(), Result: "banned-ip", Note: "dashboard " + reason + ": banned for " + dur.Round(time.Second).String()}, true)
		})
	for path, f := range map[string]string{"/": "web/index.html", "/app.js": "web/app.js", "/app.css": "web/app.css"} {
		b, err := fs.ReadFile(webFS, f)
		if err != nil {
			panic(err)
		}
		ct := "text/html; charset=utf-8"
		if path == "/app.js" {
			ct = "text/javascript; charset=utf-8"
		} else if path == "/app.css" {
			ct = "text/css; charset=utf-8"
		}
		d.static[path] = asset{b, ct}
	}
	go func() { // purge expired sessions and idle limiter entries
		for range time.Tick(time.Minute) {
			now := time.Now()
			d.mu.Lock()
			for k, exp := range d.sessions {
				if now.After(exp) {
					delete(d.sessions, k)
				}
			}
			d.mu.Unlock()
			d.lim.prune(now)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", d.serveStatic)
	mux.HandleFunc("/api/login", d.login)
	mux.HandleFunc("/api/logout", d.auth(true, d.logout))
	mux.HandleFunc("/api/state", d.auth(false, d.state))
	mux.HandleFunc("/api/stream", d.auth(false, d.stream))
	mux.HandleFunc("/api/release", d.auth(true, d.release))
	mux.HandleFunc("/api/unban", d.auth(true, d.unban))
	return &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.serve(mux, w, r) }),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second, // no WriteTimeout: SSE uses per-write deadlines
		MaxHeaderBytes:    8 << 10,
		ConnState:         conns.hook,
	}
}

func (d *dashboard) serve(mux *http.ServeMux, w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	if dec := d.lim.admit(remoteIP(r), time.Now()); dec.v != vOK {
		h.Set("Retry-After", strconv.Itoa(int(dec.retry.Seconds())+1))
		jsonErr(w, 429, "Too many attempts - try again later")
		return
	}
	mux.ServeHTTP(w, r)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"error": msg})
	w.Write(b)
}

func (d *dashboard) serveStatic(w http.ResponseWriter, r *http.Request) {
	a, ok := d.static[r.URL.Path]
	if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", a.ct)
	w.Write(a.body)
}

// ----- auth: token -> random 256-bit session cookie (HttpOnly, SameSite=Strict) -----

func (d *dashboard) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("X-Requested-With") != "acm" {
		jsonErr(w, 403, "Forbidden")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&req); err != nil {
		jsonErr(w, 400, "Bad request")
		return
	}
	sum := sha256.Sum256([]byte(req.Token)) // fixed-length digests + constant-time compare
	ip := remoteIP(r)
	if subtle.ConstantTimeCompare(sum[:], d.tokenSum[:]) != 1 {
		d.lim.fault(ip, time.Now(), 1, "token guessing")
		time.Sleep(300 * time.Millisecond) // slow online guessing further
		jsonErr(w, 401, "Wrong token")
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		jsonErr(w, 500, "Server error")
		return
	}
	id := hex.EncodeToString(b)
	d.mu.Lock()
	d.sessions[id] = time.Now().Add(sessionTTL)
	d.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "dsid", Value: id, Path: "/", HttpOnly: true, Secure: d.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(okBody))
}

func (d *dashboard) valid(r *http.Request) (string, bool) {
	c, err := r.Cookie("dsid")
	if err != nil {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.sessions[c.Value]
	if ok && time.Now().After(exp) {
		delete(d.sessions, c.Value)
		ok = false
	}
	return c.Value, ok
}

// auth wraps a handler with session check; state-changing routes also need the
// custom header (cannot be sent cross-site without a CORS preflight, which we never grant).
func (d *dashboard) auth(mutating bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := d.valid(r); !ok {
			d.lim.fault(remoteIP(r), time.Now(), 1, "unauthenticated access")
			jsonErr(w, 401, "Sign in required")
			return
		}
		if mutating && (r.Method != http.MethodPost || r.Header.Get("X-Requested-With") != "acm") {
			jsonErr(w, 403, "Forbidden")
			return
		}
		next(w, r)
	}
}

func (d *dashboard) logout(w http.ResponseWriter, r *http.Request) {
	if id, ok := d.valid(r); ok {
		d.mu.Lock()
		delete(d.sessions, id)
		d.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "dsid", Path: "/", MaxAge: -1, HttpOnly: true, Secure: d.secure, SameSite: http.SameSiteStrictMode})
	w.Write([]byte(okBody))
}

// ----- data -----

func (d *dashboard) state(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	stats, series := d.s.hub.snapshot(now)
	events, last := d.s.hub.since(0, 120)
	bans, clients := d.s.lim.views(now, 8)
	c := d.s.cfg
	out := map[string]any{
		"now": now.UnixMilli(), "stats": stats, "series": series, "events": events, "lastId": last,
		"records": d.s.reg.snapshot(), "bans": bans, "clients": clients,
		"rv": d.s.reg.ver.Load(), "bv": d.s.hub.bv.Load(),
		"config": map[string]any{
			"listen": c.listen, "rate": c.rate, "burst": c.burst, "faultLimit": c.faultLimit,
			"ban": c.banBase.String(), "banMax": c.banMax.String(), "maxRecords": c.maxRecords,
			"maxPerIP": c.maxPerIP, "maxConns": c.maxConns, "firstWriterWins": !c.allowOverwrite,
			"tls": c.tlsCert != "", "ttl": c.ttl.String(),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (d *dashboard) stream(w http.ResponseWriter, r *http.Request) {
	if d.sse.Add(1) > 10 {
		d.sse.Add(-1)
		jsonErr(w, 429, "Too many live connections")
		return
	}
	defer d.sse.Add(-1)
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		now := time.Now()
		if _, ok := d.valid(r); !ok {
			return
		}
		evs, last := d.s.hub.since(after, 200)
		after = last
		stats, series := d.s.hub.snapshot(now)
		payload, _ := json.Marshal(map[string]any{"events": evs, "stats": stats, "series": series, "lastId": last,
			"rv": d.s.reg.ver.Load(), "bv": d.s.hub.bv.Load(), "records": d.s.reg.count()})
		rc.SetWriteDeadline(now.Add(5 * time.Second))
		if _, err := w.Write(append(append([]byte("data: "), payload...), '\n', '\n')); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
		}
	}
}

func (d *dashboard) release(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&req) != nil {
		jsonErr(w, 400, "Bad request")
		return
	}
	n, ok := normalizeDomain(req.Domain)
	if !ok || !d.s.reg.release(n) {
		jsonErr(w, 404, "Not registered")
		return
	}
	d.s.hub.push(Event{Kind: "admin", IP: remoteIP(r).String(), Result: "released", Domain: n, Note: "released by admin"}, true)
	w.Write([]byte(okBody))
}

func (d *dashboard) unban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&req) != nil {
		jsonErr(w, 400, "Bad request")
		return
	}
	a, err := netip.ParseAddr(req.IP)
	if err != nil || !d.s.lim.unban(a.Unmap()) {
		jsonErr(w, 404, "Not banned")
		return
	}
	d.s.hub.bv.Add(1)
	d.s.hub.push(Event{Kind: "admin", IP: a.String(), Result: "unbanned", Note: "unbanned by admin"}, true)
	w.Write([]byte(okBody))
}
