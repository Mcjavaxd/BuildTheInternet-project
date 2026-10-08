// acm-dns: hardened service-discovery / DNS service for "Build the Internet".
// Implements the acm-dns OpenAPI 3.0 contract exactly (GET /lookup, POST /register)
// and adds a live, authenticated monitoring dashboard on a separate port.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	listen, dash, token, tlsCert, tlsKey, persist, cors string
	rate, burst                                         float64
	faultLimit, maxRecords, maxPerIP, maxConns          int
	banBase, banMax, ttl                                time.Duration
	allowOverwrite                                      bool
	allow                                               []netip.Prefix
}

type server struct {
	cfg *config
	reg *registry
	lim *limiter
	hub *hub
}

const (
	strikeLimit = 50 // rate-limit rejections / minute before a ban
	maxBody     = 1024
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envF(k string, d float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(k), 64); err == nil {
		return v
	}
	return d
}
func envI(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return d
}
func envD(k string, d time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return d
}

func parseAllow(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func loadConfig() *config {
	c := &config{}
	var allow string
	flag.StringVar(&c.listen, "listen", env("DNS_LISTEN", ":8053"), "DNS API listen address (env DNS_LISTEN)")
	flag.StringVar(&c.dash, "dash", env("DNS_DASH", "localhost:9090"), "dashboard listen address, or 'off' (env DNS_DASH)")
	flag.StringVar(&c.token, "token", env("DNS_DASH_TOKEN", ""), "dashboard access token; random if empty (env DNS_DASH_TOKEN)")
	flag.StringVar(&c.tlsCert, "tls-cert", env("DNS_TLS_CERT", ""), "TLS certificate (enables HTTPS on both listeners)")
	flag.StringVar(&c.tlsKey, "tls-key", env("DNS_TLS_KEY", ""), "TLS private key")
	flag.StringVar(&c.persist, "persist", env("DNS_PERSIST", ""), "file to persist the registry across restarts")
	flag.StringVar(&c.cors, "cors-origin", env("DNS_CORS", ""), "allowed CORS origin for browser clients (default: none)")
	flag.StringVar(&allow, "trust", env("DNS_TRUST", ""), "comma-separated IPs/CIDRs exempt from limits (e.g. your team's VMs)")
	flag.Float64Var(&c.rate, "rate", envF("DNS_RATE", 50), "sustained requests/second per client")
	flag.Float64Var(&c.burst, "burst", envF("DNS_BURST", 100), "burst allowance per client")
	flag.IntVar(&c.faultLimit, "fault-limit", envI("DNS_FAULT_LIMIT", 200), "bad lookups/requests per minute before a ban")
	flag.DurationVar(&c.banBase, "ban", envD("DNS_BAN", 30*time.Second), "first ban duration (doubles on repeat)")
	flag.DurationVar(&c.banMax, "ban-max", envD("DNS_BAN_MAX", time.Hour), "maximum ban duration")
	flag.IntVar(&c.maxRecords, "max-records", envI("DNS_MAX_RECORDS", 1000), "maximum registry size")
	flag.IntVar(&c.maxPerIP, "max-per-ip", envI("DNS_MAX_PER_IP", 32), "maximum domains one host may own")
	flag.IntVar(&c.maxConns, "max-conns-per-ip", envI("DNS_MAX_CONNS", 256), "maximum open connections per client")
	flag.DurationVar(&c.ttl, "ttl", envD("DNS_TTL", 0), "expire records not refreshed within this time (0 = never)")
	flag.BoolVar(&c.allowOverwrite, "allow-overwrite", env("DNS_ALLOW_OVERWRITE", "") == "1",
		"let a different host take over a registered name (default: first writer wins)")
	flag.Parse()
	var err error
	if c.allow, err = parseAllow(allow); err != nil {
		log.Fatalf("invalid -trust list: %v", err)
	}
	return c
}

func main() {
	log.SetFlags(0)
	cfg := loadConfig()
	color := false
	if st, err := os.Stdout.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		color = true
	}
	s := &server{cfg: cfg, hub: newHub(color)}
	s.reg = newRegistry(cfg.maxRecords, cfg.maxPerIP, !cfg.allowOverwrite, cfg.ttl)
	s.lim = newLimiter(limitCfg{rate: cfg.rate, burst: cfg.burst, faultLimit: cfg.faultLimit, strikeLimit: strikeLimit,
		banBase: cfg.banBase, banMax: cfg.banMax, trusted: cfg.allow, maxClients: 200000},
		func(k netip.Addr, d time.Duration, reason string) {
			s.hub.bv.Add(1)
			s.hub.push(Event{Kind: "ban", IP: k.String(), Result: "banned-ip", Note: fmt.Sprintf("%s: banned for %s", reason, d.Round(time.Second))}, true)
		})

	if cfg.persist != "" {
		n, err := s.reg.load(cfg.persist)
		if err != nil {
			log.Fatalf("cannot load %s: %v", cfg.persist, err)
		}
		if n > 0 {
			log.Printf("restored %d records from %s", n, cfg.persist)
		}
	}

	conns := &connGuard{m: map[netip.Addr]int{}, max: cfg.maxConns, trusted: cfg.allow}
	api := &http.Server{
		Addr:              cfg.listen,
		Handler:           http.HandlerFunc(s.serveAPI),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ConnState:         conns.hook,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	var dashSrv *http.Server
	token := cfg.token
	if cfg.dash != "off" {
		if token == "" {
			b := make([]byte, 12)
			if _, err := rand.Read(b); err != nil {
				log.Fatal(err)
			}
			token = hex.EncodeToString(b)
		}
		dashSrv = newDashboard(s, token, cfg.dash, conns)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go s.janitor(ctx)
	printBanner(cfg, token)

	errc := make(chan error, 2)
	serve := func(srv *http.Server) {
		var err error
		if cfg.tlsCert != "" {
			err = srv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
		} else {
			err = srv.ListenAndServe()
		}
		errc <- err
	}
	go serve(api)
	if dashSrv != nil {
		go serve(dashSrv)
	}

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	case <-ctx.Done():
	}
	log.Println("shutting down...")
	sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api.Shutdown(sh)
	if dashSrv != nil {
		dashSrv.Shutdown(sh)
	}
	if cfg.persist != "" {
		s.reg.save(cfg.persist)
	}
}

func (s *server) janitor(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if s.cfg.persist != "" && s.reg.dirty.Swap(false) {
				if err := s.reg.save(s.cfg.persist); err != nil {
					log.Printf("persist failed: %v", err)
				}
			}
			if n++; n%15 == 0 { // every 30 s
				s.reg.expire(now)
				s.lim.prune(now)
			}
		}
	}
}

func printBanner(c *config, token string) {
	scheme := "http"
	if c.tlsCert != "" {
		scheme = "https"
	}
	fmt.Println(`
   __ _  ___ _ __ ___         __| |_ __  ___
  / _` + "`" + ` |/ __| '_ ` + "`" + ` _ \ _____ / _` + "`" + ` | '_ \/ __|
 | (_| | (__| | | | | |_____| (_| | | | \__ \
  \__,_|\___|_| |_| |_|      \__,_|_| |_|___/   service discovery`)
	fmt.Printf("\n  API        %s on %s\n", scheme, c.listen)
	if c.dash != "off" {
		fmt.Printf("  Dashboard  %s://%s/#t=%s\n  Token      %s\n", scheme, c.dash, token, token)
	}
	pol := "first writer wins (409 on takeover)"
	if c.allowOverwrite {
		pol = "overwrite allowed (flagged on dashboard)"
	}
	fmt.Printf("  Limits     %.0f req/s, burst %.0f, ban %s..%s, %d conns/IP\n", c.rate, c.burst, c.banBase, c.banMax, c.maxConns)
	fmt.Printf("  Policy     %s\n\n", pol)
}

// ---------------------------------------------------------------- API ----

func remoteIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap() // never trust X-Forwarded-For: it is client-controlled
}

const (
	errMissing  = `{"error":"Missing required 'domain' field"}`
	errBadJSON  = `{"error":"Invalid JSON body"}`
	errBadName  = `{"error":"Invalid domain name"}`
	errNotFound = `{"error":"Domain not registered"}`
	errTooMany  = `{"error":"Too many requests - temporarily blocked"}`
	errConflict = `{"error":"Domain already registered by another host"}`
	errQuota    = `{"error":"Registration quota exceeded for this host"}`
	errFull     = `{"error":"Registry full"}`
	errMethod   = `{"error":"Method not allowed"}`
	errNoRoute  = `{"error":"Not found"}`
	errTooBig   = `{"error":"Request body too large"}`
	okBody      = `{"status":"ok"}`
)

func reply(w http.ResponseWriter, code int, body string) {
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func (s *server) serveAPI(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	if s.cfg.cors != "" {
		h.Set("Access-Control-Allow-Origin", s.cfg.cors)
		h.Set("Vary", "Origin")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST")
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if r.URL.Path == "/health" {
		reply(w, 200, okBody)
		return
	}
	ip := remoteIP(r)
	if d := s.lim.admit(ip, start); d.v != vOK {
		secs := int(d.retry.Seconds()) + 1
		h.Set("Retry-After", strconv.Itoa(secs))
		reply(w, http.StatusTooManyRequests, errTooMany)
		res, note := "rate-limited", ""
		if d.v == vBanned {
			res = "banned"
		}
		if d.suppressed > 0 {
			note = fmt.Sprintf("+%d more rejected", d.suppressed)
		}
		s.hub.push(Event{Kind: "block", Method: r.Method, Path: trunc(r.URL.Path, 32), IP: ip.String(),
			Status: 429, Result: res, Note: note}, d.logIt)
		return
	}
	switch r.URL.Path {
	case "/lookup":
		s.lookup(w, r, ip, start)
	case "/register":
		s.register(w, r, ip, start)
	default:
		reply(w, 404, errNoRoute)
	}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *server) evt(kind, res string, status int, domain string, ip netip.Addr, start time.Time, dest, note string, m string) {
	s.hub.push(Event{Kind: kind, Method: m, Domain: domain, IP: ip.String(), Status: status,
		Result: res, Dest: dest, Note: note, US: time.Since(start).Microseconds()}, true)
}

func (s *server) lookup(w http.ResponseWriter, r *http.Request, ip netip.Addr, start time.Time) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		reply(w, 405, errMethod)
		return
	}
	raw := r.URL.Query().Get("domain")
	if len(r.URL.RawQuery) > 512 || raw == "" {
		reply(w, 400, errMissing)
		s.lim.fault(ip, start, 2, "malformed requests")
		s.evt("lookup", "bad-request", 400, "", ip, start, "", "missing domain", "GET")
		return
	}
	d, ok := normalizeDomain(raw)
	if !ok {
		reply(w, 400, errBadName)
		s.lim.fault(ip, start, 2, "malformed requests")
		s.evt("lookup", "bad-request", 400, "", ip, start, "", "invalid domain name", "GET")
		return
	}
	dest, found := s.reg.lookup(d, start)
	if !found {
		reply(w, 404, errNotFound)
		s.lim.fault(ip, start, 1, "name enumeration / brute force")
		s.evt("lookup", "not-found", 404, d, ip, start, "", "", "GET")
		return
	}
	// d and dest are validated character sets, so manual JSON assembly is safe and fast.
	reply(w, 200, `{"domain":"`+d+`","destination":"`+dest+`"}`)
	s.evt("lookup", "resolved", 200, d, ip, start, dest, "", "GET")
}

func (s *server) register(w http.ResponseWriter, r *http.Request, ip netip.Addr, start time.Time) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		reply(w, 405, errMethod)
		return
	}
	bad := func(body, note string) {
		reply(w, 400, body)
		s.lim.fault(ip, start, 2, "malformed requests")
		s.evt("register", "bad-request", 400, "", ip, start, "", note, "POST")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	var req struct {
		Domain *string `json:"domain"`
	}
	if err := dec.Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			reply(w, 413, errTooBig)
			s.lim.fault(ip, start, 3, "malformed requests")
			s.evt("register", "bad-request", 413, "", ip, start, "", "body too large", "POST")
			return
		}
		bad(errBadJSON, "invalid JSON")
		return
	}
	if _, err := dec.Token(); err != io.EOF { // reject trailing garbage / request smuggling attempts
		bad(errBadJSON, "trailing data")
		return
	}
	if req.Domain == nil || *req.Domain == "" {
		bad(errMissing, "missing domain")
		return
	}
	d, ok := normalizeDomain(*req.Domain)
	if !ok {
		bad(errBadName, "invalid domain name")
		return
	}
	res, prev := s.reg.register(d, ip, start)
	me := ip.String()
	switch res {
	case regCreated:
		reply(w, 200, okBody)
		s.evt("register", "registered", 200, d, ip, start, me, "", "POST")
	case regRefreshed:
		reply(w, 200, okBody)
		s.evt("register", "refreshed", 200, d, ip, start, me, "", "POST")
	case regOverwritten:
		reply(w, 200, okBody)
		s.evt("register", "overwritten", 200, d, ip, start, me, "was "+prev, "POST")
	case regConflict:
		reply(w, 409, errConflict)
		s.lim.fault(ip, start, 20, "registration hijack attempts")
		s.evt("register", "conflict", 409, d, ip, start, "", "owned by "+prev, "POST")
	case regPerIPLimit:
		reply(w, 429, errQuota)
		s.lim.fault(ip, start, 10, "registration flooding")
		s.evt("register", "limit", 429, d, ip, start, "", "per-host quota", "POST")
	default:
		reply(w, 503, errFull)
		s.evt("register", "full", 503, d, ip, start, "", "registry full", "POST")
	}
}
