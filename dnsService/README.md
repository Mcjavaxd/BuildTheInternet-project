# acm-dns — hardened service discovery for "Build the Internet"

Implements the `acm-dns` OpenAPI 3.0 contract **unchanged** (`GET /lookup`, `POST /register`) in Go
(standard library only, one static binary, no dependencies) and adds a live monitoring dashboard.

## Run (on your Linux VM)

```bash
chmod +x dist/acm-dns-linux-amd64     # use ...-arm64 on an ARM VM
./dist/acm-dns-linux-amd64            # API on :8053, dashboard on localhost:9090
```

The terminal prints a dashboard link like `http://localhost:9090/#t=<token>`. Open it in the VM's browser.
The token travels in the URL fragment, which browsers never send to the server.

To let teammates' machines reach the API, nothing changes: it listens on all interfaces. Teammates give their
services the DNS address at startup (never hard-coded), e.g. `DNS_ADDR=<this-vm>:8053`.

Build from source (Go 1.21+; Debian's apt Go may be older, so prefer the binaries or go.dev/dl):
`go build -o acm-dns .`

## Options (flag or env var)

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `-listen` | `DNS_LISTEN` | `:8053` | API address |
| `-dash` | `DNS_DASH` | `localhost:9090` | dashboard address (`off` disables; use `:9090` to open it to the LAN) |
| `-token` | `DNS_DASH_TOKEN` | random | dashboard token |
| `-trust` | `DNS_TRUST` | none | IPs/CIDRs exempt from limits (your team's VMs) |
| `-allow-overwrite` | `DNS_ALLOW_OVERWRITE=1` | off | let another host take over a name |
| `-rate` / `-burst` | | 50 / 100 | per-client requests/second |
| `-fault-limit` | | 200 | bad requests per minute before a ban |
| `-ban` / `-ban-max` | | 30s / 1h | ban length, doubling on repeat |
| `-max-records`, `-max-per-ip` | | 1000, 32 | registry caps |
| `-ttl` | | 0 (never) | expire names not re-registered in time |
| `-persist` | | off | save registry to a file (0600) across restarts |
| `-tls-cert` / `-tls-key` | | off | HTTPS for API and dashboard |
| `-cors-origin` | | none | allow one browser origin to call the API |

## Security features

1. **Brute-force / enumeration defence**: every client has a token bucket (429 + `Retry-After`). Unknown-name
   lookups, malformed requests and hijack attempts add to a per-minute fault score; crossing the limit bans the
   client for 30 s, doubling on each repeat up to 1 h. A request flood also earns a ban.
2. **Name-hijack protection**: first writer wins. A different host registering an existing name gets `409` and a
   heavy fault score. The owner re-registering is idempotent. Admins can release a name from the dashboard.
3. **Source IP is the TCP peer address**, never `X-Forwarded-For`, so it cannot be spoofed in headers.
   IPv6 clients are rate-limited per /64.
4. **Strict input validation**: RFC-style names only (`a-z 0-9 _ -`, labels <= 63, total <= 253), 1 KB body cap,
   JSON must be a single object (trailing data rejected), URL query capped. Responses for validated values are built
   from safe character sets, so no injection is possible.
5. **Resource limits**: per-host name quota, global registry cap, fixed-size event buffer, per-IP connection cap,
   header/read/write/idle timeouts (slowloris), 8 KB headers.
6. **Hardened dashboard**: separate port, bound to localhost by default, 256-bit random session cookie
   (`HttpOnly`, `SameSite=Strict`, `Secure` under TLS), constant-time token check on SHA-256 digests, login lockout with
   escalating bans, custom-header CSRF check on every state-changing call, strict CSP (no inline script, no external
   resources), clickjacking and sniffing headers, all dynamic text inserted with `textContent` (no XSS).
7. Security headers on every API response, no CORS unless configured, graceful shutdown, optional TLS.

Extra HTTP codes beyond the contract (`405`, `409`, `413`, `429`, `503`) are additions, which the rules allow.
The contract's own responses are untouched.

## Dashboard

Totals, a 60-second stacked traffic chart (resolved / registered / not found / malformed / blocked), a live
request feed, the registry (with Release buttons), blocked clients (with Unban), busiest clients, and the active
defences. The terminal also prints a colour-coded access log.

## Test it

```bash
./test.sh              # contract checks, input hardening, then a 600-request enumeration attack
```

Stronger demo for the judges (run from another machine, or after restarting the server):
`seq 1 5000 | xargs -P 50 -I{} curl -s -o /dev/null "http://<dns>:8053/lookup?domain=x{}"`
and watch the Blocked counter, chart and Blocked clients panel on the dashboard while the server stays up.

## How other services should use it (no hard-coded IPs)

```python
import os, requests, time
DNS = os.environ["DNS_ADDR"]                       # e.g. 10.0.0.5:8053 given at start-up
while True:                                        # fallback registration loop
    try:
        if requests.post(f"http://{DNS}/register", json={"domain": "acm-db"}, timeout=2).ok: break
    except requests.RequestException: pass
    time.sleep(1)
db = requests.get(f"http://{DNS}/lookup", params={"domain": "acm-db"}, timeout=2).json()["destination"]
```

Keep retry loops at about 1 request/second or slower; a poll loop that fast stays far below the limits.
