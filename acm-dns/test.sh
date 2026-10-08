#!/usr/bin/env bash
# Contract + security + brute-force test for acm-dns.
# Usage: ./test.sh [host:port]      (default localhost:8053)
# Start the server first, e.g.:  ./acm-dns
BASE="http://${1:-localhost:8053}"
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi
}
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@"; }
body() { curl -s --max-time 5 "$@"; }

echo "== Contract =="
check "register -> 200"            200 "$(code -X POST $BASE/register -H 'Content-Type: application/json' -d '{"domain":"auth-service"}')"
check "register body"              '{"status":"ok"}' "$(body -X POST $BASE/register -d '{"domain":"auth-service"}')"
check "lookup -> 200"              200 "$(code "$BASE/lookup?domain=auth-service")"
echo "  info  lookup body: $(body "$BASE/lookup?domain=auth-service")"
check "lookup unknown -> 404"      404 "$(code "$BASE/lookup?domain=nope-$RANDOM")"
check "lookup unknown error body"  '{"error":"Domain not registered"}' "$(body "$BASE/lookup?domain=nope2")"
check "register missing -> 400"    400 "$(code -X POST $BASE/register -d '{}')"
check "register bad JSON -> 400"   400 "$(code -X POST $BASE/register -d '{bad')"
check "case-insensitive lookup"    200 "$(code "$BASE/lookup?domain=AUTH-Service")"

echo "== Input hardening =="
check "reject injection in name"   400 "$(code -X POST $BASE/register -d '{"domain":"a\";drop"}')"
check "reject path traversal"      400 "$(code "$BASE/lookup?domain=../../etc/passwd")"
check "reject 300-char name"       400 "$(code -X POST $BASE/register -d "{\"domain\":\"$(printf 'a%.0s' $(seq 300))\"}")"
check "reject oversized body"      413 "$(code -X POST $BASE/register -d "{\"domain\":\"x\",\"pad\":\"$(printf 'a%.0s' $(seq 3000))\"}")"
check "reject trailing garbage"    400 "$(code -X POST $BASE/register -d '{"domain":"ok-name"}{"x":1}')"
check "wrong method -> 405"        405 "$(code -X DELETE "$BASE/lookup?domain=auth-service")"
check "unknown route -> 404"       404 "$(code $BASE/admin)"
echo "  info  headers: $(curl -sI "$BASE/lookup?domain=auth-service" | tr -d '\r' | grep -iE 'x-content-type|cache-control' | tr '\n' ' ')"

echo "== Brute force: name enumeration (wordlist of 600 lookups) =="
sleep 1
seq 1 600 | xargs -P 20 -I{} curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 "$BASE/lookup?domain=guess-{}" | sort | uniq -c | sed 's/^/  /'
sleep 0.5
check "attacker is now blocked (429)" 429 "$(code "$BASE/lookup?domain=auth-service")"
check "server still alive (/health)"  200 "$(code $BASE/health)"
echo
echo "Result: $pass passed, $fail failed"
[ $fail -eq 0 ]
