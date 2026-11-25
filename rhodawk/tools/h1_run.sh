#!/bin/bash
# HackerOne 20-Day Hunt — Master Runner
# Runs all automation tools in the right order.
#
# Release audit R-08: tokens are NO LONGER embedded in this file and are
# never passed on a command line (visible in `ps`), echoed to stdout, or
# tee'd into logs. Provide them one of two ways:
#
#   1. Environment variables (recommended):
#        export RHODAWK_H1_TOKEN_A='...'   # Account A Bearer token (resource owner — main account)
#        export RHODAWK_H1_TOKEN_B='...'   # Account B Bearer token (attacker — second account)
#        ./h1_run.sh
#
#   2. A chmod 600 token file, two lines (A then B):
#        install -m 600 /dev/null ~/.rhodawk/h1_tokens   # then paste the tokens
#        RHODAWK_H1_TOKEN_FILE="$HOME/.rhodawk/h1_tokens" ./h1_run.sh
#
# Optional environment variables:
#   RHODAWK_H1_REPORT_ID      A report ID that Account A owns (sandbox program)
#   RHODAWK_H1_USER_ID        Account A's numeric user ID (auto-fetched if unset)
#   RHODAWK_H1_PROGRAM        Account A's sandbox program handle
#   RHODAWK_H1_EMAIL          Account A's email (password reset test)
#   RHODAWK_H1_ATTACHMENT_URL Signed S3 URL from a private report attachment
#
# Usage:
#   chmod +x h1_run.sh
#   ./h1_run.sh

set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Token loading (env vars, or a 0600 two-line file) ──────────────────────
TOKEN_A="${RHODAWK_H1_TOKEN_A:-}"
TOKEN_B="${RHODAWK_H1_TOKEN_B:-}"

if [[ -z "$TOKEN_A" || -z "$TOKEN_B" ]] && [[ -n "${RHODAWK_H1_TOKEN_FILE:-}" ]]; then
  if [[ ! -f "$RHODAWK_H1_TOKEN_FILE" ]]; then
    echo "ERROR: RHODAWK_H1_TOKEN_FILE points at a missing file: $RHODAWK_H1_TOKEN_FILE" >&2
    exit 1
  fi
  perms=$(stat -c '%a' "$RHODAWK_H1_TOKEN_FILE")
  if [[ "$perms" != "600" ]]; then
    echo "ERROR: $RHODAWK_H1_TOKEN_FILE must be chmod 600 (it is $perms)." >&2
    echo "  Fix:  chmod 600 \"$RHODAWK_H1_TOKEN_FILE\"" >&2
    exit 1
  fi
  TOKEN_A="$(sed -n '1p' "$RHODAWK_H1_TOKEN_FILE")"
  TOKEN_B="$(sed -n '2p' "$RHODAWK_H1_TOKEN_FILE")"
fi

if [[ -z "$TOKEN_A" || -z "$TOKEN_B" ]]; then
  echo "ERROR: Account A and B tokens are required." >&2
  echo "" >&2
  echo "Provide them via RHODAWK_H1_TOKEN_A / RHODAWK_H1_TOKEN_B, or a 0600" >&2
  echo "two-line file via RHODAWK_H1_TOKEN_FILE (see header of this script)." >&2
  echo "" >&2
  echo "To get your token:" >&2
  echo "  1. Login to hackerone.com" >&2
  echo "  2. Open DevTools -> Network -> any /graphql request" >&2
  echo "  3. Copy the 'Authorization: Bearer ...' value" >&2
  exit 1
fi

REPORT_ID="${RHODAWK_H1_REPORT_ID:-}"
USER_ID="${RHODAWK_H1_USER_ID:-}"
PROGRAM="${RHODAWK_H1_PROGRAM:-}"
EMAIL_A="${RHODAWK_H1_EMAIL:-}"
ATTACHMENT_URL="${RHODAWK_H1_ATTACHMENT_URL:-}"

# ─── Credential-safe plumbing ────────────────────────────────────────────────
# Bearer headers live in 0600 temp files passed to curl via `-H @file`, so the
# token values never appear in argv (no `ps` leakage) and are wiped on exit.
umask 077
HDR_A="$(mktemp "${TMPDIR:-/tmp}/rhodawk-h1-a.XXXXXX")"
HDR_B="$(mktemp "${TMPDIR:-/tmp}/rhodawk-h1-b.XXXXXX")"
cleanup() { rm -f -- "$HDR_A" "$HDR_B"; }
trap cleanup EXIT INT TERM
printf 'Authorization: Bearer %s\n' "$TOKEN_A" > "$HDR_A"
printf 'Authorization: Bearer %s\n' "$TOKEN_B" > "$HDR_B"

# Tokens reach the Python scanners via the environment, never via argv.
export RHODAWK_H1_TOKEN_A RHODAWK_H1_TOKEN_B

# Runtime output goes to the data home, never into the package directory.
FINDINGS_BASE="${RHODAWK_HOME:-$HOME/.rhodawk}/findings/hackerone"
mkdir -p "$FINDINGS_BASE/auto"
chmod 700 "$FINDINGS_BASE" 2>/dev/null || true
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="$FINDINGS_BASE/auto/scan_${TIMESTAMP}.log"
touch "$LOG"
chmod 600 "$LOG"

echo "═══════════════════════════════════════════════════"
echo "  HackerOne Automated Hunt"
echo "  Date: $(date)"
echo "  Log: $LOG"
echo "═══════════════════════════════════════════════════"
echo ""

# Helper to get Account A's user ID if not set
if [[ -z "$USER_ID" ]]; then
  echo "[*] Fetching Account A user ID..."
  USER_ID=$(curl -s \
    -H "@$HDR_A" \
    -H "Content-Type: application/json" \
    https://hackerone.com/graphql \
    -d '{"query":"{ me { id databaseId } }"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('me',{}).get('databaseId',''))" 2>/dev/null || true)
  echo "  Account A user ID: ${USER_ID:-(could not fetch — set RHODAWK_H1_USER_ID)}"
fi

echo ""
echo "══ PHASE 1: Authenticated GraphQL Schema Mapping ══"
echo ""
# Map all authenticated mutations (not visible unauthenticated)
curl -s \
  -H "@$HDR_A" \
  -H "Content-Type: application/json" \
  https://hackerone.com/graphql \
  -d '{"query":"{ __type(name: \"Mutation\") { fields { name args { name type { name kind } } } } }"}' \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
fields = d.get('data', {}).get('__type', {}).get('fields', [])
print(f'  Authenticated mutations found: {len(fields)}')
for f in sorted(fields, key=lambda x: x['name']):
    args = ', '.join(a['name'] for a in f.get('args', []))
    print(f\"  {f['name']}({args})\")
" 2>/dev/null | tee -a "$LOG" || echo "  (mutation mapping failed — check token validity)" | tee -a "$LOG"

echo ""
echo "  Authenticated queries:"
curl -s \
  -H "@$HDR_A" \
  -H "Content-Type: application/json" \
  https://hackerone.com/graphql \
  -d '{"query":"{ __type(name: \"Query\") { fields { name } } }"}' \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
fields = d.get('data', {}).get('__type', {}).get('fields', [])
names = sorted(f['name'] for f in fields)
print(f'  Total queries: {len(names)}')
for n in names: print(f'  - {n}')
" 2>/dev/null | tee -a "$LOG" || echo "  (query mapping failed — check token validity)" | tee -a "$LOG"

sleep 2

echo ""
echo "══ PHASE 2: Cross-User IDOR Scanner ══"
echo ""
# Tokens are exported (RHODAWK_H1_TOKEN_A/B); nothing secret on this argv.
echo "  Running: h1_idor_scanner.py ${REPORT_ID:+--report-id $REPORT_ID} ${USER_ID:+--user-id $USER_ID} ${PROGRAM:+--program $PROGRAM}"
if ! python3 "$TOOLS_DIR/h1_idor_scanner.py" \
      ${REPORT_ID:+--report-id "$REPORT_ID"} \
      ${USER_ID:+--user-id "$USER_ID"} \
      ${PROGRAM:+--program "$PROGRAM"} \
      ${ATTACHMENT_URL:+--attachment-url "$ATTACHMENT_URL"} \
      2>&1 | tee -a "$LOG"; then
  echo "  (IDOR scanner exited non-zero — partial results above)" | tee -a "$LOG"
fi

sleep 2

echo ""
echo "══ PHASE 3: Auth / OAuth Checks ══"
echo ""
if ! python3 "$TOOLS_DIR/h1_oauth_tester.py" \
      --check-cors \
      --check-oauth \
      --check-ssrf \
      2>&1 | tee -a "$LOG"; then
  echo "  (OAuth tester exited non-zero — partial results above)" | tee -a "$LOG"
fi

if [[ -n "$EMAIL_A" ]]; then
  echo ""
  echo "  [Password Reset Test] email=$EMAIL_A"
  if ! python3 "$TOOLS_DIR/h1_oauth_tester.py" \
        --check-reset \
        --email "$EMAIL_A" \
        2>&1 | tee -a "$LOG"; then
    echo "  (password reset test exited non-zero)" | tee -a "$LOG"
  fi
fi

sleep 2

echo ""
echo "══ PHASE 4: Race Condition Tests ══"
echo ""

# Negative bounty test (safe — doesn't actually award, tests validation)
if [[ -n "$REPORT_ID" ]]; then
  if ! python3 "$TOOLS_DIR/h1_race.py" \
        --test negative-bounty \
        --report-id "$REPORT_ID" \
        2>&1 | tee -a "$LOG"; then
    echo "  (race test exited non-zero)" | tee -a "$LOG"
  fi
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  SCAN COMPLETE"
echo "  Full log: $LOG"
echo "═══════════════════════════════════════════════════"
echo ""
echo "MANUAL TESTS STILL REQUIRED:"
echo "  [ ] Hai AI — test IDOR via chat (Day 17) — must be done in browser"
echo "  [ ] GitHub OAuth redirect_uri — browser + Burp (Day 9)"
echo "  [ ] SSRF webhook — sandbox program integration settings (Day 15)"
echo "  [ ] 2FA rate limit — run: RHODAWK_H1_TOKEN_A=... python3 h1_race.py --test 2fa"
echo "  [ ] PullRequest.com — manual browse + Autorize (Day 16)"
echo "  [ ] Stored XSS — submit report with payloads (Day 14)"
echo ""
echo "NEXT IF NO FINDINGS:"
echo "  Move to a different target — try live app testing on another program"
