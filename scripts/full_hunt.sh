#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# full_hunt.sh — Complete Bug Bounty Hunt Pipeline
# Author: RhodawkAI (RhodawkAI)
# Usage: bash full_hunt.sh target.com [OPTIONS]
#
# This runs:
#   Phase 1: Passive Recon (subdomains, URLs, tech)
#   Phase 2: Content Discovery (dirs, params, JS analysis)
#   Phase 3: Vulnerability Scanning (nuclei, XSS, CORS)
#
# Options:
#   --quick       Skip slow scans (default: full)
#   --recon-only  Only run Phase 1
#   --scan-only   Only run Phase 3 (needs existing recon)
#   --token JWT   Include Bearer token in scans
#   --cookie STR  Include Cookie header in scans
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# ── Config ────────────────────────────────────────────────────────────────────
TARGET="${1}"
TARGETURL="https://${TARGET}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# Audit R-01: session tree goes to the data home, never CWD-relative
# ./recon (a hunt from the repo root used to pollute the source tree).
OUT="${RHODAWK_HOME:-$HOME/.rhodawk}/recon/${TARGET}_${TIMESTAMP}"
# Commit 3 path fix: the shared tooling (_auth_helper.sh, banner.sh,
# scope_checker.py) lives under <repo>/rhodawk/tools/ — the legacy
# "$(dirname $0)/.." pointed at the repo ROOT, where no tools/ directory
# exists, so every `source` below silently failed under `set -e`.
TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)/rhodawk"

# Auth (optional)
TOKEN=""
COOKIE=""
QUICK=false
RECON_ONLY=false
SCAN_ONLY=false

# Commit 3: mandatory scope pre-flight. The legacy pipeline used to launch
# subfinder/crt.sh/amass against ANY target with zero scope validation —
# full_hunt.sh now refuses unscoped runs (exit 3) unless --no-scope-check is
# explicitly passed for local demo testing.
SCOPE_DOMAIN_ARGS=()
SCOPE_EXCLUDE_ARGS=()
SCOPE_MANIFEST=""
NO_SCOPE_CHECK=false

# Wordlists (adjust paths to match your install)
WL_DIRS="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
WL_FILES="/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt"
WL_API="/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
WL_SUBS="/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
WL_PARAMS="/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt"

# Fallback wordlists if primary missing
[ ! -f "$WL_DIRS" ]   && WL_DIRS="/usr/share/wordlists/dirb/common.txt"
[ ! -f "$WL_DIRS" ]   && WL_DIRS="/usr/share/dirb/wordlists/common.txt"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; RESET='\033[0m'; BOLD='\033[1m'

# ── Helper Functions ──────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)] $*${RESET}"; }
ok()   { echo -e "${GREEN}[✓] $*${RESET}"; }
warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
err()  { echo -e "${RED}[✗] $*${RESET}"; }
sep()  { echo -e "${BLUE}════════════════════════════════════════${RESET}"; }

check_tool() {
    command -v "$1" &>/dev/null && echo true || echo false
}

# macOS compatibility: GNU timeout may not exist; use gtimeout or passthrough
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        timeout() { gtimeout "$@"; }
        export -f timeout
    else
        timeout() { shift; "$@"; }
        export -f timeout
    fi
fi

# ── Parse Args ────────────────────────────────────────────────────────────────
shift  # Remove TARGET from args
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --quick)       QUICK=true ;;
        --recon-only)  RECON_ONLY=true ;;
        --scan-only)   SCAN_ONLY=true ;;
        --token)       TOKEN="$2"; shift ;;
        --cookie)      COOKIE="$2"; shift ;;
        --scope-domain)
            [ "$#" -lt 2 ] && { err "--scope-domain requires a pattern"; exit 1; }
            SCOPE_DOMAIN_ARGS+=("$2"); shift ;;
        --scope-exclude)
            [ "$#" -lt 2 ] && { err "--scope-exclude requires a pattern"; exit 1; }
            SCOPE_EXCLUDE_ARGS+=("$2"); shift ;;
        --scope-manifest)
            [ "$#" -lt 2 ] && { err "--scope-manifest requires a path"; exit 1; }
            SCOPE_MANIFEST="$2"; shift ;;
        --no-scope-check) NO_SCOPE_CHECK=true ;;
        *) warn "Unknown option: $1" ;;
    esac
    shift
done

# ── Validate ──────────────────────────────────────────────────────────────────
if [ -z "$TARGET" ]; then
    echo "Usage: bash full_hunt.sh target.com [--quick] [--token JWT] [--cookie COOKIE]"
    echo "                     [--scope-manifest PATH | --scope-domain PATTERN]... [--no-scope-check]"
    exit 1
fi

# ── Scope pre-flight gate (Commit 3 — fail-closed, 0 packets unscoped) ────────
# Runs BEFORE any network activity (before subfinder/amass/crt.sh in Phase 1
# and before the output dirs even exist). A run needs a verified compiled
# scope manifest OR at least one --scope-domain pattern, validated through
# the SAME deterministic ScopeChecker the engine uses; anything else exits 3
# after an audit entry is appended.
_rhodawk_fullhunt_audit_block() {
    local _hm="${RHODAWK_HOME:-$HOME/.rhodawk}/hunt-memory"
    mkdir -p "$_hm" 2>/dev/null || return 0
    printf '{"ts":"%s","url":"https://%s","method":"GET","scope_check":"fail","error":"full_hunt.sh: %s","schema_version":1}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TARGET" "$1" >> "$_hm/audit.jsonl" 2>/dev/null || true
}

_FULLHUNT_SCOPE_ARGS=()
if [ "$NO_SCOPE_CHECK" = true ]; then
    warn "Scope gate: --no-scope-check opt-out — running UNSCOPED (demo/testing only)"
elif [ -n "$SCOPE_MANIFEST" ]; then
    if [ ! -f "$SCOPE_MANIFEST" ]; then
        err "SCOPE BLOCK: --scope-manifest '$SCOPE_MANIFEST' not found (fail-closed)"
        _rhodawk_fullhunt_audit_block "manifest not found: $SCOPE_MANIFEST"
        exit 3
    fi
    _FULLHUNT_SCOPE_ARGS=(--manifest "$SCOPE_MANIFEST")
    if ! python3 "$TOOLS_DIR/tools/scope_checker.py" \
            ${_FULLHUNT_SCOPE_ARGS[@]+"${_FULLHUNT_SCOPE_ARGS[@]}"} "$TARGET" >/dev/null 2>&1; then
        err "SCOPE BLOCK: target '$TARGET' is outside the scope manifest or the manifest is tampered (SHA-256 verified, fail-closed)"
        _rhodawk_fullhunt_audit_block "target outside scope manifest: $SCOPE_MANIFEST"
        exit 3
    fi
    ok "Scope gate: compiled manifest verified ($SCOPE_MANIFEST)"
elif [ ${#SCOPE_DOMAIN_ARGS[@]} -eq 0 ]; then
    err "SCOPE BLOCK: unscoped runs are refused — pass --scope-manifest PATH or --scope-domain PATTERN (repeatable), or --no-scope-check for local demo testing"
    _rhodawk_fullhunt_audit_block "no scope source provided (fail-closed pre-flight gate)"
    exit 3
else
    for _p in "${SCOPE_EXCLUDE_ARGS[@]}"; do
        _FULLHUNT_SCOPE_ARGS+=(--exclude-domain "$_p")
    done
    for _p in "${SCOPE_DOMAIN_ARGS[@]}"; do
        _FULLHUNT_SCOPE_ARGS+=(--domain "$_p")
    done
    if ! python3 "$TOOLS_DIR/tools/scope_checker.py" \
            ${_FULLHUNT_SCOPE_ARGS[@]+"${_FULLHUNT_SCOPE_ARGS[@]}"} "$TARGET" >/dev/null 2>&1; then
        err "SCOPE BLOCK: target '$TARGET' is outside the provided scope patterns"
        _rhodawk_fullhunt_audit_block "target outside provided scope patterns"
        exit 3
    fi
    ok "Scope gate: target validated against ${#SCOPE_DOMAIN_ARGS[@]} scope pattern(s)"
fi

# ── Create output dirs ────────────────────────────────────────────────────────
mkdir -p "$OUT"/{subdomains,urls,content,js,params,vulns,reports}

# ── Auth headers ──────────────────────────────────────────────────────────────
# Build RHODAWK_AUTH_HEADERS (newline-separated) from --token / --cookie and
# any pre-existing env value, then source _auth_helper.sh so RHODAWK_AUTH_ARGS is
# splattable into curl/httpx/nuclei/katana/ffuf invocations below.
_RHODAWK_HEADERS_TMP="${RHODAWK_AUTH_HEADERS:-}"
[ -n "$TOKEN" ]  && _RHODAWK_HEADERS_TMP="${_RHODAWK_HEADERS_TMP:+$_RHODAWK_HEADERS_TMP$'\n'}Authorization: Bearer $TOKEN"
[ -n "$COOKIE" ] && _RHODAWK_HEADERS_TMP="${_RHODAWK_HEADERS_TMP:+$_RHODAWK_HEADERS_TMP$'\n'}Cookie: $COOKIE"
export RHODAWK_AUTH_HEADERS="$_RHODAWK_HEADERS_TMP"
unset _RHODAWK_HEADERS_TMP

# shellcheck source=tools/_auth_helper.sh
# Helper computes RHODAWK_AUTH_ARGS + RHODAWK_SESSION_ID from RHODAWK_AUTH_HEADERS.
. "$TOOLS_DIR/tools/_auth_helper.sh"

# ═══════════════════════════════════════════════════════════════════════════════
# shellcheck source=tools/banner.sh
. "$TOOLS_DIR/tools/banner.sh"
print_banner "Full Hunt Pipeline · Ethical Bug Bounty" "$TARGET" \
    "Passive recon|subdomains, URLs, tech fingerprinting" \
    "Content discovery|directories, parameters, JS analysis" \
    "Vuln scanning|nuclei templates, XSS, CORS, auth checks" \
    "Reporting|writes findings to $OUT/reports/"

echo -e "${CYAN}  Output:    ${BOLD}${OUT}/${RESET}"
echo -e "${CYAN}  Started:   $(date)${RESET}"
[ -n "$TOKEN" ]  && echo -e "${GREEN}  Auth:      Bearer token provided${RESET}"
[ -n "$COOKIE" ] && echo -e "${GREEN}  Auth:      Cookie provided${RESET}"
[ "$QUICK" = true ] && echo -e "${YELLOW}  Mode:      QUICK (slower scans skipped)${RESET}"
sep
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: PASSIVE RECON
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$SCAN_ONLY" = false ]; then

log "PHASE 1: Passive Reconnaissance"
sep

# ── Subdomain enumeration ─────────────────────────────────────────────────────
log "Enumerating subdomains..."

if [ "$(check_tool subfinder)" = true ]; then
    subfinder -d "$TARGET" -silent -o "$OUT/subdomains/subfinder.txt" 2>/dev/null
    ok "Subfinder: $(wc -l < $OUT/subdomains/subfinder.txt) subdomains"
else
    warn "subfinder not found — skipping"
fi

if [ "$(check_tool amass)" = true ] && [ "$QUICK" = false ]; then
    amass enum -passive -d "$TARGET" -o "$OUT/subdomains/amass.txt" 2>/dev/null
    ok "Amass: $(wc -l < $OUT/subdomains/amass.txt 2>/dev/null || echo 0) subdomains"
fi

# crt.sh query
log "Querying crt.sh..."
curl -sk "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | \
    python3 -c "import json,sys; [print(x['name_value']) for x in json.load(sys.stdin) if '*' not in x['name_value']]" 2>/dev/null | \
    sort -u > "$OUT/subdomains/crtsh.txt"
ok "crt.sh: $(wc -l < $OUT/subdomains/crtsh.txt) entries"

# Merge and deduplicate
cat "$OUT"/subdomains/*.txt 2>/dev/null | sort -u > "$OUT/subdomains/all_subs.txt"
ok "Total unique subdomains: $(wc -l < $OUT/subdomains/all_subs.txt)"

# ── Post-enumeration scope filter (B3 / R-16) ────────────────────────────────
# Enumeration sources (subfinder / amass / crt.sh) return whatever the wild
# internet recorded for the base domain — permuted, stale, and attacker-
# influenceable. Every discovered subdomain is screened through the SAME
# deterministic scope decision as the pre-flight gate BEFORE httpx probes
# anything, so a wildcard DNS entry or a poisoned certificate record can never
# turn into live probe traffic against a host the program never scoped.
# Dropped hosts are quarantined for review, not silently deleted.
if [ "$NO_SCOPE_CHECK" = false ] && [ -s "$OUT/subdomains/all_subs.txt" ]; then
    log "Scope filter: screening discovered subdomains before probing..."
    if python3 "$TOOLS_DIR/tools/scope_checker.py" \
            ${_FULLHUNT_SCOPE_ARGS[@]+"${_FULLHUNT_SCOPE_ARGS[@]}"} \
            --input-file "$OUT/subdomains/all_subs.txt" \
            --dropped-file "$OUT/subdomains/scope_dropped.txt" \
            >/dev/null 2>&1; then
        _dropped_n=0
        [ -f "$OUT/subdomains/scope_dropped.txt" ] && \
            _dropped_n="$(wc -l < "$OUT/subdomains/scope_dropped.txt" | tr -d ' ')"
        [ "$_dropped_n" -gt 0 ] 2>/dev/null && \
            warn "Scope filter dropped $_dropped_n out-of-scope subdomain(s) (see subdomains/scope_dropped.txt)"
        if [ ! -s "$OUT/subdomains/all_subs.txt" ]; then
            warn "Every discovered subdomain was out of scope — 0 live probes will be sent (enumeration output only)"
        fi
    else
        err "SCOPE BLOCK: scope filter FAILED for subdomains/all_subs.txt — aborting instead of probing unfiltered enumeration output"
        _rhodawk_fullhunt_audit_block "post-enumeration scope filter failed for all_subs.txt"
        exit 3
    fi
fi

# ── Probe live subdomains ─────────────────────────────────────────────────────
if [ "$(check_tool httpx)" = true ]; then
    log "Probing live subdomains..."
    cat "$OUT/subdomains/all_subs.txt" | httpx -silent ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} -o "$OUT/subdomains/live_subs.txt" 2>/dev/null
    ok "Live subdomains: $(wc -l < $OUT/subdomains/live_subs.txt)"
fi

# ── Historical URL discovery ───────────────────────────────────────────────────
log "Fetching historical URLs..."

if [ "$(check_tool gau)" = true ]; then
    gau "$TARGET" --blacklist png,jpg,gif,svg,ico,css,woff,ttf 2>/dev/null > "$OUT/urls/gau.txt"
    ok "GAU: $(wc -l < $OUT/urls/gau.txt) URLs"
fi

if [ "$(check_tool waybackurls)" = true ]; then
    echo "$TARGET" | waybackurls 2>/dev/null > "$OUT/urls/wayback.txt"
    ok "Wayback: $(wc -l < $OUT/urls/wayback.txt) URLs"
fi

# Merge all URLs
cat "$OUT"/urls/*.txt 2>/dev/null | sort -u > "$OUT/urls/all_urls.txt"
ok "Total unique URLs: $(wc -l < $OUT/urls/all_urls.txt)"

# ── Fingerprint main target ────────────────────────────────────────────────────
log "Fingerprinting technology stack..."
if [ "$(check_tool httpx)" = true ]; then
    httpx -u "$TARGETURL" -tech-detect -title -status-code -content-length \
        -o "$OUT/reports/fingerprint.txt" -silent 2>/dev/null
    cat "$OUT/reports/fingerprint.txt"
fi

fi  # end RECON_ONLY check

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: CONTENT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$RECON_ONLY" = false ] && [ "$SCAN_ONLY" = false ]; then

echo ""
log "PHASE 2: Content Discovery"
sep

# ── Crawl with katana ──────────────────────────────────────────────────────────
# 5 min cap: depth-5 katana runs can hang indefinitely on content-heavy
# targets (news, video, infinite calendars). Depth reduced to 3 to match
# agents/recon-agent.md and commands/recon.md.
if [ "$(check_tool katana)" = true ]; then
    log "Crawling with katana (5 min cap, depth 3)..."
    timeout 300 katana -u "$TARGETURL" -d 3 -jc -kf all ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} -o "$OUT/urls/katana.txt" -silent 2>/dev/null || true
    ok "Katana: $(wc -l < $OUT/urls/katana.txt 2>/dev/null || echo 0) URLs"
    [ -s "$OUT/urls/katana.txt" ] && cat "$OUT/urls/katana.txt" >> "$OUT/urls/all_urls.txt"
    sort -u "$OUT/urls/all_urls.txt" -o "$OUT/urls/all_urls.txt"
fi

# ── Directory fuzzing ─────────────────────────────────────────────────────────
if [ "$(check_tool ffuf)" = true ] && [ -f "$WL_DIRS" ]; then
    log "Fuzzing directories..."
    ffuf -u "$TARGETURL/FUZZ" -w "$WL_DIRS" \
        -mc 200,301,302,403 -t 40 -s \
        ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
        -o "$OUT/content/ffuf_dirs.json" -of json \
        2>/dev/null
    ok "ffuf dirs: $(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('results',[])))" "$OUT/content/ffuf_dirs.json" 2>/dev/null || echo 0) found"
else
    warn "ffuf or wordlist not available for directory scan"
fi

# ── File extension fuzzing ────────────────────────────────────────────────────
if [ "$(check_tool ffuf)" = true ] && [ -f "$WL_FILES" ] && [ "$QUICK" = false ]; then
    log "Fuzzing files with extensions..."
    ffuf -u "$TARGETURL/FUZZ" -w "$WL_FILES" \
        -e .php,.bak,.old,.env,.json,.xml,.yml,.yaml,.txt,.zip \
        -mc 200,301,302,403 -t 30 -s \
        ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
        -o "$OUT/content/ffuf_files.json" -of json 2>/dev/null
    ok "ffuf files: $(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('results',[])))" "$OUT/content/ffuf_files.json" 2>/dev/null || echo 0) found"
fi

# ── JS analysis ───────────────────────────────────────────────────────────────
log "Extracting and analyzing JS files..."
cat "$OUT/urls/all_urls.txt" | grep "\.js" | sort -u > "$OUT/js/js_files.txt"
ok "JS files discovered: $(wc -l < $OUT/js/js_files.txt)"

if [ -f "$(which linkfinder.py 2>/dev/null)" ] || [ -f "$HOME/tools/LinkFinder/linkfinder.py" ]; then
    LF_PATH="$(find $HOME -name 'linkfinder.py' 2>/dev/null | head -1)"
    if [ -n "$LF_PATH" ]; then
        log "Running LinkFinder on JS files..."
        cat "$OUT/js/js_files.txt" | while read url; do
            python3 "$LF_PATH" -i "$url" -o cli 2>/dev/null
        done | sort -u > "$OUT/js/js_endpoints.txt"
        ok "JS endpoints found: $(wc -l < $OUT/js/js_endpoints.txt)"
    fi
fi

# ── GF filtering of known vuln params ────────────────────────────────────────
if [ "$(check_tool gf)" = true ]; then
    log "Filtering vuln-prone params with gf..."
    for vuln in xss sqli ssrf redirect lfi rce idor ssti; do
        cat "$OUT/urls/all_urls.txt" | gf $vuln 2>/dev/null > "$OUT/vulns/gf_${vuln}.txt"
        COUNT=$(wc -l < "$OUT/vulns/gf_${vuln}.txt" 2>/dev/null || echo 0)
        # ${vuln^^} is bash-4 only; macOS ships bash 3.2 → use tr for uppercasing.
        VU=$(printf '%s' "$vuln" | tr '[:lower:]' '[:upper:]')
        [ "$COUNT" -gt 0 ] && warn "$COUNT potential $VU candidates → $OUT/vulns/gf_${vuln}.txt"
    done
fi

fi  # end recon/content check

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$RECON_ONLY" = false ]; then

echo ""
log "PHASE 3: Vulnerability Scanning"
sep

# ── Nuclei scan ───────────────────────────────────────────────────────────────
if [ "$(check_tool nuclei)" = true ]; then
    log "Running Nuclei (critical + high)..."
    nuclei -u "$TARGETURL" \
        -severity critical,high \
        -o "$OUT/vulns/nuclei_critical_high.txt" \
        ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
        -silent 2>/dev/null
    ok "Nuclei critical/high: $(wc -l < $OUT/vulns/nuclei_critical_high.txt) findings"

    if [ "$QUICK" = false ]; then
        nuclei -u "$TARGETURL" \
            -severity medium \
            -o "$OUT/vulns/nuclei_medium.txt" \
            ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
            -silent 2>/dev/null
        ok "Nuclei medium: $(wc -l < $OUT/vulns/nuclei_medium.txt) findings"
    fi
else
    warn "nuclei not found — skipping automated vuln scan"
fi

# ── XSS scan ─────────────────────────────────────────────────────────────────
if [ "$(check_tool dalfox)" = true ] && [ -s "$OUT/vulns/gf_xss.txt" ]; then
    log "Testing XSS candidates with dalfox..."
    cat "$OUT/vulns/gf_xss.txt" | dalfox pipe \
        ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
        -o "$OUT/vulns/xss_found.txt" --silence 2>/dev/null
    ok "XSS found: $(wc -l < $OUT/vulns/xss_found.txt)"
fi

# ── CORS scan ─────────────────────────────────────────────────────────────────
log "Checking CORS misconfiguration..."
CORS_RESULT=$(curl -sk "$TARGETURL/api/" \
    ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
    -H "Origin: https://evil.com" \
    -I 2>/dev/null | grep -i "access-control-allow-origin: https://evil.com" || true)
if [ -n "$CORS_RESULT" ]; then
    warn "POTENTIAL CORS VULNERABILITY DETECTED!"
    echo "$CORS_RESULT" > "$OUT/vulns/cors_vuln.txt"
else
    ok "Basic CORS check passed"
fi

# ── Subdomain takeover ────────────────────────────────────────────────────────
if [ "$(check_tool subzy)" = true ] && [ -s "$OUT/subdomains/all_subs.txt" ]; then
    log "Checking subdomain takeover..."
    subzy run --targets "$OUT/subdomains/all_subs.txt" \
        --output "$OUT/vulns/takeover.json" \
        --hide-fails --concurrency 20 2>/dev/null
    ok "Takeover scan complete → $OUT/vulns/takeover.json"
fi

# ── Generate dork URLs ────────────────────────────────────────────────────────
if [ -f "$(dirname $0)/dork_runner.py" ]; then
    log "Generating Google dorks..."
    python3 "$(dirname $0)/dork_runner.py" -d "$TARGET" -c all \
        -o "$OUT/reports/dorks.txt" \
        --html "$OUT/reports/dork_report.html" 2>/dev/null
    ok "Dork report → $OUT/reports/dork_report.html"
fi

fi  # end scan check

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
sep
echo -e "${BOLD}${GREEN}  ✅ HUNT COMPLETE — SUMMARY REPORT${RESET}"
sep

echo -e "${CYAN}  Target:${RESET} $TARGET"
echo -e "${CYAN}  Output:${RESET} $OUT/"
echo -e "${CYAN}  Time:  ${RESET} $(date)"
echo ""

# Stats
[ -f "$OUT/subdomains/all_subs.txt" ] && \
    echo -e "${YELLOW}  Subdomains:         $(wc -l < $OUT/subdomains/all_subs.txt)${RESET}"
[ -f "$OUT/subdomains/live_subs.txt" ] && \
    echo -e "${YELLOW}  Live subdomains:    $(wc -l < $OUT/subdomains/live_subs.txt)${RESET}"
[ -f "$OUT/urls/all_urls.txt" ] && \
    echo -e "${YELLOW}  Total URLs:         $(wc -l < $OUT/urls/all_urls.txt)${RESET}"
[ -f "$OUT/js/js_endpoints.txt" ] && \
    echo -e "${YELLOW}  JS endpoints:       $(wc -l < $OUT/js/js_endpoints.txt)${RESET}"
[ -f "$OUT/vulns/nuclei_critical_high.txt" ] && \
    echo -e "${RED}  Nuclei critical/high: $(wc -l < $OUT/vulns/nuclei_critical_high.txt)${RESET}"
[ -f "$OUT/vulns/xss_found.txt" ] && \
    echo -e "${RED}  XSS found:          $(wc -l < $OUT/vulns/xss_found.txt)${RESET}"

echo ""
echo -e "${BOLD}  Next steps:${RESET}"
echo -e "  1. Check $OUT/vulns/ for automated findings"
echo -e "  2. Open $OUT/reports/dork_report.html for Google dorking"
echo -e "  3. Manually test: $OUT/vulns/gf_*.txt (IDOR, SSRF, SQLi)"
echo -e "  4. Analyze JS: $OUT/js/js_endpoints.txt"
echo -e "  5. Test JWT attacks if auth endpoints found"
sep
echo ""
