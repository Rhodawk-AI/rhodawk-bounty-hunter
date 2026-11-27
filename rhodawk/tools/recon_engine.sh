#!/bin/bash
# =============================================================================
# Enhanced Recon Engine
# Full reconnaissance pipeline for bug bounty targets
# Usage: ./recon_engine.sh <target-domain> [--quick]
# =============================================================================

set -o pipefail

# ── RTW_HOME resolution (live-run fix, fresh shells) ──────────────────────────
# install.sh persists rtw_home to ~/.rhodawk/config.json and `rhodawk
# doctor` already reads it — but a fresh shell without `export RTW_HOME=...`
# made the engine skip Phase 1.5/5.5 entirely (`[[ -n "${RTW_HOME:-}" ]]`
# gate). Resolve it ONCE here, before any phase: the environment always
# wins, config.json fills the gap.
if [ -z "${RTW_HOME:-}" ]; then
    _rtw_cfg="${RHODAWK_CONFIG_FILE:-$HOME/.rhodawk/config.json}"
    _rtw_from_cfg=""
    if [ -f "$_rtw_cfg" ] && command -v python3 >/dev/null 2>&1; then
        _rtw_from_cfg="$(python3 -c '
import json, sys
try:
    v = json.loads(open(sys.argv[1], encoding="utf-8").read()).get("rtw_home", "")
except Exception:
    v = ""
print(v if isinstance(v, str) else "")
' "$_rtw_cfg" 2>/dev/null || true)"
    fi
    if [ -n "$_rtw_from_cfg" ]; then
        export RTW_HOME="$_rtw_from_cfg"
    fi
    unset _rtw_cfg _rtw_from_cfg
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_err()   { echo -e "${RED}[-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_step()  { echo -e "    ${CYAN}[>]${NC} $1"; }
log_done()  { echo -e "    ${GREEN}[✓]${NC} $1"; }
log_vuln()  { echo -e "    ${RED}[VULN]${NC} $1"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
# Upstream accepted: ./recon_engine.sh <target> [--quick]. The RhodawkAI
# Edition adds repeatable --scope-domain/--scope-exclude flags (forwarded to
# the reconFTW gap-fill adapter, which enforces Rhodawk's fail-closed ScopeChecker)
# plus an explicit --no-scope-check opt-out for local demo testing. Positional
# behavior (<target> [--quick]) is preserved.
TARGET=""
QUICK_MODE=""
JS_CRAWL=0
SCOPE_DOMAIN_ARGS=()
SCOPE_EXCLUDE_ARGS=()
SCOPE_MANIFEST_ARG=""
SCOPE_OPT_OUT=0
_rtw_engine_usage() {
    echo "Usage: $0 <target> [--quick] [--js-crawl]"
    echo "                     [--scope-domain PATTERN]... [--scope-exclude PATTERN]..."
    echo "                     [--scope-manifest PATH] [--no-scope-check]"
    echo "  target = FQDN, IP, CIDR, or path to a file of domains/hosts"
    echo "  --scope-manifest PATH   use a compiled_scope.json manifest (Commit 2"
    echo "                          artifact, SHA-256 verified) as the single scope"
    echo "                          authority; auto-detected at"
    echo "                          \$RECON_DIR/scope/compiled_scope.json when present"
    echo "  --scope-domain / --scope-exclude are forwarded to the reconFTW"
    echo "  gap-fill adapter (Phases 1.5/5.5). Without any scope source (or"
    echo "  without --no-scope-check) the engine fails closed."
    echo "  --js-crawl              opt-in headless JS crawl (Phase 5.75, Playwright):"
    echo "                          capture runtime XHR/fetch endpoints of SPA targets."
    echo "                          Skips with a WARN when Playwright/Chromium is"
    echo "                          unavailable; requires a scope authority."
}
while [ $# -gt 0 ]; do
    case "$1" in
        --quick)
            QUICK_MODE="--quick"; shift ;;
        --js-crawl)
            JS_CRAWL=1; shift ;;
        --normalize-only)
            # Hidden upstream mode (tests/test_target_normalize.py): print the
            # normalized target and exit; see the QUICK_MODE check below.
            QUICK_MODE="--normalize-only"; shift ;;
        --scope-domain)
            [ $# -lt 2 ] && { echo "[-] --scope-domain requires a pattern" >&2; exit 1; }
            SCOPE_DOMAIN_ARGS+=("$2"); shift 2 ;;
        --scope-exclude)
            [ $# -lt 2 ] && { echo "[-] --scope-exclude requires a pattern" >&2; exit 1; }
            SCOPE_EXCLUDE_ARGS+=("$2"); shift 2 ;;
        --scope-manifest)
            [ $# -lt 2 ] && { echo "[-] --scope-manifest requires a path" >&2; exit 1; }
            SCOPE_MANIFEST_ARG="$2"; shift 2 ;;
        --no-scope-check)
            SCOPE_OPT_OUT=1; shift ;;
        -h|--help)
            _rtw_engine_usage; exit 0 ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                echo "[-] unexpected extra argument: $1" >&2
                _rtw_engine_usage >&2
                exit 1
            fi
            shift ;;
    esac
done
[ -n "$TARGET" ] || { _rtw_engine_usage >&2; exit 1; }
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Flatten (repeatable + comma-separated) scope patterns ONCE — used by the
# pre-flight scope gate AND the B2 redirect-destination classification.
SC_CHECK_ARGS=()
for _p in ${SCOPE_DOMAIN_ARGS[@]+"${SCOPE_DOMAIN_ARGS[@]}"}; do
    IFS=',' read -r -a _sc_parts <<< "$_p"
    for _c in "${_sc_parts[@]}"; do
        [ -n "$_c" ] && SC_CHECK_ARGS+=(--domain "$_c")
    done
done
for _p in ${SCOPE_EXCLUDE_ARGS[@]+"${SCOPE_EXCLUDE_ARGS[@]}"}; do
    IFS=',' read -r -a _sc_parts <<< "$_p"
    for _c in "${_sc_parts[@]}"; do
        [ -n "$_c" ] && SC_CHECK_ARGS+=(--exclude-domain "$_c")
    done
done

# ── reconFTW gap-fill plumbing (RhodawkAI Edition, Fixes 1+2) ─────────────────
# Deterministic delegation to reconFTW's equivalent functions via
# tools/rtw_adapter.py — never an LLM judgment call. Two split phases:
#   Phase 1.5 — subdomain/infra gap-fill BEFORE Phase 2 (httpx), so newly
#               discovered subdomains are probed in the same run.
#   Phase 5.5 — web/JS/TLS gap-fill after Phase 5, BEFORE Phase 6 (ffuf), so
#               the URL corpus feeds downstream phases and the Summary.
# Scope patterns are forwarded verbatim; the adapter refuses to spawn any
# reconFTW subprocess without them (fail closed) unless --no-scope-check.
RTW_ADAPTER="$BASE_DIR/tools/rtw_adapter.py"
RTW_SCOPE_ARGS=()
if [ "$SCOPE_OPT_OUT" = "1" ]; then
    RTW_SCOPE_ARGS+=(--no-scope-check)
else
    for _p in "${SCOPE_DOMAIN_ARGS[@]}"; do RTW_SCOPE_ARGS+=(--scope-domain "$_p"); done
    for _p in "${SCOPE_EXCLUDE_ARGS[@]}"; do RTW_SCOPE_ARGS+=(--scope-exclude "$_p"); done
fi

_rtw_ready() {
    [ -n "${RTW_HOME:-}" ] || return 1
    [ -f "$RTW_ADAPTER" ] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
}

_rtw_run_phase() {
    # $1 = phase id ("1.5" | "5.5"); SKIPPED capabilities are normal.
    _rtw_ready || return 1
    python3 "$RTW_ADAPTER" phase "$1" --target "$TARGET" --recon-dir "$RECON_DIR" \
        ${RTW_SCOPE_ARGS[@]+"${RTW_SCOPE_ARGS[@]}"}
}

# ── B3: post-enumeration scope filter ────────────────────────────────────
# Hosts/URLs discovered by subfinder/crt.sh/wayback/katana/gau or the
# reconFTW gap-fill are filtered through the SAME ScopeChecker rules as the
# pre-flight gate BEFORE any probing tool reads them. Dropped lines are
# written to <recon_dir>/scope/dropped_oos.txt (prefixed with their source
# file); the dropped total lands in the Recon Summary and in recon_truth.json
# (counts.scope_dropped). No-op when --no-scope-check is passed; patternless
# targets self-scope to the target itself (ip/local/cidr); list targets are
# filtered when scope patterns or a verified manifest are provided (Commit 3
# closes the previous blind-trust bypass) and only skip filtering when the
# list itself is the only scope definition.
SCOPE_DROPPED_TOTAL=0
_rhodawk_scope_filter() {
    [ "$SCOPE_OPT_OUT" = "1" ] && return 0
    local _f="$1"
    [ -f "$_f" ] || return 0
    [ -s "$_f" ] || return 0
    local _filter_args=()
    if [ -n "${SCOPE_MANIFEST:-}" ]; then
        # Commit 3: a verified compiled manifest is the single scope authority
        # for filtering — for EVERY target type, including list-mode targets
        # (previously a list skipped filtering entirely, trusting its
        # contents blindly). Explicit patterns alongside a manifest could
        # only widen scope, so they are ignored (loudly).
        if [ ${#SCOPE_DOMAIN_ARGS[@]} -gt 0 ]; then
            log_warn "Scope filter: --scope-domain patterns IGNORED — the verified manifest is the single authority"
        fi
        _filter_args=(--manifest "$SCOPE_MANIFEST")
    elif [ ${#SCOPE_DOMAIN_ARGS[@]} -gt 0 ]; then
        _filter_args=("${SC_CHECK_ARGS[@]}")
    else
        case "$(printf '%s' "${TARGET_TYPE:-}" | tr -d '[:space:]')" in
            ip|local|cidr) _filter_args=(--domain "$TARGET") ;;
            *) return 0 ;;
        esac
    fi
    mkdir -p "$RECON_DIR/scope"
    local _rel="${_f#$RECON_DIR/}"
    local _tmp_in="$RECON_DIR/scope/.filter_in.txt"
    local _tmp_drop="$RECON_DIR/scope/.filter_dropped.txt"
    cp "$_f" "$_tmp_in" 2>/dev/null || return 0
    if python3 "$BASE_DIR/tools/scope_checker.py" \
            ${_filter_args[@]+"${_filter_args[@]}"} \
            --input-file "$_tmp_in" --output "$_f" \
            --dropped-file "$_tmp_drop" >/dev/null 2>&1; then
        if [ -s "$_tmp_drop" ]; then
            local _n
            _n=$(grep -c . "$_tmp_drop" 2>/dev/null || echo 0)
            while IFS= read -r _oos_line; do
                [ -z "$_oos_line" ] && continue
                printf '%s\t%s\n' "$_rel" "$_oos_line" >> "$RECON_DIR/scope/dropped_oos.txt"
            done < "$_tmp_drop"
            SCOPE_DROPPED_TOTAL=$((SCOPE_DROPPED_TOTAL + _n))
            log_info "Scope filter: dropped $_n out-of-scope line(s) from $_rel (scope/dropped_oos.txt)"
        fi
    else
        # Commit 3 FAIL-CLOSED fix (was fail-open): the checker itself failed
        # — previously the UNFILTERED backup was restored and the run
        # continued, probing whatever subfinder returned. Never probe
        # unfiltered data: log, audit, and abort before any probe tool runs.
        log_err "SCOPE BLOCK: scope filter FAILED for $_rel (scope_checker.py exited non-zero) — aborting the run instead of probing unfiltered data"
        _rhodawk_audit_scope_block "scope filter crash on ${_rel}: scope_checker.py exited non-zero (fail-closed)"
        rm -f "$_tmp_in" "$_tmp_drop"
        exit 3
    fi
    rm -f "$_tmp_in" "$_tmp_drop"
}

# Auth-aware hunting: load RHODAWK_AUTH_HEADERS / RHODAWK_SESSION_ID into
# RHODAWK_AUTH_ARGS=(-H 'Name: val' ...). Empty session = no-op.
# shellcheck source=tools/_auth_helper.sh
. "$(dirname "$0")/_auth_helper.sh"

# OS-specific install hints for missing tools (dep_install_hint / warn_missing).
# shellcheck source=tools/_dep_hint.sh
. "$(dirname "$0")/_dep_hint.sh"

# Domain-list mode: if the target is a readable regular file, treat its
# contents as a pre-resolved scope list (one host per line, # comments OK).
# Useful for programs without wildcards where subdomain enum is wasted work.
# Output dir is derived from the file basename so multiple lists don't collide.
if [ -f "$TARGET" ] && [ -r "$TARGET" ]; then
    TARGET_TYPE="list"
    LIST_FILE="$TARGET"
    TARGET="$(basename "$LIST_FILE")"
    TARGET="${TARGET%.*}"
fi

# ── Normalize a URL/host/host:port into a bare host (+ optional port) ─────────
# Scanners need `9am.io`, not `https://9am.io/`; without this the pipeline ran
# `nmap https://9am.io/` (0 hosts) and wrote output to `recon/https:/9am.io`.
# Mirrors tools/target_normalize.py (cross-checked in tests). Sets globals
# TARGET (bare host, lowercased) and TARGET_PORT (empty when none). Skipped for
# file-list targets, whose TARGET is already a basename.
TARGET_PORT=""
_normalize_target() {
    local s="$1"
    # trim whitespace
    s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"
    # strip scheme://
    shopt -s nocasematch
    [[ "$s" =~ ^[a-z][a-z0-9+.-]*:// ]] && s="${s#*://}"
    shopt -u nocasematch
    # drop path/query/fragment
    s="${s%%[/?#]*}"
    # userinfo user:pass@host -> host
    s="${s##*@}"
    local host="$s" port=""
    if [[ "$s" == \[*\]* ]]; then                 # [IPv6] or [IPv6]:port
        host="${s#\[}"; host="${host%%\]*}"
        local rest="${s##*\]}"
        [[ "$rest" =~ ^:([0-9]+)$ ]] && port="${BASH_REMATCH[1]}"
    elif [[ "$s" == *:*:* ]]; then                 # bare IPv6, leave intact
        host="$s"
    elif [[ "$s" =~ ^(.+):([0-9]+)$ ]]; then       # host:port
        host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    fi
    while [[ "$host" == *. ]]; do host="${host%.}"; done   # all trailing dots (match Python rstrip('.'))
    host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
    TARGET="$host"; TARGET_PORT="$port"
}
# Normalize hostnames/URLs only. A CIDR must keep its /NN mask (normalization
# would strip it as a path) and a file-list target is already a basename.
if [ "${TARGET_TYPE:-}" != "list" ] && [ "${TARGET_TYPE:-}" != "cidr" ] \
   && ! [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
    _normalize_target "$TARGET"
fi

# C10: host:port targets key their own recon dir (127.0.0.1:8082 ->
# 127.0.0.1_8082) so two ports on one host never overwrite each other's
# artifacts. RECON_OUT_DIR is pinned by engine.py (which keys it the same
# way via target_normalize.recon_dirname); the standalone-shell default keys
# host_port here. Portless targets keep today's bare-host path.
if [ -n "${RECON_OUT_DIR:-}" ]; then
    RECON_DIR="$RECON_OUT_DIR"
else
    # Audit R-01: standalone default goes to the data home, never
    # $BASE_DIR/recon (a hunt launched from a git clone used to write its
    # session tree into the source/package directory, polluting builds).
    RECON_DIR="${RHODAWK_HOME:-$HOME/.rhodawk}/recon/$TARGET${TARGET_PORT:+_$TARGET_PORT}"
fi

# ── Compiled scope manifest (Commit 3): detect BEFORE rate-limit defaults ────
# Explicit --scope-manifest wins; otherwise auto-detect the Commit 2 artifact
# at $RECON_DIR/scope/compiled_scope.json (written by scope_compiler.py —
# re-running the engine for a target whose scope was previously compiled now
# picks it up automatically). Existence is checked here; SHA-256 integrity and
# target membership are enforced by the pre-flight scope gate below (fail-
# closed, exit 3) so a tampered manifest can never authorize a run.
SCOPE_MANIFEST=""
if [ -n "${SCOPE_MANIFEST_ARG:-}" ]; then
    SCOPE_MANIFEST="$SCOPE_MANIFEST_ARG"
elif [ -f "$RECON_DIR/scope/compiled_scope.json" ]; then
    SCOPE_MANIFEST="$RECON_DIR/scope/compiled_scope.json"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
THREADS="${RHODAWK_THREADS:-50}"
RATE_LIMIT="${RHODAWK_RATE_LIMIT:-150}"  # requests per second

# shellcheck source=tools/banner.sh
. "$(dirname "$0")/banner.sh"
print_banner "Recon Engine · Bug Bounty" "$TARGET" \
    "Subdomain enum|subfinder · amass · crt.sh · wayback" \
    "Live probe|httpx + dnsx with tech fingerprinting" \
    "URL crawl|katana · gau · waybackurls" \
    "Templates|nuclei sweep (optional)"

# Prefer Go tools in ~/go/bin — but never RE-prepend system bins ahead of a
# caller-provided PATH: on a root VPS /usr/local/bin holds the host's real
# scanners (subfinder/httpx/nuclei/...), which shadowed the test-suite stub
# PATH and hung engine-level tests on live network probes (EXIT_CODE=124).
# Tests/CI set RHODAWK_NO_BIN_PATH=1 to skip this entirely.
if [ -z "${RHODAWK_NO_BIN_PATH:-}" ]; then
    export PATH="$HOME/go/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
fi

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

# ── Detect target type (passed from hunt.py or auto-detected here) ────────────
# "local" = loopback / RFC-1918 private / *.local — no public subdomain recon.
_detect_target_type() {
    local t="$1"
    # CIDR first so 10.0.0.0/24 is a range, not a single "local" host.
    if   [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then echo "cidr"
    elif [[ "$t" == "localhost" || "$t" == "ip6-localhost" || "$t" == "::1" ]]; then echo "local"
    elif [[ "$t" == *.localhost || "$t" == *.local ]];         then echo "local"
    elif [[ "$t" =~ ^127\. ]];                                 then echo "local"
    elif [[ "$t" =~ ^10\. ]];                                  then echo "local"
    elif [[ "$t" =~ ^192\.168\. ]];                            then echo "local"
    elif [[ "$t" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]];          then echo "local"
    elif [[ "$t" =~ ^169\.254\. ]];                            then echo "local"
    elif [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];        then echo "ip"
    else echo "domain"; fi
}

_expand_cidr_hosts() {
    local target="$1"
    python3 - "$target" <<'PY'
import ipaddress
import itertools
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = [str(host) for host in itertools.islice(network.hosts(), 254)]
if not hosts:
    hosts = [str(network.network_address)]
print("\n".join(hosts))
PY
}
TARGET_TYPE="${TARGET_TYPE:-$(_detect_target_type "$TARGET")}"

# Refuse a target that normalized away or carries path-traversal characters, so
# $RECON_DIR can never point outside recon/ (belt-and-suspenders with the
# Python-side safe_target_dirname check). A CIDR legitimately contains '/'.
if [ "$TARGET_TYPE" != "list" ] && [ "$TARGET_TYPE" != "cidr" ]; then
    if [ -z "$TARGET" ] || [ "$TARGET" = "." ] || [[ "$TARGET" == */* ]] || [[ "$TARGET" == *..* ]]; then
        echo "[-] Refusing unsafe/empty target '$1' after normalization" >&2
        exit 2
    fi
fi

# Debug/test hook: print the parsed target and exit before doing any scanning.
#   recon_engine.sh <target> --normalize-only
if [ "$QUICK_MODE" = "--normalize-only" ] || [ "${RHODAWK_NORMALIZE_ONLY:-0}" = "1" ]; then
    printf 'host=%s\nport=%s\ntype=%s\n' "$TARGET" "$TARGET_PORT" "$TARGET_TYPE"
    exit 0
fi

# ============================================================
# Pre-flight scope gate (RhodawkAI Edition, live-run Fix 1 — fail-closed)
# Runs BEFORE any network activity (the DNS wildcard pre-check below and
# Phase 1 subfinder/crt.sh/wayback), so an unscoped or out-of-scope target
# costs 0 packets sent and 0 tools executed. Rules:
#   --no-scope-check    explicit demo opt-out — gate skipped (loud warning)
#   IP/CIDR/local       self-scoped to the target itself — gate satisfied
#   domain-list file    the file IS the pre-resolved scope list — satisfied
#   domain target       requires >=1 --scope-domain pattern AND ScopeChecker
#                       must pass; otherwise: audited + exit 3 immediately.
# ============================================================
_rhodawk_audit_scope_block() {
    # Reuse the adapter's schema-validated audit writer; if the adapter cannot
    # run, append the same JSON fields it would (make_audit_entry fallback).
    if python3 "$RTW_ADAPTER" audit-block --target "$TARGET" --reason "$1" \
        >/dev/null 2>&1; then
        return 0
    fi
    local _hm="${RHODAWK_HOME:-$HOME/.rhodawk}/hunt-memory"
    mkdir -p "$_hm" 2>/dev/null || return 0
    printf '{"ts":"%s","url":"https://%s","method":"GET","scope_check":"fail","error":"recon_engine.sh: %s","schema_version":1}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TARGET" "$1" >> "$_hm/audit.jsonl" 2>/dev/null || true
}

SCOPE_GATE_BLOCK=""
if [ "$SCOPE_OPT_OUT" = "1" ]; then
    log_warn "Scope gate: --no-scope-check opt-out — running UNSCOPED (demo/testing only)"
elif [ -n "$SCOPE_MANIFEST" ]; then
    # Commit 3: a compiled manifest (explicit --scope-manifest or auto-detected)
    # IS the scope authority. Fail closed on: missing file, tampered SHA-256
    # hash, or a target that the manifest does not authorize. List-mode
    # targets validate the manifest here; their contents are enforced line-
    # by-line by _rhodawk_scope_filter (no more blind trust).
    if [ ! -f "$SCOPE_MANIFEST" ]; then
        SCOPE_GATE_BLOCK="--scope-manifest '$SCOPE_MANIFEST' not found (fail-closed)"
    elif ! python3 "$BASE_DIR/tools/scope_checker.py" --manifest "$SCOPE_MANIFEST" >/dev/null 2>&1; then
        SCOPE_GATE_BLOCK="scope manifest failed SHA-256 integrity validation: $SCOPE_MANIFEST"
    elif [ "$TARGET_TYPE" != "list" ] && ! python3 "$BASE_DIR/tools/scope_checker.py" --manifest "$SCOPE_MANIFEST" "$TARGET" >/dev/null 2>&1; then
        SCOPE_GATE_BLOCK="target '$TARGET' is outside the scope manifest"
    else
        log_info "Scope gate: compiled manifest verified ($SCOPE_MANIFEST)"
    fi
elif [ "$TARGET_TYPE" != "domain" ]; then
    log_info "Scope gate: target type '$TARGET_TYPE' self-scopes to the target itself"
elif [ ${#SCOPE_DOMAIN_ARGS[@]} -eq 0 ]; then
    SCOPE_GATE_BLOCK="no --scope-domain pattern provided (fail-closed pre-flight gate)"
else
    if ! python3 "$BASE_DIR/tools/scope_checker.py" \
            ${SC_CHECK_ARGS[@]+"${SC_CHECK_ARGS[@]}"} "$TARGET" >/dev/null 2>&1; then
        SCOPE_GATE_BLOCK="target '$TARGET' is outside the provided scope patterns"
    fi
fi
if [ -n "$SCOPE_GATE_BLOCK" ]; then
    log_err "SCOPE BLOCK: $SCOPE_GATE_BLOCK"
    log_err "0 packets sent, 0 tools executed. Pass --scope-domain PATTERN (repeatable) or --no-scope-check for local demo testing."
    _rhodawk_audit_scope_block "$SCOPE_GATE_BLOCK"
    exit 3
fi

# ── Manifest-derived runtime knobs (Commit 3) ─────────────────────────────────
# The verified manifest now drives: (a) every downstream scope check (B2
# redirect classification, filters) via SC_CHECK_ARGS repointed at the
# manifest; (b) mandatory auth headers exported into RHODAWK_AUTH_HEADERS
# (only when the caller did not supply any — caller-provided headers win);
# (c) RHODAWK_RATE_LIMIT integer-ceilinged from manifest.max_rps (caller-provided
# value wins). Re-source _auth_helper.sh so RHODAWK_AUTH_ARGS picks up the
# exported manifest headers before the first probe runs.
if [ -n "$SCOPE_MANIFEST" ]; then
    if [ ${#SCOPE_DOMAIN_ARGS[@]} -gt 0 ]; then
        log_warn "Scope authority: --scope-domain patterns present alongside a manifest — patterns are IGNORED everywhere (manifest wins)"
    fi
    SC_CHECK_ARGS=(--manifest "$SCOPE_MANIFEST")

    if [ -z "${RHODAWK_AUTH_HEADERS:-}" ]; then
        _mf_headers="$(python3 - "$SCOPE_MANIFEST" <<'PYEOF'
import json, sys
try:
    m = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
h = m.get("mandatory_headers") or {}
if isinstance(h, dict):
    print("\n".join(f"{k}: {v}" for k, v in h.items()), end="")
PYEOF
)" || _mf_headers=""
        if [ -n "${_mf_headers:-}" ]; then
            export RHODAWK_AUTH_HEADERS="$_mf_headers"
            log_info "Scope manifest: exported RHODAWK_AUTH_HEADERS from mandatory_headers"
        fi
        unset _mf_headers
    fi

    if [ -z "${RHODAWK_RATE_LIMIT:-}" ]; then
        _mf_rps="$(python3 - "$SCOPE_MANIFEST" <<'PYEOF'
import json, math, sys
try:
    m = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
v = m.get("max_rps")
if isinstance(v, (int, float)) and v > 0:
    print(int(math.ceil(v)))
PYEOF
)" || _mf_rps=""
        if [ -n "${_mf_rps:-}" ]; then
            export RHODAWK_RATE_LIMIT="$_mf_rps"
            log_info "Scope manifest: exported RHODAWK_RATE_LIMIT=$_mf_rps (integer ceiling of max_rps)"
        fi
        unset _mf_rps
    fi

    # Rebuild RHODAWK_AUTH_ARGS now that manifest headers (if any) are exported.
    # shellcheck source=tools/_auth_helper.sh
    . "$(dirname "$0")/_auth_helper.sh"
fi

# For IP/CIDR/local: always scope-lock — no subdomain enum needed
if [ "$TARGET_TYPE" = "ip" ] || [ "$TARGET_TYPE" = "cidr" ] || [ "$TARGET_TYPE" = "local" ]; then
    SCOPE_LOCK=1
fi

# Resolve an absolute path to the *ProjectDiscovery* httpx, NOT the unrelated
# Python httpx CLI which Brew installs at /opt/homebrew/bin/httpx and which
# silently rejects PD flags like -silent / -tech-detect with "No such option"
# — producing 0 live hosts on macs where Brew's bin precedes ~/go/bin on PATH
# despite the export above.
#
# The PD binary's `-version` output contains the literal substring
# "projectdiscovery"; the Python httpx CLI doesn't. Fall back to the bare
# `httpx` token when no PD binary is found anywhere so the existing
# command-not-found error path still fires with a clear message.
_resolve_pd_httpx() {
    local cand
    # RHODAWK_HTTPX_BIN wins first: it lets tests/CI pin the stubbed httpx
    # even when the host has a real PD httpx at one of the fixed paths below.
    for cand in \
        "${RHODAWK_HTTPX_BIN:-}" \
        "$HOME/go/bin/httpx" \
        "/opt/homebrew/bin/httpx" \
        "/usr/local/bin/httpx" \
        "$(command -v httpx 2>/dev/null)"; do
        [ -z "$cand" ] && continue
        [ -x "$cand" ] || continue
        if "$cand" -version 2>&1 | grep -qi "projectdiscovery"; then
            echo "$cand"; return 0
        fi
    done
    echo "httpx"
    return 1
}
HTTPX_BIN="$(_resolve_pd_httpx || true)"
if ! "$HTTPX_BIN" -version 2>&1 | grep -qi "projectdiscovery"; then
    echo "[!] WARNING: ProjectDiscovery httpx not found on PATH. Live-host probing will fail." >&2
    dep_install_hint httpx >&2
fi
export HTTPX_BIN

# ── B5: run isolation — archive the previous run, wipe stale artifacts ──────
# A re-run in the same recon dir used to mix old artifacts into the new
# Summary (a dead httpx still reported run 1's live hosts). Archive the
# previous truth (the delta baseline) under .prev_run/ and clear everything
# else, so every Summary value counts the CURRENT run only. The previous
# truth stays available to recon_fusion.py via .prev_run/recon_truth.json.
if [ -d "$RECON_DIR" ] && [ -n "$(ls -A "$RECON_DIR" 2>/dev/null)" ]; then
    mkdir -p "$RECON_DIR/.prev_run"
    # B6: a leftover .run_incomplete marker means the previous run never
    # reached a clean exit (killed watchdog, crashed phase) — warn and archive
    # it so fuse records previous_run_incomplete=true in this run's truth.
    if [ -f "$RECON_DIR/.run_incomplete" ]; then
        log_warn "Previous recon run for $TARGET did not complete cleanly — artifacts archived to .prev_run; previous_run_incomplete will be recorded"
        mv -f "$RECON_DIR/.run_incomplete" "$RECON_DIR/.prev_run/run_incomplete"
    fi
    [ -f "$RECON_DIR/recon_truth.json" ] && \
        mv -f "$RECON_DIR/recon_truth.json" "$RECON_DIR/.prev_run/recon_truth.json"
    # Commit 3: the scope/ directory is STANDING AUTHORIZATION STATE, not a
    # stale run artifact — compiled_scope.json (auto-detected by the gate on
    # the next run) and the cumulative dropped_oos.txt quarantine log must
    # survive the wipe. Excluding scope/ here also prevents the run from
    # destroying its own scope authority mid-run when --scope-manifest points
    # into $RECON_DIR.
    find "$RECON_DIR" -mindepth 1 -maxdepth 1 -not -name '.prev_run' -not -name 'scope' \
        -exec rm -rf {} + 2>/dev/null || true
fi

# B6: mark this run incomplete until a clean exit removes the marker.
# The recon dir may not exist yet on a brand-new target (the rotation block
# above only runs when $RECON_DIR is already populated), so create it first —
# a bare touch used to fail with "No such file or directory" (v2.0.4).
mkdir -p "$RECON_DIR"
touch "$RECON_DIR/.run_incomplete"

mkdir -p "$RECON_DIR"/{subdomains,live,ports,urls,js,dirs,params}

# Safety net: merge partial subdomain results on early exit (watchdog kill, etc.)
_emergency_merge_subs() {
    if [ ! -s "$RECON_DIR/subdomains/all.txt" ] && \
       ls "$RECON_DIR/subdomains/"*.txt &>/dev/null; then
        cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/^\*\.//' \
            | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
            | sort -u > "$RECON_DIR/subdomains/all.txt" 2>/dev/null || true
    fi
}
trap _emergency_merge_subs EXIT

echo "============================================="
echo "  Recon Engine — $TARGET"
echo "  Output: $RECON_DIR/"
echo "  Mode: $([ "$QUICK_MODE" = "--quick" ] && echo "Quick" || echo "Full")"
echo "  Time: $(date)"
rhodawk_auth_active && rhodawk_auth_banner
echo "============================================="
echo ""

# ============================================================
# DNS wildcard pre-check — surfaces wildcard zones BEFORE Phase 1
# brute-forces 5,000+ candidates that all collapse to a single IP.
# Three random labels are queried under the apex; if 2+ resolve, the
# zone has a wildcard A record. Persists `subdomains/wildcard_dns.json`
# so a downstream pass can filter brute-forced subs whose A record
# matches `WILDCARD_DNS_IP`, saving 10+ min of dead-host probing on
# CDN-fronted brands and parked-domain marketing zones.
# Skipped for IP/CIDR/list targets (no apex to dork) and when `dig`
# isn't on PATH.
# ============================================================
_detect_dns_wildcard() {
    local apex="$1" hits=0 r1 r2 r3
    [ -z "$apex" ] && return
    [[ "$apex" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]] && return
    if ! command -v dig &>/dev/null; then return; fi
    r1=$(dig +short +time=2 +tries=1 "bb-no-such-$RANDOM-$RANDOM.$apex" A 2>/dev/null | head -1)
    r2=$(dig +short +time=2 +tries=1 "bb-no-such-$RANDOM-$RANDOM.$apex" A 2>/dev/null | head -1)
    r3=$(dig +short +time=2 +tries=1 "bb-no-such-$RANDOM-$RANDOM.$apex" A 2>/dev/null | head -1)
    [ -n "$r1" ] && hits=$((hits+1))
    [ -n "$r2" ] && hits=$((hits+1))
    [ -n "$r3" ] && hits=$((hits+1))
    if [ "$hits" -ge 2 ]; then
        export WILDCARD_DNS=1
        export WILDCARD_DNS_IP="$r1"
        log_warn "DNS wildcard detected on $apex (random labels resolved to $r1) — brute-forced subs will collapse to wildcard_ip"
        cat > "$RECON_DIR/subdomains/wildcard_dns.json" <<EOF
{"target":"$apex","wildcard":true,"wildcard_ip":"${WILDCARD_DNS_IP:-}","detected_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","note":"random labels resolved — brute-forced subs that resolve to wildcard_ip should be filtered before httpx live-probe to avoid wasted dirsearch on dead hosts."}
EOF
    fi
}
if [ "${TARGET_TYPE:-domain}" = "domain" ]; then
    _detect_dns_wildcard "$TARGET"
fi

# ============================================================
# Phase 1: Subdomain Enumeration (or Host Discovery for IP/CIDR)
# ============================================================
log_info "Phase 1: Subdomain Enumeration"

# ── For domain-list targets: load the file directly, skip enum entirely ───
if [ "$TARGET_TYPE" = "list" ]; then
    log_info "Domain-list target — loading $LIST_FILE (skipping subdomain enum)"
    grep -vE '^[[:space:]]*(#|$)' "$LIST_FILE" \
        | tr -d '\r' \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/^\*\.//' \
        | awk 'NF' \
        | sort -u > "$RECON_DIR/subdomains/all.txt"
    LIST_COUNT=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
    if [ "$LIST_COUNT" -eq 0 ]; then
        log_err "Domain list $LIST_FILE has no usable entries — aborting"
        exit 1
    fi
    log_ok "Loaded $LIST_COUNT host(s) from list"
    SCOPE_LOCK=1
elif [ "$TARGET_TYPE" = "cidr" ]; then
    log_info "CIDR target — running nmap ping sweep to discover live hosts"
    if command -v nmap &>/dev/null; then
        nmap -sn "$TARGET" -oG - 2>/dev/null \
            | awk '/Up$/{print $2}' \
            > "$RECON_DIR/subdomains/all.txt" || true
        LIVE_COUNT=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
        if [ "$LIVE_COUNT" -eq 0 ]; then
            log_warn "nmap did not identify live hosts — expanding the CIDR locally for downstream probing"
            _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
        fi
        log_ok "CIDR sweep: $(wc -l < "$RECON_DIR/subdomains/all.txt") live host(s) discovered"
    else
        log_warn "nmap not installed — expanding the CIDR locally for downstream probing"
        _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
    fi
    # Skip all subdomain enum tools — jump straight to live host probing
elif [ "$TARGET_TYPE" = "ip" ] || [ "$TARGET_TYPE" = "local" ]; then
    if [ "$TARGET_TYPE" = "local" ]; then
        log_info "Local/private target — skipping subdomain enum, crt.sh and wayback (no public data)"
    else
        log_info "Single IP target — skipping subdomain enumeration"
    fi
    # Seed the live-probe list with the exact host[:port] so httpx hits the
    # app's port (e.g. localhost:3000) instead of only 80/443.
    echo "${TARGET}${TARGET_PORT:+:$TARGET_PORT}" > "$RECON_DIR/subdomains/all.txt"
else

# Subfinder (passive, fast)
if command -v subfinder &>/dev/null; then
    log_step "Running subfinder..."
    # Bounded (live-run Fix 1b): passive enum must never hang the run.
    timeout 180 subfinder -d "$TARGET" -silent -all -t 50 -o "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || true
    log_done "subfinder: $(wc -l < "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || echo 0) subdomains"
else
    warn_missing subfinder "subdomain enumeration"
fi

# Amass (passive)
if command -v amass &>/dev/null && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "Running amass (passive, 5min timeout)..."
    timeout 300 amass enum -passive -d "$TARGET" -o "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || true
    # Ensure amass output file exists even if amass failed
    [ ! -f "$RECON_DIR/subdomains/amass.txt" ] && touch "$RECON_DIR/subdomains/amass.txt"
    log_done "amass: $(wc -l < "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || echo 0) subdomains"
else
    [ "$QUICK_MODE" = "--quick" ] && log_warn "Skipping amass (quick mode)"
fi

# crt.sh (certificate transparency)
log_step "Querying crt.sh..."
timeout 60 curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name and name.endswith('.$TARGET'):
                names.add(name)
            elif name and '*' not in name and '.' in name:
                names.add(name)
    for n in sorted(names):
        print(n)
except: pass
" > "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || true
log_done "crt.sh: $(wc -l < "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || echo 0) subdomains"

# Wayback subdomains
log_step "Querying Wayback Machine for subdomains..."
timeout 60 curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null \
    | sed -nE "s|.*://([a-zA-Z0-9._-]+\.$TARGET).*|\1|p" \
    | sort -u > "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || true
log_done "wayback: $(wc -l < "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || echo 0) subdomains"

# Merge and deduplicate all subdomains
cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/subdomains/all.txt"
TOTAL_SUBS=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
log_ok "Total unique subdomains: $TOTAL_SUBS"

# Always include the seed host itself: deep (4+-level) hostnames, DNS-only
# zones and internal names return nothing from passive enum, and the app
# often lives exactly on the seed (mirrors the ip/local seeding above).
echo "${TARGET}${TARGET_PORT:+:$TARGET_PORT}" >> "$RECON_DIR/subdomains/all.txt"
sort -u -o "$RECON_DIR/subdomains/all.txt" "$RECON_DIR/subdomains/all.txt"
TOTAL_SUBS=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
log_ok "Seed host included; probe list now: $TOTAL_SUBS host(s)"

fi  # end of domain-only subdomain enum block

# B3 filter point 1/4: after the Phase 1 merge, BEFORE httpx reads all.txt.
_rhodawk_scope_filter "$RECON_DIR/subdomains/all.txt"

# ============================================================
# Phase 1.5: reconFTW Subdomain/Infra Gap-Fill (RhodawkAI Edition)
# ASN/CIDR enum, DNS permutation, CDN/origin isolation — delegated to
# reconFTW (sub_asn / sub_permut / cdnprovider) via tools/rtw_adapter.py.
# Discovered subdomains are merged into subdomains/all.txt (scope-filtered,
# deduplicated) so Phase 2 httpx probes them in this same run.
# ============================================================
echo ""
log_info "Phase 1.5: reconFTW Subdomain/Infra Gap-Fill"
if _rtw_ready; then
    if [ "$SCOPE_OPT_OUT" = "1" ]; then
        log_warn "reconFTW gap-fill running UNSCOPED (--no-scope-check) — demo/testing only"
    elif [ ${#SCOPE_DOMAIN_ARGS[@]} -eq 0 ]; then
        log_warn "No --scope-domain given — reconFTW delegation will fail closed (adapter blocks; pass scope patterns or --no-scope-check)"
    fi
    _rtw_run_phase "1.5" || log_step "reconFTW Phase 1.5 reported failures — continuing native pipeline"
    mkdir -p "$RECON_DIR/subdomains"
    touch "$RECON_DIR/subdomains/all.txt"
    RTW_SUB_FILES=0
    for _f in "$RECON_DIR"/rtw/*/rtw_subdomains.txt; do
        [ -s "$_f" ] || continue
        cat "$_f" >> "$RECON_DIR/subdomains/all.txt"
        RTW_SUB_FILES=$((RTW_SUB_FILES + 1))
    done
    if [ "$RTW_SUB_FILES" -gt 0 ]; then
        sort -u -o "$RECON_DIR/subdomains/all.txt" "$RECON_DIR/subdomains/all.txt"
        TOTAL_SUBS=$(wc -l < "$RECON_DIR/subdomains/all.txt")
        log_done "reconFTW gap-fill: merged subdomains from $RTW_SUB_FILES file(s); probe list now: $TOTAL_SUBS host(s)"
    else
        log_step "No reconFTW subdomain output to merge (skipped capabilities / missing deps are normal)"
    fi
else
    log_step "reconFTW gap-fill not configured (RTW_HOME unset) — skipping (upstream behavior)"
fi

# B3 filter point 2/4: after the Phase 1.5 merge (gap-fill output was already
# post-call filtered by the adapter; this re-checks the merged probe list).
_rhodawk_scope_filter "$RECON_DIR/subdomains/all.txt"

# ── C6: pre-probe third-party SaaS CNAME quarantine (Commit 3) ────────────────
# httpx is about to probe subdomains/all.txt. A subdomain whose CNAME points
# into third-party SaaS (Zendesk, Statuspage, Greenhouse, Workday, ...)
# is NOT the program's own infrastructure: probing it sends program traffic
# to a vendor and flags recon activity on a shared tenant. BEFORE httpx
# fires, resolve CNAMEs for the probe list and quarantine every alias whose
# canonical target belongs to a known third-party SaaS: removed from
# subdomains/all.txt, recorded in scope/dropped_oos.txt (source tag
# cname_saas_gate), counted into SCOPE_DROPPED_TOTAL (Recon Summary +
# recon_truth.json counts.scope_dropped).
# Resolution order: dnsx -cname -resp (batched, fast) → dig +short CNAME
# (bounded per-host) → Python socket.gethostbyname_ex (stdlib fallback;
# returns the canonical name of the CNAME chain). RHODAWK_CNAME_MAP_FILE
# (test/CI seam) injects pre-resolved "host<TAB>canonical" pairs and skips
# all network resolution. All resolution paths are time-bounded; when
# nothing can be resolved the gate is a no-op (the scope filters above
# remain the fail-closed enforcement layer).
_rhodawk_cname_saas_gate() {
    [ -s "$RECON_DIR/subdomains/all.txt" ] || return 0
    mkdir -p "$RECON_DIR/scope"
    local _cn_data="$RECON_DIR/scope/.cname_resp.txt"
    : > "$_cn_data"
    if [ -n "${RHODAWK_CNAME_MAP_FILE:-}" ] && [ -f "$RHODAWK_CNAME_MAP_FILE" ]; then
        cp "$RHODAWK_CNAME_MAP_FILE" "$_cn_data" 2>/dev/null || true
    elif command -v dnsx >/dev/null 2>&1; then
        timeout 90 dnsx -l "$RECON_DIR/subdomains/all.txt" -cname -resp -silent \
            -o "$_cn_data" >/dev/null 2>&1 || true
    elif command -v dig >/dev/null 2>&1; then
        # dig fallback: one host per query, bounded per query and capped at
        # the first 1000 hosts (deterministic, sorted input) so a huge list
        # can never stall the run. Output mirrors the dnsx/map file shape.
        local _h _n=0
        while IFS= read -r _h && [ "$_n" -lt 1000 ]; do
            [ -z "$_h" ] && continue
            _n=$((_n + 1))
            local _tgt
            _tgt="$(timeout 3 dig +short CNAME "$_h" 2>/dev/null | head -n 1 || true)"
            [ -n "$_tgt" ] && printf '%s\t%s\n' "$_h" "$_tgt" >> "$_cn_data" || true
        done < "$RECON_DIR/subdomains/all.txt"
    else
        # Pure-stdlib fallback: gethostbyname_ex returns the canonical
        # (CNAME-chain) name — a different canonical name means the host is
        # a CNAME alias. Non-resolving hosts are skipped (no data = no
        # decision, and the scope filters remain authoritative).
        timeout 60 python3 - "$RECON_DIR/subdomains/all.txt" "$_cn_data" <<'PYEOF' 2>/dev/null || true
import socket, sys
socket.setdefaulttimeout(2.0)
hosts = [h.strip() for h in open(sys.argv[1], encoding="utf-8", errors="replace") if h.strip()][:1000]
with open(sys.argv[2], "w", encoding="utf-8") as out:
    for h in hosts:
        try:
            canonical = socket.gethostbyname_ex(h)[0]
        except Exception:
            continue
        if canonical and canonical.lower() != h.lower():
            out.write(f"{h}\t{canonical}\n")
PYEOF
    fi

    # Match + quarantine (pure Python over the collected CNAME data).
    local _cn_out
    _cn_out="$(python3 - "$RECON_DIR/subdomains/all.txt" "$_cn_data" "$RECON_DIR/scope/dropped_oos.txt" <<'PYEOF' 2>/dev/null || true
import sys
probe_path, cname_path, dropped_path = sys.argv[1], sys.argv[2], sys.argv[3]
SAAS = ("zendesk.com", "statuspage.io", "freshdesk.com", "myworkdayjobs.com",
        "greenhouse.io", "lever.co", "salesforce.com", "shopify.com",
        "github.io", "marketo.com")

def clean(tok):
    return tok.strip().strip("[]").rstrip(".").lower()

def is_saas(host):
    host = (host or "").lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in SAAS)

# host -> the SaaS canonical target that quarantined it
quarantined = {}
for line in open(cname_path, encoding="utf-8", errors="replace"):
    toks = [clean(t) for t in line.split() if clean(t)]
    if len(toks) < 2:
        continue
    # First token is the queried host (dnsx response or map file). Quarantine
    # it when ANY token on the line resolves to a third-party SaaS domain:
    # either the CNAME answer (host is an alias INTO the SaaS tenant) or the
    # queried host itself (the program pointed a subdomain at a SaaS host).
    saas_tokens = [t for t in toks if is_saas(t)]
    if saas_tokens:
        alias = next((t for t in toks[1:] if is_saas(t)), saas_tokens[0])
        quarantined.setdefault(toks[0], alias)

kept, dropped = [], []
for raw in open(probe_path, encoding="utf-8", errors="replace"):
    h = raw.strip()
    if not h:
        continue
    key = h.lower()
    alias = quarantined.get(key) or quarantined.get(key.split(":")[0])
    if alias:
        dropped.append((h, alias))
    else:
        kept.append(h)

if dropped:
    with open(dropped_path, "a", encoding="utf-8") as df:
        for h, alias in dropped:
            df.write(f"cname_saas_gate\t{h}\tCNAME {alias}\n")
    with open(probe_path, "w", encoding="utf-8") as pf:
        for h in kept:
            pf.write(h + "\n")
print(len(dropped))
PYEOF
)"
    if [ -n "${_cn_out:-}" ] && [ "$_cn_out" -gt 0 ] 2>/dev/null; then
        SCOPE_DROPPED_TOTAL=$((SCOPE_DROPPED_TOTAL + _cn_out))
        log_info "SaaS CNAME gate: quarantined $_cn_out third-party alias(es) from the probe list (scope/dropped_oos.txt)"
    fi
    rm -f "$_cn_data"
}
_rhodawk_cname_saas_gate

# ============================================================
# Phase 2: HTTP Probing
# ============================================================
echo ""
log_info "Phase 2: HTTP Probing"

if [ -x "$HTTPX_BIN" ] && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
    log_step "Probing with httpx (status, title, tech, content-length)..."
    # Scope safety: when scope enforcement is active (SCOPE_ENFORCED=1, exported
    # by tools/hunt.py run_recon whenever a ScopeChecker is configured — always
    # true on the desktop agent path), do NOT follow redirects. An in-scope host
    # can 302 to an out-of-scope host, and httpx would follow it and put traffic
    # on the wire toward a host outside the program allowlist. Redirects are
    # still visible via the status code + Location; we just don't fetch them.
    HTTPX_REDIRECT_ARGS=(-follow-redirects)
    if [ "${SCOPE_ENFORCED:-0}" = "1" ]; then
        HTTPX_REDIRECT_ARGS=()
        log_info "Scope enforcement on: httpx redirect-following disabled (no off-scope hops)"
    fi
    "$HTTPX_BIN" -l "$RECON_DIR/subdomains/all.txt" \
        -silent \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        ${HTTPX_REDIRECT_ARGS[@]+"${HTTPX_REDIRECT_ARGS[@]}"} \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
        -o "$RECON_DIR/live/httpx_full.txt" 2>/dev/null || true

    # Extract just the URLs for other tools
    awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/urls.txt" 2>/dev/null || true

    LIVE_COUNT=$(wc -l 2>/dev/null < "$RECON_DIR/live/urls.txt" || echo 0)
    log_done "Live hosts: $LIVE_COUNT"

    # Separate by status code
    grep '\[200\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_200.txt" 2>/dev/null || true
    grep '\[30[12]\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || true
    grep '\[403\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_403.txt" 2>/dev/null || true
    grep '\[401\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_401.txt" 2>/dev/null || true

    log_done "200 OK: $(wc -l < "$RECON_DIR/live/status_200.txt" 2>/dev/null || echo 0)"
    log_done "3xx Redirect: $(wc -l < "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || echo 0)"
    log_done "403 Forbidden: $(wc -l < "$RECON_DIR/live/status_403.txt" 2>/dev/null || echo 0)"
    log_done "401 Auth Required: $(wc -l < "$RECON_DIR/live/status_401.txt" 2>/dev/null || echo 0)"

    # B2: when scoped, httpx no longer follows redirects blindly (above). A
    # redirect destination is RECORDED as a finding in live/redirects.txt and
    # probed ONLY if it is in scope: the Location is read with an in-scope
    # HEAD request (curl, bounded), classified through the same scope rules
    # as every other asset, and only in-scope destinations enter a bounded
    # second httpx pass. Out-of-scope destinations are never fetched.
    if [ "${SCOPE_ENFORCED:-0}" = "1" ] && [ -s "$RECON_DIR/live/status_3xx.txt" ] \
       && command -v curl &>/dev/null; then
        log_step "Scoped redirect handling: recording destinations (no blind follow)..."
        : > "$RECON_DIR/live/redirects.txt"
        : > "$RECON_DIR/live/redirects_inscope.txt"
        _redir_n=0
        while IFS= read -r _line && [ "$_redir_n" -lt 50 ]; do
            _url=$(printf '%s' "$_line" | awk '{print $1}')
            [ -z "$_url" ] && continue
            _loc=$(curl -sI --max-time 5 ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} "$_url" 2>/dev/null \
                | awk 'tolower($1)=="location:"{sub(/\r$/,"",$2); print $2; exit}')
            [ -z "$_loc" ] && continue
            _dest_host=$(printf '%s' "$_loc" | sed 's|https\?://||;s|[/:].*||')
            _dest_port=$(printf '%s' "$_loc" | sed -nE 's|https?://[^/]*:([0-9]+).*|\1|p')
            _in_scope=0
            if [ ${#SCOPE_DOMAIN_ARGS[@]} -gt 0 ]; then
                python3 "$BASE_DIR/tools/scope_checker.py" \
                    ${SC_CHECK_ARGS[@]+"${SC_CHECK_ARGS[@]}"} "$_loc" >/dev/null 2>&1 && _in_scope=1
            else
                # Self-scoped target: the destination host must match the
                # target host — and when the target carries an explicit port
                # (host:port lab target), the destination must use that port.
                if [ "$_dest_host" = "$TARGET" ]; then
                    if [ -n "$TARGET_PORT" ]; then
                        [ "$_dest_port" = "$TARGET_PORT" ] && _in_scope=1
                    else
                        _in_scope=1
                    fi
                fi
            fi
            if [ "$_in_scope" = "1" ]; then
                printf '[IN-SCOPE] %s <- redirect from %s\n' "$_loc" "$_url" >> "$RECON_DIR/live/redirects.txt"
                printf '%s\n' "$_loc" >> "$RECON_DIR/live/redirects_inscope.txt"
            else
                printf '[OOS] %s <- redirect from %s (recorded, NOT probed)\n' "$_loc" "$_url" >> "$RECON_DIR/live/redirects.txt"
                log_info "Redirect destination out of scope — recorded, not probed: $_loc"
            fi
            _redir_n=$((_redir_n + 1))
        done < "$RECON_DIR/live/status_3xx.txt"
        if [ -s "$RECON_DIR/live/redirects_inscope.txt" ]; then
            log_step "Probing in-scope redirect destinations only..."
            sort -u -o "$RECON_DIR/live/redirects_inscope.txt" "$RECON_DIR/live/redirects_inscope.txt"
            "$HTTPX_BIN" -l "$RECON_DIR/live/redirects_inscope.txt" \
                -silent -status-code -threads "$THREADS" -rate-limit "$RATE_LIMIT" \
                ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
                -o "$RECON_DIR/live/httpx_redirect_probe.txt" 2>/dev/null || true
            [ -s "$RECON_DIR/live/httpx_redirect_probe.txt" ] && \
                cat "$RECON_DIR/live/httpx_redirect_probe.txt" >> "$RECON_DIR/live/httpx_full.txt"
            awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" 2>/dev/null | sort -u > "$RECON_DIR/live/urls.txt" || true
            LIVE_COUNT=$(wc -l 2>/dev/null < "$RECON_DIR/live/urls.txt" || echo 0)
        fi
    fi
else
    if ! [ -x "$HTTPX_BIN" ]; then
        warn_missing httpx "HTTP probing"
    else
        log_warn "No hosts to probe (empty subdomains/all.txt) — skipping HTTP probing"
    fi
fi

# ============================================================
# Phase 2.5: CDN/Origin Classification (RhodawkAI Edition, Step 2A)
# Classify every live host into CDN_EDGE / THIRD_PARTY_SAAS /
# FIRST_PARTY_ORIGIN so Phase 3 spends nmap minutes on origins only — never
# on Cloudflare/Vercel/Akamai/Fastly/CloudFront edges, and never on
# third-party SaaS endpoints (Shopify, HubSpot, Zendesk, GitHub Pages, ...).
# Evidence per host (best-effort, bounded to the first 100 live hosts):
#   - CNAME + A record via dig (2s/1-try caps)
#   - httpx tech-detect column captured in Phase 2
# The classifier itself lives in tools/recon_fusion.py (pure Python, unit
# tested) so bash and the fusion pass share ONE implementation.
# ============================================================
HOSTS_DIR="$RECON_DIR/hosts"
HOST_CLASSES="$HOSTS_DIR/host_classes.txt"
ORIGIN_TARGETS="$HOSTS_DIR/origin_targets.txt"
mkdir -p "$HOSTS_DIR"
: > "$HOST_CLASSES"; : > "$ORIGIN_TARGETS"; : > "$HOSTS_DIR/resolution.txt"

if [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_info "Phase 2.5: CDN/Origin Classification"
    log_step "Resolving CNAME/A records (bounded: first 100 live hosts)..."
    head -100 "$RECON_DIR/live/urls.txt" | while IFS= read -r live_url; do
        host=$(printf '%s' "$live_url" | sed 's|https\?://||;s|[/:].*||')
        [ -z "$host" ] && continue
        cname="" ; ip=""
        if command -v dig &>/dev/null; then
            cname=$(dig +short +time=2 +tries=1 "$host" CNAME 2>/dev/null | head -1)
            ip=$(dig +short +time=2 +tries=1 "$host" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        fi
        printf '%s\t%s\t%s\n' "$host" "$ip" "$cname" >> "$HOSTS_DIR/resolution.txt"
    done
    if python3 "$BASE_DIR/tools/recon_fusion.py" classify --recon-dir "$RECON_DIR" >/dev/null 2>&1; then
        ORIGIN_COUNT=$(grep -c 'FIRST_PARTY_ORIGIN' "$HOST_CLASSES" 2>/dev/null)
        CDN_COUNT=$(grep -c 'CDN_EDGE' "$HOST_CLASSES" 2>/dev/null)
        SAAS_COUNT=$(grep -c 'THIRD_PARTY_SAAS' "$HOST_CLASSES" 2>/dev/null)
        log_done "Classified: ${ORIGIN_COUNT:-0} first-party origin(s), ${CDN_COUNT:-0} CDN edge(s), ${SAAS_COUNT:-0} third-party SaaS"
        awk -F'\t' '$3 == "FIRST_PARTY_ORIGIN" { print ($2 != "" ? $2 : $1) }' \
            "$HOST_CLASSES" > "$ORIGIN_TARGETS" 2>/dev/null || true
        sort -u -o "$ORIGIN_TARGETS" "$ORIGIN_TARGETS" 2>/dev/null || true
    else
        log_warn "host classification failed — Phase 3 falls back to the legacy single-target nmap"
    fi
fi

# ============================================================
# Phase 3: Port Scanning (origin-only — Step 2A)
# ============================================================
echo ""
log_info "Phase 3: Port Scanning"

if command -v nmap &>/dev/null; then
    # Step 2A: never nmap a CDN edge or a SaaS endpoint — scanning a
    # Cloudflare/Akamai edge only fingerprints the CDN, and scanning
    # Shopify/Zendesk hosts probes the vendor, not the program. Log every
    # skip explicitly instead of silently widening or narrowing the scan.
    if [ -s "$HOST_CLASSES" ]; then
        awk -F'\t' '$3 == "CDN_EDGE" || $3 == "THIRD_PARTY_SAAS" {
            ip = ($2 != "" ? $2 : $1)
            provider = ($4 != "" ? $4 : "unknown")
            printf "[i] Skipping nmap on %s host/IP %s (%s)\n", $3, ip, provider
        }' "$HOST_CLASSES"
    fi
    if [ -s "$ORIGIN_TARGETS" ]; then
        log_step "Running nmap (top 1000 ports) on FIRST_PARTY_ORIGIN target(s) only: $(wc -l < "$ORIGIN_TARGETS" | tr -d ' ')"
        nmap -sV --top-ports 1000 -T4 --open -iL "$ORIGIN_TARGETS" \
            -oN "$RECON_DIR/ports/nmap_results.txt" \
            -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
        log_done "Nmap scan complete (origin IPs only)"
    elif [ -s "$HOST_CLASSES" ]; then
        log_warn "No FIRST_PARTY_ORIGIN targets classified — skipping nmap entirely (0 origin IPs, 0 packets spent on edges)"
        : > "$RECON_DIR/ports/nmap_greppable.txt"
    else
        log_step "Running nmap (top 1000 ports) on $TARGET..."
        nmap -sV --top-ports 1000 -T4 --open "$TARGET" \
            -oN "$RECON_DIR/ports/nmap_results.txt" \
            -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
        log_done "Nmap scan complete"
    fi

    # Extract open ports (macOS compatible - no grep -P)
    grep "open" "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null \
        | sed -nE 's/.*[^0-9]([0-9]+)\/open.*/\1\/open/p' \
        | sort -u > "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || true
    log_done "Open ports: $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
else
    warn_missing nmap "port scan"
fi

# ============================================================
# Phase 4: URL Collection
# ============================================================
echo ""
log_info "Phase 4: URL Collection"

# GAU - Get All URLs (wayback, commoncrawl, otx, urlscan)
# Local/private hosts have no public archive — skip straight to active crawling.
if [ "$TARGET_TYPE" = "local" ]; then
    log_info "Local target — skipping gau/wayback (no historical data); relying on katana crawl"
elif command -v gau &>/dev/null; then
    log_step "Running gau (historical URLs)..."
    echo "$TARGET" | gau --threads 20 --o "$RECON_DIR/urls/gau.txt" 2>/dev/null || \
    echo "$TARGET" | gau > "$RECON_DIR/urls/gau.txt" 2>/dev/null || true
    log_done "gau: $(wc -l < "$RECON_DIR/urls/gau.txt" 2>/dev/null || echo 0) URLs"
else
    log_warn "gau not installed — using wayback fallback. To install gau:"
    dep_install_hint gau
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=5000" \
        > "$RECON_DIR/urls/wayback.txt" 2>/dev/null || true
    log_done "wayback: $(wc -l < "$RECON_DIR/urls/wayback.txt" 2>/dev/null || echo 0) URLs"
fi

# katana — active crawl on live hosts (5 min cap prevents infinite crawl on
# content-heavy sites like news/video portals)

# Single managed Chromium (Step 3): the exact path lives in capabilities.json
# ("chromium_path", recorded once by install_tools.sh --browser). NO disk
# scanning at runtime — if that path is set and executable, flip katana into
# headless SPA mode (CHROME_BIN/CHROME_PATH + -system-chrome) so JS chunk
# extraction reaches SPA routes; otherwise standard HTTP crawl.
_rhodawk_chromium_path() {
    python3 - <<'PY' 2>/dev/null || true
import json
import os
from pathlib import Path

cap = os.environ.get("RHODAWK_CAPABILITIES_FILE")
if cap:
    p = Path(cap).expanduser()
else:
    bh = os.environ.get("RHODAWK_HOME")
    p = (Path(bh).expanduser() if bh
         else Path.home() / ".rhodawk") / "capabilities.json"
try:
    val = json.loads(p.read_text()).get("chromium_path", "")
except Exception:
    val = ""
print(val if isinstance(val, str) else "")
PY
}
CHROMIUM_PATH="$(_rhodawk_chromium_path)"
KATANA_BROWSER_ARGS=()
if [ -n "$CHROMIUM_PATH" ] && [ -x "$CHROMIUM_PATH" ]; then
    export CHROME_BIN="$CHROMIUM_PATH" CHROME_PATH="$CHROMIUM_PATH"
    KATANA_BROWSER_ARGS=(-headless -system-chrome)
    log_step "Managed Chromium: $CHROMIUM_PATH — katana headless SPA mode (JS chunk extraction)"
fi

if command -v katana &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Running katana (active crawl, 5min cap, top 50 hosts)..."
    if [ ${#KATANA_BROWSER_ARGS[@]} -eq 0 ]; then
        log_info "Tip: bash install_tools.sh --browser enables headless SPA crawling"
    fi
    head -50 "$RECON_DIR/live/urls.txt" > "$RECON_DIR/urls/katana_targets.txt"
    timeout 300 katana \
        -list "$RECON_DIR/urls/katana_targets.txt" \
        -d 3 -jc -kf all -silent \
        -c 50 -p 20 \
        ${KATANA_BROWSER_ARGS[@]+"${KATANA_BROWSER_ARGS[@]}"} \
        ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
        -o "$RECON_DIR/urls/katana.txt" 2>/dev/null || true
    log_done "katana: $(wc -l < "$RECON_DIR/urls/katana.txt" 2>/dev/null || echo 0) URLs"
fi

# Merge all collected URLs
cat "$RECON_DIR/urls/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/urls/all.txt" 2>/dev/null || true
log_done "Total unique URLs: $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"

# B3 filter point 3/4: after the Phase 4 URL collection merge (gau/katana).
_rhodawk_scope_filter "$RECON_DIR/urls/all.txt"

# Filter interesting URLs
if [ -s "$RECON_DIR/urls/all.txt" ]; then
    # URLs with parameters (potential injection points)
    grep '?' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/with_params.txt" 2>/dev/null || true
    log_done "URLs with parameters: $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"

    # JS files
    grep -iE '\.js(\?|$)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
    log_done "JS files: $(wc -l < "$RECON_DIR/urls/js_files.txt" 2>/dev/null || echo 0)"

    # API endpoints
    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || true
    log_done "API endpoints: $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"

    # Potentially sensitive paths
    grep -iE '\.(env|config|xml|json|yaml|yml|bak|backup|old|orig|sql|db|log|txt|conf|ini|htaccess|htpasswd|git)' \
        "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || true
    log_done "Sensitive paths: $(wc -l < "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || echo 0)"
fi

# ============================================================
# Phase 5: JS Analysis
# ============================================================
echo ""
log_info "Phase 5: JavaScript Analysis"

if [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    log_step "Extracting endpoints from JS files (top 50)..."
    mkdir -p "$RECON_DIR/js"

    head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
        curl -s --max-time 10 ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} "$js_url" 2>/dev/null | \
            sed -nE 's/.*["'"'"']([a-zA-Z0-9_/.-]*(\/[a-zA-Z0-9_/.-]+)+)["'"'"'].*/\1/p' \
            >> "$RECON_DIR/js/endpoints_raw.txt" 2>/dev/null || true
    done

    if [ -f "$RECON_DIR/js/endpoints_raw.txt" ]; then
        sort -u "$RECON_DIR/js/endpoints_raw.txt" > "$RECON_DIR/js/endpoints.txt"
        log_done "JS endpoints: $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"

        # Extract potential secrets from JS
        head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
            curl -s --max-time 10 ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} "$js_url" 2>/dev/null | \
                grep -oiE '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9_\-]{8,}' \
                >> "$RECON_DIR/js/potential_secrets.txt" 2>/dev/null || true
        done
        if [ -s "$RECON_DIR/js/potential_secrets.txt" ]; then
            sort -u "$RECON_DIR/js/potential_secrets.txt" -o "$RECON_DIR/js/potential_secrets.txt"
            log_warn "Potential secrets found in JS: $(wc -l < "$RECON_DIR/js/potential_secrets.txt")"
        fi
    fi
else
    log_warn "No JS files found — skipping JS analysis"
fi

# ============================================================
# Phase 5.5: reconFTW Web/JS/TLS Gap-Fill (RhodawkAI Edition)
# JS source-map/AST secret extraction, virtual-host discovery, TLS IP pivots,
# favicon fingerprinting — delegated to reconFTW (jschecks / virtualhosts /
# tls_ip_pivots / favirecon_tech) via tools/rtw_adapter.py. Newly discovered
# JS endpoints/routes are merged into the URL corpus (urls/all.txt) so Phase 6
# directory fuzzing, the candidate classifiers and the final Summary see them.
# ============================================================
echo ""
log_info "Phase 5.5: reconFTW Web/JS/TLS Gap-Fill"
if _rtw_ready; then
    _rtw_run_phase "5.5" || log_step "reconFTW Phase 5.5 reported failures — continuing native pipeline"
    mkdir -p "$RECON_DIR/urls"
    touch "$RECON_DIR/urls/all.txt"
    RTW_URL_FILES=0
    for _f in "$RECON_DIR"/rtw/*/rtw_urls.txt; do
        [ -s "$_f" ] || continue
        cat "$_f" >> "$RECON_DIR/urls/all.txt"
        RTW_URL_FILES=$((RTW_URL_FILES + 1))
    done
    if [ "$RTW_URL_FILES" -gt 0 ]; then
        sort -u -o "$RECON_DIR/urls/all.txt" "$RECON_DIR/urls/all.txt"
        log_done "reconFTW gap-fill: merged URLs from $RTW_URL_FILES file(s) into urls/all.txt"
    else
        log_step "No reconFTW URL output to merge (skipped capabilities / missing deps are normal)"
    fi
else
    log_step "reconFTW gap-fill not configured (RTW_HOME unset) — skipping (upstream behavior)"
fi

# ============================================================
# Phase 5.75: Headless JS Crawl (OPT-IN — requires --js-crawl)
# Loads live hosts in a real headless Chromium (Playwright) and captures the
# XHR/fetch endpoints an SPA only exposes at runtime (see CRAWLER-REDESIGN.md).
# Scope contract is identical to every other phase: seeds are pre-checked
# against the resolved scope authority, the captured URL file passes through
# the SAME B3 scope filter below, and missing Playwright/Chromium degrades to
# a WARN + skip (never a hard failure). Opt-out runs skip the phase entirely.
# ============================================================
if [ "$JS_CRAWL" = "1" ]; then
    if [ "$SCOPE_OPT_OUT" = "1" ]; then
        log_step "Headless JS crawl skipped (--no-scope-check: browsing without a scope authority is refused)"
    else
        echo ""
        log_info "Phase 5.75: Headless JS Crawl"
        _js_crawl_scope_args=()
        if [ -n "${SCOPE_MANIFEST:-}" ]; then
            _js_crawl_scope_args=(--manifest "$SCOPE_MANIFEST")
        elif [ ${#SC_CHECK_ARGS[@]} -gt 0 ]; then
            _js_crawl_scope_args=(${SC_CHECK_ARGS[@]+"${SC_CHECK_ARGS[@]}"})
        else
            case "$(printf '%s' "${TARGET_TYPE:-}" | tr -d '[:space:]')" in
                ip|local|cidr) _js_crawl_scope_args=(--domain "$TARGET") ;;
                *)
                    log_err "SCOPE BLOCK: --js-crawl requires a scope authority (manifest or --scope-domain patterns)"
                    _rhodawk_audit_scope_block "js-crawl invoked without any scope authority (fail-closed)"
                    exit 3 ;;
            esac
        fi
        # Seeds: live hosts first (top 10), same-origin discovered URLs second.
        mkdir -p "$RECON_DIR/js_crawl"
        _js_seeds="$RECON_DIR/js_crawl/.seeds.txt"
        grep -E '^https?://' "$RECON_DIR/live/urls.txt" 2>/dev/null | head -10 > "$_js_seeds" || true
        grep -E '^https?://' "$RECON_DIR/urls/all.txt" 2>/dev/null | head -10 >> "$_js_seeds" || true
        sort -u -o "$_js_seeds" "$_js_seeds" 2>/dev/null || true
        if [ ! -s "$_js_seeds" ]; then
            # httpx absent or zero live hosts — the normalized target is still
            # a valid seed (this is exactly the SPA-demo case: one host, no
            # probing tooling). Build the seed from TARGET/TARGET_PORT.
            case "$TARGET_TYPE" in
                ip|local|cidr) _js_seed="http://$TARGET" ;;
                *) _js_seed="https://$TARGET" ;;
            esac
            if [ -n "$TARGET_PORT" ]; then
                case "$TARGET_PORT" in
                    443) _js_seed="https://$TARGET:$TARGET_PORT" ;;
                    *)   _js_seed="http://$TARGET:$TARGET_PORT" ;;
                esac
            fi
            printf '%s\n' "$_js_seed" > "$_js_seeds"
            log_step "No live URLs yet — seeding the crawl with the target itself ($_js_seed)"
        fi
        if [ -s "$_js_seeds" ]; then
            if python3 "$BASE_DIR/tools/js_crawl.py" \
                    $(sed 's/^/--url /' "$_js_seeds" | tr '\n' ' ') \
                    --recon-dir "$RECON_DIR" \
                    ${_js_crawl_scope_args[@]+"${_js_crawl_scope_args[@]}"} \
                    --max-pages 10 --timeout 180; then
                if [ -s "$RECON_DIR/js_crawl/endpoints.txt" ]; then
                    # Same B3 contract as every other URL source: the crawled
                    # corpus is scope-filtered BEFORE it touches urls/all.txt.
                    _rhodawk_scope_filter "$RECON_DIR/js_crawl/endpoints.txt"
                    mkdir -p "$RECON_DIR/urls"
                    cat "$RECON_DIR/js_crawl/endpoints.txt" >> "$RECON_DIR/urls/all.txt"
                    sort -u -o "$RECON_DIR/urls/all.txt" "$RECON_DIR/urls/all.txt"
                    log_done "Headless JS crawl: $(wc -l < "$RECON_DIR/js_crawl/endpoints.txt" 2>/dev/null || echo 0) endpoint(s) merged into urls/all.txt"
                else
                    log_step "Headless JS crawl: no endpoints captured (see js_crawl/summary.json)"
                fi
            else
                log_warn "Headless JS crawl failed — continuing (see js_crawl/summary.json)"
            fi
        else
            log_step "Headless JS crawl: no seed URLs — skipping"
        fi
        rm -f "$_js_seeds"
    fi
fi

# B3 filter point 4/4: after the Phase 5.5 merge (before Phase 6 fuzzing and
# the Summary read the URL corpus).
_rhodawk_scope_filter "$RECON_DIR/urls/all.txt"

# ============================================================
# Phase 6: Directory Fuzzing
# ============================================================
echo ""
log_info "Phase 6: Directory Fuzzing"

WORDLIST_DIR="$BASE_DIR/wordlists"
LEGACY_WORDLIST_DIR="$BASE_DIR/tools/wordlists"

if command -v ffuf &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    # Select wordlist
    WORDLIST=""
    if [ -f "$WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$WORDLIST_DIR/common.txt"
    elif [ -f "$LEGACY_WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$LEGACY_WORDLIST_DIR/common.txt"
    elif [ -f "$WORDLIST_DIR/raft-medium-dirs.txt" ]; then
        WORDLIST="$WORDLIST_DIR/raft-medium-dirs.txt"
    elif [ -f "$LEGACY_WORDLIST_DIR/raft-medium-dirs.txt" ]; then
        WORDLIST="$LEGACY_WORDLIST_DIR/raft-medium-dirs.txt"
    elif [ -f /usr/share/wordlists/dirb/common.txt ]; then
        WORDLIST="/usr/share/wordlists/dirb/common.txt"
    fi

    if [ -n "$WORDLIST" ]; then
        # Fuzz top 5 live hosts
        FUZZ_COUNT=0
        MAX_FUZZ=$([ "$QUICK_MODE" = "--quick" ] && echo 2 || echo 5)

        while IFS= read -r url && [ "$FUZZ_COUNT" -lt "$MAX_FUZZ" ]; do
            domain=$(echo "$url" | sed 's|https\?://||;s|[/:].*||')
            log_step "Fuzzing: $url"
            ffuf -u "${url}/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,301,302,403,405 \
                -ac \
                -t "$THREADS" \
                -rate "$RATE_LIMIT" \
                -sf \
                -timeout 10 \
                ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
                -o "$RECON_DIR/dirs/ffuf_${domain}.json" \
                -of json 2>/dev/null || true
            ((FUZZ_COUNT++))
        done < "$RECON_DIR/live/urls.txt"

        log_done "Directory fuzzing complete ($FUZZ_COUNT hosts)"
    else
        log_warn "No wordlist found — run: python3 tools/hunt.py --setup-wordlists"
    fi
else
    if ! command -v ffuf &>/dev/null; then
        warn_missing ffuf "directory fuzzing"
    else
        log_warn "No live hosts — skipping directory fuzzing"
    fi
fi

# ============================================================
# Phase 6.5: Config File Exposure Check
# ============================================================
echo ""
log_info "Phase 6.5: Config File Exposure Check"

if [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Checking for exposed config files (env.js, app_env.js, .env, etc.)..."
    CONFIG_PATHS=(
        "/env.js"
        "/app_env.js"
        "/config.js"
        "/settings.js"
        "/.env"
        "/.env.local"
        "/.env.production"
        "/.env.development"
        "/config/env.js"
        "/static/env.js"
        "/assets/env.js"
    )

    mkdir -p "$RECON_DIR/exposure"
    : > "$RECON_DIR/exposure/config_files.txt"

    while IFS= read -r base_url; do
        for path in "${CONFIG_PATHS[@]}"; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} "${base_url}${path}" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ]; then
                CONTENT_TYPE=$(curl -sI --max-time 5 ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} "${base_url}${path}" 2>/dev/null | grep -i content-type | head -1)
                # Only flag if it returns JS/JSON/text (not HTML error pages)
                if echo "$CONTENT_TYPE" | grep -qiE '(javascript|json|text/plain)'; then
                    echo "[EXPOSED] ${base_url}${path}" >> "$RECON_DIR/exposure/config_files.txt"
                    log_vuln "Config exposed: ${base_url}${path}"
                fi
            fi
        done
    done < <(head -30 "$RECON_DIR/live/urls.txt")

    CONFIG_COUNT=$(wc -l < "$RECON_DIR/exposure/config_files.txt" 2>/dev/null | tr -d ' ')
    [ "$CONFIG_COUNT" -gt 0 ] && log_warn "Exposed config files: $CONFIG_COUNT" || log_done "Config files: clean"
else
    log_warn "No live hosts — skipping config check"
fi

# ============================================================
# Phase 7: Parameter Discovery
# ============================================================
echo ""
log_info "Phase 7: Parameter Discovery"

if [ -s "$RECON_DIR/urls/with_params.txt" ]; then
    log_step "Extracting parameters from collected URLs..."

    # Extract parameter names (macOS compatible - no grep -P)
    sed -nE 's/.*[?&]([^=&]+)=.*/\1/p' "$RECON_DIR/urls/with_params.txt" 2>/dev/null \
        | sort | uniq -c | sort -rn > "$RECON_DIR/params/param_frequency.txt" 2>/dev/null || true

    # Get unique param names
    awk '{print $2}' "$RECON_DIR/params/param_frequency.txt" > "$RECON_DIR/params/unique_params.txt" 2>/dev/null || true
    log_done "Unique parameters: $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

    # Flag interesting params (potential injection points)
    grep -iE '(url|redirect|next|return|callback|dest|file|path|page|template|include|src|ref|uri|link|target|goto|out|view|dir|show|site|domain|rurl|return_to|continue|window|data|reference|to|img|load|doc|download)' \
        "$RECON_DIR/params/unique_params.txt" > "$RECON_DIR/params/interesting_params.txt" 2>/dev/null || true

    if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
        log_warn "Interesting params (potential vulns): $(wc -l < "$RECON_DIR/params/interesting_params.txt")"
        echo "      Params: $(head -5 "$RECON_DIR/params/interesting_params.txt" | tr '\n' ', ')"
    fi
else
    log_warn "No parameterized URLs found — skipping"
fi

# ============================================================
# Phase 8: CI/CD Workflow Scan (auto-detect GitHub org)
# ============================================================
log_info "Phase 8: CI/CD Workflow Scan"

GITHUB_ORGS=""
CICD_SCANNER="$(dirname "$0")/cicd_scanner.sh"

# Extract github.com/<org> patterns from recon data
for f in "$RECON_DIR/live/httpx_full.txt" "$RECON_DIR/js/endpoints.txt" "$RECON_DIR/urls/all.txt"; do
    if [ -f "$f" ]; then
        GITHUB_ORGS="$GITHUB_ORGS $(grep -oE 'github\.com/[a-zA-Z0-9_-]+' "$f" 2>/dev/null | sed 's#.*github\.com/##' || true)"
    fi
done

# Deduplicate and limit to 5
GITHUB_ORGS=$(echo "$GITHUB_ORGS" | tr ' ' '\n' | grep -v '^$' | sort -u | head -5)

if [ -n "$GITHUB_ORGS" ] && [ -x "$CICD_SCANNER" ] && command -v sisakulint &>/dev/null; then
    for ORG in $GITHUB_ORGS; do
        log_info "CI/CD scan: org:$ORG"
        bash "$CICD_SCANNER" "org:$ORG" --output-dir "$RECON_DIR/cicd/$ORG/" || true
    done
else
    if [ -z "$GITHUB_ORGS" ]; then
        log_warn "GitHub org not detected — CI/CD scan skipped"
    elif ! command -v sisakulint &>/dev/null; then
        log_warn "sisakulint not installed — CI/CD scan skipped"
    fi
fi

# ============================================================
# Phase 9: Nuclei vulnerability sweep (optional, gated on installed binary)
# ============================================================
echo ""
log_info "Phase 9: Nuclei Vulnerability Sweep"

if command -v nuclei &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    NUCLEI_OUT="$RECON_DIR/nuclei"
    mkdir -p "$NUCLEI_OUT"
    NUC_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 50 || echo 200)
    NUC_SEV=$([ "$QUICK_MODE" = "--quick" ] && echo "high,critical" || echo "medium,high,critical")
    NUC_TIMEOUT=$([ "$QUICK_MODE" = "--quick" ] && echo 600 || echo 1800)

    head -"$NUC_LIMIT" "$RECON_DIR/live/urls.txt" > "$NUCLEI_OUT/targets.txt"
    log_step "nuclei on $(wc -l < "$NUCLEI_OUT/targets.txt" | tr -d ' ') hosts (severity=$NUC_SEV, timeout=${NUC_TIMEOUT}s)..."

    NUC_RL="${NUC_RATE_LIMIT:-300}"
    NUC_C="${NUC_CONCURRENCY:-50}"
    NUC_BS="${NUC_BULK_SIZE:-50}"

    timeout "$NUC_TIMEOUT" nuclei \
        -l "$NUCLEI_OUT/targets.txt" \
        -severity "$NUC_SEV" \
        -rl "$NUC_RL" \
        -c "$NUC_C" \
        -bs "$NUC_BS" \
        -silent \
        -stats \
        ${RHODAWK_AUTH_ARGS[@]+"${RHODAWK_AUTH_ARGS[@]}"} \
        -jsonl \
        -o "$NUCLEI_OUT/findings.jsonl" 2>/dev/null || true

    if [ -s "$NUCLEI_OUT/findings.jsonl" ]; then
        # Severity buckets for human review
        for sev in critical high medium low info; do
            grep -F "\"severity\":\"$sev\"" "$NUCLEI_OUT/findings.jsonl" \
                > "$NUCLEI_OUT/${sev}.jsonl" 2>/dev/null || true
            n=$(wc -l < "$NUCLEI_OUT/${sev}.jsonl" 2>/dev/null | tr -d ' ')
            [ "$n" -gt 0 ] && log_done "nuclei $sev: $n"
        done
    else
        log_done "nuclei: no findings"
    fi
else
    [ -z "$(command -v nuclei)" ] && warn_missing nuclei "template scan"
fi

# ============================================================
# Phase 10: Subdomain takeover quick-check (CNAME fingerprint grep)
# ============================================================
echo ""
log_info "Phase 10: Subdomain Takeover Quick-Check"

if command -v dig &>/dev/null && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
    TAKEOVER_OUT="$RECON_DIR/takeover_candidates.txt"
    : > "$TAKEOVER_OUT"
    SUB_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 100 || echo 500)

    log_step "Resolving CNAMEs for top $SUB_LIMIT subdomains..."
    head -"$SUB_LIMIT" "$RECON_DIR/subdomains/all.txt" | while IFS= read -r host; do
        [ -z "$host" ] && continue
        cname=$(dig +short "$host" CNAME 2>/dev/null | head -1)
        [ -z "$cname" ] && continue
        # Match common claimable-service CNAME suffixes (extend list as needed)
        case "$cname" in
            *github.io.*|*herokuapp.com.*|*herokussl.com.*|\
            *s3.amazonaws.com.*|*s3-website*.amazonaws.com.*|\
            *azurewebsites.net.*|*cloudapp.net.*|*trafficmanager.net.*|\
            *shopify.com.*|*myshopify.com.*|\
            *wordpress.com.*|*ghost.io.*|*tumblr.com.*|\
            *pantheonsite.io.*|*surge.sh.*|*netlify.app.*|*vercel.app.*|\
            *zendesk.com.*|*helpjuice.com.*|*helpscout.net.*|*statuspage.io.*|\
            *fastly.net.*|*readme.io.*|*intercom.help.*)
                echo "$host  CNAME→ $cname" >> "$TAKEOVER_OUT" ;;
        esac
    done

    n=$(wc -l < "$TAKEOVER_OUT" | tr -d ' ')
    if [ "$n" -gt 0 ]; then
        log_warn "$n potential takeover candidate(s) — review $TAKEOVER_OUT"
        log_warn "Confirm with: ./tools/takeover_scanner.sh --recon $RECON_DIR"
    else
        log_done "Takeover quick-check: clean"
    fi
fi

# ============================================================
# Canonical Fusion (RhodawkAI Edition, Step 2B/2C) — runs BEFORE the LLM
# analysis pass: merge every recon artifact + published reconFTW outputs
# into <recon_dir>/recon_truth.json (dedup, provenance, SimHash host
# clustering, CDN/origin classes, tool_health), diff against the previous
# run into delta.json (previous truth archived to recon_truth.prev.json),
# and mirror to ~/.rhodawk/recon/<target>/recon_truth.json.
# ============================================================
echo ""
log_info "Canonical Fusion (recon_truth.json)"
if command -v python3 &>/dev/null && [ -f "$BASE_DIR/tools/recon_fusion.py" ]; then
    if python3 "$BASE_DIR/tools/recon_fusion.py" fuse --recon-dir "$RECON_DIR" --target "$TARGET" \
        ${RTW_SCOPE_ARGS[@]+"${RTW_SCOPE_ARGS[@]}"} ; then
        :
    else
        _fuse_rc=$?
        # B1: a failed fusion is never swallowed silently — visible warning
        # plus a FAILED FUSION row in rtw_manifest.json (surfaces in
        # recon_truth.json tool_health and the health-table).
        log_err "CANONICAL FUSION FAILED (exit $_fuse_rc) — recon_truth.json/delta.json were NOT regenerated this run; raw artifacts remain the fallback"
        python3 "$BASE_DIR/tools/recon_fusion.py" mark-failed --target "$TARGET" \
            --reason "fuse failed (exit $_fuse_rc) in recon_engine.sh" >/dev/null 2>&1 || true
    fi
else
    log_err "python3 / recon_fusion.py unavailable — canonical fusion SKIPPED (no recon_truth.json this run)"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================="
echo "  Recon Summary — $TARGET"
echo "  Completed: $(date)"
echo "============================================="
echo ""
echo "  Subdomains:        $(wc -l 2>/dev/null < "$RECON_DIR/subdomains/all.txt" || echo 0)"
echo "  Live hosts:        $(wc -l 2>/dev/null < "$RECON_DIR/live/urls.txt" || echo 0)"
echo "  URLs collected:    $(wc -l 2>/dev/null < "$RECON_DIR/urls/all.txt" || echo 0)"
[ -f "$RECON_DIR/ports/open_ports.txt" ] && \
echo "  Open ports:        $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/with_params.txt" ] && \
echo "  Parameterized:     $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/api_endpoints.txt" ] && \
echo "  API endpoints:     $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/js/endpoints.txt" ] && \
echo "  JS endpoints:      $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/params/unique_params.txt" ] && \
echo "  Unique params:     $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

[ -d "$RECON_DIR/cicd" ] && \
echo "  CI/CD findings:   $(find "$RECON_DIR/cicd" -name 'scan_results.txt' -exec grep -cF '.github/workflows/' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')"

[ -f "$RECON_DIR/nuclei/findings.jsonl" ] && \
echo "  Nuclei hits:       $(wc -l < "$RECON_DIR/nuclei/findings.jsonl" | tr -d ' ')"
[ -f "$RECON_DIR/takeover_candidates.txt" ] && \
echo "  Takeover candidates: $(wc -l < "$RECON_DIR/takeover_candidates.txt" | tr -d ' ')"

# RhodawkAI Edition: reconFTW gap-fill results (Phases 1.5 + 5.5)
for _rtw_dir in "$RECON_DIR"/rtw/*/; do
    [ -d "$_rtw_dir" ] || continue
    _rtw_fn="$(basename "$_rtw_dir")"
    _rtw_n=$(cat "$_rtw_dir"rtw_*.txt 2>/dev/null | grep -c . || true)
    if [ "${_rtw_n:-0}" -gt 0 ]; then
        echo "  rtw gap-fill ${_rtw_fn}: ${_rtw_n} line(s) (reconftw delegate)"
    fi
done
[ -f "$RECON_DIR/subdomains/all.txt" ] && \
echo "  Probe list (post gap-fill): $(wc -l < "$RECON_DIR/subdomains/all.txt" | tr -d ' ') subdomains"
[ -f "$RECON_DIR/urls/all.txt" ] && \
echo "  URL corpus (post gap-fill): $(wc -l < "$RECON_DIR/urls/all.txt" | tr -d ' ') urls"
echo "  Scope-filtered (dropped OOS): $SCOPE_DROPPED_TOTAL line(s) (scope/dropped_oos.txt)"

# Step 2C: 1-line run-over-run delta summary.
if [ -f "$RECON_DIR/delta.json" ]; then
    DELTA_LINE=$(python3 "$BASE_DIR/tools/recon_fusion.py" delta-line --recon-dir "$RECON_DIR" 2>/dev/null || true)
    [ -n "$DELTA_LINE" ] && echo "  $DELTA_LINE"
fi

# Step 1B: honest per-capability health table for the reconFTW delegation —
# a 0.1s silent no-op can never hide behind rc=0.
if [ -f "$RTW_ADAPTER" ] && command -v python3 &>/dev/null; then
    RTW_HEALTH="$(python3 "$RTW_ADAPTER" health-table --target "$TARGET" 2>/dev/null || true)"
    if [ -n "$RTW_HEALTH" ]; then
        echo ""
        echo "$RTW_HEALTH"
        echo ""
    fi
fi

echo ""
echo "  Results: $RECON_DIR/"
echo "============================================="
echo ""
echo "  Next:"
echo "    ./tools/vuln_scanner.sh $RECON_DIR        # active vuln probes"
echo "    ./tools/takeover_scanner.sh --recon $RECON_DIR   # confirm CNAME takeovers"
echo "    ./tools/secrets_hunter.sh --js-bundle $RECON_DIR  # leaked-cred sweep"
echo "============================================="

# B6: clean exit — remove the run-incomplete marker so the next run does not
# report previous_run_incomplete. If the engine is killed before this point
# the marker survives and the next run records + warns about the interruption.
rm -f "$RECON_DIR/.run_incomplete"
