# shellcheck shell=bash
# =============================================================================
# _scope_gate.sh — shared fail-closed scope gate for the active shell tools.
#
# Sourced (never executed). Mirrors recon_engine.sh's Commit 3 gate so every
# downstream scanner inherits the same contract:
#
#   rhodawk_scope_gate_init <recon_dir_or_""> <target_or_"">
#       Resolves the scope manifest from, in order:
#         1. $RHODAWK_SCOPE_MANIFEST (explicit — wins over everything);
#         2. <recon_dir>/scope/compiled_scope.json (session artifact);
#         3. ${RHODAWK_HOME:-~/.rhodawk}/recon/<target>/scope/compiled_scope.json
#            (target-derived default, same keying as rtw_adapter.manifest_path).
#       No manifest resolvable -> FAIL CLOSED (returns 3; JSONL audit entry;
#       0 probes). The operator must run `rhodawk scope-compile <handle>`,
#       set RHODAWK_SCOPE_MANIFEST, or explicitly opt out for authorized
#       local testing via RHODAWK_SCOPE_UNSAFE=1 (a visible warning goes to
#       stderr whenever the bypass is active). The bypass NEVER skips
#       integrity validation: a manifest that resolves and then fails the
#       SHA-256 check is still a hard stop.
#       A manifest that is MISSING or FAILS the SHA-256 integrity check is a
#       hard stop: audited to hunt-memory/audit.jsonl, returns 3 (caller exits).
#
#   rhodawk_scope_gate_check <url_or_host>
#       When the gate is active, the target must be inside the verified
#       manifest. Returns 3 (after auditing) when out of scope; no-op when the
#       gate is inactive.
#
#   rhodawk_scope_gate_filter <url_file> [dropped_file]
#       When the gate is active, filters the file IN PLACE through the
#       manifest (quarantining dropped lines when [dropped_file] is given).
#       A checker failure aborts the caller (returns 3) instead of letting it
#       probe unfiltered data.
#
# Exit code 3 = SCOPE BLOCK, matching recon_engine.sh.
# =============================================================================

_SCOPE_GATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_SCOPE_GATE_MANIFEST=""
_SCOPE_GATE_ACTIVE=0
_SCOPE_GATE_TARGET=""
_SCOPE_GATE_TOOL="$(basename "${BASH_SOURCE[0]}")"

_rhodawk_scope_audit_block() {
    # Schema-validated writer when the adapter can run; same JSON fields as the
    # manual fallback otherwise (recon_engine.sh behavior).
    if command -v python3 >/dev/null 2>&1; then
        if python3 "$_SCOPE_GATE_DIR/rtw_adapter.py" audit-block \
            --target "${_SCOPE_GATE_TARGET:-unknown}" --reason "$1" \
            >/dev/null 2>&1; then
            return 0
        fi
    fi
    local _hm="${RHODAWK_HOME:-$HOME/.rhodawk}/hunt-memory"
    mkdir -p "$_hm" 2>/dev/null || return 0
    local _safe_reason
    _safe_reason="$(printf '%s' "$1" | tr -d '"\\')"
    printf '{"ts":"%s","url":"https://%s","method":"GET","scope_check":"fail","error":"%s: %s","schema_version":1}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${_SCOPE_GATE_TARGET:-unknown}" \
        "${_SCOPE_GATE_TOOL}" "$_safe_reason" \
        >> "$_hm/audit.jsonl" 2>/dev/null || true
}

rhodawk_scope_gate_init() {
    _SCOPE_GATE_TARGET="${2:-}"
    _SCOPE_GATE_MANIFEST="${RHODAWK_SCOPE_MANIFEST:-}"
    _SCOPE_GATE_ACTIVE=0

    if [ -z "$_SCOPE_GATE_MANIFEST" ] && [ -n "${1:-}" ] \
        && [ -f "${1}/scope/compiled_scope.json" ]; then
        _SCOPE_GATE_MANIFEST="${1}/scope/compiled_scope.json"
    fi
    if [ -z "$_SCOPE_GATE_MANIFEST" ] && [ -n "$_SCOPE_GATE_TARGET" ]; then
        # Reduce URL/host to the manifest directory key (rtw_adapter.host_key
        # semantics: strip scheme, userinfo, path, port; lowercase; no dot).
        local _key
        _key="$(printf '%s' "$_SCOPE_GATE_TARGET" \
            | tr '[:upper:]' '[:lower:]' \
            | sed -e 's#^[a-z][a-z0-9+.-]*://##' \
                  -e 's#[/?].*$##' \
                  -e 's#^.*@##' \
                  -e 's#:.*$##' \
                  -e 's#\.$##')"
        if [ -n "$_key" ] && [ -f "${RHODAWK_HOME:-$HOME/.rhodawk}/recon/$_key/scope/compiled_scope.json" ]; then
            _SCOPE_GATE_MANIFEST="${RHODAWK_HOME:-$HOME/.rhodawk}/recon/$_key/scope/compiled_scope.json"
        fi
    fi

    if [ -z "$_SCOPE_GATE_MANIFEST" ]; then
        # Layer 2 hardening (live-sandbox finding): with no compiled scope
        # manifest resolvable, the old behavior was FAIL-OPEN (gate inactive,
        # return 0) — scanners then probed with zero scope validation. Fail
        # closed instead; RHODAWK_SCOPE_UNSAFE=1 is the explicit opt-out for
        # authorized local testing and still prints a visible warning.
        if [ "${RHODAWK_SCOPE_UNSAFE:-}" = "1" ]; then
            echo "[!] SCOPE GATE BYPASSED: RHODAWK_SCOPE_UNSAFE=1 — running UNSCOPED (authorized local testing only). No scope constraints apply." >&2
            return 0
        fi
        echo "[-] SCOPE BLOCK: no compiled scope manifest resolved for target '${_SCOPE_GATE_TARGET:-<none>}' — 0 probes sent (fail-closed)." >&2
        echo "    To authorize scanning, run:  rhodawk scope-compile <handle>" >&2
        echo "    (writes <recon_dir>/scope/compiled_scope.json), or set" >&2
        echo "    RHODAWK_SCOPE_MANIFEST=/path/to/compiled_scope.json, or set" >&2
        echo "    RHODAWK_SCOPE_UNSAFE=1 to opt out explicitly for authorized local testing." >&2
        _rhodawk_scope_audit_block "no compiled scope manifest resolved — run blocked (fail-closed)"
        return 3
    fi

    if [ ! -f "$_SCOPE_GATE_MANIFEST" ]; then
        echo "[-] SCOPE BLOCK: scope manifest not found: $_SCOPE_GATE_MANIFEST" >&2
        _rhodawk_scope_audit_block "scope manifest not found: $_SCOPE_GATE_MANIFEST"
        return 3
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[-] SCOPE BLOCK: python3 unavailable — cannot verify manifest integrity" >&2
        _rhodawk_scope_audit_block "python3 unavailable — manifest integrity unverifiable"
        return 3
    fi
    if ! python3 "$_SCOPE_GATE_DIR/scope_checker.py" --manifest "$_SCOPE_GATE_MANIFEST" \
        >/dev/null 2>&1; then
        echo "[-] SCOPE BLOCK: scope manifest failed SHA-256 integrity validation: $_SCOPE_GATE_MANIFEST" >&2
        _rhodawk_scope_audit_block "scope manifest failed SHA-256 integrity validation: $_SCOPE_GATE_MANIFEST"
        return 3
    fi

    _SCOPE_GATE_ACTIVE=1
    echo "[*] Scope gate: compiled manifest verified ($_SCOPE_GATE_MANIFEST)"
    return 0
}

rhodawk_scope_gate_check() {
    [ "$_SCOPE_GATE_ACTIVE" = "1" ] || return 0
    local _probe="${1:-}"
    [ -n "$_probe" ] || return 0
    case "$_probe" in
        *"://"*) : ;;
        *) _probe="https://$_probe" ;;
    esac
    if ! python3 "$_SCOPE_GATE_DIR/scope_checker.py" --manifest "$_SCOPE_GATE_MANIFEST" \
        "$_probe" >/dev/null 2>&1; then
        echo "[-] SCOPE BLOCK: '$_probe' is outside the verified scope manifest" >&2
        _rhodawk_scope_audit_block "target '$_probe' is outside the verified scope manifest ($_SCOPE_GATE_MANIFEST)"
        return 3
    fi
    return 0
}

rhodawk_scope_gate_filter() {
    [ "$_SCOPE_GATE_ACTIVE" = "1" ] || return 0
    local _file="${1:-}"
    local _dropped="${2:-}"
    [ -n "$_file" ] && [ -f "$_file" ] || return 0
    if ! python3 "$_SCOPE_GATE_DIR/scope_checker.py" \
        --manifest "$_SCOPE_GATE_MANIFEST" --filter-file "$_file" \
        ${_dropped:+"--dropped-file" "$_dropped"} \
        >/dev/null 2>&1; then
        echo "[-] SCOPE BLOCK: scope filter FAILED for $_file — aborting instead of probing unfiltered data" >&2
        _rhodawk_scope_audit_block "scope filter FAILED for $_file (checker error) — run aborted"
        return 3
    fi
    return 0
}
