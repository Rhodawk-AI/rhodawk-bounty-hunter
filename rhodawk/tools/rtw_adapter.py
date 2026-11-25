#!/usr/bin/env python3
"""
rtw_adapter.py — deterministic reconFTW delegation for RhodawkAI Bounty Hunter,
RhodawkAI Edition.

Wherever Rhodawk's own recon pipeline hits a capability it does not have, this
adapter transparently delegates to reconFTW's equivalent function. The
routing decision is DETERMINISTIC CODE, never LLM judgment: the LLM reads
~/.rhodawk/capabilities.json and follows an explicit rule worded
identically across every prompt layer, but this file — not the model —
decides what is actually allowed to run.

Six-step decision flow (no LLM judgment at any step):

1. Capability requested by typed ID (CAP_ASN_ENUM, CAP_DNS_PERMUT,
   CAP_CDN_ISOLATE, CAP_JS_SOURCEMAPS, CAP_VHOSTS, CAP_TLS_PIVOTS,
   CAP_FAVICON — the 7 rows of the verified gap map in capability_registry.py).
2. If Rhodawk has a native tool for the capability, refuse to delegate and let
   the caller use the native path — this adapter is never called for
   anything Rhodawk already owns.
3. Dedup/freshness check against ~/.rhodawk/recon/<host>/rtw_manifest.json
   — key (target, capability_id, input_hash), TTL 7 days (the same freshness
   constant agents/autopilot.md already uses for cached recon). A fresh hit
   short-circuits to the cached result with ZERO subprocess spawn.
4. Availability check against capabilities.json (written by
   capability_registry.py — the single source of truth). RTW_MISSING_DEPS
   returns SKIPPED(reason=...) and the caller continues: one missing key or
   binary never blocks the whole recon run.
5. Scope gate — ScopeChecker.explain(target) pre-call (fail-closed, Rhodawk's
   own tools/scope_checker.py), then ScopeChecker.filter_file() on every
   reconFTW output file post-call. reconFTW's own -x/-i flags are never
   trusted as the boundary; this is Rhodawk's one real safety advantage over
   reconFTW and the fork must not weaken it. Blocked calls are logged to
   hunt-memory/audit.jsonl and NO reconFTW subprocess is spawned.
6. Invoke via reconFTW's own supported single-function interface — ALL 7
   capabilities (live-run Step 1B fix: the previous `source reconftw.sh
   --source-only` subshells silently no-op'd for sub_permut / cdnprovider /
   jschecks — rc=0 in 0.1s with empty workdirs):
       bash <RTW_HOME>/reconftw.sh -d <target> -c <fn> -f <workdir>/rtw_override.cfg \
            -o <workdir> --no-banner
   (subprocess, never sourced into this process). Capabilities that want a
   seed list so reconFTW does not re-run subfinder/httpx from scratch get the
   isolated workdir pre-populated with Rhodawk's already-discovered
   subdomains/subdomains.txt / webs/webs.txt BEFORE the call.

An ephemeral rtw_override.cfg is written on EVERY call, always:
VULNS_GENERAL=false, CDN_BYPASS=false, NOTIFICATION=false, and rate limits
mapped down from Rhodawk's own RateLimiter ceiling (recon_rps=10) — reconFTW's
aggressive defaults (TLSX_THREADS=1000) stay capped. The requested function's
own gate flag(s) (ASN_ENUM, SUBPERMUTE, CDN_IP, JSCHECKS, VIRTUALHOSTS,
FAVIRECON, TLSX_PORTS/TLS_IP_PIVOTS) are explicitly enabled in the cfg.
modules/vulns.sh is never in scope: Rhodawk's verifier spine is the only thing
allowed to promote a finding, and reconFTW's raw scanner output never
bypasses it.

Honesty accounting (live-run Step 1B fix — the pre-seeded input lines used to
be counted as findings, so a 0.1s no-op reported COMPLETED_WITH_FINDINGS with
findings_count: 2):
  - the exact pre-seeded line set is snapshotted BEFORE launch;
  - net_new_count = output lines − seed lines, recorded on the manifest, and
    COMPLETED_WITH_FINDINGS requires returncode == 0 AND net_new_count > 0;
  - stdout/stderr are scanned for reconFTW skip/error markers (SKIP,
    reason: config, command not found, No candidate, API key) — a silent
    skip is reported as SKIPPED_SILENT (or DEGRADED when net-new lines still
    landed) with the exact extracted reason in "reason".

Result states (traced on the manifest, mirroring Rhodawk's tracer vocabulary):
    COMPLETED_WITH_FINDINGS | COMPLETED_EMPTY | FAILED | TIMEOUT | SKIPPED
    | SKIPPED_SILENT | DEGRADED
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Make the rhodawk package importable whether this file runs as a script
# (python3 rhodawk/tools/rtw_adapter.py) or as a module (from tools import
# rtw_adapter) — recon_engine.sh Phases 1.5 and 5.5 invoke it as a script.
_TOOLS_DIR = Path(__file__).resolve().parent
_RHODAWK_DIR = _TOOLS_DIR.parent
if str(_RHODAWK_DIR) not in sys.path:
    sys.path.insert(0, str(_RHODAWK_DIR))

from tools.capability_registry import (  # noqa: E402
    CAPABILITIES,
    CapabilitySpec,
    RTW_COMMIT_PIN,
    STATE_NATIVE,
    STATE_RTW_AVAILABLE,
    STATE_RTW_MISSING_DEPS,
    capabilities_path,
    load_state,
    rtw_home,
    rtw_script,
)

try:
    from rhodawk._compat import get_env, ensure_home_migrated
except ImportError:  # flat / script execution — resolve package dir
    import os as _compat_os, sys as _compat_sys
    _compat_dir = _compat_os.path.abspath(__file__)
    for _ in range(2):
        _compat_dir = _compat_os.path.dirname(_compat_dir)
    if _compat_dir not in _compat_sys.path:
        _compat_sys.path.insert(0, _compat_dir)
    from _compat import get_env, ensure_home_migrated

try:
    from tools.scope_checker import ScopeChecker, ScopeError  # noqa: E402
except ImportError:  # pragma: no cover - scope_checker always ships with the fork
    ScopeChecker = None
    ScopeError = Exception

try:
    from memory.audit_log import AuditLog  # noqa: E402
    from memory.schemas import make_audit_entry  # noqa: E402
except ImportError:  # pragma: no cover - audit schema always ships with the fork
    AuditLog = None
    make_audit_entry = None

# ── Constants ─────────────────────────────────────────────────────────────────

RESULT_COMPLETED_WITH_FINDINGS = "COMPLETED_WITH_FINDINGS"
RESULT_COMPLETED_EMPTY = "COMPLETED_EMPTY"
RESULT_FAILED = "FAILED"
RESULT_TIMEOUT = "TIMEOUT"
RESULT_SKIPPED = "SKIPPED"
RESULT_SKIPPED_SILENT = "SKIPPED_SILENT"
RESULT_DEGRADED = "DEGRADED"

# reconFTW skip/error markers scanned in the delegated function's combined
# stdout+stderr (Step 1B fix 3 — silent 0.1s no-ops are surfaced, not scored).
RTW_SKIP_MARKERS = ("skip", "reason: config", "command not found",
                    "no candidate", "api key")

# Same freshness constant agents/autopilot.md uses for cached recon ("if found
# and < 7 days old, skip").
TTL_DAYS = 7

# Per-capability subprocess ceiling. reconFTW functions are scoped and
# non-interactive; 30 min is generous for a single function.
DEFAULT_TIMEOUT_SECS = 1800

# Rate limits mapped down from Rhodawk's own RateLimiter ceiling
# (memory/audit_log.py RateLimiter: recon_rps=10.0, test_rps=1.0). reconFTW's
# aggressive defaults — TLSX_THREADS=1000, HTTPX_THREADS=50 etc. — stay capped.
RATE_LIMIT_RPS = 10          # Rhodawk RateLimiter recon ceiling
THREADS_CAP = 25             # conservative cap for reconFTW thread knobs

# Safety-critical overrides written to the ephemeral cfg on EVERY call.
RTW_OVERRIDE_BASE = {
    # Vuln scanning is out of scope for this integration: Rhodawk's verifier spine
    # (tools/verifier.py) is the only thing allowed to promote a finding.
    "VULNS_GENERAL": "false",
    # Origin-IP discovery is an active attack primitive — off unless Rhodawk's own
    # pipeline ever opts in explicitly.
    "CDN_BYPASS": "false",
    # No external notifications from delegated runs.
    "NOTIFICATION": "false",
    # Rate/thread caps (down-mapped from Rhodawk's RateLimiter, not reconFTW's).
    "HTTPX_RATELIMIT": str(RATE_LIMIT_RPS),
    "HTTPX_THREADS": str(THREADS_CAP),
    "TLSX_THREADS": str(THREADS_CAP),
    "FAVIRECON_RATE_LIMIT": str(RATE_LIMIT_RPS),
    "FAVIRECON_CONCURRENCY": str(THREADS_CAP),
    "INTERLACE_THREADS": str(THREADS_CAP),
    # Capability gates: reconFTW's single-function mode still respects the
    # per-function config gates, and VIRTUALHOSTS defaults false upstream —
    # so every gate the 7 functions check is explicitly enabled here.
    "ASN_ENUM": "true",
    "SUBPERMUTE": "true",
    "VIRTUALHOSTS": "true",
    "FAVIRECON": "true",
    "CDN_IP": "true",
    "JSCHECKS": "true",
    "TLSX_PORTS": "true",
    "TLS_IP_PIVOTS": "true",
}

# Per-function gate flags — the REQUESTED function's flag(s) are written to
# the override cfg explicitly (Step 1B fix 1) so a silent config-gate skip is
# impossible for the capability actually being delegated.
FUNCTION_GATE_FLAGS = {
    "sub_asn": ["ASN_ENUM"],
    "sub_permut": ["SUBPERMUTE"],
    "cdnprovider": ["CDN_IP"],
    "jschecks": ["JSCHECKS"],
    "virtualhosts": ["VIRTUALHOSTS"],
    "favirecon_tech": ["FAVIRECON"],
    "tls_ip_pivots": ["TLSX_PORTS", "TLS_IP_PIVOTS"],
}

MANIFEST_FILENAME = "rtw_manifest.json"
MANIFEST_VERSION = 1


# ── Paths ─────────────────────────────────────────────────────────────────────

def data_home() -> Path:
    env = get_env("RHODAWK_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".rhodawk"


def manifest_path(target_host: str) -> Path:
    """~/.rhodawk/recon/<host>/rtw_manifest.json (RHODAWK_HOME aware)."""
    return data_home() / "recon" / host_key(target_host) / MANIFEST_FILENAME


def audit_log_path() -> Path:
    env = os.environ.get("RHODAWK_AUDIT_FILE")
    if env:
        return Path(env).expanduser()
    return data_home() / "hunt-memory" / "audit.jsonl"


def host_key(target: str) -> str:
    """Normalize a URL/host into the manifest directory key (mirrors
    recon_engine.sh's _normalize_target: strip scheme, userinfo, path, port,
    trailing dots; lowercase)."""
    s = (target or "").strip()
    s = s.split("://", 1)[1] if "://" in s else s
    s = s.rsplit("@", 1)[-1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if s.startswith("[") and "]" in s:          # bare IPv6 — keep intact
        s = s[1:s.index("]")]
    elif s.count(":") == 1 and s.rsplit(":", 1)[1].isdigit():
        s = s.rsplit(":", 1)[0]                 # host:port
    return s.rstrip(".").lower() or "unknown"


# ── Scope gate (step 5) ───────────────────────────────────────────────────────

def build_scope_checker(domains: List[str], excluded: List[str]):
    """Build Rhodawk's ScopeChecker from CLI/config-provided allow patterns.

    Returns None when no scope is configured — matching Rhodawk's own model where
    enforcement is enabled only when program scope is loaded. When a checker
    IS configured the gate is fail-closed.
    """
    domains = [d for d in domains if d and d.strip()]
    if not domains or ScopeChecker is None:
        return None
    try:
        return ScopeChecker(domains, excluded_domains=excluded or None)
    except ScopeError:
        return None


def load_scope_from_config() -> Tuple[List[str], List[str]]:
    """Load scope patterns from ~/.rhodawk/config.json (keys:
    scope_domains / scope_excluded_domains), so harness and ReAct runtimes
    inherit the program scope Rhodawk already knows about."""
    try:
        config = json.loads(
            (Path.home() / ".rhodawk" / "config.json").read_text(encoding="utf-8"))
        domains = config.get("scope_domains") or []
        excluded = config.get("scope_excluded_domains") or []
        if isinstance(domains, list) and isinstance(excluded, list):
            return [str(d) for d in domains], [str(d) for d in excluded]
    except (OSError, ValueError):
        pass
    return [], []


def audit_scope_block(target: str, reason: str) -> None:
    """Log a scope block to hunt-memory/audit.jsonl (schema-validated via
    Rhodawk's own audit entry builder)."""
    entry = None
    if make_audit_entry is not None:
        try:
            entry = make_audit_entry(
                url=f"https://{host_key(target)}",
                method="GET",
                scope_check="fail",
                error=f"rtw_adapter: {reason}",
            )
        except Exception:
            entry = None
    if entry is None:
        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "url": f"https://{host_key(target)}",
            "method": "GET",
            "scope_check": "fail",
            "error": f"rtw_adapter: {reason}",
            "schema_version": 1,
        }
    try:
        if AuditLog is not None:
            AuditLog(audit_log_path()).log(entry)
        else:
            path = audit_log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError:
        pass  # audit failure never turns into a scope bypass


# ── Ephemeral override cfg ────────────────────────────────────────────────────

def override_cfg_text(spec: Optional[CapabilitySpec] = None) -> str:
    lines = [
        "# rtw_override.cfg — ephemeral, written by rtw_adapter.py on every call.",
        "# Safety envelope: vuln scanning off, origin bypass off, notifications",
        "# off, rates capped to Rhodawk's RateLimiter ceiling. Never edit reconFTW's",
        "# own reconftw.cfg for this integration.",
    ]
    if spec is not None:
        flags = FUNCTION_GATE_FLAGS.get(spec.rtw_function, [])
        lines.append(f"# Requested function: {spec.rtw_function} — gate flag(s) "
                     f"explicitly enabled below: {', '.join(flags) or '(none)'}.")
    for key, val in RTW_OVERRIDE_BASE.items():
        lines.append(f"{key}={val}")
    return "\n".join(lines) + "\n"


def write_override_cfg(workdir: Path,
                       spec: Optional[CapabilitySpec] = None) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    cfg = workdir / "rtw_override.cfg"
    cfg.write_text(override_cfg_text(spec), encoding="utf-8")
    return cfg


# ── Command construction (pure — exercised by plan/dry-run) ───────────────────

def build_cli_command(spec: CapabilitySpec, target: str, workdir: Path,
                      cfg: Path) -> List[str]:
    """Step 6 (the ONLY invocation mode — Step 1B removed the brittle
    --source-only subshells): reconFTW's supported single-function interface.
    Subprocess, never sourced into this process."""
    return [
        "bash", str(rtw_script()),
        "-d", target,
        "-c", spec.rtw_function,
        "-f", str(cfg),
        "-o", str(workdir),
        "--no-banner",
    ]


def seed_files(spec: CapabilitySpec, recon_dir: Path, workdir: Path) -> List[str]:
    """Pre-populate the isolated workdir from Rhodawk's own recon output so
    delegated functions don't re-run subfinder/httpx from scratch.
    Returns the list of seeded workdir-relative paths (empty = nothing to seed)."""
    seeded = []
    layout = {
        "subdomains/all.txt": "subdomains/subdomains.txt",
        "live/urls.txt": "webs/webs.txt",
    }
    for src_rel, dst_rel in layout.items():
        if src_rel not in spec.seeds:
            continue
        src = recon_dir / src_rel
        if not src.is_file():
            continue
        dst = workdir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        seeded.append(dst_rel)
    return seeded


def input_hash(spec: CapabilitySpec, target: str, recon_dir: Path) -> str:
    """Stable digest of (capability, target, seed content) — the dedup key.
    Identical inputs dedup; new recon data invalidates the cache."""
    h = hashlib.sha256()
    h.update(spec.capability_id.encode())
    h.update(b"\x00")
    h.update(host_key(target).encode())
    h.update(b"\x00")
    for seed_rel in sorted(spec.seeds):
        src = recon_dir / seed_rel
        if src.is_file():
            h.update(seed_rel.encode())
            h.update(b"\x00")
            h.update(src.read_bytes())
        h.update(b"\x01")
    return h.hexdigest()


# ── Manifest (steps 2-3) ──────────────────────────────────────────────────────

def load_manifest(target: str) -> dict:
    path = manifest_path(target)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("version") == MANIFEST_VERSION:
            return data
    except (OSError, ValueError):
        pass
    return {"version": MANIFEST_VERSION, "ttl_days": TTL_DAYS, "entries": []}


def save_manifest(target: str, manifest: dict) -> Path:
    path = manifest_path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def fresh_entry(manifest: dict, cap_id: str, target: str, digest: str) -> Optional[dict]:
    """Step 3: dedup/freshness — (target, capability_id, input_hash) within TTL."""
    now = time.time()
    for entry in manifest.get("entries", []):
        if (entry.get("capability_id") == cap_id
                and entry.get("target") == host_key(target)
                and entry.get("input_hash") == digest):
            started = _parse_ts(entry.get("finished") or entry.get("started"))
            if started is not None and (now - started) < TTL_DAYS * 86400:
                if entry.get("status") in (RESULT_COMPLETED_WITH_FINDINGS,
                                           RESULT_COMPLETED_EMPTY):
                    return entry
    return None


def _parse_ts(text: Optional[str]) -> Optional[float]:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def upsert_entry(manifest: dict, entry: dict) -> None:
    entries = manifest.setdefault("entries", [])
    key = (entry["capability_id"], entry["target"], entry["input_hash"])
    entries[:] = [e for e in entries
                  if (e.get("capability_id"), e.get("target"), e.get("input_hash")) != key]
    entries.append(entry)


# ── Output harvesting + post-call scope filter (step 5, post-call) ────────────

def harvest_outputs(workdir: Path) -> List[str]:
    """Every file reconFTW produced in the workdir (relative paths)."""
    outputs = []
    if not workdir.is_dir():
        return outputs
    for path in sorted(workdir.rglob("*")):
        if path.is_file() and path.name != "rtw_override.cfg" and path.stat().st_size > 0:
            outputs.append(str(path.relative_to(workdir)))
    return outputs


def findings_count(workdir: Path, outputs: List[str]) -> int:
    n = 0
    for rel in outputs:
        try:
            with open(workdir / rel, "r", encoding="utf-8", errors="replace") as fh:
                n += sum(1 for line in fh if line.strip())
        except OSError:
            continue
    return n


def filter_outputs_to_scope(workdir: Path, checker, target: str) -> dict:
    """Post-call scope filter: ScopeChecker.filter_file() over every harvested
    output file. reconFTW's own -x/-i is never trusted as the boundary.
    Out-of-scope lines are dropped into a quarantined copy; files are rewritten
    in place with only in-scope lines. Returns filter stats."""
    stats = {"files_filtered": 0, "lines_in": 0, "lines_kept": 0, "lines_dropped": 0}
    if checker is None:
        return stats
    for rel in harvest_outputs(workdir):
        path = workdir / rel
        try:
            kept = path.with_suffix(path.suffix + ".inscope")
            in_n, out_n = checker.filter_file(str(path), str(kept))
            kept_bytes = kept.read_text(encoding="utf-8", errors="replace") if kept.exists() else ""
            path.write_text(kept_bytes, encoding="utf-8")
            kept.unlink(missing_ok=True)
            stats["files_filtered"] += 1
            stats["lines_in"] += in_n + out_n
            stats["lines_kept"] += in_n
            stats["lines_dropped"] += out_n
        except Exception:
            # If filtering a file fails, quarantine it rather than emit
            # unfiltered content — fail closed, one file at a time.
            try:
                (workdir / (rel + ".quarantined")).write_bytes(path.read_bytes())
                path.unlink()
            except OSError:
                pass
    return stats


def publish_outputs(spec: CapabilitySpec, target: str, workdir: Path,
                    recon_dir: Path, outputs: List[str]) -> List[str]:
    """Copy filtered outputs into Rhodawk's recon dir: <recon_dir>/rtw/<function>/.
    Published files already went through filter_outputs_to_scope."""
    out_dir = recon_dir / "rtw" / spec.rtw_function
    out_dir.mkdir(parents=True, exist_ok=True)
    published = []
    for rel in outputs:
        src = workdir / rel
        if not src.is_file() or src.stat().st_size == 0:
            continue
        dst = out_dir / Path(rel).name
        # Flatten name collisions across subdirs deterministically.
        i = 1
        while dst.exists():
            dst = out_dir / f"{Path(rel).stem}_{i}{Path(rel).suffix}"
            i += 1
        shutil.copyfile(src, dst)
        published.append(str(dst))
    return published


# ── Standardized outputs for the recon_engine.sh merge (Fix 1b) ──────────────

_URL_LINE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")
_HOST_LINE_RE = re.compile(
    r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$")


def classify_lines(workdir: Path, outputs: List[str]) -> Dict[str, List[str]]:
    """Classify harvested (already scope-filtered) output lines into the two
    standardized buckets the recon_engine.sh merge consumes:
        rtw_subdomains.txt — bare hosts (Phase 1.5 merge into subdomains/all.txt)
        rtw_urls.txt       — full URLs  (Phase 5.5 merge into urls/all.txt)
    Lines that fit neither bucket stay only in the raw published files."""
    subs: List[str] = []
    urls: List[str] = []
    seen = set()
    for rel in outputs:
        try:
            with open(workdir / rel, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for line in lines:
            token = line.strip().split()[0] if line.strip() else ""
            if not token or token in seen:
                continue
            seen.add(token)
            if _URL_LINE_RE.match(token):
                urls.append(token)
            elif _HOST_LINE_RE.match(token):
                subs.append(token)
    return {"subdomains": subs, "urls": urls}


def write_standard_outputs(recon_dir: Path, rtw_function: str, workdir: Path,
                           outputs: List[str]) -> Dict[str, int]:
    """Write <recon_dir>/rtw/<function>/rtw_subdomains.txt and rtw_urls.txt
    (sorted, deduplicated) from the scope-filtered harvest. recon_engine.sh
    Phase 1.5 cats rtw_subdomains.txt into subdomains/all.txt; Phase 5.5 cats
    rtw_urls.txt into urls/all.txt. Returns line counts per bucket."""
    buckets = classify_lines(workdir, outputs)
    out_dir = recon_dir / "rtw" / rtw_function
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    for bucket, lines in buckets.items():
        unique = sorted(set(lines))
        path = out_dir / f"rtw_{bucket}.txt"
        if unique:
            path.write_text("\n".join(unique) + "\n", encoding="utf-8")
            counts[bucket] = len(unique)
        elif path.exists():
            path.unlink()  # stale bucket from an earlier run of the same function
    return counts


# ── Honest accounting (Step 1B fixes 2+3) ─────────────────────────────────────

def _snapshot_seed_lines(workdir: Path, seeded: List[str]) -> set:
    """Exact set of pre-seeded lines (stripped), snapshotted BEFORE
    reconftw.sh launches — the baseline for net_new_count."""
    lines = set()
    for rel in seeded:
        path = workdir / rel
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = raw.strip()
                if stripped:
                    lines.add(stripped)
        except OSError:
            continue
    return lines


def _drop_seed_lines(workdir: Path, outputs: List[str],
                     seed_lines: set) -> Tuple[List[str], int]:
    """Rewrite each harvested output net-new-only (drop the pre-seeded lines
    so they are neither counted nor published) and return
    (re-harvested outputs, net_new_line_count)."""
    if not seed_lines:
        return outputs, findings_count(workdir, outputs)
    net_new = 0
    for rel in list(outputs):
        path = workdir / rel
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        kept = [line for line in lines
                if line.strip() and line.strip() not in seed_lines]
        if len(kept) != len(lines):
            try:
                path.write_text("\n".join(kept) + ("\n" if kept else ""),
                                encoding="utf-8")
            except OSError:
                continue
        net_new += len(kept)
    return harvest_outputs(workdir), net_new


def _detect_skip_reason(stdout_text: str, stderr_text: str) -> str:
    """Step 1B fix 3: scan the delegated function's combined stdout/stderr for
    reconFTW skip/error markers. Returns the exact extracted reason or ""."""
    blob = f"{stdout_text or ''}\n{stderr_text or ''}"
    for raw in blob.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        low = stripped.lower()
        for marker in RTW_SKIP_MARKERS:
            if marker in low:
                return f"skip marker '{marker}' in reconftw output: {stripped[:200]}"
    return ""


def format_health_table(manifest: dict) -> str:
    """Step 1B fix 4: the recon health table —
    Capability | Function | Status | Duration | Net-New | Reason — from the
    latest manifest entry per capability. Printed at the end of
    recon_engine.sh so a 0.1s silent no-op can never hide behind rc=0."""
    latest: Dict[str, dict] = {}
    for entry in manifest.get("entries", []):
        cid = entry.get("capability_id")
        if cid:
            latest[cid] = entry
    header = (f"{'Capability':<18} | {'Function':<16} | {'Status':<22} | "
              f"{'Duration':>8} | {'Net-New':>7} | Reason")
    rows = [header, "-" * len(header)]
    for cid in sorted(latest):
        e = latest[cid]
        rows.append(
            f"{cid:<18} | {str(e.get('rtw_function', '?')):<16} | "
            f"{str(e.get('status', '?')):<22} | "
            f"{str(e.get('duration_secs', '-')):>8} | "
            f"{str(e.get('net_new_count', '-')):>7} | "
            f"{str(e.get('reason', '') or '')}"
        )
    return "\n".join(rows)


# ── The six-step flow ─────────────────────────────────────────────────────────

def _remove_path(p: Path) -> None:
    """Delete a file/symlink/dir tree, never raising."""
    try:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        elif p.exists() or p.is_symlink():
            p.unlink()
    except OSError:
        pass


def _ensure_rtw_bookkeeping_dir(path: Path) -> None:
    """reconftw.sh -c appends into .log/_.txt and .called_fn/.status_<fn>:
    BOTH bookkeeping paths are DIRECTORIES upstream. A plain file at either
    path (created by older releases) failed the live rhodawkai.com run with
    `Recon/<domain>/.log/_.txt: Not a directory` — replace any stale
    file/symlink with a real directory first. Never raises."""
    try:
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            path.unlink()
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def _reconftw_domain(target: str) -> str:
    """The $domain reconftw.sh derives from -d: scheme, path, port stripped.
    Empty/unsafe values disable the Recon bridge entirely."""
    t = (target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split(":", 1)[0].split("?", 1)[0].split("#", 1)[0]
    t = t.rstrip(".").lower()
    if not t or t in (".", "..") or "/" in t or "\\" in t:
        return ""
    return t


def _bridge_recon_dir(target: str, workdir: Path) -> Tuple[Optional[Path],
                                                           Optional[Path]]:
    """reconftw.sh -c hardcodes dir="${SCRIPTPATH}/Recon/$domain" (upstream
    commit 3925211, line 858) and IGNORES `-o <workdir>` — every delegated
    function ran inside an empty directory and never saw the seeded inputs.
    Bridge it: for the duration of the subprocess call,
    <RTW_HOME>/Recon/<domain> is a symlink to <workdir>. A pre-existing path
    at that spot is renamed aside (lightweight lock via PID-suffixed backup)
    and restored by the caller's finally. Returns (link, backup); either may
    be None. Never raises — a broken bridge degrades to upstream behavior."""
    try:
        domain = _reconftw_domain(target)
        if not domain:
            return None, None
        recon_root = rtw_home() / "Recon"
        recon_root.mkdir(parents=True, exist_ok=True)
        link = recon_root / domain
        if link.is_symlink() and link.resolve() == workdir.resolve():
            return link, None          # already bridged to this workdir
        backup = None
        if link.is_symlink() or link.exists():
            backup = link.with_name(f"{link.name}.rhodawk-bak-{os.getpid()}")
            _remove_path(backup)
            link.rename(backup)
        os.symlink(workdir, link)
        return link, backup
    except OSError:
        return None, None


def _unbridge_recon_dir(link: Optional[Path], backup: Optional[Path],
                        workdir: Path) -> None:
    """Tear down the Recon/<domain> symlink (only while it still points at
    OUR workdir) and restore anything renamed aside. Never raises."""
    if link is None:
        return
    try:
        if link.is_symlink():
            try:
                points_at_ours = link.resolve() == Path(workdir).resolve()
            except OSError:
                points_at_ours = False
            if points_at_ours:
                link.unlink()
        if backup is not None and backup.exists() and not link.exists():
            backup.rename(link)
    except OSError:
        pass


def _rtw_head_commit() -> Optional[str]:
    """`git rev-parse HEAD` of the RTW checkout, or None when it is not a git
    repo / git is unavailable (unknown commit is NOT a mismatch — only a
    verifiably different HEAD blocks delegation). Cheap (<50ms), run before
    every delegated subprocess."""
    repo = rtw_home()
    if not (repo / ".git").is_dir():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15, shell=False)
    except (OSError, subprocess.SubprocessError):
        return None
    head = (proc.stdout or "").strip()
    return head if head else None


def run_capability(capability_id: str, target: str,
                   recon_dir: Optional[Path] = None,
                   scope_domains: Optional[List[str]] = None,
                   scope_excluded: Optional[List[str]] = None,
                   checker=None,
                   allow_unscoped: bool = False,
                   force: bool = False,
                   timeout_secs: Optional[int] = None,
                   workdir_root: Optional[Path] = None,
                   env: Optional[Dict[str, str]] = None) -> dict:
    """Delegate one capability to reconFTW deterministically. Never raises —
    returns a result dict with a status in the tracer vocabulary."""
    spec = CAPABILITIES.get(capability_id)
    if spec is None:
        return _result(RESULT_SKIPPED, capability_id, target,
                       reason=f"unknown capability_id: {capability_id}")
    target_host = host_key(target)
    recon_dir = Path(recon_dir) if recon_dir else _default_recon_dir(target_host)
    timeout_secs = int(timeout_secs or os.environ.get("RTW_TIMEOUT", DEFAULT_TIMEOUT_SECS))
    manifest = load_manifest(target)
    digest = input_hash(spec, target, recon_dir)

    # Step 2 — native guard: never delegate what Rhodawk owns.
    # RESERVED (B8): NATIVE_CAPABILITY_IDS is an empty frozenset today, so no
    # shipped capability ever takes this branch — it is deliberate dead code,
    # kept as the spec-drift safety net: if a future registry version marks a
    # capability NATIVE in capabilities.json, this guard refuses to delegate
    # it (documented by tests/test_rtw_capability.py's native-skip test).
    state_map = load_state()
    if state_map.get(capability_id) == STATE_NATIVE:
        return _result(RESULT_SKIPPED, capability_id, target, digest=digest,
                       reason="capability is NATIVE — use Rhodawk's own pipeline")

    # Step 3 — dedup/freshness (unless --force).
    if not force:
        cached = fresh_entry(manifest, capability_id, target, digest)
        if cached is not None:
            return _result(cached.get("status", RESULT_COMPLETED_EMPTY),
                           capability_id, target, digest=digest,
                           cached=True, reason="fresh manifest entry (TTL 7d), zero subprocess",
                           entry=dict(cached))

    # Step 4 — availability (single source of truth: capabilities.json).
    if state_map.get(capability_id) == STATE_RTW_MISSING_DEPS:
        reason = "capabilities.json: RTW_MISSING_DEPS"
        return _result(RESULT_SKIPPED, capability_id, target, digest=digest,
                       reason=reason + " — continuing without delegation")

    # Step 5 (pre-call) — scope gate, FAIL CLOSED. reconFTW delegation is a
    # bigger hammer than Rhodawk's native pipeline, so it is gated harder than
    # upstream: without explicit scope patterns (caller-provided checker,
    # --scope-domain args, or config.json scope_domains) the delegation is
    # refused — no reconFTW subprocess, block logged to audit.jsonl. The only
    # opt-out is --no-scope-check (allow_unscoped), for local demo testing.
    if checker is None and not allow_unscoped:
        cfg_domains, cfg_excluded = load_scope_from_config()
        merged_domains = list(scope_domains or []) + cfg_domains
        merged_excluded = list(scope_excluded or []) + cfg_excluded
        checker = build_scope_checker(merged_domains, merged_excluded)
    if checker is None and not allow_unscoped:
        reason = ("fail-closed: no scope patterns configured — pass --scope-domain "
                  "(repeatable) or --no-scope-check to opt out for local demo testing")
        audit_scope_block(target, reason)
        return _result(RESULT_SKIPPED, capability_id, target, digest=digest,
                       reason=reason, blocked=True)
    if checker is not None:
        decision = checker.explain(f"https://{target_host}")
        if not decision.get("in_scope", False):
            reason = ("out-of-scope target blocked BEFORE reconFTW subprocess: "
                      f"{decision.get('reason', 'not on program allowlist')}")
            audit_scope_block(target, reason)
            return _result(RESULT_SKIPPED, capability_id, target, digest=digest,
                           reason=reason, blocked=True)

    # Availability could be stale (e.g. the checkout was deleted/moved after
    # capabilities.json was written) — verify the entry point directly rather
    # than spawning blind.
    if not rtw_script().is_file():
        return _result(RESULT_SKIPPED, capability_id, target, digest=digest,
                       reason=f"RTW_HOME/reconftw.sh not found at {rtw_home()} — RTW_HOME unset behaves as upstream Rhodawk")

    # Run-time pin re-verification: the registry and doctor only check the
    # pin at install/doctor time — a moved or rebased reconFTW checkout must
    # never run unpinned delegated code. On a verifiable HEAD != pin mismatch
    # the delegation is refused (SKIPPED) and the refusal is recorded on the
    # manifest so tool_health surfaces it.
    pin_head = _rtw_head_commit()
    if pin_head is not None and pin_head != RTW_COMMIT_PIN:
        reason = (f"pin mismatch: RTW HEAD {pin_head} != pinned {RTW_COMMIT_PIN} "
                  f"— refusing to delegate (re-clone or update the pin)")
        entry = _entry(spec, target_host, digest, RESULT_SKIPPED, _utcnow(),
                       reason=reason)
        upsert_entry(manifest, entry)
        save_manifest(target, manifest)
        return _result(RESULT_SKIPPED, capability_id, target, digest=digest,
                       reason=reason, entry=entry)

    # ── Execute ────────────────────────────────────────────────────────────
    root = workdir_root or (recon_dir / "rtw" / ".work")
    workdir = root / f"{spec.rtw_function}_{int(time.time())}"
    workdir.mkdir(parents=True, exist_ok=True)
    seeded = seed_files(spec, recon_dir, workdir)
    cfg = write_override_cfg(workdir, spec)
    # Step 1B fix 2: snapshot the EXACT pre-seeded line set BEFORE launching
    # reconftw.sh — outputs are diffed against it (net_new_count), so seeded
    # inputs can never be counted or published as delegate findings again.
    seed_lines = _snapshot_seed_lines(workdir, seeded)

    argv = build_cli_command(spec, target, workdir, cfg)

    child_env = env or os.environ.copy()
    # Live-run fix: reconftw.sh resolves its lib/ + modules/ base from
    # $SCRIPTPATH. When the invoking shell carried a stale SCRIPTPATH (or
    # reconFTW's compiled-in default /opt/reconftw), sub_permut and
    # tls_ip_pivots sourced /opt/reconftw/modules/utils.sh instead of the
    # RTW_HOME checkout. Pin it to OUR RTW_HOME on every delegated call.
    child_env["SCRIPTPATH"] = str(rtw_script().parent)
    started_iso = _utcnow()
    t0 = time.time()
    # Step 3 fix: reconftw.sh -c ignores -o and hardcodes
    # ${SCRIPTPATH}/Recon/$domain. Pre-create the bookkeeping DIRECTORIES the
    # single-function mode appends into (.log/_.txt, .called_fn/.status_<fn>),
    # bridge the seeded workdir in via <RTW_HOME>/Recon/<domain> -> <workdir>
    # (a directory), and ALWAYS tear the bridge down again.
    _ensure_rtw_bookkeeping_dir(workdir / ".log")
    _ensure_rtw_bookkeeping_dir(workdir / ".called_fn")
    recon_link, recon_backup = _bridge_recon_dir(target, workdir)
    try:
        proc = subprocess.run(
            argv, shell=False, cwd=str(workdir), env=child_env,
            capture_output=True, text=True, timeout=timeout_secs,
        )
        rc = proc.returncode
        stdout_text = proc.stdout or ""
        stderr_tail = (proc.stderr or "")[-2000:]
    except subprocess.TimeoutExpired:
        entry = _entry(spec, target_host, digest, RESULT_TIMEOUT, started_iso,
                       argv=argv, workdir=str(workdir), seeded=seeded,
                       net_new_count=0,
                       reason=f"timeout after {timeout_secs}s")
        upsert_entry(manifest, entry)
        save_manifest(target, manifest)
        return _result(RESULT_TIMEOUT, capability_id, target, digest=digest,
                       entry=entry, reason=f"timeout after {timeout_secs}s")
    except OSError as exc:
        entry = _entry(spec, target_host, digest, RESULT_FAILED, started_iso,
                       argv=argv, workdir=str(workdir), seeded=seeded,
                       net_new_count=0, reason=str(exc))
        upsert_entry(manifest, entry)
        save_manifest(target, manifest)
        return _result(RESULT_FAILED, capability_id, target, digest=digest,
                       entry=entry, reason=f"subprocess error: {exc}")
    finally:
        # <RTW_HOME>/Recon/ stays clean across runs: the bridge symlink is
        # removed and any pre-existing path renamed aside is restored.
        _unbridge_recon_dir(recon_link, recon_backup, workdir)

    if rc != 0:
        # Live-run fix: a failed function produced nothing. Never publish or
        # count the pre-seeded inputs (e.g. subdomains/subdomains.txt) as
        # findings — they would otherwise surface as findings_count and rows
        # in the Recon Summary despite the non-zero exit.
        status = RESULT_FAILED
        outputs = []
        findings = 0
        net_new_count = 0
        skip_reason = ""
        filter_stats = {"files_filtered": 0, "lines_in": 0,
                        "lines_kept": 0, "lines_dropped": 0}
        published = []
        standard_counts = {}
    else:
        # Step 5 (post-call) — filter every output file to scope.
        filter_stats = filter_outputs_to_scope(workdir, checker, target)
        # Re-harvest: filtering may have emptied files.
        outputs = harvest_outputs(workdir)
        # Step 1B fix 2 — seed diffing: strip the pre-seeded lines from the
        # harvested outputs (files rewritten net-new-only), then count.
        outputs, net_new_count = _drop_seed_lines(workdir, outputs, seed_lines)
        findings = net_new_count
        # Step 1B fix 3 — silent-skip detection from stdout/stderr.
        skip_reason = _detect_skip_reason(stdout_text, stderr_tail)
        if skip_reason:
            # The function reported a skip/error marker: never score it as a
            # clean run. Net-new output turns it DEGRADED, not healthy.
            status = RESULT_DEGRADED if net_new_count > 0 else RESULT_SKIPPED_SILENT
        elif net_new_count > 0:
            status = RESULT_COMPLETED_WITH_FINDINGS
        else:
            status = RESULT_COMPLETED_EMPTY

        published = publish_outputs(spec, target, workdir, recon_dir, outputs)
        standard_counts = write_standard_outputs(recon_dir, spec.rtw_function,
                                                 workdir, outputs)

    entry = _entry(spec, target_host, digest, status, started_iso, argv=argv,
                   workdir=str(workdir), seeded=seeded, outputs=outputs,
                   published=published, standard_outputs=standard_counts,
                   findings_count=findings, net_new_count=net_new_count,
                   seed_lines=len(seed_lines),
                   filter=filter_stats, duration_secs=round(time.time() - t0, 1),
                   returncode=rc)
    if skip_reason:
        entry["reason"] = skip_reason
    if stderr_tail.strip():
        entry["stderr_tail"] = stderr_tail[-800:]
    upsert_entry(manifest, entry)
    save_manifest(target, manifest)

    return _result(status, capability_id, target, digest=digest, entry=entry,
                   reason=skip_reason or _status_reason(status, net_new_count, rc))


def run_all(target: str, **kwargs) -> List[dict]:
    """recon_engine.sh Phase 1.5 / Phase 5.5 entry point: every RTW_AVAILABLE
    capability not yet run fresh this session. SKIPPED results for missing
    deps are normal. Callers pass split=True to get the two phase groups."""
    state = load_state()
    results = []
    for cap_id in sorted(CAPABILITIES):
        if state.get(cap_id) != STATE_RTW_AVAILABLE:
            results.append(_result(RESULT_SKIPPED, cap_id, target,
                                   reason=f"capabilities.json: {state.get(cap_id, 'UNKNOWN')}"))
            continue
        results.append(run_capability(cap_id, target, **kwargs))
    return results


# Phase grouping (Fix 1): subdomain/infra capabilities run in Phase 1.5 —
# BEFORE httpx probing — so newly discovered subdomains get probed this run.
# Web/JS/TLS capabilities run in Phase 5.5 — after URL collection, before
# directory fuzzing.
PHASE_1_5_CAPABILITIES = ("CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE")
PHASE_5_5_CAPABILITIES = ("CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                          "CAP_FAVICON")


def run_phase(phase: str, target: str, **kwargs) -> List[dict]:
    """Run one split phase's capability group ('1.5' or '5.5')."""
    cap_ids = {"1.5": PHASE_1_5_CAPABILITIES,
               "5.5": PHASE_5_5_CAPABILITIES}.get(str(phase))
    if cap_ids is None:
        raise ValueError(f"unknown phase: {phase} (expected '1.5' or '5.5')")
    state = load_state()
    results = []
    for cap_id in cap_ids:
        if state.get(cap_id) != STATE_RTW_AVAILABLE:
            results.append(_result(RESULT_SKIPPED, cap_id, target,
                                   reason=f"capabilities.json: {state.get(cap_id, 'UNKNOWN')}"))
            continue
        results.append(run_capability(cap_id, target, **kwargs))
    return results


def _default_recon_dir(target_host: str) -> Path:
    """Mirror recon_engine.sh: $BASE_DIR/recon/<target> (BASE_DIR = rhodawk/),
    or $RECON_OUT_DIR when set. Falls back to data-home recon/."""
    env_dir = os.environ.get("RECON_OUT_DIR")
    if env_dir:
        return Path(env_dir) / target_host
    base = _RHODAWK_DIR
    if os.access(base, os.W_OK):
        return base / "recon" / target_host
    return data_home() / "recon" / target_host


def _status_reason(status: str, findings: int, rc: int) -> str:
    if status == RESULT_FAILED:
        return f"reconftw function exited rc={rc}"
    if status == RESULT_COMPLETED_WITH_FINDINGS:
        return f"{findings} net-new finding line(s) collected"
    if status == RESULT_SKIPPED_SILENT:
        return "function exited rc=0 but produced no net-new output (silent skip)"
    if status == RESULT_DEGRADED:
        return f"skip markers in reconftw output, but {findings} net-new line(s) collected"
    return "function completed, no net-new output lines"


def _entry(spec, target_host, digest, status, started_iso, **extra) -> dict:
    entry = {
        "capability_id": spec.capability_id,
        "rtw_function": spec.rtw_function,
        "target": target_host,
        "input_hash": digest,
        "status": status,
        "started": started_iso,
        "finished": _utcnow(),
    }
    entry.update(extra)
    return entry


def _result(status, capability_id, target, digest=None, cached=False,
            reason="", entry=None, blocked=False) -> dict:
    return {
        "status": status,
        "capability_id": capability_id,
        "target": host_key(target),
        "input_hash": digest,
        "cached": cached,
        "blocked": blocked,
        "reason": reason,
        "entry": entry,
    }


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── CLI ───────────────────────────────────────────────────────────────────────

def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", required=True, help="FQDN / IP in scope")
    parser.add_argument("--recon-dir", default=None,
                        help="Rhodawk recon dir for this target (default: <rhodawk>/recon/<target>)")
    parser.add_argument("--scope-domain", action="append", default=[],
                        help="In-scope pattern (repeat or comma-separate). Fail-closed gate.")
    parser.add_argument("--scope-exclude", action="append", default=[],
                        help="Out-of-scope pattern (repeat or comma-separate).")
    parser.add_argument("--no-scope-check", action="store_true",
                        help="opt out of the fail-closed scope gate (local demo testing only)")
    parser.add_argument("--force", action="store_true",
                        help="ignore fresh manifest entries and re-run")
    parser.add_argument("--timeout", type=int, default=None,
                        help=f"subprocess ceiling in seconds (default {DEFAULT_TIMEOUT_SECS})")


def _flatten(vals: List[str]) -> List[str]:
    out = []
    for v in vals:
        out += [p.strip() for p in v.split(",") if p.strip()]
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rtw_adapter.py",
        description="Deterministic reconFTW delegation — RhodawkAI Bounty Hunter.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="delegate one capability by typed ID")
    p_run.add_argument("capability_id")
    _add_target_args(p_run)
    p_run.add_argument("--quiet", action="store_true",
                       help="one-line summary instead of JSON")

    p_all = sub.add_parser("run-all", help="delegate every RTW_AVAILABLE capability")
    _add_target_args(p_all)
    p_all.add_argument("--quiet", action="store_true",
                       help="one-line summaries instead of JSON")

    p_phase = sub.add_parser("phase",
                             help="delegate one split phase's group: '1.5' (subdomain/infra) "
                                  "or '5.5' (web/JS/TLS) — used by recon_engine.sh")
    p_phase.add_argument("phase", choices=["1.5", "5.5"])
    _add_target_args(p_phase)
    p_phase.add_argument("--quiet", action="store_true",
                         help="one-line summaries instead of JSON")

    p_plan = sub.add_parser("plan", help="print the exact command(s) without executing")
    p_plan.add_argument("capability_id", nargs="?", default=None)
    _add_target_args(p_plan)

    p_status = sub.add_parser("status", help="show the rtw_manifest.json for a target")
    p_status.add_argument("--target", required=True)
    p_status.add_argument("--json", action="store_true")

    p_health = sub.add_parser("health-table",
                              help="print the recon health table "
                                   "(Capability | Function | Status | Duration | Net-New | Reason) "
                                   "from rtw_manifest.json — recon_engine.sh prints it at the end")
    p_health.add_argument("--target", required=True)

    p_audit = sub.add_parser("audit-block",
                             help="append a schema-validated scope-block entry to "
                                  "hunt-memory/audit.jsonl (used by the recon_engine.sh "
                                  "pre-flight scope gate)")
    p_audit.add_argument("--target", required=True)
    p_audit.add_argument("--reason", required=True)

    args = parser.parse_args(argv)
    scope_domains = _flatten(args.scope_domain if hasattr(args, "scope_domain") else [])
    scope_excluded = _flatten(args.scope_exclude if hasattr(args, "scope_exclude") else [])
    recon_dir = Path(args.recon_dir) if getattr(args, "recon_dir", None) else None
    timeout = getattr(args, "timeout", None)

    if args.cmd == "status":
        manifest = load_manifest(args.target)
        if args.json:
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print(f"manifest: {manifest_path(args.target)}")
            for e in manifest.get("entries", []):
                print(f"  {e.get('capability_id'):<28} {e.get('status'):<26} "
                      f"finished={e.get('finished')} findings={e.get('findings_count', '-')}")
        return 0

    if args.cmd == "health-table":
        manifest = load_manifest(args.target)
        if manifest.get("entries"):
            print(format_health_table(manifest))
        return 0

    if args.cmd == "audit-block":
        audit_scope_block(args.target, args.reason)
        return 0

    if args.cmd == "plan":
        # Dry-run: construct the exact command(s) without touching the target.
        ids = [args.capability_id] if args.capability_id else sorted(CAPABILITIES)
        rc = 0
        for cap_id in ids:
            spec = CAPABILITIES.get(cap_id)
            if spec is None:
                print(f"[-] unknown capability_id: {cap_id}", file=sys.stderr)
                rc = 2
                continue
            workdir = Path(args.recon_dir or (_default_recon_dir(host_key(args.target)))) / "rtw" / ".plan"
            workdir.mkdir(parents=True, exist_ok=True)
            cfg = write_override_cfg(workdir, spec)
            print(f"[plan] {cap_id} ({spec.rtw_function}):")
            print("  " + " ".join(shlex.quote(a) for a in
                                   build_cli_command(spec, args.target, workdir, cfg)))
        return rc

    if args.cmd == "run":
        res = run_capability(args.capability_id, args.target, recon_dir=recon_dir,
                             scope_domains=scope_domains, scope_excluded=scope_excluded,
                             allow_unscoped=args.no_scope_check,
                             force=args.force, timeout_secs=timeout)
        if args.quiet:
            print(_quiet_line(res))
        else:
            print(json.dumps(res, indent=2, sort_keys=True, default=str))
        # FAILED/TIMEOUT are real failures; SKIPPED is a normal outcome
        # (missing deps, scope block, native guard) — the caller keeps going.
        return 0 if res["status"] in (RESULT_COMPLETED_WITH_FINDINGS,
                                      RESULT_COMPLETED_EMPTY,
                                      RESULT_SKIPPED) else 1

    if args.cmd == "phase":
        results = run_phase(args.phase, args.target, recon_dir=recon_dir,
                            scope_domains=scope_domains, scope_excluded=scope_excluded,
                            allow_unscoped=args.no_scope_check,
                            force=args.force, timeout_secs=timeout)
        if args.quiet:
            for res in results:
                print(_quiet_line(res))
        else:
            print(json.dumps(results, indent=2, sort_keys=True, default=str))
        return 0

    # run-all
    results = run_all(args.target, recon_dir=recon_dir, scope_domains=scope_domains,
                      scope_excluded=scope_excluded, allow_unscoped=args.no_scope_check,
                      force=args.force, timeout_secs=timeout)
    if args.quiet:
        for res in results:
            print(_quiet_line(res))
    else:
        print(json.dumps(results, indent=2, sort_keys=True, default=str))
    return 0


def _quiet_line(res: dict) -> str:
    cached = " (cached)" if res.get("cached") else ""
    return (f"[rtw] {res.get('status', '?'):<26} "
            f"{res.get('capability_id', '?'):<17}{cached} {res.get('reason', '')}")


if __name__ == "__main__":
    sys.exit(main())
