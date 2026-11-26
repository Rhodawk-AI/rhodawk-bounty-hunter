"""Adapters over existing RhodawkAI Bounty Hunter tools (no second engine)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
try:
    from rhodawk._compat import get_env, ensure_home_migrated
except ImportError:  # flat / script execution — resolve package dir
    import os as _compat_os, sys as _compat_sys
    _compat_dir = _compat_os.path.abspath(__file__)
    for _ in range(3):
        _compat_dir = _compat_os.path.dirname(_compat_dir)
    if _compat_dir not in _compat_sys.path:
        _compat_sys.path.insert(0, _compat_dir)
    from _compat import get_env, ensure_home_migrated

REPO = Path(__file__).resolve().parents[2]


# ── State roots ────────────────────────────────────────────────────────────────
# REPO is the CODE root (tools/, mcp servers, shell scripts — the package
# install tree). Runtime data (recon/, findings/, reports/, hunt-memory/)
# lives under the DATA HOME, resolved exactly like rhodawk/engine.py
# ::_data_home(): $RHODAWK_HOME else ~/.rhodawk, with the install tree never
# used as a fallback. Tree-rooted writes leaked into built wheels (release
# audit R-01) and split MCP state from the CLI/agent state (pre-launch
# audit G1): every runtime read/write below goes through the helpers.

def _data_home() -> Path:
    env = get_env("RHODAWK_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".rhodawk"


def _recon_root() -> Path:
    return _data_home() / "recon"


def _findings_root() -> Path:
    return _data_home() / "findings"


def _reports_root() -> Path:
    return _data_home() / "reports"


def _memory_root() -> Path:
    """Mirrors memory/hunt_journal.default_memory_root(): an explicit
    RHODAWK_MEMORY_DIR wins; otherwise hunt-memory lives under the data home.
    The old CWD-relative default ("hunt-memory") pointed at a directory the
    journal/research writers never populated (pre-launch audit G2)."""
    env = get_env("RHODAWK_MEMORY_DIR")
    if env:
        return Path(env).expanduser()
    return _data_home() / "hunt-memory"


def _sys_path() -> None:
    import sys
    root = str(REPO)
    if root not in sys.path:
        sys.path.insert(0, root)


def _build_checker(domains: list[str] | None, excluded: list[str] | None = None):
    """Build the ONE authoritative ScopeChecker (same class the agent path uses),
    or None if no domains / a dangerous config. Never a second implementation."""
    if not domains:
        return None
    _sys_path()
    from tools.scope_checker import ScopeChecker, ScopeError

    try:
        return ScopeChecker(domains=domains, excluded_domains=excluded)
    except ScopeError as exc:
        import sys as _sys
        print(f"WARNING: rejected unsafe scope configuration: {exc}", file=_sys.stderr)
        return None


# Recon-output files that later scanners read. Mirrors
# agent.ToolDispatcher._filter_recon_urls_to_scope so the MCP path filters
# discovered (possibly out-of-scope) hosts before any active scan reads them.
_RECON_URL_FILES = (
    ("urls", "all.txt"),
    ("urls", "with_params.txt"),
    ("urls", "js_files.txt"),
    ("urls", "api_endpoints.txt"),
    ("urls", "graphql.txt"),
    ("live", "urls.txt"),
)


def _filter_recon_to_scope(target: str, checker) -> dict[str, int]:
    """Drop out-of-scope URLs from recon files in place. Returns per-file counts.
    No-op when checker is None (caller decides fail-closed behavior separately)."""
    dropped: dict[str, int] = {}
    if checker is None:
        return dropped
    recon_dir = _recon_root() / target
    for parts in _RECON_URL_FILES:
        f = recon_dir.joinpath(*parts)
        if not f.is_file():
            continue
        try:
            _kept, out = checker.filter_file(str(f))
            if out:
                dropped["/".join(parts)] = out
        except OSError:
            continue
    return dropped


class UnsafeTargetError(ValueError):
    """Raised when a target/relative path would escape the data-home sandbox."""


def _safe_under(base: Path, *parts: str) -> Path:
    """Join parts under `base` and confirm the result stays inside it.

    `target` reaches these tools from an MCP client and is explicitly untrusted
    (server.py), so a value like '../../../../etc' must not escape the recon
    root. Mirrors the resolve()+containment check rhodawk_get_finding uses.
    """
    base_r = base.resolve()
    candidate = base_r.joinpath(*parts).resolve()
    if candidate != base_r and base_r not in candidate.parents:
        raise UnsafeTargetError(f"path escapes {base_r}")
    return candidate


def scope_check(target: str, domains: list[str], excluded: list[str] | None = None) -> dict[str, Any]:
    _sys_path()
    from tools.scope_checker import ScopeChecker

    checker = ScopeChecker(domains=domains, excluded_domains=excluded)
    ok = checker.is_in_scope(target)
    return {
        "status": "completed",
        "target": target,
        "scope": {"status": "authorized" if ok else "out_of_scope", "domains": domains},
        "in_scope": ok,
        "summary": f"{target} is {'in' if ok else 'OUT OF'} scope",
        "next_action": "continue" if ok else "stop",
    }


def run_recon(target: str, *, timeout: int = 600, scope_checker=None) -> dict[str, Any]:
    """Invoke tools/recon_engine.sh (existing recon).

    If a scope_checker is supplied, recon-discovered URL files are filtered to
    scope in place before any downstream scanner reads them.
    """
    script = REPO / "tools" / "recon_engine.sh"
    if not script.exists():
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": "recon_engine.sh missing"}
    try:
        recon_dir = _safe_under(_recon_root(), target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc)}
    env = os.environ.copy()
    env["RHODAWK_TARGET"] = target
    # Pin the output dir to the contained path so recon_engine.sh cannot be
    # steered outside the data home's recon root by a crafted target.
    env["RECON_OUT_DIR"] = str(recon_dir)
    # Forward the policy engine's ScopeChecker patterns so the reconFTW
    # gap-fill (recon_engine.sh Phases 1.5/5.5) runs under the same fail-closed
    # scope as every other MCP tool. No checker → delegation fails closed
    # inside the adapter (native pipeline unaffected).
    cmd = ["bash", str(script), target]
    if scope_checker is not None:
        for pattern in getattr(scope_checker, "domains", None) or []:
            cmd += ["--scope-domain", str(pattern)]
        for pattern in getattr(scope_checker, "excluded_domains", None) or []:
            cmd += ["--scope-exclude", str(pattern)]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "RESOURCE_LIMIT", "reason": "recon timed out"}
    summary = {
        "status": "completed" if proc.returncode == 0 else "failed",
        "target": target,
        "research": {"stage": "recon"},
        "exit_code": proc.returncode,
        "recon_dir": str(recon_dir) if recon_dir.is_dir() else None,
        "stdout_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-1000:],
        "next_action": "review_attack_surface",
    }
    # Scope-filter discovered URLs in place before anything reads them.
    if recon_dir.is_dir() and scope_checker is not None:
        dropped = _filter_recon_to_scope(target, scope_checker)
        if dropped:
            summary["scope_filtered_out_of_scope"] = dropped
    # ingest leads if recon produced output
    if recon_dir.is_dir():
        try:
            _sys_path()
            from tools.lead_board import ingest
            ingest(target, str(recon_dir))
            summary["memory_updates"] = ["lead_board.ingest"]
        except Exception as exc:  # noqa: BLE001
            summary["lead_ingest_error"] = str(exc)
    return summary


def run_rtw_capability(capability_id: str, target: str, *,
                       scope_checker=None, force: bool = False,
                       timeout: int | None = None) -> dict[str, Any]:
    """Delegate ONE recon capability gap to reconFTW via tools/rtw_adapter.py.

    This is the MCP runtime's route into the same deterministic six-step flow
    every other runtime uses (engine Phase 1.5/5.5, ReAct agent, harness):
    identical manifest schema, identical fail-closed scope gate, identical
    audit trail. The policy engine's ScopeChecker is passed through so the
    adapter's pre-call gate and post-call output filter use the MCP session's
    program scope. No checker → the adapter fails closed on its own.
    """
    _sys_path()
    try:
        from tools import rtw_adapter
    except ImportError as exc:
        return {"status": "failed", "error": "UNAVAILABLE",
                "reason": f"rtw_adapter import failed: {exc}"}
    try:
        recon_dir = _safe_under(_recon_root(), target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc)}
    result = rtw_adapter.run_capability(
        capability_id, target,
        recon_dir=recon_dir if recon_dir else None,
        checker=scope_checker,
        force=force,
        timeout_secs=timeout,
    )
    return result


def read_recon_file(target: str, relative: str, limit: int = 50) -> dict[str, Any]:
    # Both `target` and `relative` are untrusted; contain the joined path so it
    # cannot become an arbitrary-file-read primitive outside the recon root.
    try:
        path = _safe_under(_recon_root(), target, relative)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc), "target": target}
    if not path.exists():
        return {
            "status": "completed",
            "target": target,
            "items": [],
            "summary": f"No file at recon/{target}/{relative}",
        }
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    return {
        "status": "completed",
        "target": target,
        "path": str(path),
        "total": len(lines),
        "items": lines[:limit],
        "summary": f"{min(limit, len(lines))} of {len(lines)} lines",
        "next_action": "expand_on_demand",
    }


def attack_surface(target: str) -> dict[str, Any]:
    """Summarize existing recon artifacts (passive)."""
    try:
        base = _safe_under(_recon_root(), target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc), "target": target}
    if not base.is_dir():
        return {
            "status": "completed",
            "target": target,
            "summary": "No recon artifacts yet — run rhodawk_recon first",
            "next_action": "rhodawk_recon",
        }
    counts = {}
    for rel in ("subdomains/all.txt", "live/urls.txt", "urls/all.txt", "params/all.txt"):
        p = base / rel
        if p.exists():
            counts[rel] = sum(1 for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
    return {
        "status": "completed",
        "target": target,
        "research": {"stage": "attack_surface"},
        "counts": counts,
        "summary": f"Attack surface snapshot for {target}",
        "next_action": "rhodawk_next_lead",
    }


def run_hunt(target: str, *, quick: bool = False, timeout: int = 900, scope_checker=None) -> dict[str, Any]:
    _sys_path()
    # Hard block: never launch active testing against an out-of-scope base
    # target, and filter recon-discovered hosts to scope before the scanner
    # (vuln_scanner.sh) reads them. Uses the one authoritative ScopeChecker.
    if scope_checker is not None:
        if not scope_checker.is_in_scope(target):
            return {
                "status": "denied",
                "error": "OUT_OF_SCOPE",
                "target": target,
                "reason": f"{target} is out of scope — refusing to hunt",
                "next_action": "Choose an in-scope target",
            }
        _filter_recon_to_scope(target, scope_checker)
    try:
        from tools import hunt as hunt_mod
    except Exception:
        hunt_mod = None
    if hunt_mod and hasattr(hunt_mod, "hunt_target"):
        try:
            # hunt_target re-runs recon (which can repopulate URL files with
            # out-of-scope hosts) and then the vuln scanner. Install the SAME
            # ScopeChecker process-wide for the duration so hunt.py's own gate
            # (block out-of-scope target, filter recon files before scanning)
            # applies inside hunt_target too. Restore afterward to avoid leaking
            # scope across MCP calls.
            _prev = getattr(hunt_mod, "_SCOPE_CHECKER", None)
            if scope_checker is not None and hasattr(hunt_mod, "set_scope_checker"):
                hunt_mod.set_scope_checker(scope_checker)
            try:
                result = hunt_mod.hunt_target(target)
            finally:
                if scope_checker is not None and hasattr(hunt_mod, "set_scope_checker"):
                    hunt_mod.set_scope_checker(_prev)
            return {
                "status": "completed",
                "target": target,
                "research": {"stage": "hunt"},
                "result": str(result)[:3000],
                "summary": f"Hunt finished for {target}",
                "next_action": "rhodawk_list_findings",
            }
        except TypeError:
            pass
        except Exception as exc:  # noqa: BLE001
            return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}
    # Fallback: vuln_scanner.sh if present
    scanner = REPO / "tools" / "vuln_scanner.sh"
    if scanner.exists():
        try:
            proc = subprocess.run(
                ["bash", str(scanner), target],
                cwd=str(REPO), capture_output=True, text=True, timeout=timeout,
            )
            return {
                "status": "completed" if proc.returncode == 0 else "failed",
                "target": target,
                "research": {"stage": "hunt"},
                "exit_code": proc.returncode,
                "stdout_tail": (proc.stdout or "")[-2000:],
                "summary": f"vuln_scanner finished for {target}",
                "next_action": "rhodawk_list_findings",
            }
        except subprocess.TimeoutExpired:
            return {"status": "failed", "error": "RESOURCE_LIMIT", "reason": "hunt timed out"}
    return {
        "status": "completed",
        "target": target,
        "research": {"stage": "hunt"},
        "summary": "Hunt adapter: use slash /hunt or agent mode for full tool-calling hunt",
        "next_action": "rhodawk_next_lead",
    }


def list_findings(target: str, limit: int = 20) -> dict[str, Any]:
    try:
        root = _safe_under(_findings_root(), target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc), "target": target}
    if not root.is_dir():
        return {"status": "completed", "target": target, "findings": [], "summary": "No findings directory"}
    items = []
    for p in sorted(root.rglob("*"))[:200]:
        if p.is_file() and p.suffix in {".json", ".md", ".txt"}:
            items.append(str(p.relative_to(_data_home())))
            if len(items) >= limit:
                break
    return {
        "status": "completed",
        "target": target,
        "findings": items,
        "summary": f"{len(items)} finding artifacts",
        "next_action": "rhodawk_validate",
    }


def get_validation(target: str) -> dict[str, Any]:
    # search validation.json under findings
    root = _findings_root()
    hits = list(root.rglob("validation.json")) if root.is_dir() else []
    if target:
        hits = [h for h in hits if target in str(h)]
    if not hits:
        return {"status": "completed", "validation": None, "summary": "No validation.json found"}
    path = hits[0]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": "corrupt validation.json"}
    return {
        "status": "completed",
        "path": str(path),
        "validation": data,
        "summary": f"status={data.get('status')}",
        "next_action": "rhodawk_generate_report" if data.get("status") == "validated_finding" else "investigate",
    }


def generate_report_stub(target: str, finding_id: str | None = None) -> dict[str, Any]:
    """Point at existing report artifacts; do not invent content."""
    reports = _reports_root() / target
    findings = _findings_root() / target
    files = []
    for base in (reports, findings):
        if base.is_dir():
            files.extend(str(p.relative_to(_data_home())) for p in base.rglob("*-report.md"))
            files.extend(str(p.relative_to(_data_home())) for p in base.rglob("*report*.md"))
    if not files:
        return {
            "status": "completed",
            "error": "INSUFFICIENT_EVIDENCE",
            "summary": "No report artifacts — run /validate then /report (or rhodawk report)",
            "finding_id": finding_id,
            "next_action": "rhodawk_validate",
        }
    return {
        "status": "completed",
        "target": target,
        "reports": files[:20],
        "summary": "Existing report drafts (reuse project report format; do not auto-submit)",
        "next_action": "human_review",
    }


def memory_patterns(target: str | None = None, tech: list[str] | None = None) -> dict[str, Any]:
    _sys_path()
    mem = _memory_root()
    path = mem / "patterns.jsonl"
    if not path.exists():
        return {"status": "completed", "patterns": [], "summary": "No patterns.jsonl yet"}
    from memory.pattern_db import PatternDB

    db = PatternDB(path)
    if tech:
        matched = db.match(tech)
    else:
        matched = db.read_all()
    if target:
        matched = [p for p in matched if p.get("target") == target or not target]
    # generalized patterns may omit target filter for cross-target — still redact
    return {
        "status": "completed",
        "patterns": matched[:50],
        "summary": f"{len(matched)} patterns",
        "isolation": "target filter applied" if target else "generalized + all local patterns",
    }


def memory_search(query: str, target: str | None = None, limit: int = 30) -> dict[str, Any]:
    _sys_path()
    mem = _memory_root()
    journal = mem / "journal.jsonl"
    hits = []
    q = query.lower()
    if journal.exists():
        from memory.hunt_journal import HuntJournal
        for row in HuntJournal(journal).read_all():
            if target and row.get("target") != target:
                continue
            blob = json.dumps(row, ensure_ascii=False).lower()
            if q in blob:
                hits.append(row)
            if len(hits) >= limit:
                break
    return {
        "status": "completed",
        "query": query,
        "target": target,
        "hits": hits,
        "summary": f"{len(hits)} journal hits",
    }


def leads_show(target: str) -> dict[str, Any]:
    _sys_path()
    from tools.lead_board import load_ledger
    leads = load_ledger(target)
    return {
        "status": "completed",
        "target": target,
        "leads": leads[:50],
        "summary": f"{len(leads)} leads",
        "next_action": "rhodawk_next_lead",
    }


def leads_next(target: str) -> dict[str, Any]:
    _sys_path()
    from tools.lead_board import load_ledger, rank_key
    leads = [l for l in load_ledger(target) if l.get("status") == "new"]
    if not leads:
        return {"status": "completed", "target": target, "lead": None, "summary": "No untouched leads"}
    lead = sorted(leads, key=rank_key)[0]
    return {
        "status": "completed",
        "target": target,
        "lead": lead,
        "summary": f"Next: {lead.get('id')} {lead.get('skill')} — {lead.get('why')}",
        "next_action": "investigate_then_touch",
    }


def leads_update(target: str, lead_id: str, status: str, note: str | None = None,
                 finding_id: str | None = None) -> dict[str, Any]:
    _sys_path()
    from tools.lead_board import touch
    touch(target, lead_id, status, note, finding_id=finding_id)
    return {
        "status": "completed",
        "target": target,
        "lead_id": lead_id,
        "new_status": status,
        "summary": f"Updated {lead_id} → {status}",
    }


def program_stats(handle: str) -> dict[str, Any]:
    _sys_path()
    try:
        from mcp.hackerone_mcp_server import get_program_stats  # type: ignore
    except Exception:
        try:
            import importlib.util
            path = REPO / "mcp" / "hackerone-mcp" / "server.py"
            spec = importlib.util.spec_from_file_location("h1mcp", path)
            mod = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(mod)
            get_program_stats = mod.get_program_stats
        except Exception as exc:  # noqa: BLE001
            return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}
    try:
        data = get_program_stats(handle)
        return {"status": "completed", "program": handle, "data": data, "summary": f"Stats for {handle}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}


def program_policy(handle: str) -> dict[str, Any]:
    _sys_path()
    try:
        import importlib.util
        path = REPO / "mcp" / "hackerone-mcp" / "server.py"
        spec = importlib.util.spec_from_file_location("h1mcp", path)
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
        data = mod.get_program_policy(handle)
        return {"status": "completed", "program": handle, "policy": data, "summary": f"Policy for {handle}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}


def research(
    target: str,
    mode: str,
    domains: list[str],
    *,
    approve: bool = False,
) -> dict[str, Any]:
    """High-level workflow stages — does not auto-run everything."""
    mode = (mode or "RECON").upper()
    checker = _build_checker(domains)
    stages: list[dict[str, Any]] = []
    out: dict[str, Any] = {
        "status": "completed",
        "target": target,
        "scope": {"status": "authorized", "domains": domains},
        "research": {"stage": mode.lower()},
        "findings": [],
        "leads": [],
        "evidence": [],
        "memory_updates": [],
        "next_action": "continue",
    }
    if mode in {"RECON", "FULL"}:
        stages.append(run_recon(target, scope_checker=checker))
        out["research"]["stage"] = "recon"
    if mode in {"HUNT", "FULL"}:
        stages.append(run_hunt(target, scope_checker=checker))
        out["research"]["stage"] = "hunt"
        out["findings"] = list_findings(target).get("findings", [])
    if mode == "VALIDATE":
        stages.append(get_validation(target))
        out["research"]["stage"] = "validation"
    if mode == "REPORT":
        stages.append(generate_report_stub(target))
        out["research"]["stage"] = "report"
    if mode in {"RECON", "HUNT", "FULL"}:
        lead = leads_next(target)
        out["leads"] = [lead.get("lead")] if lead.get("lead") else []
    out["stages"] = stages
    out["summary"] = f"Mode {mode} finished for {target} (approve={approve})"
    if mode == "FULL":
        out["next_action"] = "rhodawk_validate"
    elif mode == "RECON":
        out["next_action"] = "rhodawk_next_lead"
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Commit 3 — bounded surface-slicing tools + scope compilation adapter
# ══════════════════════════════════════════════════════════════════════════════

_SLICE_BYTE_CAP = 4096


def _json_size(payload: Any) -> int:
    """Serialized byte size. ensure_ascii=True (the json.dumps default) makes
    len(str) == byte length, so caps are byte-exact."""
    return len(json.dumps(payload, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":")))


def _cap_bytes(payload: dict[str, Any], cap: int = _SLICE_BYTE_CAP,
               items_key: str = "items") -> dict[str, Any]:
    """Guarantee the serialized payload never exceeds `cap` bytes.

    Deterministic shedding order: (1) drop tail items from `items_key`,
    (2) halve the free-text fields ("snippet", then "summary"), (3) last
    resort return a truncated raw-JSON carrier. Same input always yields
    the same output. Size is measured with COMPACT separators (the JSON
    MCP transports actually emit); the shedding target keeps ~96 bytes of
    headroom below the cap so even a client that re-serializes with
    space-separated separators stays within `cap`.
    """
    target = min(cap, 3900)
    if _json_size(payload) <= target:
        return payload
    p = json.loads(json.dumps(payload))  # deep copy, order-stable
    items = p.get(items_key)
    if isinstance(items, list):
        while items and _json_size(p) > target:
            items.pop()
    for text_key in ("snippet", "summary"):
        v = p.get(text_key)
        if isinstance(v, str):
            while v and _json_size(p) > target:
                v = v[: max(len(v) // 2, 1)]
            p[text_key] = v
    if _json_size(p) <= target:
        return p
    raw = json.dumps(p, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return {
        "status": "completed",
        "truncated": True,
        "truncated_json": raw[:cap],
        "summary": f"payload exceeded {_SLICE_BYTE_CAP} bytes and was truncated",
    }


def _read_json_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _disclosed_reports_counts(target: str) -> tuple[dict[str, int], str]:
    """Best-effort h1-brain disclosed_reports.db lookup (read-only).

    The DB is optional tooling: when it is absent, unreadable, or has an
    unexpected schema this returns ({}, note) and the surface ranking simply
    runs without report-history boosting. Never raises."""
    candidates = []
    env_home = os.environ.get("RHODAWK_HOME")
    if env_home:
        candidates.append(Path(env_home).expanduser() / "h1-brain" / "disclosed_reports.db")
        candidates.append(Path(env_home).expanduser() / "h1_brain" / "disclosed_reports.db")
    candidates.append(Path.home() / ".rhodawk" / "h1-brain" / "disclosed_reports.db")
    candidates.append(Path.home() / ".rhodawk" / "h1_brain" / "disclosed_reports.db")
    candidates.append(Path.home() / ".rhodawk" / "disclosed_reports.db")
    db_path = next((c for c in candidates if c.is_file()), None)
    if db_path is None:
        return {}, "h1-brain: disclosed_reports.db not present (skipped)"
    try:
        import sqlite3
        apex = target.lower().lstrip("*.") or target.lower()
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        try:
            counts: dict[str, int] = {}
            for table in ("disclosed_reports", "reports"):
                try:
                    rows = con.execute(
                        f"SELECT host, COUNT(*) c FROM {table} "
                        "WHERE lower(host) LIKE ? GROUP BY lower(host) LIMIT 500",
                        (f"%{apex}%",)).fetchall()
                    for host, cnt in rows:
                        if isinstance(host, str) and host:
                            counts[host.lower()] = counts.get(host.lower(), 0) + int(cnt)
                    if counts:
                        break
                except sqlite3.Error:
                    continue
        finally:
            con.close()
        return counts, f"h1-brain: {db_path.name} consulted ({len(counts)} host rows)"
    except Exception as exc:  # noqa: BLE001 — optional enrichment must never fail a read-only tool
        return {}, f"h1-brain: unavailable ({type(exc).__name__})"


def prioritized_surface(target: str, limit: int = 20) -> dict[str, Any]:
    """Compact ranked attack-surface list from recon_truth.json (read-only).

    Deterministic scoring: HTTP 200 > auth walls (401/403) > redirects, with
    boosts for parameterized URLs, open ports, fingerprints and net-new
    hosts; h1-brain disclosed-report history (when present) adds a bounded
    bonus. Response is capped at 4096 serialized bytes.
    """
    limit = max(1, min(int(limit), 50))
    try:
        base = _safe_under(_recon_root(), target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc),
                "target": target}
    truth = _read_json_file(base / "recon_truth.json")
    report_counts, brain_note = _disclosed_reports_counts(target)

    scored: dict[str, dict] = {}

    def _entry(host: str) -> dict:
        return scored.setdefault(host.lower(), {"host": host, "score": 0, "reasons": []})

    for rec in truth.get("hosts") or []:
        if not isinstance(rec, dict) or not rec.get("host"):
            continue
        e = _entry(str(rec["host"]))
        code = rec.get("status_code")
        if code == 200:
            e["score"] += 40
            e["reasons"].append("http 200")
        elif code in (301, 302, 303, 307, 308):
            e["score"] += 25
            e["reasons"].append("redirect")
        elif code in (401, 403):
            e["score"] += 20
            e["reasons"].append(f"auth wall {code}")
        elif code:
            e["score"] += 5
            e["reasons"].append(f"status {code}")
        if rec.get("title"):
            e["score"] += 5
        tech = rec.get("tech") or []
        e["score"] += min(2 * len(tech), 10)
        if tech:
            e["reasons"].append(f"tech: {','.join(map(str, tech[:4]))}")

    for row in truth.get("urls") or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "")
        if "?" in url and "://" in url:
            host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0].lower()
            e = _entry(host)
            e["score"] += 15
            if "parameters" not in e["reasons"]:
                e["reasons"].append("parameterized URLs")

    for row in truth.get("open_ports") or []:
        if isinstance(row, dict) and row.get("host") and row.get("port"):
            e = _entry(str(row["host"]))
            e["score"] += 8
            if f"port {row['port']}" not in e["reasons"]:
                e["reasons"].append(f"port {row['port']}")

    for host in truth.get("new_subdomains") or []:
        if isinstance(host, str) and host:
            e = _entry(host)
            e["score"] += 10
            if "net-new this run" not in e["reasons"]:
                e["reasons"].append("net-new this run")

    for host, cnt in report_counts.items():
        bonus = min(3 * int(cnt), 15)
        entry = _entry(host)
        if entry["score"] == 0:
            # host known only from disclosed-report history — still real,
            # previously-confirmed surface for this program
            entry["reasons"].append("surface from disclosed-report history")
        entry["score"] += bonus
        entry["reasons"].append(f"disclosed reports: {cnt}")

    items = sorted(
        ({"host": e["host"], "priority": e["score"], "reasons": e["reasons"][:4]}
         for e in scored.values()),
        key=lambda x: (-x["priority"], x["host"]),
    )[:limit]
    payload = {
        "status": "completed",
        "target": target,
        "items": items,
        "sources": {
            "recon_truth": bool(truth),
            "h1_brain": brain_note,
        },
        "summary": f"{len(items)} ranked surface entr(ies) for {target}",
        "next_action": "rhodawk_inspect_endpoint_slice",
    }
    return _cap_bytes(payload, items_key="items")


def inspect_endpoint_slice(target: str, endpoint: str) -> dict[str, Any]:
    """Strictly bounded slice of ONE endpoint (read-only, local artifacts).

    Returns only: HTTP status, fingerprint/headers context (httpx tech
    detection), parameters observed for the endpoint, and a short snippet of
    the matching probe line. No bodies, no secrets dumps, response capped at
    4096 serialized bytes.
    """
    endpoint = (endpoint or "").strip()
    try:
        base = _safe_under(_recon_root(), target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc),
                "target": target}
    ep_norm = endpoint.lower()
    if "://" in ep_norm:
        ep_norm = ep_norm.split("://", 1)[1]
    ep_norm = ep_norm.rstrip("/")

    def _first_token(line: str) -> str:
        return (line.split() or [""])[0].lower()

    def _token_matches(tok: str) -> bool:
        tok = tok.rstrip("/")
        tok_noscheme = tok.split("://", 1)[1] if "://" in tok else tok
        return tok == ep_norm or tok_noscheme == ep_norm

    status_code, title, tech, snippet = None, "", [], ""
    httpx_path = base / "live" / "httpx_full.txt"
    if httpx_path.is_file():
        for raw in httpx_path.read_text(encoding="utf-8", errors="replace").splitlines():
            tok = _first_token(raw)
            if tok and _token_matches(tok):
                snippet = raw[:512]
                parts = raw.split("[")
                for i, chunk in enumerate(parts[1:], start=1):
                    val = chunk.split("]")[0].strip()
                    if val.isdigit() and status_code is None:
                        status_code = int(val)
                    elif i == 2 and val and not title:
                        title = val
                    elif i >= 3 and val and "," in val:
                        tech = [t.strip() for t in val.split(",") if t.strip()][:10]
                break

    params: list[str] = []
    params_path = base / "params" / "all.txt"
    if params_path.is_file() and endpoint:
        ep_path = "/" in ep_norm and "/" + ep_norm.split("/", 1)[1] or ""
        ep_host = ep_norm.split("/", 1)[0]
        for raw in params_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            low = line.lower()
            if ep_host in low or (ep_path and ep_path.lower() in low):
                params.append(line[:200])
            if len(params) >= 20:
                break

    payload = {
        "status": "completed" if status_code is not None or snippet else "not_probed",
        "target": target,
        "endpoint": endpoint,
        "http": {"status_code": status_code, "title": title[:200], "tech": tech},
        "params": params,
        "snippet": snippet,
        "summary": (f"endpoint slice: status={status_code}, "
                    f"{len(params)} param lines" if status_code is not None
                    else "endpoint not found in live/httpx_full.txt"),
    }
    return _cap_bytes(payload, items_key="params")


def compile_scope(program_handle: str) -> dict[str, Any]:
    """Compile a program's scope via tools/scope_compiler.py (no subprocess).

    Credentials are loaded exclusively through tools/credentials.py and are
    only ever used inside Authorization headers by the compiler — they are
    never logged, echoed, or stored in the manifest. Returns the compiler's
    redacted summary (counts, filesystem paths, short hash — never tokens).
    """
    _sys_path()
    try:
        from tools.scope_compiler import ScopeCompilerError, compile_and_save
    except ImportError as exc:
        return {"status": "failed", "error": "RESEARCH_FAILED",
                "reason": f"scope_compiler unavailable: {exc}"}
    creds = None
    try:
        from tools.credentials import load_credentials
        creds = load_credentials(interactive=False)
    except Exception:  # noqa: BLE001 — keyless fallback is fine
        creds = None
    try:
        summary = compile_and_save(program_handle, creds=creds)
    except (ScopeCompilerError, ValueError) as exc:
        return {"status": "failed", "error": "RESEARCH_FAILED",
                "reason": str(exc)[:300]}
    handle = summary.get("program_handle", "")
    return {
        "status": "completed",
        **summary,
        "summary": (f"Compiled scope for {handle}: "
                    f"{summary.get('allow_patterns')} allow / "
                    f"{summary.get('exclude_patterns')} exclude "
                    f"(sha256:{summary.get('manifest_sha256', '')[:16]})"),
        "next_action": "active tools now authorized by this manifest",
    }
