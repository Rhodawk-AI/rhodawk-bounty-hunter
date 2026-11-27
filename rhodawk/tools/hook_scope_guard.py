#!/usr/bin/env python3
"""hook_scope_guard.py -- deterministic PreToolUse scope guard (Commit 4).

Wired from ``hooks/hooks.json`` as a Claude Code ``PreToolUse`` hook. Every
tool call that could touch the network arrives as JSON on stdin:

    {"session_id": "...", "tool_name": "Bash", "tool_input": {"command": "..."}}

Behaviour (fail-closed, deterministic -- no judgment calls):

- **read-only / non-target tools** (Read, Grep, rhodawk_scope_check,
  rhodawk_prioritized_surface, ...) -> ``exit 0`` immediately;
- **active recon/hunt/network tools** (``rhodawk_recon``, ``rhodawk_hunt``,
  ``rhodawk_hunt_class``, ``rhodawk_research``,
  ``rhodawk_run_rtw_capability``, Bash calls containing
  ``recon_engine.sh`` / ``full_hunt.sh`` / ``rtw_adapter.py`` /
  ``scope_aggregator.sh`` / ``hunt.py`` / ``rhodawk recon|hunt``) require a
  valid ``compiled_scope.json``:

    resolution order (first source that yields a path is authoritative,
    no silent fallback to a different manifest):
      1. ``--manifest <path>`` CLI flag of this guard;
      2. ``--scope-manifest <path>`` / ``--manifest <path>`` inside the Bash
         command string itself;
      3. ``tool_input["manifest_path"]`` (MCP tools carry it);
      4. ``$RHODAWK_SCOPE_MANIFEST`` environment variable;
      5. target-derived default location:
         ``recon/<target>/scope/compiled_scope.json``;
      6. otherwise: a ``recon/*/scope/compiled_scope.json`` glob -- allowed
         only when exactly one manifest exists (ambiguous -> block).

    The resolved file must load through
    ``CompiledScopeManifest.load(..., require_valid_hash=True)`` (SHA-256
    integrity). Missing file, tampered content, or an unloadable contract
    -> ``exit 2`` with a ``SCOPE_HOOK_BLOCK`` message on stderr (Claude Code
    surfaces stderr + exit 2 back to the model as a tool-call block).

Exit codes: ``0`` allow, ``2`` block (including an unparseable or non-object
stdin payload — fail closed), ``1`` internal usage error.
Note: this gate is deliberately stricter than the MCP tool contract -- the
caller-supplied ``scope_domains`` path does NOT satisfy the hook. The
PreToolUse hook is the outermost boundary, so it accepts only the
hash-verified manifest. Compile one with ``rhodawk scope-compile`` /
``rhodawk_compile_scope``.

CLI convenience (no stdin needed):

    python3 rhodawk/tools/hook_scope_guard.py --manifest <path> \
        --tool rhodawk_recon --target <target>

Zero secret leakage: reads tool-call JSON and manifest paths only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
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

HERE = Path(__file__).resolve().parent          # rhodawk/tools
RHODAWK_DIR = HERE.parent                     # rhodawk/
REPO_ROOT = RHODAWK_DIR.parent                # repository root

BLOCK_PREFIX = "SCOPE_HOOK_BLOCK"
MANIFEST_REL = "scope/compiled_scope.json"

# ── contract import (same duck-typing as scope_checker.py) ────────────────

def _load_contract():
    """Import CompiledScopeManifest from either supported import path."""
    try:
        sys.path.insert(0, str(HERE))
        from contracts.scope import CompiledScopeManifest  # type: ignore
        return CompiledScopeManifest
    except ImportError:
        pass
    try:
        sys.path.insert(0, str(RHODAWK_DIR))
        from contracts.scope import CompiledScopeManifest  # type: ignore
        return CompiledScopeManifest
    except ImportError:
        pass
    return None


# ── classification ────────────────────────────────────────────────────────

# MCP tools that drive active network traffic (name as registered on
# rhodawk-mcp; matched on the trailing segment so the mcp__server__ prefix
# does not matter).
ACTIVE_TOOL_NAMES = {
    "rhodawk_recon",
    "rhodawk_hunt",
    "rhodawk_hunt_class",
    "rhodawk_research",
    "rhodawk_run_rtw_capability",
}

# Bash command substrings that always mean active recon/hunt/network work.
ACTIVE_COMMAND_SUBSTRINGS = (
    "recon_engine.sh",
    "full_hunt.sh",
    "rtw_adapter.py",
    "scope_aggregator.sh",
    "hunt.py",
)

# CLI invocations of the engine, e.g. `rhodawk recon X`, `python3
# rhodawk/engine.py hunt X`, `rhodawk full-hunt`.
ACTIVE_CLI_RE = re.compile(
    r"\brhodawk(?:\.py|/engine\.py)?\s+(?:recon|hunt|full-hunt)\b"
    r"|\brhodawk\s+engine\.py\s+(?:recon|hunt|full-hunt)\b"
)

# Reads a command string and returns the first positional target after an
# active script/subcommand (skipping flag tokens and their values).
_TARGET_AFTER_SCRIPT_RE = re.compile(
    r"(?:recon_engine\.sh|full_hunt\.sh)\s+([^\s-][^\s]*)"
)
_TARGET_AFTER_SUBCMD_RE = re.compile(
    r"\brhodawk(?:\.py|/engine\.py)?\s+(?:recon|hunt|full-hunt)\s+([^\s-][^\s]*)"
)
_MANIFEST_IN_COMMAND_RE = re.compile(
    r"(?:--scope-manifest|--manifest)[\s=](\"[^\"]+\"|'[^']+'|\S+)"
)

# Fix 2 (mission item 2): bare curl/wget to an arbitrary host is real
# network traffic toward a possibly out-of-scope target. When a scope
# manifest IS resolvable, every explicit http(s) URL in the command must be
# inside the verified manifest; without any manifest the documented
# allow-behavior is unchanged (fail-closed only against a KNOWN authority).
CURL_WGET_RE = re.compile(r"\b(?:curl|wget)\b")
_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def classify(tool_name: str, tool_input: dict) -> str:
    """Return 'active' when the tool call drives target-side network work."""
    name = (tool_name or "").strip()
    short = name.split("__")[-1] if "__" in name else name

    if name in ACTIVE_TOOL_NAMES or short in ACTIVE_TOOL_NAMES:
        return "active"

    if name == "Bash" or short == "Bash":
        command = str(tool_input.get("command") or "")
        if command:
            if any(sub in command for sub in ACTIVE_COMMAND_SUBSTRINGS):
                return "active"
            if ACTIVE_CLI_RE.search(command):
                return "active"
            if CURL_WGET_RE.search(command):
                # Fix 2: bare curl/wget IS network work. Classified as
                # "fetch": checked against a RESOLVABLE manifest when one
                # exists (out-of-scope URL host ⇒ blocked); without any
                # manifest the documented allow behavior is unchanged, so
                # installers / doctor Bash usage keeps working.
                return "fetch"

    return "readonly"  # read-only and unknown tools are non-target -> allow


# ── manifest resolution ──────────────────────────────────────────────────

def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _extract_target(command: str) -> str:
    """Best-effort target extraction from a Bash command string."""
    for regex in (_TARGET_AFTER_SCRIPT_RE, _TARGET_AFTER_SUBCMD_RE):
        match = regex.search(command)
        if match:
            return _strip_quotes(match.group(1))
    return ""


def _normalize_target(raw: str) -> str:
    """Map a target/asset string to the recon directory name."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.strip("/")
    if "/" in raw:  # file-of-hosts target -> recon_engine list mode uses basename
        raw = os.path.basename(raw)
    return raw


def _expand_relative(candidate: str):
    """Yield absolute paths for a possibly-relative manifest path."""
    expanded = os.path.expanduser(candidate)
    p = Path(expanded)
    if p.is_absolute():
        yield p
        return
    yield Path.cwd() / p
    yield REPO_ROOT / p


def resolve_manifest(explicit, tool_input, command, env) -> tuple:
    """Return (path_or_None, failure_reason_or_None, source_name).

    The first source that yields a path is authoritative -- if that path
    does not exist we block instead of silently trying a weaker source.
    """
    # 1. guard's own --manifest flag
    if explicit:
        return explicit, None, "--manifest flag"
    # 2. manifest referenced inside the Bash command itself
    if command:
        match = _MANIFEST_IN_COMMAND_RE.search(command)
        if match:
            return _strip_quotes(match.group(1)), None, "command --scope-manifest"
    # 3. MCP tool_input carries manifest_path
    mp = tool_input.get("manifest_path")
    if isinstance(mp, str) and mp.strip():
        return mp.strip(), None, "tool_input.manifest_path"
    # 4. environment
    env_path = get_env("RHODAWK_SCOPE_MANIFEST", default="").strip()
    if env_path:
        return env_path, None, "$RHODAWK_SCOPE_MANIFEST"
    # 5. target-derived default location
    target = ""
    for key in ("target", "target_domain", "domain", "asset",
                "program_handle", "handle"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            target = value.strip()
            break
    if not target and command:
        target = _extract_target(command)
    target = _normalize_target(target)
    if target:
        derived = f"recon/{target}/{MANIFEST_REL}"
        return derived, None, f"target-derived ({target})"
    # 6. exactly one manifest under recon/ (ambiguous -> block)
    base_roots = [Path.cwd(), REPO_ROOT]
    seen = set()
    matches = []
    for root in base_roots:
        try:
            for found in root.glob(f"recon/*/{MANIFEST_REL}"):
                resolved = found.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    matches.append(resolved)
        except OSError:
            continue
    if len(matches) == 1:
        return matches[0], None, "auto-detected single manifest"
    if len(matches) > 1:
        return None, (
            f"{len(matches)} manifests under recon/*/scope/ -- pass one "
            "explicitly (--scope-manifest <path>)"), "glob"
    return None, None, "none"


def verify_manifest(raw_path: str):
    """Return (ok, error_message). Loads with require_valid_hash=True."""
    contract = _load_contract()
    if contract is None:
        return False, ("integrity checker unavailable: contracts/scope.py "
                       "could not be imported (fail-closed)")
    last_error = None
    for path in _expand_relative(raw_path):
        if not path.is_file():
            if last_error is None:
                last_error = f"manifest not found: {path}"
            continue
        try:
            contract.load(str(path), require_valid_hash=True)
        except FileNotFoundError:
            last_error = f"manifest not found: {path}"
        except ValueError as exc:
            # an existing-but-tampered manifest is authoritative: block now,
            # never silently fall through to another location
            return False, f"manifest failed integrity verification: {exc}"
        except Exception as exc:  # noqa: BLE001 -- any load failure blocks
            return False, f"manifest could not be loaded: {exc}"
        else:
            return True, None
    return False, (last_error or f"manifest not found: {raw_path}")


# ── fetch (curl/wget) scope check — Fix 2 ─────────────────────────────────

def _load_scope_checker():
    """Import ScopeChecker from either supported import path."""
    try:
        sys.path.insert(0, str(HERE))
        from scope_checker import ScopeChecker  # type: ignore
        return ScopeChecker
    except ImportError:
        pass
    try:
        sys.path.insert(0, str(RHODAWK_DIR))
        from tools.scope_checker import ScopeChecker  # type: ignore
        return ScopeChecker
    except ImportError:
        pass
    return None


def _out_of_scope_fetch_urls(command: str, checker) -> list:
    """http(s) URLs in a curl/wget command that the verified manifest does
    NOT cover. Non-URL curl invocations (--help, file uploads) yield []."""
    hosts_out = []
    for url in _HTTP_URL_RE.findall(command or ""):
        try:
            if not checker.is_in_scope(url):
                parsed = urlparse(url)
                hosts_out.append(parsed.netloc or url)
        except Exception:  # noqa: BLE001 — uncheckable URL: fail-closed
            hosts_out.append(url)
    return hosts_out


# ── main ─────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic PreToolUse scope guard "
                    "(SCOPE_HOOK_BLOCK on missing/tampered manifest)")
    parser.add_argument("--manifest", default=None,
                        help="Authoritative compiled_scope.json path")
    parser.add_argument("--tool", default=None,
                        help="Tool name override (no-stdin invocation)")
    parser.add_argument("--target", default=None,
                        help="Target override for default-location lookup")
    parser.add_argument("--command", default=None,
                        help="Command string override (Bash simulation)")
    args = parser.parse_args(argv)

    payload: dict = {}
    try:
        stdin_data = "" if sys.stdin.isatty() else (sys.stdin.read() or "")
    except Exception:  # noqa: BLE001
        stdin_data = ""
    if stdin_data.strip():
        # FAIL CLOSED (R-11): a hook payload we cannot parse is NOT treated as
        # a harmless read-only call — the only safe assumption is that it may
        # be an active network tool whose scope we cannot verify, so it is
        # blocked (exit 2) with an actionable message. The previous fail-open
        # behavior let malformed JSON bypass the scope gate entirely.
        try:
            parsed = json.loads(stdin_data)
        except ValueError:
            print(f"{BLOCK_PREFIX}: unparseable hook payload (invalid JSON) — "
                  "blocked fail-closed. Ensure the PreToolUse hook receives a "
                  "JSON object with tool_name/tool_input.", file=sys.stderr)
            return 2
        if not isinstance(parsed, dict):
            print(f"{BLOCK_PREFIX}: malformed hook payload (expected a JSON "
                  "object, got " + type(parsed).__name__ + ") — blocked "
                  "fail-closed.", file=sys.stderr)
            return 2
        payload = parsed

    tool_name = args.tool or str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    tool_input = dict(tool_input) if isinstance(tool_input, dict) else {}
    # CLI overrides participate in classification exactly like stdin JSON.
    if args.command is not None and not tool_input.get("command"):
        tool_input["command"] = args.command
    if args.target and not tool_input.get("target"):
        tool_input["target"] = args.target

    command = args.command if args.command is not None \
        else str(tool_input.get("command") or "")

    classification = classify(tool_name, tool_input)
    if classification == "fetch":
        # Fix 2 (mission item 2): curl/wget with explicit http(s) URLs is
        # checked against a RESOLVABLE manifest. Without any resolvable
        # manifest the allow-behavior is unchanged (manifest-less sessions
        # keep working: installers, doctor Bash, ad-hoc curls to unrelated
        # services). With one, out-of-scope fetch hosts are blocked — the
        # same contract every bundled scanner already honors.
        path, _res_err, source = resolve_manifest(
            args.manifest, tool_input, command, os.environ)
        if path is not None:
            ok, error = verify_manifest(str(path))
            if not ok:
                # FAIL CLOSED: a manifest that resolves but fails verification
                # (tampered, unreadable, missing) must block the fetch —
                # silently allowing here would disable the scope gate.
                print(f"{BLOCK_PREFIX}: curl/wget denied — {error} "
                      f"(source: {source})", file=sys.stderr)
                return 2
            ScopeChecker = _load_scope_checker()
            if ScopeChecker is None:
                print(f"{BLOCK_PREFIX}: curl/wget denied — scope checker "
                      f"unavailable (fail-closed) (source: {source})",
                      file=sys.stderr)
                return 2
            try:
                checker = ScopeChecker.from_manifest(str(path))
            except ValueError as exc:  # tampered manifest
                print(f"{BLOCK_PREFIX}: curl/wget denied — manifest "
                      f"failed integrity verification ({exc}) "
                      f"(source: {source})", file=sys.stderr)
                return 2
            oos = _out_of_scope_fetch_urls(command, checker)
            if oos:
                print(f"{BLOCK_PREFIX}: curl/wget target(s) outside "
                      f"the verified scope manifest (source: {source}): "
                      f"{', '.join(sorted(set(oos)))}. Re-run "
                      f"`rhodawk scope-compile <handle>` if the "
                      f"program scope changed.", file=sys.stderr)
                return 2
        return 0  # no manifest resolvable / non-URL fetch: unchanged behavior
    if classification != "active":
        return 0  # read-only / non-target: allow without checks

    explicit = args.manifest
    path, resolution_error, source = resolve_manifest(
        explicit, tool_input, command, os.environ)

    if path is None:
        reason = resolution_error or (
            "no compiled_scope.json could be located -- compile scope first: "
            "rhodawk scope-compile <handle> (or set RHODAWK_SCOPE_MANIFEST)")
        print(f"{BLOCK_PREFIX}: active recon/hunt tool '{tool_name}' denied "
              f"(source: {source}). {reason}", file=sys.stderr)
        return 2

    ok, error = verify_manifest(str(path))
    if not ok:
        print(f"{BLOCK_PREFIX}: active recon/hunt tool '{tool_name}' denied "
              f"(manifest source: {source}). {error}", file=sys.stderr)
        return 2

    return 0  # verified manifest intact -- allow


if __name__ == "__main__":
    sys.exit(main())
