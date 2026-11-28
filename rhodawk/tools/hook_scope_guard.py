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
      5. target-derived default location, anchored to the runtime data home
         (B-4: never an attacker-plantable ``Path.cwd()``):
         ``${RHODAWK_HOME:-~/.rhodawk}/recon/<target>/scope/compiled_scope.json``;
      6. otherwise: a ``recon/*/scope/compiled_scope.json`` glob under the
         data home (``$RHODAWK_HOME`` — CWD only when it lives INSIDE the
         data home) -- allowed only when exactly one manifest exists
         (ambiguous -> block).

    The resolved file must load through
    ``CompiledScopeManifest.load(..., require_valid_hash=True)`` (SHA-256
    integrity). Missing file, tampered content, or an unloadable contract
    -> ``exit 2`` with a ``SCOPE_HOOK_BLOCK`` message on stderr (Claude Code
    surfaces stderr + exit 2 back to the model as a tool-call block).

B-3: raw network one-liners in Bash calls are ACTIVE work, not read-only —
``nc`` / ``ncat`` / ``socat`` / ``openssl s_client`` and
``python[23] -c "import urllib|requests|http.client|httpx|socket ..."``
classify as ``active`` and require the same verified manifest as scanners.
B-3/B-4: ``curl`` / ``wget`` to a NON-loopback host with NO resolvable
manifest now fails closed (``exit 2``); loopback and non-URL fetches stay
allowed, and ``RHODAWK_HOOK_ALLOW_UNSCOPED_FETCH=1`` is the explicit opt-in
for authorized unscoped fetches.

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

# ── durable-copy repo resolution (live-sandbox P0 fix) ────────────────────
# install.sh copies this guard to ~/.rhodawk/hooks/hook_scope_guard.py and
# records the source repo in ~/.rhodawk/hooks/.repo_root (0600). The copy is
# NOT two directories below the package, so the historical "flat import"
# fallback below resolves nothing and the module import crashed with an
# exit-1 ModuleNotFoundError traceback before main() could fail closed.
# Resolution order here: $RHODAWK_REPO_DIR, then the .repo_root record. When
# a valid repo is found, BOTH the repo root and the rhodawk/ package dir go
# on sys.path so `rhodawk._compat`, `contracts.scope` (rhodawk/contracts)
# and `scope_checker` all import cleanly — even under bare system python3,
# cwd=/tmp and a stripped env (no PYTHONPATH).
_REPO_HINT = os.environ.get("RHODAWK_REPO_DIR", "")
if not _REPO_HINT:
    try:
        _hint_file = Path(__file__).resolve().parent / ".repo_root"
        if _hint_file.is_file():
            _REPO_HINT = _hint_file.read_text(encoding="utf-8").strip()
    except OSError:
        _REPO_HINT = ""
if _REPO_HINT:
    try:
        _repo_root = Path(_REPO_HINT).resolve()
        if (_repo_root / "rhodawk").is_dir():
            for _p in (str(_repo_root), str(_repo_root / "rhodawk")):
                if _p not in sys.path:
                    sys.path.insert(0, _p)
    except OSError:
        pass

try:
    from rhodawk._compat import get_env, ensure_home_migrated
except ImportError:  # flat / script execution — resolve package dir
    try:
        import os as _compat_os, sys as _compat_sys
        _compat_dir = _compat_os.path.abspath(__file__)
        for _ in range(2):
            _compat_dir = _compat_os.path.dirname(_compat_dir)
        if _compat_dir not in _compat_sys.path:
            _compat_sys.path.insert(0, _compat_dir)
        from _compat import get_env, ensure_home_migrated
    except ImportError:
        # Broken environment (repo deleted AND venv uninstalled): NEVER crash
        # the hook with an exit-1 traceback — fail closed instead. Minimal
        # stdlib shims keep execution on its way to main(), which returns
        # exit 2 (SCOPE_HOOK_BLOCK) whenever contracts/scope.py or
        # ScopeChecker cannot be imported.
        def get_env(new_name, *legacy_names, default=None):
            value = os.environ.get(new_name)
            if value is not None:
                return value
            for legacy in legacy_names:
                value = os.environ.get(legacy)
                if value is not None:
                    return value
            return default

        def ensure_home_migrated() -> None:
            return None

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

# ── Layer 1B Issue #5 (SECURITY): direct active-scanner invocations ───────
# Live defect: `nuclei -u https://example.com` in a Bash tool call classified
# as "readonly" and exited 0 (ALLOW) with ZERO scope manifest present — the
# PreToolUse gate was trivially bypassed by calling the bundled scanners
# directly instead of through the rhodawk engine.
ACTIVE_SCANNER_BINARIES = frozenset((
    "nuclei", "ffuf", "nmap", "masscan", "naabu", "httpx", "katana",
    "subfinder", "amass", "gau", "waybackurls", "dnsx", "sqlmap", "dalfox",
    "nikto", "gobuster", "feroxbuster", "dirsearch", "wfuzz", "hydra",
    "wpscan", "interactsh-client", "arjun", "kiterunner", "kr",
))

# A scanner counts as INVOKED when its name sits in command position: at the
# start of the command, after a shell separator/opener (newline, ;, |, &,
# $(, backtick, (, {, quotes), or after a wrapper (sudo/env/timeout/... incl.
# their short flags) plus env assignments. A path prefix (/usr/bin/nmap,
# ~/.go/bin/nuclei) still counts. "echo nuclei", `command -v nuclei`,
# `which nuclei`, wordlist names (nuclei-templates) do NOT match: the name is
# a plain argument there (no separator/wrapper before it).
_SCANNER_NAME_ALT = "|".join(
    sorted(ACTIVE_SCANNER_BINARIES, key=len, reverse=True))
_SCANNER_WRAPPER = (
    r"(?:\w+=\S+"
    r"|sudo(?:\s+-\w+)*"
    r"|nohup|nice(?:\s+-n\s*\d+)?|time|env|command|stdbuf|flock|watch|xargs"
    r"|timeout(?:\s+\d+\S*)?)"
)
_SCANNER_INVOCATION_RE = re.compile(
    r"(?:^|[\n;|&]|\$\(|`|\(|\{|['\"])\s*"
    r"(?:" + _SCANNER_WRAPPER + r"\s+)*"
    r"(?:[~\w./+-]*/)?"
    r"(" + _SCANNER_NAME_ALT + r")"
    r"(?![\w.-])"
    # Benign version/help/existence probes are NOT active scans: when the
    # FIRST argument after the binary is exactly a version/help flag
    # (nuclei -version, nmap --version, ffuf -h, sqlmap --help ...) the call
    # is a probe. A real scan never starts with one of these tokens.
    r"(?:\s+(-{1,2}(?:version|h|help|V)|version|help)(?![\w-]))?"
)

# Explicit target arguments of scanner invocations (Layer 1B Issue #5):
# -u/-url/-target/-d/-domain/-host values, checked against the verified
# manifest in addition to every http(s) URL in the command. Bare -t/-h are
# deliberately NOT consumed here (-t is threads in ffuf, -h is help in most
# tools); a bare-host value gets an https:// scheme prepended for the check.
_SCANNER_TARGET_FLAG_RE = re.compile(
    r"(?:^|[\s;|&])-(?:u|url|target|d|domain|host)\s+"
    r"(\"[^\"]+\"|'[^']+'|[^\s]+)",
    re.IGNORECASE,
)

# B-3: raw network one-liners. nc/ncat/socat/`openssl s_client` are arbitrary
# socket clients (connect, bind shells, TLS tunnels) — they were classified
# "readonly" and bypassed the hook entirely. Same command-position + version
# probe semantics as the scanner regex.
_NET_CLIENT_RE = re.compile(
    r"(?:^|[\n;|&]|\$\(|`|\(|\{|['\"])\s*"
    r"(?:[~\w./+-]*/)?(?:nc|ncat|socat)(?![\w.-])"
)
# version/help probes (nc -h, ncat --help, socat -V) stay benign — same
# contract as the active-scanner regex.
_NET_CLIENT_PROBE_RE = re.compile(
    r"(?:^|[\n;|&]|\$\(|`|\(|\{|['\"])\s*"
    r"(?:[~\w./+-]*/)?(?:nc|ncat|socat)\s+"
    r"(?:-{1,2}(?:version|h|help|V))(?![\w-])"
)
_OPENSSL_S_CLIENT_RE = re.compile(r"\bopenssl\s+s_client\b")
# python/python3 -c one-liners whose CODE imports a network library — the
# quoted argument is inspected, so `echo "import urllib"` never matches.
_PY_C_RE = re.compile(r"\bpython[0-9wx.]*\s+-c\s*(?:'([^']*)'|\"([^\"]*)\")")
_NET_LIB_MARKERS = ("urllib", "requests", "http.client", "httpx", "socket")


def python_net_oneliner(command: str) -> bool:
    """True when a `python[23] -c <code>` argument references a network lib.

    B-3: `python3 -c "import urllib.request; ..."` fetched arbitrary hosts
    while classified read-only. Only the quoted code of a real -c invocation
    counts; plain mentions in echo/args do not."""
    for match in _PY_C_RE.finditer(command or ""):
        code = match.group(1) or match.group(2) or ""
        if any(marker in code for marker in _NET_LIB_MARKERS):
            return True
    return False


def network_one_liner(command: str) -> str | None:
    """Return the offending tool when the command drives raw network I/O
    (nc/ncat/socat/openssl s_client or a python -c network one-liner).
    Version/help probes (nc -h) stay benign, mirroring scanner_invocation."""
    if _NET_CLIENT_PROBE_RE.search(command or ""):
        return None
    if _NET_CLIENT_RE.search(command or ""):
        return "nc/ncat/socat"
    if _OPENSSL_S_CLIENT_RE.search(command or ""):
        return "openssl s_client"
    if python_net_oneliner(command or ""):
        return "python -c network one-liner"
    return None


def scanner_invocation(command: str) -> str | None:
    """Return the scanner binary name when `command` really invokes one.

    Version/help/existence probes (nuclei -version, which nuclei,
    command -v ffuf, nmap --help) return None — they must never trip the
    fail-closed gate. Real invocations (nuclei -u https://example.com,
    ffuf -u https://target.com/FUZZ -w list.txt) return the binary name.
    """
    match = _SCANNER_INVOCATION_RE.search(command or "")
    if not match or match.group(2):
        return None  # no scanner in command position, or a benign probe
    return match.group(1)


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
            # Layer 1B Issue #5: a direct scanner invocation (nuclei, ffuf,
            # nmap, ...) IS active work. Version/help/existence probes
            # (nuclei -version, which nuclei) are NOT — scanner_invocation
            # returns None for them so they stay read-only.
            if scanner_invocation(command):
                return "active"
            # B-3: raw network one-liners (nc/ncat/socat/openssl s_client,
            # python -c urllib/requests/socket/...) are active network work,
            # not read-only — previously they bypassed the hook entirely.
            if network_one_liner(command):
                return "active"
            if CURL_WGET_RE.search(command):
                # Fix 2 + B-3: bare curl/wget IS network work. Classified as
                # "fetch": with a RESOLVABLE manifest, out-of-scope URL hosts
                # are blocked; without one, fetches to NON-loopback hosts now
                # FAIL CLOSED (loopback + non-URL fetches stay allowed;
                # RHODAWK_HOOK_ALLOW_UNSCOPED_FETCH=1 is the explicit opt-in).
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


def _data_home() -> Path:
    """Runtime data home: $RHODAWK_HOME when set, else ~/.rhodawk.

    B-4: manifest auto-discovery anchors here (and only here, plus a CWD
    that itself lives inside the data home) so a self-consistent manifest
    planted in an arbitrary working directory can never self-authorize."""
    env = get_env("RHODAWK_HOME", default="")
    if env and env.strip():
        return Path(env.strip()).expanduser()
    return Path.home() / ".rhodawk"


def _expand_relative(candidate: str):
    """Yield absolute paths for a possibly-relative manifest path."""
    expanded = os.path.expanduser(candidate)
    p = Path(expanded)
    if p.is_absolute():
        yield p
        return
    yield Path.cwd() / p
    yield REPO_ROOT / p
    # B-4: also try the data home for relative explicit paths — an operator
    # may pass a data-home-relative manifest from any working directory.
    yield _data_home() / p


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
        # B-4: anchored to the data home — the old CWD-relative
        # `recon/<target>/scope/compiled_scope.json` let a planted
        # self-consistent manifest in an arbitrary working directory
        # self-authorize any active tool.
        derived = _data_home() / "recon" / target / MANIFEST_REL
        return str(derived), None, f"target-derived ({target}, data home)"
    # 6. exactly one manifest under recon/ — anchored to the data home
    # (B-4); a CWD outside the data home is never trusted as a glob root.
    base_roots = [_data_home()]
    try:
        cwd = Path.cwd().resolve()
        home = _data_home().resolve()
        if cwd == home or home in cwd.parents:
            base_roots.append(cwd)
    except OSError:
        pass
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


# B-3: loopback hosts are benign fetch targets (local doctor/API servers);
# everything else needs a manifest or the explicit opt-in.
_LOOPBACK_HOST_RE = re.compile(
    r"^(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[?::1\]?|0\.0\.0\.0)(?::\d+)?$",
    re.IGNORECASE,
)


def _external_fetch_urls(command: str) -> list:
    """http(s) URLs in a fetch command whose host is NOT loopback (B-3)."""
    out = []
    for url in _HTTP_URL_RE.findall(command or ""):
        try:
            host = (urlparse(url).netloc or "").split("@")[-1]
        except Exception:  # noqa: BLE001 — unparseable: treat as external
            out.append(url)
            continue
        if not host or not _LOOPBACK_HOST_RE.match(host.strip()):
            out.append(url)
    return out


def _out_of_scope_scanner_targets(command: str, checker) -> list:
    """Layer 1B Issue #5: explicit targets of a direct scanner invocation
    that the verified manifest does NOT cover — every http(s) URL in the
    command plus the values of -u/-url/-target/-d/-domain/-host. Bare-host
    values get an https:// scheme prepended for the scope check."""
    hosts_out = []
    checked = set()

    def _check(raw: str) -> None:
        raw = _strip_quotes(raw)
        if not raw or raw in checked:
            return
        checked.add(raw)
        try:
            if not checker.is_in_scope(raw):
                parsed = urlparse(
                    raw if "://" in raw else "https://" + raw)
                hosts_out.append(parsed.netloc or raw)
        except Exception:  # noqa: BLE001 — uncheckable target: fail-closed
            hosts_out.append(raw)

    for url in _HTTP_URL_RE.findall(command or ""):
        _check(url)
    for flag_value in _SCANNER_TARGET_FLAG_RE.findall(command or ""):
        _check(flag_value)
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
            return 0  # in-scope / loopback / non-URL fetch: allowed
        # B-3 fail-closed: NO manifest resolvable + a NON-loopback fetch
        # target. The old behavior allowed any curl/wget through (installers
        # / doctor convenience), which let a model probe arbitrary hosts with
        # zero scope validation. Loopback + non-URL fetches stay allowed;
        # RHODAWK_HOOK_ALLOW_UNSCOPED_FETCH=1 is the explicit opt-in.
        external = _external_fetch_urls(command)
        if external and get_env("RHODAWK_HOOK_ALLOW_UNSCOPED_FETCH",
                                default="").strip() != "1":
            print(f"{BLOCK_PREFIX}: curl/wget to non-loopback target(s) "
                  f"{', '.join(sorted(set(external)))} denied — no compiled "
                  f"scope manifest resolved. Run `rhodawk scope-compile "
                  f"<handle>`, pass --manifest / RHODAWK_SCOPE_MANIFEST, or "
                  f"set RHODAWK_HOOK_ALLOW_UNSCOPED_FETCH=1 to explicitly "
                  f"authorize unscoped fetches.", file=sys.stderr)
            return 2
        return 0  # loopback / non-URL fetch / explicit opt-in: allowed
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

    # Layer 1B Issue #5: even with a VERIFIED manifest, the explicit
    # URL/host targets of a direct scanner invocation must be inside the
    # verified scope — otherwise `nuclei -u https://evil-oos.com` runs
    # unblocked on any machine that happens to hold one valid manifest.
    scanner_bin = scanner_invocation(command) if command else None
    if scanner_bin:
        ScopeChecker = _load_scope_checker()
        if ScopeChecker is None:
            print(f"{BLOCK_PREFIX}: scanner '{scanner_bin}' denied — scope "
                  f"checker unavailable (fail-closed) (source: {source})",
                  file=sys.stderr)
            return 2
        try:
            checker = ScopeChecker.from_manifest(str(path))
        except ValueError as exc:  # tampered manifest
            print(f"{BLOCK_PREFIX}: scanner '{scanner_bin}' denied — manifest "
                  f"failed integrity verification ({exc}) "
                  f"(source: {source})", file=sys.stderr)
            return 2
        oos = _out_of_scope_scanner_targets(command, checker)
        if oos:
            print(f"{BLOCK_PREFIX}: scanner '{scanner_bin}' target(s) outside "
                  f"the verified scope manifest (source: {source}): "
                  f"{', '.join(sorted(set(oos)))}. Re-run "
                  f"`rhodawk scope-compile <handle>` if the program scope "
                  f"changed.", file=sys.stderr)
            return 2

    return 0  # verified manifest intact -- allow


if __name__ == "__main__":
    sys.exit(main())
