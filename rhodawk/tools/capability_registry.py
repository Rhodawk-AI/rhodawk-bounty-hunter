#!/usr/bin/env python3
"""
capability_registry.py — boot-time tool binding for RhodawkAI Bounty Hunter,
RhodawkAI Edition.

The upstream project has no centralized preflight tool registry: every stage in
recon_engine.sh does its own inline `command -v <tool>` guard. This module
builds that missing registry. It runs at install time (--rebuild) and at
session start (banner + availability snapshot) and answers exactly one
question for every recon capability:

    NATIVE            Rhodawk owns it; never delegate.
    RTW_AVAILABLE     Rhodawk lacks it AND reconFTW can provide it right now:
                      RTW_HOME/reconftw.sh is executable AND every backing
                      binary of that capability is on PATH AND every required
                      env key is set.
    RTW_MISSING_DEPS  Delegation possible in principle, but some binary or
                      env key is missing — the adapter SKIPS these (never
                      blocks the run).

Order of operations every run (never reordered):

1. Check disk first, anywhere on PATH (shutil.which, not a fixed install dir).
   A tool present from a prior install, a system package manager, or a manual
   install counts as satisfied.
2. If found, check version against a pinned minimum and offer/trigger an
   update path if stale (see rtw_pin_upgrade()).
3. If missing, install: Rhodawk-native tools route to install_tools.sh; the 7
   delegated capabilities' backing binaries route to per-capability go-install
   with explicit @version pins (reconftw's tools.lock format). reconFTW's own
   installer is NEVER run wholesale (~70 unrelated binaries).
4. Print a setup banner at the very start of any run listing every
   required/optional API key (Rhodawk's set + the reconFTW-side keys this
   integration needs), matching Rhodawk's Req/Opt convention.
5. Persist final state to ~/.rhodawk/capabilities.json as
   {capability_id: state}. That file is the single source of truth every
   layer (bash, Python, harness prompt) reads — nothing re-derives
   availability independently.

This file is the fork's own secrets boundary: it reads env vars and
~/.rhodawk/config.json only, and shares nothing with any external product.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
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

# ── Constants ─────────────────────────────────────────────────────────────────

# reconFTW pinned commit (verified 2026-11-21 against upstream six2dez/reconftw).
RTW_COMMIT_PIN = "39252113a854bdac0b785f144b9fae1fa8ca35fc"

STATE_NATIVE = "NATIVE"
STATE_RTW_AVAILABLE = "RTW_AVAILABLE"
STATE_RTW_MISSING_DEPS = "RTW_MISSING_DEPS"

# Capabilities Rhodawk already owns at parity — the adapter refuses to delegate
# these (defense against future spec drift; see rtw_adapter.py step 2).
NATIVE_CAPABILITY_IDS = frozenset()

# Rhodawk-native recon inventory (cross-checked against the `command -v` /
# `warn_missing` guards in tools/recon_engine.sh at the pinned commit).
NATIVE_RHODAWK_TOOLS = [
    "subfinder", "amass", "httpx", "dnsx", "nuclei", "katana", "gau",
    "waybackurls", "ffuf", "nmap", "gf", "anew", "dig", "jq", "arjun",
    "sisakulint", "naabu", "interactsh-client",
]


@dataclass(frozen=True)
class CapabilitySpec:
    """One delegatable recon capability (§1 gap map, recon phase only)."""

    capability_id: str
    rtw_function: str          # reconFTW function name (-c <fn>)
    description: str
    required_tools: List[str]  # backing binaries, all must be on PATH
    optional_tools: List[str] = field(default_factory=list)
    required_env: List[str] = field(default_factory=list)  # env keys hard-required by the function
    rtw_mode: str = "cli"      # "cli" = reconftw.sh -d/-c/-f/-o; "source_only" = seeded subshell
    seeds: List[str] = field(default_factory=list)  # Rhodawk recon outputs to pre-populate
    abh_output_subdir: str = ""


# The 7-row verified capability-gap map. Nothing Rhodawk owns at parity is here
# (passive subs, port scan, GraphQL, S3 buckets, auth-aware crawl, vuln
# scanning — modules/vulns.sh is out of scope entirely).
CAPABILITIES: Dict[str, CapabilitySpec] = {
    spec.capability_id: spec
    for spec in [
        CapabilitySpec(
            capability_id="CAP_ASN_ENUM",
            rtw_function="sub_asn",
            description="ASN/CIDR enumeration via asnmap (reconFTW sub_asn)",
            required_tools=["asnmap", "jq"],
            optional_tools=["mapcidr", "anew"],
            required_env=["PDCP_API_KEY"],  # reconFTW hard-requires this for asnmap
            rtw_mode="cli",
        ),
        CapabilitySpec(
            capability_id="CAP_DNS_PERMUT",
            rtw_function="sub_permut",
            description="DNS brute/permutation via gotator+puredns (reconFTW sub_permut)",
            required_tools=["gotator", "puredns"],
            optional_tools=["regulator", "dsieve", "anew"],
            rtw_mode="cli",
            seeds=["subdomains/all.txt"],
        ),
        CapabilitySpec(
            capability_id="CAP_VHOSTS",
            rtw_function="virtualhosts",
            description="Virtual-host discovery via VhostFinder+ffuf (reconFTW virtualhosts)",
            required_tools=["VhostFinder", "ffuf"],
            optional_tools=["anew"],
            rtw_mode="cli",
            seeds=["live/urls.txt"],
        ),
        CapabilitySpec(
            capability_id="CAP_TLS_PIVOTS",
            rtw_function="tls_ip_pivots",
            description="TLS-certificate IP pivots via tlsx (reconFTW tls_ip_pivots)",
            required_tools=["tlsx", "httpx"],
            optional_tools=["puredns", "anew"],
            rtw_mode="cli",
            seeds=["live/urls.txt"],
        ),
        CapabilitySpec(
            capability_id="CAP_FAVICON",
            rtw_function="favirecon_tech",
            description="Favicon fingerprinting via favirecon (reconFTW favirecon_tech)",
            required_tools=["favirecon"],
            optional_tools=["anew"],
            rtw_mode="cli",
            seeds=["live/urls.txt"],
        ),
        CapabilitySpec(
            capability_id="CAP_CDN_ISOLATE",
            rtw_function="cdnprovider",
            description="General CDN/origin isolation via cdncheck (reconFTW cdnprovider)",
            required_tools=["cdncheck"],
            optional_tools=["hakoriginfinder", "anew"],  # hakoriginfinder only if CDN_BYPASS ever enabled
            rtw_mode="cli",
            seeds=["live/urls.txt"],
        ),
        CapabilitySpec(
            capability_id="CAP_JS_SOURCEMAPS",
            rtw_function="jschecks",
            description="JS source-map/AST secret extraction (reconFTW jschecks)",
            required_tools=["sourcemapper", "jsluice", "subjs"],
            optional_tools=["mantra", "anew"],
            rtw_mode="cli",
            seeds=["live/urls.txt"],
        ),
    ]
}

# reconFTW-side backing binaries. Pins copied from reconFTW's tools.lock where
# present; tools not pinned there use pin-on-first-install: the first install
# resolves @latest, records the resolved version, and every later install or
# upgrade re-installs that recorded version explicitly (no brew floating).
RTW_TOOL_PINS: Dict[str, str] = {
    # From reconFTW tools.lock (stability-critical, upstream-pinned):
    "puredns": "github.com/d3mondev/puredns/v2@v2.1.1",
    "tlsx": "github.com/projectdiscovery/tlsx/cmd/tlsx@v1.1.7",
}
RTW_TOOL_MODULES: Dict[str, str] = {
    # Module paths copied verbatim from reconFTW install.sh (pinned commit).
    "asnmap": "github.com/projectdiscovery/asnmap/cmd/asnmap",
    "mapcidr": "github.com/projectdiscovery/mapcidr/cmd/mapcidr",
    "gotator": "github.com/Josue87/gotator",
    "cdncheck": "github.com/projectdiscovery/cdncheck/cmd/cdncheck",
    "hakoriginfinder": "github.com/hakluke/hakoriginfinder",
    "favirecon": "github.com/edoardottt/favirecon/cmd/favirecon",
    "VhostFinder": "github.com/wdahlenburg/VhostFinder",
    "sourcemapper": "github.com/denandz/sourcemapper",
    "jsluice": "github.com/BishopFox/jsluice/cmd/jsluice",
    "mantra": "github.com/brosck/mantra",
    "subjs": "github.com/lc/subjs",
    "dsieve": "github.com/trickest/dsieve",
}

# API keys surfaced by the setup banner. Provider rows are kept in sync with
# brain.py PROVIDER_KEY_ENV (brain.py:267-286 at the pinned commit).
BANNER_PROVIDER_KEYS = [
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY", "GROQ_API_KEY",
    "DEEPSEEK_API_KEY", "GEMINI_API_KEY", "MOONSHOT_API_KEY",
    "MISTRAL_API_KEY", "TOGETHER_API_KEY", "CEREBRAS_API_KEY",
    "PERPLEXITY_API_KEY", "OPENROUTER_API_KEY", "ORCAROUTER_API_KEY",
    "REQUESTY_API_KEY", "LITELLM_API_KEY",
]
# req=True → missing key degrades behavior; opt=True → graceful skip.
BANNER_RHODAWK_KEYS = [
    ("chaos_api_key (env CHAOS_API_KEY or config.json)", "optional — extra subfinder/Chaos source; skipped if absent"),
    ("h1_api_token (env H1_API_TOKEN or config.json)", "optional — HackerOne scope sync; skipped if absent"),
]
BANNER_RTW_KEYS = [
    ("PDCP_API_KEY", "required for CAP_ASN_ENUM delegation only (reconFTW sub_asn / asnmap); other capabilities unaffected"),
]


# ── Paths ─────────────────────────────────────────────────────────────────────

def data_home() -> Path:
    ensure_home_migrated()
    """Mirror engine.py DATA_HOME: RHODAWK_HOME wins, else writable clone dir
    is out of scope here — this registry always keys on ~/.rhodawk so the
    capabilities file is findable from every runtime (bash/agent/harness)."""
    return Path.home() / ".rhodawk"


def capabilities_path() -> Path:
    env = get_env("RHODAWK_CAPABILITIES_FILE")
    if env:
        return Path(env).expanduser()
    home = get_env("RHODAWK_HOME")
    if home:
        return Path(home).expanduser() / "capabilities.json"
    return data_home() / "capabilities.json"


def capabilities_meta_path() -> Path:
    return capabilities_path().with_name("capabilities_meta.json")


def _rtw_home_from_config() -> Path:
    """rtw_home persisted by install.sh into ~/.rhodawk/config.json.
    RHODAWK_CONFIG_FILE overrides the path for tests/CI. Never raises."""
    path = (get_env("RHODAWK_CONFIG_FILE")
            or str(Path.home() / ".rhodawk" / "config.json"))
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8")).get("rtw_home")
        return Path(str(value)).expanduser()
    except (OSError, ValueError, AttributeError, TypeError):
        return Path.home() / "Tools" / "reconftw"


def rtw_home() -> Path:
    """Resolution order: RTW_HOME env → config.json rtw_home (persisted by
    install.sh) → ~/Tools/reconftw. New shells therefore never need
    RTW_HOME re-exported after install."""
    env = os.environ.get("RTW_HOME")
    if env:
        return Path(env).expanduser()
    return _rtw_home_from_config()


def rtw_script() -> Path:
    return rtw_home() / "reconftw.sh"


# ── Disk / version checks (steps 1-2) ─────────────────────────────────────────

def which_tool(tool: str) -> Optional[str]:
    """Step 1: check disk anywhere on PATH — never a fixed install dir."""
    return shutil.which(tool)


def probe_version(tool: str, path: str) -> Optional[str]:
    """Best-effort version probe (`tool -version` / `--version` / `-V`).

    Returns the first non-empty output line, or None when the binary does not
    answer any conventional flag within the timeout. Never raises.
    """
    for flag in ("-version", "--version", "-V"):
        try:
            proc = subprocess.run(
                [path, flag], capture_output=True, text=True, timeout=15,
                shell=False,
            )
            out = (proc.stdout or "").strip() or (proc.stderr or "").strip()
            if out:
                return out.splitlines()[0].strip()
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def tool_status(tool: str, min_version: Optional[str] = None) -> dict:
    """Steps 1+2 combined: found? where? which version? stale against pin?"""
    path = which_tool(tool)
    if not path:
        return {"tool": tool, "found": False, "path": None,
                "version": None, "stale": False, "pin": min_version}
    version = probe_version(tool, path)
    stale = False
    if min_version and version:
        # Lexical containment: both sides carry the upstream tag format
        # (vX.Y.Z). A found version older than the pin is "stale" only when we
        # can compare cleanly; unknown formats never flag stale silently —
        # they surface version=None for the banner to show.
        stale = _version_lt(_normalize_version(version), _normalize_version(min_version))
    return {"tool": tool, "found": True, "path": path,
            "version": version, "stale": stale, "pin": min_version}


def _normalize_version(text: str) -> Optional[tuple]:
    import re
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", text or "")
    if not m:
        return None
    return tuple(int(part) for part in m.groups())


def _version_lt(a: Optional[tuple], b: Optional[tuple]) -> bool:
    if a is None or b is None:
        return False
    return a < b


def recorded_pins() -> Dict[str, str]:
    """Pin-on-first-install store: tool → '<module>@<version>'."""
    try:
        data = json.loads(capabilities_meta_path().read_text(encoding="utf-8"))
        return data.get("recorded_pins", {})
    except (OSError, ValueError):
        return {}


def record_pin(tool: str, pin: str) -> None:
    meta_path = capabilities_meta_path()
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    meta.setdefault("recorded_pins", {})[tool] = pin
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")


def rtw_pin_for(tool: str) -> str:
    """Explicit @version pin for a reconFTW-side tool (tools.lock first,
    recorded first-install pin second, module@latest last resort)."""
    if tool in RTW_TOOL_PINS:
        return RTW_TOOL_PINS[tool]
    recorded = recorded_pins().get(tool)
    if recorded:
        return recorded
    return f"{RTW_TOOL_MODULES[tool]}@latest"


def rtw_pin_upgrade(tool: str) -> List[str]:
    """Step 2 update path for a stale/missing reconFTW-side binary: go install
    the explicit pin. Never runs reconFTW's own installer."""
    pin = rtw_pin_for(tool)
    if pin.endswith("@latest") and tool in RTW_TOOL_MODULES:
        # Resolve once, then pin: install @latest then record the probe.
        resolved = f"{RTW_TOOL_MODULES[tool]}@latest"
    else:
        resolved = pin
    cmd = ["go", "install", "-v", resolved]
    proc = subprocess.run(cmd, shell=False, timeout=600)
    if proc.returncode == 0 and not pin.endswith("@latest"):
        record_pin(tool, pin)
    elif proc.returncode == 0:
        path = which_tool(tool)
        version = probe_version(tool, path) if path else None
        if version:
            record_pin(tool, f"{RTW_TOOL_MODULES[tool]}@{version}")
    return cmd


# ── reconFTW repo readiness ───────────────────────────────────────────────────

def check_rtw_repo() -> dict:
    """RTW_AVAILABLE requires RTW_HOME/reconftw.sh executable — not a blanket
    'reconftw cloned somewhere' flag. Reports the pinned-commit check too."""
    home = rtw_home()
    script = rtw_script()
    info = {"rtw_home": str(home), "script": str(script),
            # Live-run fix: os.access(p, os.X_OK) returns True for root on
            # Linux even for mode-0644 files, which marked a non-executable
            # reconftw.sh as RTW_AVAILABLE on root VPSes. Check the mode bits.
            "executable": script.is_file() and bool(os.stat(script).st_mode & 0o111),
            "commit_matches_pin": None}
    if (home / ".git").is_dir():
        try:
            proc = subprocess.run(
                ["git", "-C", str(home), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=15, shell=False,
            )
            head = (proc.stdout or "").strip()
            info["commit_matches_pin"] = (head == RTW_COMMIT_PIN)
            info["head_commit"] = head
        except (OSError, subprocess.SubprocessError):
            info["commit_matches_pin"] = None
    return info


# ── Capability evaluation (the single source of truth) ────────────────────────

def evaluate_capability(cap_id: str, rtw: Optional[dict] = None) -> dict:
    spec = CAPABILITIES.get(cap_id)
    if spec is None:
        return {"capability_id": cap_id, "state": STATE_RTW_MISSING_DEPS,
                "missing_tools": [], "missing_env": [],
                "reason": f"unknown capability id: {cap_id}"}
    if cap_id in NATIVE_CAPABILITY_IDS:
        return {"capability_id": cap_id, "state": STATE_NATIVE,
                "missing_tools": [], "missing_env": [], "reason": "native"}
    if rtw is None:
        rtw = check_rtw_repo()
    missing_tools, missing_env = [], []
    if not rtw.get("executable"):
        return {"capability_id": cap_id, "state": STATE_RTW_MISSING_DEPS,
                "missing_tools": ["reconftw.sh"], "missing_env": [],
                "reason": f"RTW_HOME/reconftw.sh not executable at {rtw.get('rtw_home')} — set RTW_HOME or run install.sh"}
    for tool in spec.required_tools:
        if which_tool(tool) is None:
            missing_tools.append(tool)
    for key in spec.required_env:
        if not os.environ.get(key, "").strip():
            missing_env.append(key)
    if missing_tools or missing_env:
        return {"capability_id": cap_id, "state": STATE_RTW_MISSING_DEPS,
                "missing_tools": missing_tools, "missing_env": missing_env,
                "reason": _missing_reason(missing_tools, missing_env)}
    return {"capability_id": cap_id, "state": STATE_RTW_AVAILABLE,
            "missing_tools": [], "missing_env": [],
            "reason": f"{spec.rtw_function} ready"}


def _missing_reason(missing_tools: List[str], missing_env: List[str]) -> str:
    parts = []
    if missing_tools:
        parts.append("missing binaries: " + ", ".join(missing_tools))
    if missing_env:
        parts.append("missing env keys: " + ", ".join(missing_env))
    return "; ".join(parts) + " — run: capability_registry.py --install-capability <id>"


def evaluate_all() -> dict:
    rtw = check_rtw_repo()
    return {cap_id: evaluate_capability(cap_id, rtw=rtw)
            for cap_id in CAPABILITIES}


# ── Persistence (step 5) ──────────────────────────────────────────────────────

def rebuild(write: bool = True) -> dict:
    """Recompute and persist {capability_id: state} — the file every other
    layer reads. Returns the plain mapping."""
    evaluations = evaluate_all()
    mapping = {cap_id: ev["state"] for cap_id, ev in evaluations.items()}
    if write:
        path = capabilities_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        path.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        # Sidecar detail (never in the mapping itself — the mapping shape is
        # part of the cross-runtime contract).
        meta = {"generated": _utcnow(), "rtw": check_rtw_repo(),
                "evaluations": evaluations, "recorded_pins": recorded_pins()}
        capabilities_meta_path().write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return mapping


def load_state() -> dict:
    """Read the persisted mapping; falls back to a live rebuild when absent."""
    path = capabilities_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data:
            return data
    except (OSError, ValueError):
        pass
    return rebuild(write=True)


# ── Setup banner (step 4) ─────────────────────────────────────────────────────

def _config_key(config: dict, key: str) -> Optional[str]:
    val = config.get(key)
    if isinstance(val, str) and val.strip():
        return val
    return None


def collect_api_keys() -> List[dict]:
    import json as _json
    config = {}
    config_path = Path.home() / ".rhodawk" / "config.json"
    try:
        config = _json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    rows = []
    for label, note in BANNER_RHODAWK_KEYS:
        env_name = "CHAOS_API_KEY" if "chaos" in label else "H1_API_TOKEN"
        present = bool(os.environ.get(env_name, "").strip()) or bool(_config_key(config, label.split(" ")[0]))
        rows.append({"key": label, "required": False, "present": present, "note": note})
    for key, note in BANNER_RTW_KEYS:
        present = bool(os.environ.get(key, "").strip())
        rows.append({"key": key, "required": True, "present": present,
                     "note": note})
    return rows


def print_banner(state: Optional[dict] = None) -> None:
    """Step 4: setup banner — every required/optional API key + capability
    table, Rhodawk Req/Opt convention."""
    if state is None:
        state = load_state()
    print("=" * 72)
    print("  RhodawkAI Bounty Hunter · capability registry")
    print("=" * 72)
    print("")
    print("  API keys (Req = required for that feature, Opt = graceful skip):")
    for row in collect_api_keys():
        tag = "Req" if row["required"] else "Opt"
        mark = "set" if row["present"] else "MISSING"
        print(f"    [{tag}] {row['key']:<48} {mark}")
        print(f"         {row['note']}")
    print("")
    print("  Delegatable capabilities (recon phase only):")
    rtw = check_rtw_repo()
    ex = "yes" if rtw["executable"] else "no"
    print(f"    reconFTW at {rtw['rtw_home']} — reconftw.sh executable: {ex}")
    if rtw.get("commit_matches_pin") is False:
        print(f"    [!] HEAD {rtw.get('head_commit', '?')} != pinned {RTW_COMMIT_PIN}")
    for cap_id, st in sorted(state.items()):
        spec = CAPABILITIES.get(cap_id)
        fn = spec.rtw_function if spec else "?"
        print(f"    {cap_id:<28} {st:<18} (reconftw:{fn})")
    print("")
    print("  Single source of truth: " + str(capabilities_path()))
    print("=" * 72)


def print_summary(state: Optional[dict] = None) -> None:
    """One-line human readiness summary for installers.

    install.sh used to dump the raw state dict (or the full banner table)
    into the install log after the Done! message; this replaces that with a
    single actionable line that still points at the gap-fill installer."""
    if state is None:
        state = load_state()
    total = len(CAPABILITIES)
    ready = sum(1 for st in state.values()
                if st in (STATE_NATIVE, STATE_RTW_AVAILABLE))
    print(f"[i] reconFTW gap-fill capabilities: {ready}/{total} ready "
          f"(run 'bash install_tools.sh --rtw-deps' to install missing backing binaries)")


# ── Per-capability install (step 3) ───────────────────────────────────────────

def install_capability(cap_id: str) -> int:
    """Install ONLY the backing binaries of one delegated capability via
    pinned go-install. Rhodawk-native tools keep routing to install_tools.sh;
    reconFTW's own installer is never run wholesale."""
    spec = CAPABILITIES.get(cap_id)
    if spec is None:
        print(f"[-] unknown capability id: {cap_id}", file=sys.stderr)
        print(f"    known ids: {', '.join(sorted(CAPABILITIES))}", file=sys.stderr)
        return 2
    print(f"[*] Installing reconFTW-side dependencies for {cap_id} ({spec.rtw_function})")
    failures = 0
    go_missing = False
    for tool in spec.required_tools + spec.optional_tools:
        if which_tool(tool):
            st = tool_status(tool)
            print(f"[+] {tool} already on PATH ({st['path']})"
                  + (f" — {st['version']}" if st["version"] else ""))
            continue
        if tool not in RTW_TOOL_MODULES and tool not in RTW_TOOL_PINS:
            # Rhodawk-native inventory (jq, anew, ffuf, httpx, ...) — install_tools.sh
            # owns those; the per-capability installer only covers reconFTW-side
            # binaries, so a missing one here is a note, not a failure.
            print(f"[*] {tool}: Rhodawk-side tool — handled by install_tools.sh (skipped here)")
            continue
        if shutil.which("go") is None:
            go_missing = True
            continue
        pin = rtw_pin_for(tool)
        print(f"[>] go install {pin}")
        try:
            proc = subprocess.run(["go", "install", "-v", pin], shell=False, timeout=900)
            if proc.returncode == 0:
                if pin.endswith("@latest") and tool in RTW_TOOL_MODULES:
                    path = which_tool(tool)
                    version = probe_version(tool, path) if path else None
                    record_pin(tool, f"{RTW_TOOL_MODULES[tool]}@{version}" if version else pin)
                else:
                    record_pin(tool, pin)
                print(f"[+] {tool} installed")
            else:
                print(f"[-] {tool} failed to install ({pin})")
                failures += 1
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"[-] {tool} install error: {exc}")
            failures += 1
    if go_missing:
        print("[!] Go toolchain not found — install Go first (see install_tools.sh), then re-run.")
        return 1
    return 1 if failures else 0


def install_all_rtw() -> int:
    rc = 0
    for cap_id in CAPABILITIES:
        rc = max(rc, install_capability(cap_id))
    return rc


# ── CLI ───────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="capability_registry.py",
        description="Boot-time tool binding for RhodawkAI Bounty Hunter.",
    )
    parser.add_argument("--rebuild", action="store_true",
                        help="recompute availability and persist capabilities.json")
    parser.add_argument("--banner", action="store_true",
                        help="print the setup banner (keys + capability table)")
    parser.add_argument("--summary", action="store_true",
                        help="print a one-line readiness summary (installer UX)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable state to stdout")
    parser.add_argument("--install-capability", metavar="CAP_ID",
                        help="install one capability's backing binaries (pinned)")
    parser.add_argument("--install-all", action="store_true",
                        help="install every delegated capability's backing binaries")
    parser.add_argument("--check", metavar="CAP_ID",
                        help="evaluate one capability and print its state")
    args = parser.parse_args(argv)

    if args.install_capability:
        return install_capability(args.install_capability)
    if args.install_all:
        return install_all_rtw()
    if args.rebuild:
        mapping = rebuild(write=True)
        if args.summary:
            print_summary(mapping)
        elif args.json or not sys.stdout.isatty():
            print(json.dumps(mapping, indent=2, sort_keys=True))
        else:
            print_banner(mapping)
        return 0
    if args.summary:
        # Same live-evaluate guarantee as the --banner path (Step 1D): never
        # answer from the stale cached capabilities.json.
        print_summary({cap_id: evaluate_capability(cap_id)["state"]
                       for cap_id in CAPABILITIES})
        return 0
    state = load_state()
    if args.check:
        ev = evaluate_capability(args.check)
        if args.json:
            print(json.dumps(ev, indent=2))
        else:
            print(f"{args.check}: {ev['state']} ({ev['reason']})")
        return 0
    if args.banner:
        # Live-run fix (Step 1D): --banner without --rebuild used the stale
        # cached capabilities.json, so it could show "PDCP_API_KEY MISSING"
        # (evaluated live in the keys table) next to a stale cached
        # "CAP_ASN_ENUM RTW_AVAILABLE" row. Evaluate every capability against
        # the CURRENT process environment (PDCP_API_KEY, RTW_HOME) instead.
        print_banner({cap_id: evaluate_capability(cap_id)["state"]
                      for cap_id in CAPABILITIES})
        return 0
    if args.json:
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    print_banner(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
