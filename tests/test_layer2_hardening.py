"""Layer 2 hardening regression tests (Credentials & Scope Authority).

Live Ubuntu 24.04 sandbox testing of the Layer 2 surface surfaced four
defects, each pinned here:

1. ``$RHODAWK_HOME`` was ignored by the credentials vault helpers and by
   ``scope_compiler.resolve_output_paths()``'s mirror — an isolated sandbox
   got a stray ``~/.rhodawk/scope`` tree. Both must honor
   ``RHODAWK_HOME`` (same contract as ``engine._data_home`` /
   ``hunt._bh_home``), falling back to ``~/.rhodawk`` when unset.
2. ``_scope_gate.sh`` was fail-open when NO manifest resolved (gate inactive,
   ``return 0``): ``vuln_scanner.sh`` probed to completion with exit 0 and
   zero scope validation. The gate now fails closed (exit 3, JSONL audit
   entry, 0 probes) with actionable stderr guidance; the explicit
   ``RHODAWK_SCOPE_UNSAFE=1`` opt-out keeps authorized local testing flowing
   and NEVER skips SHA-256 integrity validation of a manifest that resolves.
3. ``vuln_scanner.sh`` defaulted ``FINDINGS_DIR`` into the package/repo tree
   (``$BASE_DIR/findings/<target>``) and its summary read the (often
   absent) ``saml/findings.txt`` through an un-suppressible ``<`` redirect —
   polluting a git clone and printing
   ``line 616: .../saml/findings.txt: No such file or directory`` on every
   quiet run. Findings now default under ``${RHODAWK_HOME:-$HOME/.rhodawk}``
   and the count is guarded.
4. ``rhodawk mcp serve`` reported ``serverInfo.version`` ``"0.1.0"`` because
   the version only came from ``.claude-plugin/plugin.json`` (absent from
   pip/pipx/uv installs). The server now resolves ``rhodawk.__version__``
   first, verified here via a real JSON-RPC ``initialize`` handshake.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import credentials, scope_compiler

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "rhodawk" / "tools"
VULN_SCANNER = TOOLS / "vuln_scanner.sh"

_WALK_EXCLUDE = {".git", ".venv", "__pycache__", ".pytest_cache", "dist",
                 "build", "node_modules", ".gh_pat_tmp"}


def _repo_snapshot() -> set[str]:
    """Relative paths of every file in the working tree (isolation probe:
    scanner subprocesses must never write inside the repo)."""
    snap: set[str] = set()
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in _WALK_EXCLUDE]
        for name in files:
            snap.add(str(Path(root, name).relative_to(REPO)))
    return snap


def _scanner_env(tmp_path: Path, extra: dict | None = None) -> dict:
    """Clean env for the scanner subprocess: conftest's RHODAWK_HOME must be
    overridden, and no scope manifest / unsafe flag may leak in."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("RHODAWK_HOME", "RHODAWK_SCOPE_MANIFEST",
                        "RHODAWK_SCOPE_UNSAFE", "FINDINGS_OUT_DIR")}
    env["RHODAWK_HOME"] = str(tmp_path / "rh-home")
    env.update(extra or {})
    return env


def _make_recon(tmp_path: Path, target: str = "unscoped.test") -> Path:
    recon = tmp_path / "rh-home" / "recon" / target
    (recon / "live").mkdir(parents=True)
    (recon / "live" / "urls.txt").write_text(
        "https://" + target + "/page\n", encoding="utf-8")
    return recon


# ── Issue #1: $RHODAWK_HOME-aware vault + scope mirror paths ─────────────────

def test_vault_dir_honors_rhodawk_home_without_touching_real_home(
        tmp_path, monkeypatch):
    fake_home = tmp_path / "fake-home"
    rh_home = tmp_path / "isolated-rh"
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("RHODAWK_HOME", str(rh_home))
    monkeypatch.delenv("RHODAWK_CREDENTIALS_FILE", raising=False)

    assert credentials.vault_dir() == rh_home
    assert credentials.vault_env_file() == rh_home / ".env"
    # resolving the vault under RHODAWK_HOME must not create anything under
    # the (fake) home's legacy location
    assert not (fake_home / ".rhodawk").exists()

    # unset -> documented fallback ~/.rhodawk (HOME pinned to tmp_path, so the
    # real host home is never touched)
    monkeypatch.delenv("RHODAWK_HOME")
    assert credentials.vault_dir() == fake_home / ".rhodawk"

    # blank-string RHODAWK_HOME must not resolve to an empty relative path
    monkeypatch.setenv("RHODAWK_HOME", "   ")
    assert credentials.vault_dir() == fake_home / ".rhodawk"


def test_scope_compiler_mirror_under_rhodawk_home_never_home_dot_rhodawk(
        tmp_path, monkeypatch):
    home_a = tmp_path / "home-a"
    rh_home = tmp_path / "isolated-rh"
    monkeypatch.setenv("HOME", str(home_a))
    monkeypatch.setenv("RHODAWK_HOME", str(rh_home))
    monkeypatch.delenv("RECON_OUT_DIR", raising=False)

    out = scope_compiler.resolve_output_paths("acme")
    assert out["mirror"] == rh_home / "scope" / "acme_compiled_scope.json"
    assert home_a / ".rhodawk" not in out["mirror"].parents
    # primary resolution stays compatible with tests/test_scope_compiler.py
    assert out["primary"] == Path("recon") / "acme" / "scope" / \
        "compiled_scope.json"

    monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "out"))
    assert scope_compiler.resolve_output_paths("acme")["primary"] == \
        tmp_path / "out" / "scope" / "compiled_scope.json"
    out_explicit = scope_compiler.resolve_output_paths(
        "acme", output=tmp_path / "m.json")
    assert out_explicit["primary"] == tmp_path / "m.json"

    # unset -> legacy ~/.rhodawk/scope default
    monkeypatch.delenv("RHODAWK_HOME")
    assert scope_compiler.resolve_output_paths("acme")["mirror"] == \
        home_a / ".rhodawk" / "scope" / "acme_compiled_scope.json"


# ── Issue #2: fail-closed scope gate + explicit opt-out ──────────────────────

def test_vuln_scanner_fails_closed_without_manifest(tmp_path):
    recon = _make_recon(tmp_path)
    before = _repo_snapshot()
    proc = subprocess.run(
        ["bash", str(VULN_SCANNER), str(recon)],
        env=_scanner_env(tmp_path), capture_output=True, text=True,
        cwd=REPO, timeout=180)
    assert proc.returncode == 3, proc.stderr[-400:]
    assert "SCOPE BLOCK" in proc.stderr
    assert "no compiled scope manifest resolved" in proc.stderr
    # actionable guidance: all three authorized paths are named
    assert "rhodawk scope-compile" in proc.stderr
    assert "RHODAWK_SCOPE_MANIFEST" in proc.stderr
    assert "RHODAWK_SCOPE_UNSAFE=1" in proc.stderr
    # audited to the JSONL block log under the isolated RHODAWK_HOME
    audit = tmp_path / "rh-home" / "hunt-memory" / "audit.jsonl"
    assert audit.is_file(), "block must be audited to hunt-memory/audit.jsonl"
    assert '"scope_check":"fail"' in audit.read_text(encoding="utf-8")
    # zero files created inside the repo tree (the old fail-open default wrote
    # findings into $BASE_DIR/findings/<target>)
    assert _repo_snapshot() == before


def test_vuln_scanner_tampered_manifest_hard_stops_even_when_unsafe_flag_set(
        tmp_path):
    recon = _make_recon(tmp_path)
    manifest_dir = recon / "scope"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "compiled_scope.json").write_text(
        json.dumps({"allow_patterns": ["*.unscoped.test"],
                    "manifest_sha256": "tampered"}),
        encoding="utf-8")
    before = _repo_snapshot()
    # RHODAWK_SCOPE_UNSAFE=1 must NOT weaken integrity validation
    proc = subprocess.run(
        ["bash", str(VULN_SCANNER), str(recon)],
        env=_scanner_env(tmp_path, {"RHODAWK_SCOPE_UNSAFE": "1"}),
        capture_output=True, text=True, cwd=REPO, timeout=180)
    assert proc.returncode == 3, proc.stderr[-400:]
    assert "SHA-256 integrity" in proc.stderr
    assert "SCOPE GATE BYPASSED" not in proc.stderr
    assert _repo_snapshot() == before


def test_vuln_scanner_unsafe_opt_out_writes_under_rhodawk_home(tmp_path):
    recon = _make_recon(tmp_path)
    before = _repo_snapshot()
    proc = subprocess.run(
        ["bash", str(VULN_SCANNER), str(recon)],
        env=_scanner_env(tmp_path, {"RHODAWK_SCOPE_UNSAFE": "1"}),
        capture_output=True, text=True, cwd=REPO, timeout=300)
    assert proc.returncode == 0, proc.stderr[-400:]
    # the bypass is loud, not silent
    assert "SCOPE GATE BYPASSED" in proc.stderr
    assert "RHODAWK_SCOPE_UNSAFE=1" in proc.stderr
    findings = tmp_path / "rh-home" / "findings" / "unscoped.test"
    assert (findings / "summary.txt").is_file(), \
        "findings must land under $RHODAWK_HOME/findings/<target>"
    # the observed live defect: unsuppressed
    # "line 616: .../saml/findings.txt: No such file or directory"
    assert "No such file or directory" not in proc.stderr
    # nothing written inside the repo tree
    assert _repo_snapshot() == before


# ── Issue #3: MCP serverInfo.version parity ──────────────────────────────────

def test_mcp_serverinfo_version_equals_package_version(tmp_path):
    import rhodawk  # noqa: PLC0415

    pytest.importorskip("mcp")
    req = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                      "clientInfo": {"name": "pytest-layer2", "version": "0"}}}
    env = {k: v for k, v in os.environ.items() if k != "RHODAWK_HOME"}
    env["RHODAWK_HOME"] = str(tmp_path / "rh-home")
    proc = subprocess.run(
        [sys.executable, "-m", "rhodawk", "mcp", "serve"],
        input=json.dumps(req) + "\n", env=env, capture_output=True,
        text=True, cwd=REPO, timeout=120)
    assert proc.returncode == 0, proc.stderr[-400:]
    lines = [ln for ln in proc.stdout.splitlines()
             if ln.strip().startswith("{")]
    assert lines, f"no JSON-RPC response: {proc.stdout[-200:]}"
    resp = json.loads(lines[0])
    server_info = resp["result"]["serverInfo"]
    assert server_info["name"] == "rhodawk"
    # live-sandbox finding: used to report the hardcoded "0.1.0" whenever
    # .claude-plugin/plugin.json was absent (pip/pipx/uv installs)
    assert server_info["version"] == rhodawk.__version__ == "2.0.5"
