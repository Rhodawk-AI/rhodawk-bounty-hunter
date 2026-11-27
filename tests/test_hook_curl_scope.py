"""Fix 2 red-to-green: the PreToolUse scope guard must check curl/wget
target hosts against a RESOLVABLE scope manifest.

Defect (rhodawk-blueprint.md gap #4 / mission item 2, README "Honest
Limitations" bullet): unknown Bash commands classify as read-only, so
`curl https://out-of-scope.example.com` exits 0 even when a verified scope
manifest IS available (RHODAWK_SCOPE_MANIFEST set) — live-reproduced on this
HEAD (`HOOK_EXIT=0` for an out-of-scope curl).

Contract after the fix (strictly additive — never weaker):
  - Bash curl/wget commands WITH explicit http(s) URLs are checked against a
    resolvable, hash-verified manifest: any out-of-scope URL host ⇒ exit 2 +
    SCOPE_HOOK_BLOCK;
  - in-scope URLs ⇒ allow (exit 0);
  - NO resolvable manifest ⇒ behavior UNCHANGED (allow) — the documented
    limitation for manifest-less sessions stays, so doctor/setup Bash usage
    (curl installers, pip, etc.) is unaffected;
  - non-fetch Bash commands (echo, ls, …) are untouched.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from contracts.scope import CompiledScopeManifest  # noqa: E402

HOOK = REPO / "rhodawk" / "tools" / "hook_scope_guard.py"


def _manifest(tmp_path: Path, patterns: list[str]) -> str:
    m = CompiledScopeManifest(program_handle="t", allow_patterns=patterns)
    return str(m.save(str(tmp_path / "compiled_scope.json")))


def _run_hook(command: str, manifest: str | None = None, tool: str = "Bash"):
    payload = {"tool_name": tool, "tool_input": {"command": command}}
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp",
           "RHODAWK_HOME": "/tmp/hooktest-home"}
    if manifest:
        env["RHODAWK_SCOPE_MANIFEST"] = manifest
    return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=60, env=env)


@pytest.mark.parametrize("cmd", [
    "curl -s https://totally-out-of-scope.example.com/api",
    "curl -s -X POST https://oos.example.test/login -d 'a=b'",
    "wget -q https://elsewhere.example.test/payload.bin -O /tmp/x",
])
def test_curl_wget_out_of_scope_blocked_when_manifest_resolvable(tmp_path, cmd):
    manifest = _manifest(tmp_path, ["127.0.0.1", "*.target-scope.test"])
    proc = _run_hook(cmd, manifest=manifest)
    assert proc.returncode == 2, f"expected block, got {proc.returncode}: {proc.stderr[-300:]}"
    assert "SCOPE_HOOK_BLOCK" in proc.stderr
    assert "outside the verified scope manifest" in proc.stderr


@pytest.mark.parametrize("cmd", [
    "curl -s http://127.0.0.1:8099/api/v2/session",
    "curl -s https://app.target-scope.test/health",
    "curl --help",
    "echo hello && ls -la",
])
def test_in_scope_or_nonfetch_commands_allowed(tmp_path, cmd):
    manifest = _manifest(tmp_path, ["127.0.0.1", "*.target-scope.test"])
    proc = _run_hook(cmd, manifest=manifest)
    assert proc.returncode == 0, f"unexpected block: {proc.stderr[-300:]}"


def test_no_manifest_behavior_unchanged():
    """Manifest-less sessions keep today's behavior (documented limitation):
    curl is allowed without a block — installers/doctor Bash usage unaffected."""
    proc = _run_hook("curl -s https://anything-at-all.example.test/x", manifest=None)
    assert proc.returncode == 0


def test_tampered_manifest_does_not_authorize_curl(tmp_path):
    """A manifest that fails hash verification must not silently allow the
    fetch — the block path fires (fail-closed)."""
    manifest = _manifest(tmp_path, ["127.0.0.1"])
    raw = json.loads(Path(manifest).read_text(encoding="utf-8"))
    raw["allow_patterns"].append("evil.example.com")
    Path(manifest).write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
    proc = _run_hook("curl -s https://evil.example.com/x", manifest=manifest)
    # Strict fail-closed: a manifest that resolves but fails verification
    # must BLOCK (exit 2 + SCOPE_HOOK_BLOCK), never fall through to allow.
    assert proc.returncode == 2, \
        f"expected fail-closed block, got {proc.returncode}: {proc.stderr[-300:]}"
    assert "SCOPE_HOOK_BLOCK" in proc.stderr
    assert "denied" in proc.stderr


def test_scope_checker_unavailable_blocks_fetch_fail_closed(tmp_path, monkeypatch, capsys):
    """Regression (fail-closed gate): when a manifest resolves and verifies,
    but the ScopeChecker itself cannot be imported, the fetch must be blocked
    (exit 2 + SCOPE_HOOK_BLOCK) — never fall through to allow (exit 0)."""
    manifest = _manifest(tmp_path, ["127.0.0.1"])
    monkeypatch.syspath_prepend(str(REPO / "rhodawk" / "tools"))
    import hook_scope_guard
    monkeypatch.setenv("RHODAWK_SCOPE_MANIFEST", manifest)
    monkeypatch.setattr(hook_scope_guard, "_load_scope_checker", lambda: None)
    rc = hook_scope_guard.main(["--tool", "Bash",
                                "--command",
                                "curl -s http://127.0.0.1:8099/api"])
    captured = capsys.readouterr()
    assert rc == 2, f"expected fail-closed block, got {rc}: {captured.err[-300:]}"
    assert "SCOPE_HOOK_BLOCK" in captured.err
    assert "scope checker unavailable" in captured.err


def test_mcp_tool_names_still_classified_active(tmp_path):
    """No regression: MCP active tools keep the existing hard gate."""
    manifest = _manifest(tmp_path, ["127.0.0.1"])
    proc = _run_hook("do work", manifest=manifest, tool="mcp__rhodawk-mcp__rhodawk_recon")
    assert proc.returncode == 0  # manifest resolves + verifies → allow
