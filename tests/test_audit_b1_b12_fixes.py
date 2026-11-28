"""B-1..B-12 audit-closing regression tests.

Independent third-party audit findings, each pinned here:
  - B-1 (P1): vault secrets leaked to scanner subprocesses on the MCP and
    RTW paths (unredacted os.environ.copy() / missing env=) — runtime
    child-env captures for the MCP adapter and the RTW delegation live here;
    the full four-module spawn matrix (engine / hunt / adapters / rtw) lives
    in tests/test_scanner_env_redaction.py.
  - B-2: MCP serverInfo.version off-by-one _REPO path on a plain clone.
  - B-3/B-4: PreToolUse hook fail-open residues (network one-liners
    classified readonly, curl/wget allowed without any manifest) and the
    CWD manifest trust anchor (a planted self-consistent manifest in the
    working directory could self-authorize active tools).
  - B-5: engine.cmd_hunt mutated os.environ with RHODAWK_SCOPE_UNSAFE=1,
    leaking the opt-out into every later subprocess of the same process.
  - B-6/B-7: $RHODAWK_HOME parity (rtw config scope, scope_compiler default
    output).
  - B-9: rhodawk_get_finding contained within $RHODAWK_HOME but NOT within
    the finding-artifact subtrees — $RHODAWK_HOME/.env (the vault) was
    readable through the MCP tool.
  - B-11: verify_h1_auth collapsed network/timeout failures into INVALID,
    locking offline operators out of working credentials.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MCP_DIR = REPO / "rhodawk" / "mcp" / "rhodawk-mcp"
HOOK = REPO / "rhodawk" / "tools" / "hook_scope_guard.py"

_LEAK_TOKENS = {
    "H1_API_TOKEN": "h1-synthetic-token",
    "ANTHROPIC_API_KEY": "sk-ant-synthetic",
    "OPENAI_API_KEY": "sk-openai-synthetic",
}


def _load_server_module():
    """Load the MCP server module by path (plain-clone semantics: no special
    sys.path seeding beyond what server.py itself does)."""
    spec = importlib.util.spec_from_file_location(
        "b12_mcp_server", MCP_DIR / "server.py")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit as exc:  # pragma: no cover - old mcp SDK
        pytest.skip(f"mcp MCPServer API unavailable: {exc}")
    return mod


def _hook_run(command: str, tool: str = "Bash", *,
              cwd: Path | None = None, env_extra: dict | None = None,
              target: str | None = None) -> subprocess.CompletedProcess:
    payload: dict = {"tool_name": tool, "tool_input": {"command": command}}
    if target:
        payload["tool_input"]["target"] = target
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp",
           "RHODAWK_HOME": "/tmp/b12-hook-home"}
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(HOOK)], input=json.dumps(payload),
        capture_output=True, text=True, timeout=60, env=env, cwd=str(cwd or REPO))


# ── B-1: runtime child-env check for MCP + RTW ──────────────────────────────

def _capture_run(monkeypatch, module, exc=subprocess.TimeoutExpired(cmd=[], timeout=1)):
    captured = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        raise exc

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    return captured


def test_b1_mcp_run_recon_child_env_zero_secrets(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "b1_adapters", MCP_DIR / "adapters.py")
    adapters = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapters)
    monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "rh"))
    for k, v in _LEAK_TOKENS.items():
        monkeypatch.setenv(k, v)
    captured = _capture_run(monkeypatch, adapters)
    out = adapters.run_recon("example.com")
    assert out.get("status") == "failed"  # timeout bail-out
    env = captured["env"]
    assert env is not None and env.get("PATH")
    for k in _LEAK_TOKENS:
        assert k not in env, f"B-1: {k} leaked to MCP recon child"


def test_b1_mcp_run_hunt_fallback_child_env_zero_secrets(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "b1_adapters_h", MCP_DIR / "adapters.py")
    adapters = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapters)
    monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "rh"))
    for k, v in _LEAK_TOKENS.items():
        monkeypatch.setenv(k, v)
    captured = _capture_run(monkeypatch, adapters)
    from tools import hunt as hunt_mod
    monkeypatch.setattr(hunt_mod, "hunt_target",
                        lambda *a, **k: (_ for _ in ()).throw(
                            TypeError("force fallback")))
    out = adapters.run_hunt("example.com")
    assert out.get("status") == "failed"
    env = captured["env"]
    assert env is not None and env.get("PATH")
    for k in _LEAK_TOKENS:
        assert k not in env, f"B-1: {k} leaked to MCP hunt-fallback child"


def test_b1_rtw_delegation_child_env_zero_secrets(monkeypatch, tmp_path):
    from tools import rtw_adapter

    monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "rh"))
    for k, v in _LEAK_TOKENS.items():
        monkeypatch.setenv(k, v)
    recon_dir = tmp_path / "rh" / "recon" / "example.com"
    recon_dir.mkdir(parents=True)
    fake_rtw = tmp_path / "fake-rtw"
    fake_rtw.mkdir()
    (fake_rtw / "reconftw.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    monkeypatch.setattr(rtw_adapter, "rtw_script", lambda: fake_rtw / "reconftw.sh")
    monkeypatch.setattr(rtw_adapter, "_rtw_head_commit", lambda: None)
    monkeypatch.setattr(rtw_adapter, "load_state", lambda: {})
    monkeypatch.setattr(rtw_adapter, "seed_files", lambda *a, **k: [])
    monkeypatch.setattr(rtw_adapter, "write_override_cfg",
                        lambda workdir, spec: str(workdir / "rtw_override.cfg"))
    monkeypatch.setattr(rtw_adapter, "_snapshot_seed_lines",
                        lambda workdir, seeded: [])
    monkeypatch.setattr(rtw_adapter, "_bridge_recon_dir",
                        lambda target, workdir: (None, None))
    captured = _capture_run(monkeypatch, rtw_adapter)
    cap_id = next(iter(rtw_adapter.CAPABILITIES))
    out = rtw_adapter.run_capability(
        cap_id, "example.com", recon_dir=recon_dir, allow_unscoped=True,
        force=True, timeout_secs=30,
        workdir_root=recon_dir / "rtw" / ".work", env=None)
    assert out.get("status") == "TIMEOUT", out  # spawn reached + captured
    env = captured["env"]
    assert env is not None and env.get("PATH")
    for k in _LEAK_TOKENS:
        assert k not in env, f"B-1: {k} leaked to reconFTW delegation child"


# ── B-2: plain-clone MCP version parity ─────────────────────────────────────

def test_b2_server_version_resolves_in_plain_clone():
    """On a plain clone (no editable install), server.py must still resolve
    the real package version — the old _REPO off-by-one left `import
    rhodawk` dead and fell back to the stale "0.1.0"."""
    probe = (
        "import importlib.util, json, sys\n"
        f"spec = importlib.util.spec_from_file_location('b2srv', '{MCP_DIR / 'server.py'}')\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "sys.stdout.write(json.dumps({'v': m._SERVER_VERSION,\n"
        "                             'repo_ok': (m._REPO / 'pyproject.toml').is_file()}))\n"
    )
    proc = subprocess.run([sys.executable, "-c", probe], cwd=str(REPO),
                          capture_output=True, text=True, timeout=120,
                          env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                               "HOME": "/tmp"})
    assert proc.returncode == 0, proc.stderr[-400:]
    data = json.loads(proc.stdout)
    assert data["repo_ok"], "_REPO must point at the repository root (B-2)"
    assert data["v"] == "2.0.5", f"B-2: stale version {data['v']!r} on plain clone"
    # the sibling package marker must not hardcode a version assignment —
    # it used to drift to a stale "0.1.0" while the package moved to 2.0.x
    init_src = (MCP_DIR / "__init__.py").read_text(encoding="utf-8")
    assert "__version__ = \"0.1.0\"" not in init_src
    assert "__version__ = _rhodawk_version or" in init_src


# ── B-3: hook classification of raw network one-liners ──────────────────────

@pytest.mark.parametrize("command", [
    "nc -z evil.test 443",
    "ncat --ssl evil.test 443",
    "socat TCP-LISTEN:9999,fork EXEC:/bin/sh",
    "openssl s_client -connect evil.test:443",
    'python3 -c "import urllib.request; urllib.request.urlopen(\'https://evil.test\')"',
    'python -c "import socket; socket.create_connection((\'evil.test\', 80))"',
    'python3 -c "import http.client; http.client.HTTPConnection(\'evil.test\').request(\'GET\', \'/\')"',
])
def test_b3_network_one_liners_require_manifest(command):
    proc = _hook_run(command)
    assert proc.returncode == 2, f"B-3: {command!r} bypassed the hook"
    assert "SCOPE_HOOK_BLOCK" in proc.stderr


def test_b3_benign_mentions_stay_readonly():
    """echo / comments / version probes that merely CONTAIN the names must
    not flip classification (only real invocations do)."""
    for cmd in ('echo "import urllib.request"',
                "nc -h 2>&1 | head -1",
                "command -v socat",
                'python3 -c "print(6*7)"'):
        proc = _hook_run(cmd)
        assert proc.returncode == 0, f"benign command blocked: {cmd!r}: {proc.stderr[-200:]}"


# ── B-3/B-4: fetch fail-closed + CWD manifest distrust ──────────────────────

def test_b4_fetch_external_no_manifest_fails_closed():
    proc = _hook_run("curl -s https://unscoped.example.test/x")
    assert proc.returncode == 2
    assert "SCOPE_HOOK_BLOCK" in proc.stderr
    assert "RHODAWK_HOOK_ALLOW_UNSCOPED_FETCH=1" in proc.stderr


def test_b4_fetch_opt_in_allows_unscoped_fetch():
    proc = _hook_run("curl -s https://unscoped.example.test/x",
                     env_extra={"RHODAWK_HOOK_ALLOW_UNSCOPED_FETCH": "1"})
    assert proc.returncode == 0, proc.stderr[-200:]


def test_b4_planted_cwd_manifest_cannot_self_authorize(tmp_path):
    """B-4: a self-consistent manifest planted in the CURRENT working
    directory (outside $RHODAWK_HOME) must not authorize an active tool via
    the target-derived or glob discovery paths."""
    plant = tmp_path / "plant"
    (plant / "recon" / "selfauth.test" / "scope").mkdir(parents=True)
    (plant / "recon" / "selfauth.test" / "scope" / "compiled_scope.json").write_text(
        json.dumps({"allow_patterns": ["*.selfauth.test"],
                    "manifest_sha256": "planted"}),
        encoding="utf-8")
    # target-derived discovery must anchor to the data home, not CWD
    proc = _hook_run("true", tool="rhodawk_recon", cwd=plant,
                     target="selfauth.test")
    assert proc.returncode == 2, "planted CWD manifest self-authorized (B-4)"
    assert "data home" in proc.stderr
    # glob discovery must not scan an outside-CWD either
    proc2 = _hook_run("true", tool="rhodawk_recon", cwd=plant,
                      target="other.test")
    assert proc2.returncode == 2


def test_b4_manifest_inside_data_home_still_auto_resolves(tmp_path):
    """The anchoring must not break the legit flow: a manifest under
    $RHODAWK_HOME/recon/<target>/scope still resolves for active tools."""
    home = tmp_path / "hook-home"
    mdir = home / "recon" / "scoped.test" / "scope"
    mdir.mkdir(parents=True)
    from contracts.scope import CompiledScopeManifest
    m = CompiledScopeManifest(program_handle="scoped",
                              allow_patterns=["*.scoped.test"])
    m.save(str(mdir / "compiled_scope.json"))
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "RHODAWK_HOME": str(home)}
    payload = {"tool_name": "rhodawk_recon",
               "tool_input": {"target": "scoped.test"}}
    proc = subprocess.run([sys.executable, str(HOOK)],
                          input=json.dumps(payload), capture_output=True,
                          text=True, timeout=60, env=env)
    assert proc.returncode == 0, f"legit data-home manifest blocked: {proc.stderr[-300:]}"


# ── B-5: no os.environ leak from cmd_hunt ───────────────────────────────────

def test_b5_cmd_hunt_passes_unsafe_flag_via_child_env_only(monkeypatch, tmp_path):
    from rhodawk import engine

    recon_dir = engine.RECON / "example.com"
    recon_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.delenv("RHODAWK_SCOPE_UNSAFE", raising=False)
    for k, v in _LEAK_TOKENS.items():
        monkeypatch.setenv(k, v)

    spawns = []

    def _fake_run_shell(cmd, cwd=None, timeout=3600, env=None, full_env=False):
        spawns.append({"cmd": cmd, "env": env, "full_env": full_env})
        return True, ""

    monkeypatch.setattr(engine, "_run_shell", _fake_run_shell)

    class _FakeBrain:
        def interpret_scan(self, *a, **k):
            return None

        def analyze_recon(self, *a, **k):
            return None

    monkeypatch.setattr(engine, "_get_brain", lambda: _FakeBrain())

    args = argparse.Namespace(target="example.com", no_scope_check=True,
                              scope_domain=[], scope_exclude=[],
                              js_crawl=False)
    engine.cmd_hunt(args)

    assert len(spawns) >= 2  # recon phase + vuln scan phase
    vuln_spawn = spawns[-1]
    # B-5: the opt-out travels ONLY in the child env
    assert os.environ.get("RHODAWK_SCOPE_UNSAFE") != "1", \
        "B-5: cmd_hunt mutated os.environ with RHODAWK_SCOPE_UNSAFE"
    assert vuln_spawn["env"].get("RHODAWK_SCOPE_UNSAFE") == "1"
    assert vuln_spawn["full_env"] is True
    # and the child env is the redacted one (B-1 unification holds here too)
    for k in _LEAK_TOKENS:
        assert k not in (vuln_spawn["env"] or {}), \
            f"B-5: {k} leaked to vuln-scan child env"


# ── B-6 / B-7: $RHODAWK_HOME parity ─────────────────────────────────────────

def test_b6_rtw_load_scope_from_config_honors_rhodawk_home(tmp_path, monkeypatch):
    from tools import rtw_adapter

    rh = tmp_path / "rh"
    rh.mkdir()
    (rh / "config.json").write_text(json.dumps({
        "scope_domains": ["*.home-scoped.test"],
        "scope_excluded_domains": ["excluded.home-scoped.test"],
    }), encoding="utf-8")
    monkeypatch.setenv("RHODAWK_HOME", str(rh))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))  # must be ignored
    (tmp_path / "home" / ".rhodawk").mkdir(parents=True)
    (tmp_path / "home" / ".rhodawk" / "config.json").write_text(json.dumps({
        "scope_domains": ["*.WRONG.test"],
    }), encoding="utf-8")
    domains, excluded = rtw_adapter.load_scope_from_config()
    assert domains == ["*.home-scoped.test"]
    assert excluded == ["excluded.home-scoped.test"]


def test_b7_scope_compiler_default_output_anchored_to_data_home(
        tmp_path, monkeypatch):
    from tools import scope_compiler

    home_a = tmp_path / "home-a"
    rh = tmp_path / "rh"
    monkeypatch.setenv("HOME", str(home_a))
    monkeypatch.setenv("RHODAWK_HOME", str(rh))
    monkeypatch.delenv("RECON_OUT_DIR", raising=False)
    out = scope_compiler.resolve_output_paths("acme")
    assert out["primary"] == rh / "recon" / "acme" / "scope" / \
        "compiled_scope.json"
    assert home_a not in out["primary"].parents
    # and nothing is CWD-relative anymore
    assert not str(out["primary"]).startswith("recon/")
    monkeypatch.delenv("RHODAWK_HOME")
    out2 = scope_compiler.resolve_output_paths("acme")
    assert out2["primary"] == home_a / ".rhodawk" / "recon" / "acme" / \
        "scope" / "compiled_scope.json"


# ── B-9: rhodawk_get_finding artifact-subtree containment ───────────────────

def test_b9_get_finding_blocks_vault_and_config(tmp_path, monkeypatch):
    mod = _load_server_module()
    rh = tmp_path / "rh"
    (rh / "findings" / "t").mkdir(parents=True)
    (rh / ".env").write_text('H1_API_TOKEN="vault-secret"\n', encoding="utf-8")
    (rh / "config.json").write_text('{"provider":"ollama"}', encoding="utf-8")
    (rh / "findings" / "t" / "f.txt").write_text("finding body", encoding="utf-8")
    monkeypatch.setenv("RHODAWK_HOME", str(rh))

    denied_env = mod.rhodawk_get_finding(target="t", path=".env")
    assert denied_env.get("status") == "denied", denied_env
    assert denied_env.get("error") == "AUTHORIZATION_REQUIRED"
    assert "vault-secret" not in json.dumps(denied_env)

    denied_cfg = mod.rhodawk_get_finding(target="t", path="config.json")
    assert denied_cfg.get("status") == "denied", denied_cfg

    # traversal back out of the data home stays denied as before
    denied_escape = mod.rhodawk_get_finding(target="t", path="../outside.txt")
    assert denied_escape.get("status") == "denied"

    # legitimate finding artifacts stay readable
    ok = mod.rhodawk_get_finding(target="t", path="findings/t/f.txt")
    assert ok.get("status") == "completed", ok
    assert "finding body" in json.dumps(ok)


# ── B-11: offline H1 auth is UNREACHABLE, never INVALID ─────────────────────

def test_b11_offline_h1_auth_is_not_invalid(monkeypatch):
    from tools import credentials

    def dead(url, headers, timeout):
        raise OSError("network down — offline operator")

    monkeypatch.setattr(credentials, "_http_request", dead)
    code, verdict = credentials.verify_h1_auth("user", "token")
    assert (code, verdict) == (0, "UNREACHABLE")
    assert verdict != "INVALID"
