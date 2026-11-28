"""Fix 4 red-to-green: vault-exported secrets must NOT reach scanner
subprocess environments.

Defect (rhodawk-blueprint.md gap #6 / mission item 4): credentials.load_
credentials() writes vault values into os.environ (credentials.py:355,670),
hunt.py copies the WHOLE environment into every scanner child
(`child_env = os.environ.copy()` — hunt.py:515,744,793,922), and engine.py's
_run_shell merges os.environ over every child (`{**os.environ, **env}`).
Live repro on this HEAD: a stubbed `subfinder` on PATH captured an exported
H1_API_TOKEN from a plain `rhodawk recon example.com` run.

Contract after the fix:
  - scanner children get a redacted env: vault secrets (platform tokens,
    passwords, OTP secrets, LLM keys) are stripped;
  - PDCP_API_KEY / CHAOS_API_KEY survive — recon binaries (subfinder/chaos)
    legitimately consume them at runtime;
  - RHODAWK_AUTH_HEADERS / RHODAWK_SESSION_ID survive — the operator-wired
    auth session exists precisely to be plumbed into scanners;
  - the caller's own environment dict is never mutated.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def test_redact_env_strips_vault_secrets():
    from tools.credentials import redact_env_for_scanners
    env = {
        "PATH": "/usr/bin:/bin",
        "H1_API_TOKEN": "h1-secret",
        "H1_TOKEN": "user:h1-secret",
        "BUGCROWD_TOKEN": "bc-cookie",
        "BUGCROWD_PASSWORD": "bc-pass",
        "INTIGRITI_TOKEN": "it-token",
        "YWH_PASSWORD": "ywh-pass",
        "OPENAI_API_KEY": "sk-openai",
        "ANTHROPIC_API_KEY": "sk-anthropic",
        "GROQ_API_KEY": "gsk_x",
        "DEEPSEEK_API_KEY": "ds-x",
        "OPENROUTER_API_KEY": "or-x",
        "XAI_API_KEY": "xai-x",           # LLM key outside the vault table
        "RECON_OUT_DIR": "/tmp/recon/x",
    }
    out = redact_env_for_scanners(env)
    for k in ("H1_API_TOKEN", "H1_TOKEN", "BUGCROWD_TOKEN", "BUGCROWD_PASSWORD",
              "INTIGRITI_TOKEN", "YWH_PASSWORD", "OPENAI_API_KEY",
              "ANTHROPIC_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY",
              "OPENROUTER_API_KEY", "XAI_API_KEY"):
        assert k not in out, f"{k} leaked into scanner env"
    assert out["PATH"] == "/usr/bin:/bin"
    assert out["RECON_OUT_DIR"] == "/tmp/recon/x"
    # caller's dict untouched
    assert env["H1_API_TOKEN"] == "h1-secret"


def test_redact_env_keeps_recon_provider_keys():
    """subfinder/httpx/chaos consume these vault keys at runtime — they stay."""
    from tools.credentials import redact_env_for_scanners
    env = {"PDCP_API_KEY": "pdcp", "CHAOS_API_KEY": "chaos",
           "H1_API_TOKEN": "h1-secret", "PATH": "/bin"}
    out = redact_env_for_scanners(env)
    assert out["PDCP_API_KEY"] == "pdcp"
    assert out["CHAOS_API_KEY"] == "chaos"
    assert "H1_API_TOKEN" not in out


def test_redact_env_keeps_auth_session_and_nonsecrets():
    """The auth session exists to be plumbed into scanners; usernames/emails
    are not secrets."""
    from tools.credentials import redact_env_for_scanners
    env = {"RHODAWK_AUTH_HEADERS": "Authorization: Bearer x",
           "RHODAWK_SESSION_ID": "abc123",
           "H1_USERNAME": "researcher", "BUGCROWD_EMAIL": "a@b.c",
           "SCOPE_ENFORCED": "1", "TARGET_TYPE": "domain"}
    out = redact_env_for_scanners(env)
    assert out["RHODAWK_AUTH_HEADERS"] == "Authorization: Bearer x"
    assert out["RHODAWK_SESSION_ID"] == "abc123"
    assert out["H1_USERNAME"] == "researcher"
    assert out["TARGET_TYPE"] == "domain"


def _capture_popen_env(monkeypatch, token: str):
    """Run hunt.run_recon with a Popen stub; return the child env it got."""
    from tools import hunt

    captured = {}

    class _FakeProc:
        def wait(self, timeout=None):
            return 0
        returncode = 0
        def kill(self):
            pass

    def _fake_popen(cmd, shell=False, cwd=None, env=None, **kw):
        captured["cmd"] = cmd
        captured["env"] = env
        raise KeyboardInterrupt  # deterministic bail-out after capture

    monkeypatch.setattr(hunt.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(hunt.subprocess, "TimeoutExpired", RuntimeError)
    monkeypatch.setenv("H1_API_TOKEN", token)
    monkeypatch.setenv("PDCP_API_KEY", "pdcp-keep")
    try:
        hunt.run_recon("example.com")
    except KeyboardInterrupt:
        pass
    return captured["env"]


def test_hunt_run_recon_child_env_redacted(monkeypatch, tmp_path):
    monkeypatch.setattr(hunt_module(), "_DATA_HOME", str(tmp_path))
    env = _capture_popen_env(monkeypatch, "h1-secret-value")
    assert env is not None
    assert "H1_API_TOKEN" not in env, "vault token reached scanner subprocess"
    assert env.get("PDCP_API_KEY") == "pdcp-keep"


def hunt_module():
    from tools import hunt
    return hunt


def test_engine_run_shell_full_env_replaces(monkeypatch, tmp_path):
    """_run_shell(full_env=True) must REPLACE (not merge) so a redacted env
    actually reaches the child; default merge behavior is unchanged."""
    from rhodawk import engine
    python = sys.executable
    probe = ("import os,sys;sys.stdout.write(os.environ.get('H1_API_TOKEN','MISSING'))")
    monkeypatch.setenv("H1_API_TOKEN", "h1-secret-value")
    from tools.credentials import redact_env_for_scanners
    red = redact_env_for_scanners(dict(os.environ))
    red["RHODAWK_HOME"] = str(tmp_path)
    # merge mode (default): token inherited — documents the old behavior
    ok, out = engine._run_shell([python, "-c", probe], timeout=30)
    assert ok and "h1-secret-value" in out
    # full_env mode: redacted env is the whole child env — token gone
    ok, out = engine._run_shell([python, "-c", probe], timeout=30,
                                env=red, full_env=True)
    assert ok and "MISSING" in out


# ── B-1 runtime: every spawn path goes through safe_scanner_env() ────────────
# The audit's B-1: the MCP adapters and the RTW delegation passed
# os.environ.copy() (or nothing at all — inheriting the full server env) to
# subprocesses, so vault/platform/LLM secrets leaked on those paths. These
# tests stub each module's subprocess layer and inspect the EXACT env dict
# the child would receive: synthetic H1_API_TOKEN / ANTHROPIC_API_KEY /
# OPENAI_API_KEY must never appear; PATH / RHODAWK wiring must survive.

_LEAK_TOKENS = {
    "H1_API_TOKEN": "h1-synthetic-token",
    "ANTHROPIC_API_KEY": "sk-ant-synthetic",
    "OPENAI_API_KEY": "sk-openai-synthetic",
}


def _inject_secrets(monkeypatch):
    for k, v in _LEAK_TOKENS.items():
        monkeypatch.setenv(k, v)


def _assert_no_secrets(env: dict, ctx: str):
    assert env is not None, f"{ctx}: no child env captured"
    for k in _LEAK_TOKENS:
        assert k not in env, f"{ctx}: {k} leaked into child environment"
    assert env.get("PATH"), f"{ctx}: PATH must survive redaction"


def _capture_subprocess_run(monkeypatch, module, *, exc):
    """Replace module.subprocess.run with an env-capturing stub that always
    bails out through the module's own timeout handler. monkeypatch restores
    the (shared, global) subprocess module after each test."""
    captured = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        raise exc

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    return captured


def test_mcp_adapters_run_recon_child_env_redacted(monkeypatch, tmp_path):
    """B-1: adapters.run_recon used os.environ.copy() unredacted."""
    import importlib.util
    import subprocess as _subprocess

    spec = importlib.util.spec_from_file_location(
        "b1_mcp_adapters", REPO / "rhodawk" / "mcp" / "rhodawk-mcp" / "adapters.py")
    adapters = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapters)
    monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "rh"))
    monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "rh" / "recon"))
    _inject_secrets(monkeypatch)
    captured = _capture_subprocess_run(
        monkeypatch, adapters, exc=_subprocess.TimeoutExpired(cmd=[], timeout=1))
    out = adapters.run_recon("example.com")
    assert out.get("status") == "failed"  # deterministic timeout bail-out
    env = captured["env"]
    _assert_no_secrets(env, "mcp adapters.run_recon")
    # child-only overrides still present
    assert env.get("RHODAWK_TARGET") == "example.com"
    assert env.get("RECON_OUT_DIR") == \
        str(tmp_path / "rh" / "recon" / "example.com")


def test_mcp_adapters_run_hunt_fallback_env_redacted(monkeypatch, tmp_path):
    """B-1: the run_hunt fallback spawned vuln_scanner.sh with NO env=
    argument — the child inherited the FULL MCP server environment."""
    import importlib.util
    import subprocess as _subprocess

    spec = importlib.util.spec_from_file_location(
        "b1_mcp_adapters_h", REPO / "rhodawk" / "mcp" / "rhodawk-mcp" / "adapters.py")
    adapters = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapters)
    monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "rh"))
    _inject_secrets(monkeypatch)
    captured = _capture_subprocess_run(
        monkeypatch, adapters, exc=_subprocess.TimeoutExpired(cmd=[], timeout=1))
    from tools import hunt as hunt_mod
    monkeypatch.setattr(hunt_mod, "hunt_target",
                        lambda *a, **k: (_ for _ in ()).throw(
                            TypeError("force engine-dispatch fallback")))
    out = adapters.run_hunt("example.com")
    assert out.get("status") == "failed"
    _assert_no_secrets(captured["env"], "mcp adapters.run_hunt fallback")


def test_rtw_adapter_delegation_env_redacted(monkeypatch, tmp_path):
    """B-1: the reconFTW delegation used a raw os.environ.copy() default."""
    from tools import rtw_adapter

    monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "rh"))
    _inject_secrets(monkeypatch)

    recon_dir = tmp_path / "rh" / "recon" / "example.com"
    recon_dir.mkdir(parents=True)
    workdir_root = recon_dir / "rtw" / ".work"

    fake_rtw = tmp_path / "fake-rtw"
    fake_rtw.mkdir()
    (fake_rtw / "reconftw.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    monkeypatch.setattr(rtw_adapter, "rtw_script",
                        lambda: fake_rtw / "reconftw.sh")
    monkeypatch.setattr(rtw_adapter, "_rtw_head_commit", lambda: None)
    # a fresh checkout has no installed reconFTW deps state — an empty state
    # map keeps Step 4 (RTW_MISSING_DEPS) from skipping before the spawn
    monkeypatch.setattr(rtw_adapter, "load_state", lambda: {})
    monkeypatch.setattr(rtw_adapter, "seed_files", lambda *a, **k: [])
    monkeypatch.setattr(rtw_adapter, "write_override_cfg",
                        lambda workdir, spec: str(workdir / "rtw_override.cfg"))
    monkeypatch.setattr(rtw_adapter, "_snapshot_seed_lines",
                        lambda workdir, seeded: [])
    monkeypatch.setattr(rtw_adapter, "_bridge_recon_dir",
                        lambda target, workdir: (None, None))
    captured = _capture_subprocess_run(
        monkeypatch, rtw_adapter,
        exc=subprocess.TimeoutExpired(cmd=[], timeout=1))
    cap_id = next(iter(rtw_adapter.CAPABILITIES))
    out = rtw_adapter.run_capability(
        cap_id, "example.com", recon_dir=recon_dir, allow_unscoped=True,
        force=True, timeout_secs=30, workdir_root=workdir_root, env=None)
    # the stub's TimeoutExpired routes through the delegation's timeout
    # handler — proving the spawn was reached and its env captured
    assert out.get("status") == "TIMEOUT", out
    _assert_no_secrets(captured["env"], "rtw_adapter delegation")
    # an explicit caller-supplied env is still honored verbatim (contract)
    explicit_env = {"PATH": "/bin", "CUSTOM": "1"}
    captured2 = _capture_subprocess_run(
        monkeypatch, rtw_adapter,
        exc=subprocess.TimeoutExpired(cmd=[], timeout=1))
    rtw_adapter.run_capability(
        cap_id, "example.com", recon_dir=recon_dir, allow_unscoped=True,
        force=True, timeout_secs=30, workdir_root=workdir_root,
        env=explicit_env)
    assert captured2["env"].get("CUSTOM") == "1"

def test_engine_and_hunt_spawn_sites_use_shared_builder():
    """Every scanner spawn site routes through safe_scanner_env() (B-1):
    behavior is covered by the runtime tests above and in
    test_audit_b1_b12_fixes.py; this pins that no site still builds a child
    env by hand (the old {**redact_env_for_scanners(os.environ), ...} or
    bare os.environ.copy() patterns)."""
    engine_src = (REPO / "rhodawk" / "engine.py").read_text(encoding="utf-8")
    assert "safe_scanner_env" in engine_src
    assert "{**redact_env_for_scanners(os.environ)" not in engine_src
    assert 'os.environ["RHODAWK_SCOPE_UNSAFE"]' not in engine_src  # B-5
    hunt_src = (REPO / "rhodawk" / "tools" / "hunt.py").read_text(encoding="utf-8")
    assert hunt_src.count("safe_scanner_env()") >= 4
    adapters_src = (REPO / "rhodawk" / "mcp" / "rhodawk-mcp" /
                    "adapters.py").read_text(encoding="utf-8")
    assert "os.environ.copy()" not in adapters_src.split("def _safe_scanner_env")[0]
    rtw_src = (REPO / "rhodawk" / "tools" / "rtw_adapter.py").read_text(
        encoding="utf-8")
    assert "safe_scanner_env()" in rtw_src
