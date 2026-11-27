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


def test_engine_cmd_recon_and_hunt_use_full_env():
    """Both engine scanner-spawn sites opt into the redacted full env."""
    src = (REPO / "rhodawk" / "engine.py").read_text(encoding="utf-8")
    assert src.count("env=child_env, full_env=True") == 2  # cmd_recon + cmd_hunt
    assert "redact_env_for_scanners" in src
