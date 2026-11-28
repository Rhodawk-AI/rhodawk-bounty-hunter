"""Layer 1B Suite A regression tests — plugin/MCP installers, PreToolUse
scanner guard, and install_tools.sh.

Covers the six observed defects, each with the live symptom that motivated it:

1. ``./install.sh --agent claude < /dev/null`` exited 1 under ``set -e`` (the
   bare ``read -r -p "Set up Burp MCP now?"`` hit EOF) instead of skipping the
   prompt; even on a TTY, Ctrl+D aborted the installer.
2. ``copy_files`` (install.sh) installed README.md into
   ``~/.claude/commands/README.md`` and ``~/.claude/agents/README.md``.
3. Five leftover "Claude Bug Bounty" strings in install.sh (lines 2, 269, 322,
   344, 365 at audit time) plus one in rhodawk/tools/__init__.py:1.
4. ``install_mcp`` ran bare system ``pip3 install 'mcp>=2.2.0'`` (PEP 668
   failure on Ubuntu 24.04 even when ~/.rhodawk/venv already had mcp), printed
   a system-python server entry, and printed "Done." BEFORE the reconFTW setup
   that runs after the agent dispatch.
5. (SECURITY) hook_scope_guard.py classified a direct
   ``nuclei -u https://example.com`` as readonly -> exit 0 (ALLOW) with zero
   scope manifest present. Covered in tests/test_hook_curl_scope.py.
6. install_tools.sh ignored --help and immediately started a root Linuxbrew
   download on Ubuntu 24.04; unknown flags were silently ignored.
"""
import json
import os
import pty
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
INSTALL_TOOLS = REPO / "install_tools.sh"


def _stub_rtw(tmp_path: Path) -> str:
    """A reconftw.sh stub so the post-dispatch reconFTW capability-delegation
    takes the "already present" fast path (no network clone during tests)."""
    rtw = tmp_path / "rtw"
    rtw.mkdir(exist_ok=True)
    stub = rtw / "reconftw.sh"
    stub.write_text("#!/bin/bash\nexit 0\n")
    stub.chmod(0o755)
    return str(rtw)


def _base_env(tmp_path: Path) -> dict:
    home = tmp_path / "home"
    (home / ".rhodawk").mkdir(parents=True, exist_ok=True)
    (tmp_path / "bin").mkdir(exist_ok=True)
    env = {
        **os.environ,
        "HOME": str(home),
        "RHODAWK_HOME": str(home / ".rhodawk"),
        "RTW_HOME": _stub_rtw(tmp_path),
        "RHODAWK_BIN_DIR": str(tmp_path / "bin"),
    }
    env.pop("RHODAWK_SKIP_DEPS", None)
    return env


# ── Issue #1 + #2 + #3: --agent claude non-interactive / README / branding ──

def test_claude_install_noninteractive_exit0_no_readme_no_stale_branding(tmp_path):
    env = _base_env(tmp_path)
    proc = subprocess.run([str(INSTALL), "--agent", "claude"],
                          cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, (
        f"exit={proc.returncode}\nSTDOUT tail:\n{proc.stdout[-800:]}\n"
        f"STDERR:\n{proc.stderr[-500:]}")
    out = proc.stdout
    # Issue #1: stdin closed -> the Burp prompt must be skipped cleanly, not
    # aborted by `read` at EOF under set -e.
    assert "Set up Burp MCP now?" not in out
    # Issue #3: zero stale branding.
    assert "Claude Bug Bounty" not in out
    assert "RhodawkAI Bounty Hunter for Claude Code" in out
    # Issue #2: commands/agents installed, but never README.md.
    root = tmp_path / "home" / ".claude"
    installed_cmds = [p.name for p in (root / "commands").glob("*")]
    installed_agents = [p.name for p in (root / "agents").glob("*")]
    assert installed_cmds, "commands/ empty — install did not run"
    assert installed_agents, "agents/ empty — install did not run"
    assert not any(n.lower() == "readme.md" for n in installed_cmds), installed_cmds
    assert not any(n.lower() == "readme.md" for n in installed_agents), installed_agents
    assert list((root / "skills").glob("*")), "skills/ empty"
    # PreToolUse scope guard registered in settings.json (Issue #1 keeps the
    # rest of the installer running to completion).
    settings = json.loads((root / "settings.json").read_text(encoding="utf-8"))
    blob = json.dumps(settings.get("hooks", {}).get("PreToolUse", []))
    assert "hook_scope_guard.py" in blob


@pytest.mark.skipif(not hasattr(pty, "openpty"), reason="pty unavailable")
def test_claude_install_tty_eof_does_not_abort(tmp_path):
    """Second half of Issue #1: with a TTY on stdin the Burp prompt IS shown,
    but EOF/Ctrl+D at the prompt degrades to "no" (guarded read) instead of
    killing the installer with exit 1."""
    env = _base_env(tmp_path)
    master, slave = pty.openpty()
    os.close(master)  # the child's read() sees EOF immediately
    try:
        proc = subprocess.run([str(INSTALL), "--agent", "claude"],
                              cwd=REPO, env=env, stdin=slave,
                              capture_output=True, text=True, timeout=300)
    finally:
        os.close(slave)
    assert proc.returncode == 0, (
        f"exit={proc.returncode}\nSTDOUT tail:\n{proc.stdout[-800:]}")
    # EOF/Ctrl+D at the prompt degraded to "no": the Burp SETUP instructions
    # must NOT be shown. (bash may suppress the `read -p` prompt itself when
    # the pty dies with EIO, so the prompt text is not asserted — the
    # behavioral contract is exit 0 + "no".)
    assert "To connect Burp MCP" not in proc.stdout
    assert not (tmp_path / "home" / ".claude" / "commands" / "README.md").exists()
    # the rest of the install still ran to completion
    assert (tmp_path / "home" / ".claude" / "settings.json").exists()


# ── Issue #4: --agent mcp uses the managed venv, never bare system pip ──────

def test_mcp_agent_reuses_managed_venv_no_bare_pip(tmp_path):
    env = _base_env(tmp_path)
    venv_dir = tmp_path / "home" / ".rhodawk" / "venv"
    venv_dir.parent.mkdir(parents=True, exist_ok=True)
    # --system-site-packages: deps (mcp, requests, ...) resolve from the
    # running test interpreter's site-packages, so the editable install that
    # install_mcp performs is fast and offline-safe while still exercising
    # the REAL venv-reuse + SDK-verification path.
    subprocess.run([sys.executable, "-m", "venv", "--system-site-packages",
                    str(venv_dir)], check=True, capture_output=True,
                   timeout=120)
    proc = subprocess.run([str(INSTALL), "--agent", "mcp"],
                          cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, (
        f"exit={proc.returncode}\nSTDOUT tail:\n{proc.stdout[-1000:]}\n"
        f"STDERR:\n{proc.stderr[-500:]}")
    out = proc.stdout
    assert "[+] Reusing existing venv" in out
    assert "[+] mcp SDK verified in the managed venv (import mcp.server OK)" in out
    # the old bare-pip paths are gone
    assert "pip install mcp failed" not in out
    assert "Installing mcp SDK (optional)" not in out
    # the managed venv really can import the SDK
    assert subprocess.run(
        [str(venv_dir / "bin" / "python"), "-c", "import mcp.server"],
        capture_output=True).returncode == 0
    # Issue #4 ordering: final "Done." AFTER the reconFTW setup
    done_at = out.find("Done. rhodawk MCP is ready:")
    rtw_at = out.find("reconFTW already present")
    assert rtw_at != -1 and done_at != -1 and rtw_at < done_at, (
        "the final Done banner must print AFTER the reconFTW setup")


def test_mcp_agent_skip_deps_still_done_after_reconftw(tmp_path):
    """Fast path: with RHODAWK_SKIP_DEPS=1 no pip is attempted at all, the
    bare-pip failure marker never appears, and Done. still comes after the
    reconFTW setup."""
    env = _base_env(tmp_path)
    env["RHODAWK_SKIP_DEPS"] = "1"
    proc = subprocess.run([str(INSTALL), "--agent", "mcp"],
                          cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout[-800:]
    out = proc.stdout
    assert "RHODAWK_SKIP_DEPS=1 — skipping venv + pip setup" in out
    assert "pip install mcp failed" not in out
    done_at = out.find("Done. rhodawk MCP is ready:")
    rtw_at = out.find("reconFTW already present")
    assert rtw_at != -1 and done_at != -1 and rtw_at < done_at


# ── Issue #6: install_tools.sh --help / unknown flags / banner ───────────────

def test_install_tools_help_exit0_before_any_install(tmp_path):
    proc = subprocess.run([str(INSTALL_TOOLS), "--help"], cwd=REPO,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout[-500:] + proc.stderr[-300:]
    out = proc.stdout + proc.stderr
    for flag in ("--rtw-deps", "--browser", "--with-cicd-scanner",
                 "--with-credential-attack", "-h, --help"):
        assert flag in out, flag
    assert "RhodawkAI Bounty Hunter Tool Installer" in out
    # --help must exit BEFORE the install banner and any package manager.
    assert "Installing tools via Homebrew" not in out
    assert "Homebrew not found" not in out
    assert "Installing tools via apt-get" not in out


def test_install_tools_unknown_flag_exit2(tmp_path):
    proc = subprocess.run([str(INSTALL_TOOLS), "--bogus-flag"], cwd=REPO,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 2
    assert "Unknown option: --bogus-flag" in proc.stderr
    assert "--rtw-deps" in proc.stderr  # usage summary included
