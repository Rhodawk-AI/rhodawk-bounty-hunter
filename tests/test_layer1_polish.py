"""Layer 1 polish regression tests — the 8 items closed after the independent
live sandbox audit of Layer 1A/1B (report: layer1ab_audit_report.md).

1. Stale "Claude Bug Bounty" branding: the two MCP client READMEs (audit §4)
   plus a repo-wide static gate (LICENSE/NOTICE/license attribution and the
   tests that assert the literal's ABSENCE are excluded).
2. Bare non-interactive ``./uninstall.sh < /dev/null`` used to die under
   ``set -e`` at the confirmation ``read`` with exit 1 and no explanation,
   having modified nothing. Now: exit 2 + actionable ``--yes`` hint, still
   touching nothing.
3. Durable PreToolUse scope guard: the hook now points at a 0700 copy under
   ``~/.rhodawk/hooks/`` (survives repo moves + every ``chmod 600`` tightening
   pass, in both install.sh and ``_compat.ensure_home_migrated()``);
   uninstalling standalone with the hook still referencing the removed venv
   interpreter prints a loud warning; uninstalling claude removes the entry
   AND the durable copy; doctor reports a dangling hook as [WARN].
4. ``rhodawk doctor`` exit contract documented in --help; ``--strict`` exits 1
   on WARN rows; ``--quiet`` collapses the fresh-box WARN wall.
5. ``--agent claude`` (and ``all``) now close with exactly one banner AFTER the
   reconFTW setup, like standalone/mcp.
6. ``--agent mcp --client claude`` merges mcpServers into
   ``~/.claude/settings.json`` atomically with a .bak backup, preserving
   pre-existing hooks/servers, idempotent on re-run.
7. ``--agent all < /dev/null`` runs end-to-end with exit 0 and a single
   closing summary.
"""
import argparse
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
UNINSTALL = REPO / "uninstall.sh"
BASH = shutil.which("bash")

PKG_DIR = str(REPO / "rhodawk")
if PKG_DIR not in sys.path:
    sys.path.insert(0, PKG_DIR)

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")


def _import(name: str):
    return importlib.import_module(name)


def _stub_rtw(tmp_path: Path) -> str:
    """A reconftw.sh stub so the post-dispatch reconFTW capability-delegation
    takes the "already present" fast path (no network clone during tests)."""
    rtw = tmp_path / "rtw"
    rtw.mkdir(exist_ok=True)
    stub = rtw / "reconftw.sh"
    stub.write_text("#!/bin/bash\nexit 0\n")
    stub.chmod(0o755)
    return str(rtw)


def _base_env(tmp_path: Path, skip_deps: bool = True) -> dict:
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
    if skip_deps:
        env["RHODAWK_SKIP_DEPS"] = "1"
    else:
        env.pop("RHODAWK_SKIP_DEPS", None)
    return env


def _run_script(script: Path, args, env, stdin=subprocess.DEVNULL):
    return subprocess.run([str(BASH), str(script), *args], cwd=str(REPO),
                          env=env, stdin=stdin, capture_output=True,
                          text=True, timeout=600)


# ── Item 1: zero stale branding ───────────────────────────────────────────────

def test_mcp_client_readmes_have_no_stale_branding():
    for readme in ("rhodawk/mcp/burp-mcp-client/README.md",
                   "rhodawk/mcp/caido-mcp-client/README.md"):
        text = (REPO / readme).read_text(encoding="utf-8")
        assert "Claude Bug Bounty" not in text, readme
        assert "RhodawkAI Bounty Hunter" in text, readme


def test_repo_wide_zero_stale_branding():
    """Static gate: no tracked file may carry the retired product branding,
    except license attribution (LICENSE, npm/LICENSE, NOTICE), _compat.py
    (assembled literals), and tests/ (which assert the literal's ABSENCE).
    Honest upstream-origin references ("Agentic-Bug-Hunter" in BENCHMARKS.md
    comparisons) are attribution, not branding leaks, and stay allowed."""
    excludes = {"LICENSE", "npm/LICENSE", "NOTICE"}
    for path in REPO.rglob("*"):
        s = str(path)
        if (".git" in path.parts or ".venv" in path.parts
                or "__pycache__" in path.parts or "node_modules" in path.parts
                or "tests" in path.parts or "egg-info" in path.parts):
            continue
        if path.name in excludes or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        assert "Claude Bug Bounty" not in text, s


# ── Item 2: bare non-interactive uninstall is a clean exit 2, not a dead end ──

def _make_installed_shape(tmp_path: Path):
    """venv with the managed marker + bin symlinks, as install.sh leaves them."""
    home = tmp_path / "home"
    rh = home / "rhodawk-home"
    venv_dir = rh / "venv"
    (venv_dir / "bin").mkdir(parents=True)
    (venv_dir / ".rhodawk-managed-venv").touch()
    (venv_dir / "bin" / "rhodawk").write_text("#!/bin/sh\nexit 0\n")
    (venv_dir / "bin" / "rhodawk").chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    os.symlink(str(venv_dir / "bin" / "rhodawk"), str(bin_dir / "rhodawk"))
    return home, rh, venv_dir, bin_dir


def test_uninstall_noninteractive_without_yes_exits2_removes_nothing(tmp_path):
    home, rh, venv_dir, bin_dir = _make_installed_shape(tmp_path)
    env = {**os.environ, "RHODAWK_BIN_DIR": str(bin_dir),
           "RHODAWK_HOME": str(rh), "RHODAWK_SKIP_DEPS": "1"}
    proc = _run_script(UNINSTALL, ["--agent", "standalone"], env)

    assert proc.returncode == 2, f"exit={proc.returncode}\n{proc.stdout}"
    # the hint must be actionable: name --yes (and stderr, not stdout)
    assert "--yes" in proc.stderr, proc.stderr
    assert "Non-interactive stdin detected" in proc.stderr
    # nothing was modified
    assert (bin_dir / "rhodawk").is_symlink()
    assert venv_dir.exists()
    assert (venv_dir / ".rhodawk-managed-venv").exists()


def test_uninstall_noninteractive_with_yes_still_works(tmp_path):
    """--yes keeps working with closed stdin (the CI path install.sh itself
    documents) — the gate above only covers the confirmation prompt."""
    home, rh, venv_dir, bin_dir = _make_installed_shape(tmp_path)
    env = {**os.environ, "RHODAWK_BIN_DIR": str(bin_dir),
           "RHODAWK_HOME": str(rh), "RHODAWK_SKIP_DEPS": "1"}
    proc = _run_script(UNINSTALL, ["--agent", "standalone", "--yes"], env)
    assert proc.returncode == 0, proc.stderr
    assert not venv_dir.exists()


# ── Item 3: durable PreToolUse scope guard ────────────────────────────────────

def test_claude_install_creates_durable_hook_copy_and_registers_it(tmp_path):
    env = _base_env(tmp_path)
    proc = _run_script(INSTALL, ["--agent", "claude"], env)
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-300:]

    home = tmp_path / "home"
    durable = home / ".rhodawk" / "hooks" / "hook_scope_guard.py"
    assert durable.is_file(), "durable hook copy missing"
    assert os.access(durable, os.X_OK), "durable hook copy lost +x"
    assert stat.S_IMODE(durable.stat().st_mode) == 0o700

    settings = json.loads((home / ".claude" / "settings.json").read_text())
    entries = settings["hooks"]["PreToolUse"]
    guard_entries = [e for e in entries
                     if any("hook_scope_guard.py" in str(h.get("command", ""))
                            for h in e.get("hooks", []))]
    assert len(guard_entries) == 1, entries
    cmd = guard_entries[0]["hooks"][0]["command"]
    assert str(durable) in cmd, "the durable path must be registered, not the repo checkout"
    assert str(REPO / "rhodawk" / "tools" / "hook_scope_guard.py") not in cmd


def test_durable_hook_copy_survives_compat_tightening_and_reinstall(tmp_path,
                                                                    monkeypatch):
    env = _base_env(tmp_path)
    first = _run_script(INSTALL, ["--agent", "claude"], env)
    assert first.returncode == 0, first.stderr

    home = tmp_path / "home"
    durable = home / ".rhodawk" / "hooks" / "hook_scope_guard.py"
    assert stat.S_IMODE(durable.stat().st_mode) == 0o700

    # _compat.ensure_home_migrated() runs on EVERY CLI startup — its 0600
    # tightening walk must skip hooks/ just like venv/ (Path.home() follows
    # the HOME env var on POSIX, matching the existing tightening tests).
    compat = _import("_compat")
    monkeypatch.setenv("HOME", str(home))
    compat.ensure_home_migrated()
    assert stat.S_IMODE(durable.stat().st_mode) == 0o700, \
        "ensure_home_migrated() chmod'ed the durable hook copy"
    assert os.access(durable, os.X_OK)

    # re-running install.sh (tightening runs at script start) keeps +x too
    second = _run_script(INSTALL, ["--agent", "claude"], env)
    assert second.returncode == 0, second.stderr
    assert stat.S_IMODE(durable.stat().st_mode) == 0o700, \
        "install.sh re-run stripped +x from the durable hook copy"
    assert os.access(durable, os.X_OK)


def test_claude_uninstall_removes_guard_entry_and_durable_copy(tmp_path):
    env = _base_env(tmp_path)
    assert _run_script(INSTALL, ["--agent", "claude"], env).returncode == 0

    home = tmp_path / "home"
    settings_path = home / ".claude" / "settings.json"
    settings = json.loads(settings_path.read_text())
    # a pre-existing user hook that must survive the uninstall
    settings["hooks"]["PreToolUse"].append(
        {"matcher": "Bash", "hooks": [{"type": "command",
                                       "command": "echo user-hook"}]})
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")

    proc = _run_script(UNINSTALL, ["--agent", "claude", "--yes"], env)
    assert proc.returncode == 0, proc.stderr

    durable = home / ".rhodawk" / "hooks" / "hook_scope_guard.py"
    assert not durable.exists(), "durable hook copy must be removed"
    settings = json.loads(settings_path.read_text())
    remaining = [e for e in settings["hooks"]["PreToolUse"]
                 if any("hook_scope_guard.py" in str(h.get("command", ""))
                        for h in e.get("hooks", []))]
    assert remaining == [], "guard entry must be removed from settings.json"
    user_hooks = [e for e in settings["hooks"]["PreToolUse"]
                  if any("user-hook" in str(h.get("command", ""))
                         for h in e.get("hooks", []))]
    assert user_hooks, "pre-existing user hooks must be preserved"


def test_uninstall_standalone_warns_when_hook_references_removed_venv(tmp_path):
    home, rh, venv_dir, bin_dir = _make_installed_shape(tmp_path)
    hooks_dir = rh / "hooks"
    hooks_dir.mkdir()
    guard = hooks_dir / "hook_scope_guard.py"
    guard.write_text("# guard stub\n")
    guard.chmod(0o700)
    claude_dir = home / ".claude"
    claude_dir.mkdir(exist_ok=True)
    (claude_dir / "settings.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [{
            "matcher": "Bash",
            "hooks": [{"type": "command",
                       "command": f"{venv_dir}/bin/python \"{guard}\""}],
        }]},
    }, indent=2) + "\n")

    env = {**os.environ, "HOME": str(home), "RHODAWK_BIN_DIR": str(bin_dir),
           "RHODAWK_HOME": str(rh), "RHODAWK_SKIP_DEPS": "1"}
    proc = _run_script(UNINSTALL, ["--agent", "standalone", "--yes"], env)
    assert proc.returncode == 0, proc.stderr
    assert not venv_dir.exists()
    assert "[!] warning" in proc.stdout
    assert "hook_scope_guard.py" in proc.stdout
    assert "--agent claude" in proc.stdout, "both remediation paths must be named"
    assert "--agent standalone" in proc.stdout


def test_doctor_flags_dangling_hook_warn_and_valid_hook_pass(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    engine = _import("engine")
    home = tmp_path / "home"
    rh = home / ".rhodawk"
    rh.mkdir(parents=True)
    claude_dir = home / ".claude"
    claude_dir.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("RTW_HOME", str(tmp_path / "no-such-rtw"))
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.setattr(engine, "load_config", lambda: {})

    # dangling: interpreter + script both missing
    (claude_dir / "settings.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [{
            "matcher": "Bash",
            "hooks": [{"type": "command",
                       "command": "/nonexistent/interp "
                                  '"/nonexistent/hook_scope_guard.py"'}],
        }]},
    }))
    with pytest.raises(SystemExit) as exc:
        engine.cmd_doctor(argparse.Namespace())
    assert exc.value.code == 0  # dangling hook is a WARN, not a FAIL
    out = capsys.readouterr().out
    warn_rows = [ln for ln in out.splitlines() if "PreToolUse hook" in ln]
    assert warn_rows and "[WARN]" in warn_rows[0]
    assert any("./install.sh --agent claude" in ln
               for ln in out.splitlines())

    # valid: real interpreter + real executable script copy
    (rh / "hooks").mkdir(exist_ok=True)
    guard = rh / "hooks" / "hook_scope_guard.py"
    guard.write_text("# guard\n")
    guard.chmod(0o700)
    (claude_dir / "settings.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [{
            "matcher": "Bash",
            "hooks": [{"type": "command",
                       "command": f"{sys.executable} \"{guard}\""}],
        }]},
    }))
    with pytest.raises(SystemExit) as exc:
        engine.cmd_doctor(argparse.Namespace())
    assert exc.value.code == 0
    out = capsys.readouterr().out
    pass_rows = [ln for ln in out.splitlines() if "PreToolUse hook" in ln]
    assert pass_rows and "[PASS]" in pass_rows[0]


# ── Item 4: doctor --strict / --quiet / exit-code docs ────────────────────────

@pytest.fixture
def fresh_doctor_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("RTW_HOME", str(tmp_path / "no-such-rtw"))
    for var in ("BRAIN_PROVIDER", "H1_API_TOKEN", "PDCP_API_KEY",
                "CHAOS_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    engine = _import("engine")
    monkeypatch.setattr(engine, "load_config", lambda: {})
    return engine


def test_doctor_help_documents_exit_code_contract(capsys, monkeypatch):
    engine = _import("engine")
    monkeypatch.setattr(sys, "argv", ["rhodawk", "doctor", "--help"])
    with pytest.raises(SystemExit) as exc:
        engine.main()
    assert exc.value.code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "Exit-code contract" in out
    assert "--strict" in out and "--quiet" in out


def test_doctor_strict_exits1_when_warnings_exist(fresh_doctor_env, capsys):
    engine = fresh_doctor_env
    with pytest.raises(SystemExit) as exc:
        engine.cmd_doctor(argparse.Namespace(strict=True, quiet=False))
    assert exc.value.code == 1, "a fresh box has WARNs — --strict must exit 1"
    out = capsys.readouterr().out
    assert "--strict" in out


def test_doctor_default_still_exits0_on_warnings(fresh_doctor_env, capsys):
    """Backward compatibility: without --strict, WARNs must keep exit 0."""
    engine = fresh_doctor_env
    with pytest.raises(SystemExit) as exc:
        engine.cmd_doctor(argparse.Namespace(strict=False, quiet=False))
    assert exc.value.code == 0


def test_doctor_quiet_collapses_warning_wall(fresh_doctor_env, capsys):
    engine = fresh_doctor_env
    with pytest.raises(SystemExit) as exc:
        engine.cmd_doctor(argparse.Namespace(strict=False, quiet=True))
    assert exc.value.code == 0
    out = capsys.readouterr().out
    # no per-row PASS/WARN wall
    assert "[PASS]" not in out
    assert "[WARN]" not in out
    # grouped optional-WARN summary + final status line present
    assert "WARN(s) suppressed" in out
    assert "environment ready" in out


# ── Item 5 + 7: unified closing banners / --agent all ─────────────────────────

def test_claude_install_closing_banner_after_reconftw(tmp_path):
    env = _base_env(tmp_path)
    proc = _run_script(INSTALL, ["--agent", "claude"], env)
    assert proc.returncode == 0, proc.stdout[-800:]
    out = proc.stdout
    rtw_at = out.find("reconFTW already present")
    banner_at = out.find("Done. RhodawkAI Bounty Hunter is ready for Claude Code:")
    assert rtw_at != -1 and banner_at != -1 and rtw_at < banner_at, out[-600:]
    assert out.count("Done. RhodawkAI Bounty Hunter is ready for Claude Code:") == 1


def test_agent_all_devnull_exit0_single_summary_no_leaks(tmp_path):
    env = _base_env(tmp_path)
    proc = _run_script(INSTALL, ["--agent", "all"], env)
    assert proc.returncode == 0, proc.stdout[-1000:] + proc.stderr[-400:]
    out = proc.stdout
    assert out.count("Done. All targets installed:") == 1
    assert "Claude Bug Bounty" not in out
    rtw_at = out.find("reconFTW already present")
    banner_at = out.find("Done. All targets installed:")
    assert rtw_at != -1 and banner_at != -1 and rtw_at < banner_at
    home = tmp_path / "home"
    # zero README.md leaks in the claude harness dirs
    for sub in ("commands", "agents"):
        names = [p.name for p in (home / ".claude" / sub).glob("*")]
        assert not any(n.lower() == "readme.md" for n in names), names
    # durable guard installed once, settings entry present
    durable = home / ".rhodawk" / "hooks" / "hook_scope_guard.py"
    assert durable.is_file() and os.access(durable, os.X_OK)
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    guard_entries = [e for e in settings["hooks"]["PreToolUse"]
                     if any("hook_scope_guard.py" in str(h.get("command", ""))
                            for h in e.get("hooks", []))]
    assert len(guard_entries) == 1


# ── Item 6: --agent mcp --client claude safe merge ────────────────────────────

def _seed_settings(path: Path):
    original = {
        "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [
                {"type": "command", "command": "echo user-hook"}]}]},
        "mcpServers": {"burp": {"command": "java", "args": ["-jar", "x.jar"]}},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(original, indent=2) + "\n")
    return original


def test_mcp_client_claude_merges_idempotently_with_backup(tmp_path):
    env = _base_env(tmp_path)
    home = tmp_path / "home"
    settings_path = home / ".claude" / "settings.json"
    original = _seed_settings(settings_path)

    first = _run_script(INSTALL, ["--agent", "mcp", "--client", "claude"], env)
    assert first.returncode == 0, first.stdout[-900:] + first.stderr[-300:]
    assert "[+] backup written" in first.stdout

    merged = json.loads(settings_path.read_text())
    # shipped entry merged in (key comes from claude-config.json: "rhodawk")
    assert "rhodawk" in merged["mcpServers"]
    assert merged["mcpServers"]["rhodawk"]["args"] == ["mcp", "serve"]
    # pre-existing server + hooks preserved verbatim
    assert merged["mcpServers"]["burp"] == original["mcpServers"]["burp"]
    assert merged["hooks"] == original["hooks"]
    # .bak holds the pre-change snapshot
    backup = json.loads((home / ".claude" / "settings.json.bak").read_text())
    assert backup == original
    backup_before = (home / ".claude" / "settings.json.bak").read_text()

    # re-run: idempotent no-op, no new backup, file unchanged
    second = _run_script(INSTALL, ["--agent", "mcp", "--client", "claude"], env)
    assert second.returncode == 0, second.stderr
    assert "already merged (idempotent no-op)" in second.stdout
    assert json.loads(settings_path.read_text()) == merged
    assert (home / ".claude" / "settings.json.bak").read_text() == backup_before


def test_mcp_client_never_overwrites_customized_entry(tmp_path):
    env = _base_env(tmp_path)
    home = tmp_path / "home"
    settings_path = home / ".claude" / "settings.json"
    _seed_settings(settings_path)
    customized = {"command": "my-own-rhodawk", "args": ["mcp", "serve"]}
    settings = json.loads(settings_path.read_text())
    settings["mcpServers"]["rhodawk"] = customized
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")

    proc = _run_script(INSTALL, ["--agent", "mcp", "--client", "claude"], env)
    assert proc.returncode == 0, proc.stderr
    assert "already exists with different content" in proc.stderr
    assert json.loads(settings_path.read_text())["mcpServers"]["rhodawk"] == customized


def test_mcp_default_stays_non_invasive(tmp_path):
    env = _base_env(tmp_path)
    home = tmp_path / "home"
    _seed_settings(home / ".claude" / "settings.json")
    proc = _run_script(INSTALL, ["--agent", "mcp"], env)
    assert proc.returncode == 0, proc.stderr
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    assert "rhodawk" not in settings.get("mcpServers", {})
    # the manual instructions still print, plus the new opt-in hint
    assert "claude-config.json" in proc.stdout
    assert "--agent mcp --client claude" in proc.stdout


def test_client_flag_rejected_for_other_agents(tmp_path):
    env = _base_env(tmp_path)
    proc = _run_script(INSTALL, ["--agent", "claude", "--client", "claude"], env)
    assert proc.returncode == 2
    assert "only supported with --agent mcp" in proc.stderr


# ── Live-sandbox P0/P1/P2 fixes: end-to-end regression tests ──────────────────

sys.path.insert(0, str(REPO))
from contracts.scope import CompiledScopeManifest  # noqa: E402

_HOOK_ENV_CLEAN = {"PATH": "/usr/bin:/bin"}  # NO PYTHONPATH, NO HOME overrides


def _write_scope_manifest(tmp_path: Path) -> str:
    m = CompiledScopeManifest(program_handle="t",
                              allow_patterns=["*.allowed.test"])
    return str(m.save(str(tmp_path / "compiled_scope.json")))


def _registered_hook_command(settings_path: Path) -> str:
    settings = json.loads(settings_path.read_text())
    cmds = [h["command"] for e in settings["hooks"]["PreToolUse"]
            for h in e.get("hooks", [])
            if "hook_scope_guard.py" in str(h.get("command", ""))]
    assert cmds, "no scope-guard hook registered"
    return cmds[0]


def _run_hook_command(command: str, payload: dict) -> subprocess.CompletedProcess:
    """Execute the EXACT command registered in settings.json, from /tmp,
    with a clean environment (no PYTHONPATH) — the live-sandbox scenario."""
    return subprocess.run(command, shell=True, cwd="/tmp",
                          env=_HOOK_ENV_CLEAN, input=json.dumps(payload),
                          capture_output=True, text=True, timeout=60)


def _make_venv_with_repo(home: Path) -> tuple[Path, Path]:
    """A managed venv that can import rhodawk/contracts/tools from the repo
    (editable-install-equivalent via a .pth file — offline, deterministic),
    plus the uninstall marker install.sh would leave behind."""
    venv_dir = home / ".rhodawk" / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--system-site-packages",
                    str(venv_dir)], check=True, capture_output=True, timeout=120)
    (venv_dir / ".rhodawk-managed-venv").touch()
    purelib = subprocess.run(
        [str(venv_dir / "bin" / "python"), "-c",
         "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        check=True, capture_output=True, text=True, timeout=60).stdout.strip()
    (Path(purelib) / "rhodawk_repo.pth").write_text(f"{REPO}\n{REPO / 'rhodawk'}\n")
    return venv_dir, venv_dir / "bin" / "python"


def test_durable_hook_inscope_allow_oos_block_registered_venv_command(tmp_path):
    """P0, venv variant: the EXACT command registered in settings.json (venv
    interpreter) must run from /tmp with a clean env — allow in-scope,
    block (exit 2, SCOPE_HOOK_BLOCK) out-of-scope. No ModuleNotFoundError."""
    home = tmp_path / "home"
    (home / ".rhodawk").mkdir(parents=True)
    venv_dir, _venv_python = _make_venv_with_repo(home)
    manifest = _write_scope_manifest(tmp_path)
    env = _base_env(tmp_path)  # RHODAWK_SKIP_DEPS=1: venv reused, no pip/network
    proc = _run_script(INSTALL, ["--agent", "claude"], env)
    assert proc.returncode == 0, proc.stdout[-600:] + proc.stderr[-300:]

    command = _registered_hook_command(home / ".claude" / "settings.json")
    assert str(venv_dir / "bin" / "python") in command, \
        "venv interpreter must be registered when the venv exists"

    ok = _run_hook_command(command, {
        "tool_name": "Bash",
        "tool_input": {"command": "nuclei -u https://app.allowed.test",
                       "manifest_path": manifest}})
    assert ok.returncode == 0, f"in-scope denied: {ok.stderr[-300:]}"
    assert "ModuleNotFoundError" not in ok.stderr

    oos = _run_hook_command(command, {
        "tool_name": "Bash",
        "tool_input": {"command": "nuclei -u https://evil.test",
                       "manifest_path": manifest}})
    assert oos.returncode == 2, f"out-of-scope allowed: {oos.stdout[-300:]}"
    assert "SCOPE_HOOK_BLOCK" in oos.stderr
    assert "evil.test" in oos.stderr
    assert "ModuleNotFoundError" not in oos.stderr and \
        "Traceback" not in oos.stderr


def test_durable_hook_works_via_repo_root_record_when_skip_deps(tmp_path):
    """P0, .repo_root variant: with no venv at all (RHODAWK_SKIP_DEPS=1), the
    hook registered with system python3 must still resolve rhodawk through
    the .repo_root record — allow in-scope, block out-of-scope, from /tmp,
    clean env."""
    env = _base_env(tmp_path)  # no venv in this home
    proc = _run_script(INSTALL, ["--agent", "claude"], env)
    assert proc.returncode == 0, proc.stdout[-600:]

    home = tmp_path / "home"
    manifest = _write_scope_manifest(tmp_path)
    durable = home / ".rhodawk" / "hooks" / "hook_scope_guard.py"
    assert durable.is_file()
    assert (home / ".rhodawk" / "hooks" / ".repo_root").is_file()

    command = _registered_hook_command(home / ".claude" / "settings.json")
    ok = _run_hook_command(command, {
        "tool_name": "Bash",
        "tool_input": {"command": "nuclei -u https://app.allowed.test",
                       "manifest_path": manifest}})
    assert ok.returncode == 0, f"in-scope denied: {ok.stderr[-400:]}"
    oos = _run_hook_command(command, {
        "tool_name": "Bash",
        "tool_input": {"command": "nuclei -u https://evil.test",
                       "manifest_path": manifest}})
    assert oos.returncode == 2 and "SCOPE_HOOK_BLOCK" in oos.stderr


def test_hook_fails_closed_without_traceback_when_repo_record_gone(tmp_path):
    """P0, broken environment: bare system python3, .repo_root deleted, no
    venv, rhodawk unimportable — the hook must NOT crash with an exit-1
    traceback; it fails CLOSED (exit 2, SCOPE_HOOK_BLOCK) on active calls."""
    env = _base_env(tmp_path)
    proc = _run_script(INSTALL, ["--agent", "claude"], env)
    assert proc.returncode == 0, proc.stdout[-600:]

    home = tmp_path / "home"
    (home / ".rhodawk" / "hooks" / ".repo_root").unlink()
    manifest = _write_scope_manifest(tmp_path)
    command = _registered_hook_command(home / ".claude" / "settings.json")

    oos = _run_hook_command(command, {
        "tool_name": "Bash",
        "tool_input": {"command": "nuclei -u https://evil.test",
                       "manifest_path": manifest}})
    assert oos.returncode == 2, \
        f"expected fail-closed block, got {oos.returncode}: {oos.stderr[-400:]}"
    assert "SCOPE_HOOK_BLOCK" in oos.stderr
    # the regression this pins: no ImportError traceback / exit 1 crash
    assert "Traceback" not in oos.stderr, oos.stderr[-400:]
    assert "ModuleNotFoundError" not in oos.stderr, oos.stderr[-400:]

    ok = _run_hook_command(command, {
        "tool_name": "Bash",
        "tool_input": {"command": "nuclei -u https://app.allowed.test",
                       "manifest_path": manifest}})
    assert ok.returncode == 2, "contract unavailable ⇒ in-scope also blocks (fail-closed)"
    assert "Traceback" not in ok.stderr


def test_agent_all_full_stack_cli_venv_registration_doctor_and_warning(tmp_path):
    """P1 end-to-end: --agent all < /dev/null links BOTH standalone commands,
    registers the venv interpreter for the hook, the registered command
    actually works from /tmp, `rhodawk doctor` reports [PASS] PreToolUse hook,
    and a subsequent standalone uninstall warns about the dangling hook."""
    home = tmp_path / "home"
    (home / ".rhodawk").mkdir(parents=True)
    venv_dir, _venv_python = _make_venv_with_repo(home)
    manifest = _write_scope_manifest(tmp_path)
    env = _base_env(tmp_path)
    proc = _run_script(INSTALL, ["--agent", "all"], env)
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-400:]

    bin_dir = tmp_path / "bin"
    assert (bin_dir / "rhodawk").is_symlink()
    assert (bin_dir / "rhodawk-agent").is_symlink()
    assert "Standalone CLI" in proc.stdout  # closing summary lists the CLI

    settings_path = home / ".claude" / "settings.json"
    command = _registered_hook_command(settings_path)
    assert str(venv_dir / "bin" / "python") in command, \
        "venv interpreter must be registered (standalone runs FIRST now)"

    ok = _run_hook_command(command, {
        "tool_name": "Bash",
        "tool_input": {"command": "nuclei -u https://app.allowed.test",
                       "manifest_path": manifest}})
    assert ok.returncode == 0, f"hook broken after --agent all: {ok.stderr[-400:]}"

    doctor = subprocess.run([str(bin_dir / "rhodawk"), "doctor"],
                            cwd="/tmp", env={**_HOOK_ENV_CLEAN,
                                             "HOME": str(home),
                                             "RHODAWK_HOME": str(home / ".rhodawk")},
                            capture_output=True, text=True, timeout=120)
    assert doctor.returncode == 0, doctor.stdout[-600:] + doctor.stderr[-300:]
    pass_rows = [ln for ln in doctor.stdout.splitlines()
                 if "PreToolUse hook" in ln]
    assert pass_rows and "[PASS]" in pass_rows[0], doctor.stdout[-600:]

    rm = _run_script(UNINSTALL, ["--agent", "standalone", "--yes"], env)
    assert rm.returncode == 0, rm.stderr
    assert not venv_dir.exists()
    assert "[!] warning" in rm.stdout and "hook_scope_guard.py" in rm.stdout


def test_claude_uninstall_removes_agents_and_repo_root_user_agents_survive(tmp_path):
    """P2 end-to-end: uninstall --agent claude removes the installed agent
    markdown files AND .repo_root alongside skills/commands/hook state,
    while unrelated user agents in ~/.claude/agents/ survive."""
    env = _base_env(tmp_path)
    home = tmp_path / "home"
    proc = _run_script(INSTALL, ["--agent", "claude"], env)
    assert proc.returncode == 0, proc.stdout[-600:]

    agents_dir = home / ".claude" / "agents"
    installed = {p.name for p in agents_dir.glob("*.md")}
    assert installed, "no agents installed — install did not run"
    (agents_dir / "my-own-agent.md").write_text("# user agent\n")
    assert (home / ".rhodawk" / "hooks" / ".repo_root").is_file(), \
        "install must record .repo_root next to the durable hook copy"

    rm = _run_script(UNINSTALL, ["--agent", "claude", "--yes"], env)
    assert rm.returncode == 0, rm.stderr
    remaining = {p.name for p in agents_dir.glob("*.md")}
    assert remaining == {"my-own-agent.md"}, \
        f"installed agents must be removed, user agents preserved: {remaining}"
    assert "Claude agent" in rm.stdout
    assert not (home / ".rhodawk" / "hooks" / ".repo_root").exists(), \
        ".repo_root must be removed with the durable hook copy"
    assert not (home / ".rhodawk" / "hooks" / "hook_scope_guard.py").exists()
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    guards = [e for e in settings["hooks"]["PreToolUse"]
              if any("hook_scope_guard.py" in str(h.get("command", ""))
                     for h in e.get("hooks", []))]
    assert guards == []
