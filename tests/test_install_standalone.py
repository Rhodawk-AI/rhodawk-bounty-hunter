"""Regression tests for the standalone install/uninstall path under bash 3.2.

bash 3.2 — still the default /bin/bash on macOS — aborts under `set -u` when an
empty array is expanded as "${arr[@]}". install.sh and uninstall.sh both build a
command-prefix array that stays empty whenever the target bin directory is
writable (the common case), so `--agent standalone` failed before it installed
anything:

    ./install.sh: line 283: install_cmd[@]: unbound variable

These tests drive the real scripts end to end in a temp bin directory, so the
regression cannot come back unnoticed on a bash 4+ developer machine.
"""

import importlib
import os
import re
import shutil
import stat
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")


def _run(script, args, bin_dir):
    env = {
        **os.environ,
        "RHODAWK_BIN_DIR": str(bin_dir),
        "RHODAWK_SKIP_DEPS": "1",
    }
    return subprocess.run(
        [BASH, os.path.join(REPO, script), *args],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120,
    )


def test_standalone_install_succeeds(tmp_path):
    bin_dir = tmp_path / "bin"
    proc = _run("install.sh", ["--agent", "standalone"], bin_dir)

    assert "unbound variable" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert (bin_dir / "rhodawk").is_symlink()


def test_standalone_install_links_to_engine(tmp_path):
    bin_dir = tmp_path / "bin"
    _run("install.sh", ["--agent", "standalone"], bin_dir)
    assert os.path.realpath(bin_dir / "rhodawk") == \
        os.path.realpath(os.path.join(REPO, "rhodawk", "engine.py"))


def test_standalone_install_is_idempotent(tmp_path):
    bin_dir = tmp_path / "bin"
    _run("install.sh", ["--agent", "standalone"], bin_dir)
    proc = _run("install.sh", ["--agent", "standalone"], bin_dir)
    assert proc.returncode == 0, proc.stderr
    assert (bin_dir / "rhodawk").is_symlink()


def test_standalone_uninstall_removes_the_command(tmp_path):
    bin_dir = tmp_path / "bin"
    _run("install.sh", ["--agent", "standalone"], bin_dir)
    assert (bin_dir / "rhodawk").is_symlink()

    proc = _run("uninstall.sh", ["--agent", "standalone", "--yes"], bin_dir)
    assert "unbound variable" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert not (bin_dir / "rhodawk").exists()


@pytest.mark.parametrize("script", ["install.sh", "uninstall.sh", "install_tools.sh"])
def test_scripts_parse_under_bash(script):
    proc = subprocess.run([BASH, "-n", os.path.join(REPO, script)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_empty_array_expansion_idiom_survives_nounset():
    """The idiom itself, pinned — this is what bash 3.2 rejects without the fix."""
    broken = subprocess.run(
        [BASH, "-c", 'set -euo pipefail; a=(); "${a[@]}" true'],
        capture_output=True, text=True,
    )
    fixed = subprocess.run(
        [BASH, "-c", 'set -euo pipefail; a=(); ${a[@]+"${a[@]}"} true'],
        capture_output=True, text=True,
    )
    # On bash 4+ both succeed; on bash 3.2 only the guarded form does.
    assert fixed.returncode == 0, fixed.stderr
    if broken.returncode != 0:
        assert "unbound variable" in broken.stderr


def test_guarded_expansion_still_passes_a_non_empty_prefix():
    proc = subprocess.run(
        [BASH, "-c", 'set -euo pipefail; a=(echo); ${a[@]+"${a[@]}"} marker'],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "marker"


# ── Layer 1A (v2.0.5): both entrypoints, once each; UX ordering ───────────────

def test_standalone_install_links_both_entrypoints_exactly_once(tmp_path):
    """The old script linked rhodawk twice (engine symlink + 'brand alias')
    and printed the same '[+] Installed: .../rhodawk -> .../engine.py' line
    two times — while rhodawk-agent was never installed at all."""
    bin_dir = tmp_path / "bin"
    proc = _run("install.sh", ["--agent", "standalone"], bin_dir)
    assert proc.returncode == 0, proc.stderr
    assert (bin_dir / "rhodawk").is_symlink()
    assert (bin_dir / "rhodawk-agent").is_symlink()
    assert os.path.realpath(bin_dir / "rhodawk-agent") == \
        os.path.realpath(os.path.join(REPO, "rhodawk", "agent.py"))
    engine_log = [ln for ln in proc.stdout.splitlines()
                  if ln.startswith("[+]") and ln.rstrip().endswith("engine.py")]
    assert len(engine_log) == 1, proc.stdout


def test_install_sh_source_single_links_and_ux_ordering():
    """Static layout pins: no duplicate symlink block, reconFTW setup before
    the final Done! banner, one banner only, and no raw capability JSON dump."""
    src = open(os.path.join(REPO, "install.sh"), encoding="utf-8").read()
    # the legacy duplicate-link block is gone
    assert "brand alias" not in src
    # rhodawk-agent is installed in every mode
    assert "rhodawk-agent" in src
    # the capability-registry rebuild runs BEFORE the final Done! banner
    # (rindex = the actual call after the function definition)
    assert src.rindex("install_rtw_capability_delegation") < \
        src.index("Done! Type from anywhere:")
    assert src.count("Done! Type from anywhere:") == 1
    # one-line summary instead of the raw JSON state dump (--rebuild --banner
    # printed a 9-line JSON dict on non-TTY installs)
    assert "--banner" not in src
    assert "--summary" in src


def test_uninstall_removes_both_entrypoints_and_managed_venv(tmp_path):
    """Standalone uninstall removes rhodawk AND rhodawk-agent, plus the venv
    only when it carries the rhodawk-managed marker — never user data."""
    home = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    venv_dir = home / "rhodawk-home" / "venv"
    (venv_dir / "bin").mkdir(parents=True)
    (venv_dir / ".rhodawk-managed-venv").touch()
    # simulate what install.sh creates in venv mode (dangling links included:
    # no real console scripts behind them)
    (bin_dir).mkdir()
    os.symlink(str(venv_dir / "bin" / "rhodawk"), str(bin_dir / "rhodawk"))
    os.symlink(str(venv_dir / "bin" / "rhodawk-agent"),
               str(bin_dir / "rhodawk-agent"))
    # user data that must survive the uninstall
    (home / "rhodawk-home" / ".env").write_text("H1_API_TOKEN=secret")
    (home / "rhodawk-home" / "recon").mkdir()

    env = {**os.environ, "RHODAWK_BIN_DIR": str(bin_dir),
           "RHODAWK_HOME": str(home / "rhodawk-home"),
           "RHODAWK_SKIP_DEPS": "1"}
    proc = subprocess.run([BASH, os.path.join(REPO, "uninstall.sh"),
                           "--agent", "standalone", "--yes"],
                          cwd=REPO, env=env, capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert not (bin_dir / "rhodawk").exists()
    assert not (bin_dir / "rhodawk-agent").exists()
    assert not venv_dir.exists()
    # user data preserved
    assert (home / "rhodawk-home" / ".env").exists()
    assert (home / "rhodawk-home" / "recon").exists()
    assert "standalone venv" in proc.stdout


def test_uninstall_preserves_unmarked_venv(tmp_path):
    """A venv without the rhodawk-managed marker is never deleted."""
    home = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    venv_dir = home / "rhodawk-home" / "venv"
    (venv_dir / "bin").mkdir(parents=True)
    (bin_dir).mkdir()
    os.symlink(str(venv_dir / "bin" / "rhodawk"), str(bin_dir / "rhodawk"))

    env = {**os.environ, "RHODAWK_BIN_DIR": str(bin_dir),
           "RHODAWK_HOME": str(home / "rhodawk-home"),
           "RHODAWK_SKIP_DEPS": "1"}
    proc = subprocess.run([BASH, os.path.join(REPO, "uninstall.sh"),
                           "--agent", "standalone", "--yes"],
                          cwd=REPO, env=env, capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert not (bin_dir / "rhodawk").exists()
    assert venv_dir.exists()
    assert "no rhodawk-managed marker" in proc.stdout


# ── P0 regression: permission tightening must never neuter the venv ──────────
# Live failure on a blank Ubuntu 24.04 box: the standalone venv was installed
# under ~/.rhodawk, then the blanket `chmod 600` passes (install.sh find pass
# + _compat.ensure_home_migrated rglob walk — which runs on EVERY `rhodawk`
# startup via engine.main()) stripped +x from venv/bin/*, so the installed
# CLI destroyed itself: `rhodawk status` ok, then the very next command
# (`rhodawk doctor`) died with exit 126 (Permission denied). chmod also
# followed symlinks like venv/bin/python3 -> /usr/bin/python3 and
# re-permissioned their TARGETS.

def _make_tighten_home(tmp_path):
    """Build a ~/.rhodawk-shaped home: managed venv + secrets + symlink traps."""
    home = tmp_path / "home"
    rh = home / ".rhodawk"
    venv_bin = rh / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    entrypoint = venv_bin / "rhodawk"
    entrypoint.write_text("#!/bin/sh\necho stub\n")
    entrypoint.chmod(0o755)
    venv_lib_file = rh / "venv" / "lib" / "pkg.py"
    venv_lib_file.parent.mkdir(parents=True)
    venv_lib_file.write_text("# venv payload\n")
    venv_lib_file.chmod(0o644)
    # symlink traps: chmod must not follow links to their targets
    py_target = tmp_path / "system-python3"
    py_target.write_text("#!/bin/sh\necho py\n")
    py_target.chmod(0o755)
    (venv_bin / "python3").symlink_to(py_target)
    outside = tmp_path / "outside-target.txt"
    outside.write_text("data")
    outside.chmod(0o644)
    (rh / "linked.log").symlink_to(outside)
    # sensitive data files that MUST still be tightened
    (rh / "config.json").write_text("{}")
    (rh / "config.json").chmod(0o644)
    (rh / ".env").write_text("H1_API_TOKEN=secret")
    (rh / ".env").chmod(0o644)
    (rh / "notes.txt").write_text("recon notes")
    (rh / "notes.txt").chmod(0o644)
    return home, rh, entrypoint, py_target, outside


def test_ensure_home_migrated_preserves_venv_and_skips_symlinks(tmp_path,
                                                                monkeypatch):
    """ensure_home_migrated() must keep venv/bin/* executable, never chmod
    through symlinks, and still tighten config.json / .env to 0600."""
    home, rh, entrypoint, py_target, outside = _make_tighten_home(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    _compat = importlib.import_module("_compat")

    _compat.ensure_home_migrated()

    # venv executable keeps its +x (this exact behavior self-destructed the CLI)
    assert os.access(entrypoint, os.X_OK), \
        "ensure_home_migrated stripped +x from venv/bin/rhodawk"
    assert stat.S_IMODE(entrypoint.stat().st_mode) == 0o755
    assert stat.S_IMODE((rh / "venv" / "lib" / "pkg.py").stat().st_mode) == 0o644
    # symlinks are never chmod'ed through — their targets keep their modes
    assert stat.S_IMODE(py_target.stat().st_mode) == 0o755
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644
    assert (rh / "venv" / "bin" / "python3").is_symlink()
    assert (rh / "linked.log").is_symlink()
    # sensitive data files are still tightened
    assert stat.S_IMODE((rh / "config.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((rh / ".env").stat().st_mode) == 0o600


def test_back_to_back_cli_invocations_keep_venv_executable(tmp_path):
    """A real `rhodawk status` followed back-to-back by `rhodawk doctor`
    against a RHODAWK_HOME whose data home holds an executable
    venv/bin/rhodawk must leave that entrypoint executable after BOTH runs
    (the incident: run 1 ok, run 2 exit 126)."""
    home, rh, entrypoint, _py_target, _outside = _make_tighten_home(tmp_path)
    env = {**os.environ, "HOME": str(home), "RHODAWK_HOME": str(rh)}
    env.pop("BRAIN_PROVIDER", None)

    proc1 = subprocess.run(
        [sys.executable, "-m", "rhodawk", "status"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=180)
    assert proc1.returncode == 0, proc1.stderr
    assert os.access(entrypoint, os.X_OK), \
        "venv entrypoint lost +x after `rhodawk status`"

    proc2 = subprocess.run(
        [sys.executable, "-m", "rhodawk", "doctor"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=180)
    assert proc2.returncode == 0, proc2.stderr
    assert os.access(entrypoint, os.X_OK), \
        "venv entrypoint lost +x after `rhodawk doctor`"
    # tightening still did its job on the sensitive files
    assert stat.S_IMODE((rh / "config.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((rh / ".env").stat().st_mode) == 0o600


def test_install_sh_tightening_block_prunes_venv(tmp_path):
    """Re-running install.sh's permission-tightening block must preserve +x
    on venv/bin/* while still tightening $HOME/.rhodawk/config.json to 0600.
    The REAL function is extracted from install.sh — no reimplementation."""
    home, rh, entrypoint, _py_target, outside = _make_tighten_home(tmp_path)
    src = open(os.path.join(REPO, "install.sh"), encoding="utf-8").read()
    match = re.search(r"^tighten_rhodawk_home_perms\(\)\s*\{.*?^\}", src,
                      re.S | re.M)
    assert match, "tighten_rhodawk_home_perms() not found in install.sh"
    script = match.group(0) + '\ntighten_rhodawk_home_perms "$1"\n'

    proc = subprocess.run([BASH, "-c", script, "tighten", str(rh)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr

    assert os.access(entrypoint, os.X_OK), \
        "install.sh tightening stripped +x from venv/bin/rhodawk"
    assert stat.S_IMODE(entrypoint.stat().st_mode) == 0o755
    assert stat.S_IMODE((rh / "venv" / "lib" / "pkg.py").stat().st_mode) == 0o644
    # non-venv data files are still tightened; symlink targets untouched
    assert stat.S_IMODE((rh / "config.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((rh / ".env").stat().st_mode) == 0o600
    assert stat.S_IMODE((rh / "notes.txt").stat().st_mode) == 0o600
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644
    assert (rh / "linked.log").is_symlink()
