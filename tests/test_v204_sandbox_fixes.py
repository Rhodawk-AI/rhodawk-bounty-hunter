"""Regression tests for the v2.0.4 live-sandbox fixes.

Three failures observed running v2.0.3 in a fresh sandbox:
  1. recon_engine.sh touched $RECON_DIR/.run_incomplete before the recon
     directory existed on a brand-new target — `touch: cannot touch
     '...recon/target.local/.run_incomplete': No such file or directory`.
  2. ffuf ran without -ac, so SPA soft-200 catch-alls (constant body for
     every nonexistent route) flooded Phase 6 with false positives.
  3. `rhodawk mcp doctor` reported a CWD-relative hunt-memory path that no
     runtime ever used, instead of the unified adapters._memory_root().
"""

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ENGINE = REPO / "rhodawk" / "tools" / "recon_engine.sh"
MCP_DIR = REPO / "rhodawk" / "mcp" / "rhodawk-mcp"


# ── Fix 1: .run_incomplete directory race ─────────────────────────────────────

def test_run_incomplete_marker_created_after_recon_dir(tmp_path):
    """mkdir -p "$RECON_DIR" must run immediately before the marker touch,
    after the B6 rotation block, and the two lines must succeed verbatim
    against a brand-new $RHODAWK_HOME/recon/<target>."""
    lines = ENGINE.read_text().splitlines()
    idx = lines.index('touch "$RECON_DIR/.run_incomplete"')
    assert lines[idx - 1] == 'mkdir -p "$RECON_DIR"', (
        'mkdir -p "$RECON_DIR" must run immediately before '
        'touch "$RECON_DIR/.run_incomplete"'
    )
    # B6 rotation of a leftover incomplete run must still exist and run
    # earlier (existing targets archive, brand-new targets fall through).
    mv_idx = next(
        i for i, ln in enumerate(lines)
        if 'mv -f "$RECON_DIR/.run_incomplete" "$RECON_DIR/.prev_run/run_incomplete"' in ln
    )
    assert mv_idx < idx, "B6 rotation must happen before the fresh marker is laid"

    # Behavioral: exact engine lines against a nonexistent recon dir.
    recon_dir = tmp_path / "sandbox-home" / "recon" / "target.local"
    assert not recon_dir.exists()
    env = {**os.environ, "RECON_DIR": str(recon_dir)}
    proc = subprocess.run(
        ["bash", "-e", "-c", 'mkdir -p "$RECON_DIR"\ntouch "$RECON_DIR/.run_incomplete"'],
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == "", proc.stderr
    assert "No such file or directory" not in proc.stderr
    assert (recon_dir / ".run_incomplete").is_file()


# ── Fix 2: ffuf SPA soft-200 auto-calibration ────────────────────────────────

def _ffuf_invocation_block() -> str:
    lines = ENGINE.read_text().splitlines()
    for i, ln in enumerate(lines):
        if 'ffuf -u "${url}/FUZZ"' in ln:
            block = [ln]
            j = i + 1
            while j < len(lines) and lines[j].rstrip().endswith("\\"):
                block.append(lines[j])
                j += 1
            if j < len(lines):
                block.append(lines[j])  # command terminator (-of json … || true)
            return "\n".join(block)
    raise AssertionError("ffuf invocation not found in recon_engine.sh")


def test_ffuf_invocation_has_auto_calibration_and_existing_flags():
    block = _ffuf_invocation_block()
    # -ac filters SPA soft-200 catch-all responses (auto-calibration).
    for flag in ("-ac", "-w", "-mc", "-t", "-rate", "-sf", "-timeout", "-o", "-of json"):
        assert re.search(rf"(^|\s){re.escape(flag)}(\s|\\|$)", block, re.M), (
            f"ffuf invocation lost required flag {flag!r}:\n{block}"
        )
    # Auth/header passthrough must stay intact.
    assert "RHODAWK_AUTH_ARGS" in block


# ── Fix 3: mcp doctor unified memory path ─────────────────────────────────────

def _run_doctor(env_extra, cwd):
    env = {k: v for k, v in os.environ.items() if k != "RHODAWK_MEMORY_DIR"}
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(MCP_DIR / "cli.py"), "doctor"],
        env=env, cwd=str(cwd), capture_output=True, text=True, timeout=120,
    )


def _doctor_memory_line(proc) -> str:
    lines = [l for l in proc.stdout.splitlines() if l.startswith("[*] RHODAWK_MEMORY_DIR=")]
    assert lines, f"doctor printed no memory path line:\n{proc.stdout}\n{proc.stderr}"
    return lines[0].split("=", 1)[1].rsplit(" exists=", 1)[0]


def test_doctor_reports_unified_memory_root_under_rhodawk_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("RHODAWK_HOME", str(home))
    monkeypatch.delenv("RHODAWK_MEMORY_DIR", raising=False)
    sys.modules.pop("adapters", None)
    sys.path.insert(0, str(MCP_DIR))
    try:
        import adapters  # flat module inside rhodawk-mcp/
        expected = adapters._memory_root()
    finally:
        if str(MCP_DIR) in sys.path:
            sys.path.remove(str(MCP_DIR))
        sys.modules.pop("adapters", None)

    proc = _run_doctor({"RHODAWK_HOME": str(home)}, cwd=tmp_path)
    reported = _doctor_memory_line(proc)
    assert reported == str(home / "hunt-memory")
    assert reported == str(expected), "doctor must report adapters._memory_root()"
    # The old bug printed the CWD-relative string "hunt-memory"; the unified
    # path must be absolute (doctor runs with cwd=tmp_path here).
    assert os.path.isabs(reported)


def test_doctor_respects_explicit_memory_dir_override(tmp_path):
    explicit = tmp_path / "custom-mem"
    proc = _run_doctor(
        {"RHODAWK_HOME": str(tmp_path / "home"), "RHODAWK_MEMORY_DIR": str(explicit)},
        cwd=tmp_path,
    )
    assert _doctor_memory_line(proc) == str(explicit)
