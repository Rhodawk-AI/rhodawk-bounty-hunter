"""Fix 6 red-to-green: `rhodawk doctor` must NOT hard-fail (exit 1) when the
reconFTW checkout is absent.

Defect (rhodawk-blueprint.md gap #8 / mission item 6): every delegated
capability is optional (RTW_MISSING_DEPS ⇒ SKIPPED, never blocks the run) and
the native stack works fully without reconFTW, yet doctor returned FAIL +
exit 1 for a missing checkout — the only FAIL on an otherwise working
system. An optional capability gap is a WARN, not a FAIL.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _run_doctor(tmp_path: Path) -> subprocess.CompletedProcess:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["RHODAWK_HOME"] = str(home)
    env["RTW_HOME"] = str(tmp_path / "no-such-reconftw")  # absent checkout
    env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-m", "rhodawk.engine", "--no-banner", "doctor"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120)


def test_doctor_missing_reconftw_is_warn_not_fail(tmp_path):
    proc = _run_doctor(tmp_path)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"doctor exited {proc.returncode}:\n{out[-800:]}"
    assert "[FAIL]" not in out, f"unexpected FAIL line:\n{out[-800:]}"
    assert "reconFTW checkout" in out  # still reported
    # and the line is a WARN, not a FAIL
    for line in out.splitlines():
        if "reconFTW checkout" in line:
            assert "WARN" in line or "PASS" in line


def test_doctor_exit_code_counts_only_fails(tmp_path):
    """Exit contract: 0 FAILs ⇒ 0. (Guard against regressions to exit 1.)"""
    proc = _run_doctor(tmp_path)
    assert proc.returncode == 0
