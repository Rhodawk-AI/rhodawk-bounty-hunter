"""Audit R-13: shell-based test suites under tests/*.sh are invisible to
pytest collection — they silently stopped running (and silently broke) when
paths moved in the v2.0.0 rename. Each suite runs here as a subprocess; a
non-zero exit fails the pytest build, and CI therefore covers them too.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

SHELL_SUITES = (
    "tests/test_cicd_scanner.sh",
)


@pytest.mark.parametrize("suite", SHELL_SUITES)
def test_shell_suite_passes(suite: str):
    path = REPO_ROOT / suite
    assert path.is_file(), f"shell test suite missing: {suite}"
    proc = subprocess.run(
        ["bash", str(path)],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, (
        f"{suite} failed (rc={proc.returncode}):\n"
        f"{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}"
    )


def test_shell_suites_reference_existing_tools():
    """Every path a shell suite points at must exist — the R-13 failure mode
    was a suite pointing at tools/cicd_scanner.sh (a path that no longer
    exists), passing nothing to nobody."""
    for suite in SHELL_SUITES:
        suite_path = REPO_ROOT / suite
        text = suite_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith("CICD_SCANNER="):
                rel = line.split("=", 1)[1].strip().strip('"')
                # In this suite SCRIPT_DIR == the repo root (dirname $0/..)
                resolved = Path(rel.replace("$SCRIPT_DIR", str(REPO_ROOT)))
                assert resolved.is_file(), \
                    f"{suite} points at a missing tool: {rel}"
