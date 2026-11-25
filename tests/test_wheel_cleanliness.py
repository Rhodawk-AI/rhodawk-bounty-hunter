"""Release audit R-01 hard gate: built distributions stay free of runtime
artifacts.

Background: pytest (and hunts launched from a git clone) used to write
recon/, findings/, hunt-memory/ etc. INTO the source tree, and packaging
(packages.find on the whole repo + a "**/*" package-data wildcard) shipped
those artifacts in the wheel and sdist. Output homes are now pinned to
$RHODAWK_HOME / ~/.rhodawk (rtw_adapter, hunt, engine, memory modules), the
conftest pins them per-test, and MANIFEST.in prunes the runtime directories.

This module guards the remaining invariant:
  1. the packaging config keeps the prunes in place (fast, always runs);
  2. a wheel built from THIS tree contains zero runtime artifacts
     (skipped when the `build` package is unavailable — CI installs it via
     requirements-dev.txt and re-checks in a dedicated step).
"""

import importlib.util
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER = Path(__file__).resolve().parent / "check_wheel_clean.py"
RUNTIME_DIRS = ("recon", "findings", "reports", "targets", "hunt-memory")


class TestPackagingConfig:
    def test_manifest_prunes_runtime_dirs(self):
        text = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        for d in RUNTIME_DIRS:
            assert f"prune rhodawk/{d}" in text, \
                f"MANIFEST.in must prune rhodawk/{d} (release audit R-01)"

    def test_package_data_is_explicit_not_wildcard(self):
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        section = text.split("[tool.setuptools.package-data]", 1)[-1]
        section = section.split("\n[", 1)[0]  # stop at the next TOML table
        # A catch-all element (glob matching every path) re-opens the R-01
        # pollution vector; each entry must name a concrete data subtree.
        entries = re.findall(r'"([^"]+)"', section)
        assert entries, "package-data table must not be empty"
        for entry in entries:
            assert not entry.startswith("*"), \
                f"catch-all package-data entry re-opens R-01: {entry}"

    def test_requirements_do_not_ship_pytest_as_runtime(self):
        runtime = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
        assert "pytest" not in runtime, \
            "pytest must stay out of runtime requirements (release audit R-03)"
        dev = (REPO_ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
        assert "pytest" in dev and "build" in dev


class TestWheelCleanliness:
    @pytest.mark.skipif(importlib.util.find_spec("build") is None,
                        reason="'build' package not installed — CI runs the same "
                               "assertion via tests/check_wheel_clean.py")
    def test_built_wheel_contains_no_runtime_artifacts(self, tmp_path):
        out_dir = tmp_path / "dist"
        proc = subprocess.run(
            [sys.executable, "-m", "build", "--wheel",
             "--outdir", str(out_dir), str(REPO_ROOT)],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=600,
        )
        assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
        wheels = sorted(out_dir.glob("*.whl"))
        assert wheels, "python -m build produced no wheel"
        proc2 = subprocess.run(
            [sys.executable, str(CHECKER), *[str(w) for w in wheels]],
            capture_output=True, text=True, timeout=120,
        )
        assert proc2.returncode == 0, proc2.stdout + proc2.stderr


class TestSourceTreeNotPrePolluted:
    """The gate is meaningless if the tree ships already polluted (files would
    be tracked). Runtime dirs must not exist as TRACKED content."""

    def test_no_tracked_runtime_artifacts(self):
        proc = subprocess.run(
            ["git", "ls-files", "--",
             "rhodawk/recon", "rhodawk/findings", "rhodawk/memory/leads",
             "recon", "findings", "hunt-memory"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
        )
        tracked = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        assert not tracked, f"runtime artifacts tracked in git: {tracked}"

    def test_wheel_clean_checker_flags_a_polluted_wheel(self, tmp_path):
        """Sanity: the checker itself detects runtime artifacts."""
        whl = tmp_path / "fake-1.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("rhodawk/__init__.py", "__version__ = '0'\n")
            zf.writestr("rhodawk/recon/target.com/subdomains.txt", "x\n")
            zf.writestr("rhodawk/memory/leads/target.com.jsonl", "x\n")
        proc = subprocess.run(
            [sys.executable, str(CHECKER), str(whl)],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 1
        assert "rhodawk/recon/target.com/subdomains.txt" in proc.stdout
