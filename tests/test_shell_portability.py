"""Guard against macOS(BSD)/Linux(GNU) shell portability regressions.

These constructs silently misbehave on macOS (BSD userland, bash 3.2):
grep -P, `date +%s%N`, bare `mktemp`, and bash-4 `${var^^}`. They had crept
into the recon/scanner scripts; these checks keep them out and confirm the
portable replacements actually work.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = [
    REPO / "rhodawk" / "tools" / "recon_engine.sh",
    REPO / "rhodawk" / "tools" / "cicd_scanner.sh",
    REPO / "rhodawk" / "tools" / "vuln_scanner.sh",
    REPO / "rhodawk" / "tools" / "bypass_403.sh",
    REPO / "scripts" / "full_hunt.sh",
]


def code_lines(path: Path) -> list[str]:
    """Lines with comments/blank stripped, so matches are real commands."""
    out = []
    for ln in path.read_text().splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(ln.split(" #", 1)[0])
    return out


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_grep_perl_flag(path):
    for ln in code_lines(path):
        assert not re.search(r"grep\s+-\S*P", ln), f"grep -P in {path.name}: {ln.strip()}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_bare_mktemp(path):
    for ln in code_lines(path):
        assert "$(mktemp)" not in ln, f"bare mktemp in {path.name}: {ln.strip()}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_bash4_upper_expansion(path):
    for ln in code_lines(path):
        assert not re.search(r"\$\{[A-Za-z_][A-Za-z0-9_]*\^\^", ln), f"${{x^^}} in {path.name}: {ln.strip()}"


def test_no_date_nanoseconds_usage_form():
    """The `$(date +%s%N)` usage form must be gone (BSD date has no %N).
    The one remaining `date +%s%N` is inside the guarded _now_ns fallback."""
    txt = (REPO / "rhodawk" / "tools" / "vuln_scanner.sh").read_text()
    assert "$(date +%s%N)" not in txt
    assert "_now_ns()" in txt  # the portable helper exists


def test_now_ns_helper_returns_positive_integer():
    script = REPO / "rhodawk" / "tools" / "vuln_scanner.sh"
    # source the helper in isolation and call it
    out = subprocess.run(
        ["bash", "-c", f'. "{script}" 2>/dev/null || true; _now_ns'],
        capture_output=True, text=True, timeout=30,
    )
    # _now_ns may run after the script's arg parsing errors; call it directly
    # via a minimal extraction instead if needed.
    val = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
    if not val.isdigit():
        # Fallback: extract and eval just the function.
        text = script.read_text()
        start = text.index("_now_ns()")
        end = text.index("\n}\n", start) + 3
        func = text[start:end]
        out = subprocess.run(["bash", "-c", func + "\n_now_ns"],
                             capture_output=True, text=True, timeout=30)
        val = out.stdout.strip()
    assert val.isdigit() and int(val) > 0, f"_now_ns returned {val!r}"


# ── Issue #6 (v2.0.5): Recon Summary must stay silent on missing files ───────

def _summary_lines(path: Path, labels: tuple[str, ...]) -> list[str]:
    """Exact `echo "  <label> … $(wc -l …)"` lines from the Recon Summary."""
    return [
        ln for ln in path.read_text().splitlines()
        if ln.strip().startswith('echo "  ') and "wc -l" in ln
        and any(label in ln for label in labels)
    ]


def test_recon_summary_missing_files_count_zero_with_zero_stderr(tmp_path):
    """Issue #6 regression: the Recon Summary counts missing optional files
    (live/urls.txt, subdomains/all.txt, urls/all.txt) as 0 with ZERO stderr.

    The old ordering `wc -l < f 2>/dev/null || echo 0` still leaked a shell
    error: redirections apply left-to-right, so the failed `< f` redirect
    prints `No such file or directory` BEFORE 2>/dev/null is in effect. The
    guard must come first: `wc -l 2>/dev/null < f || echo 0`."""
    engine = REPO / "rhodawk" / "tools" / "recon_engine.sh"
    lines = _summary_lines(engine, ("Subdomains:", "Live hosts:",
                                    "URLs collected:"))
    assert len(lines) == 3, f"expected 3 summary count lines, got {len(lines)}"
    for ln in lines:
        proc = subprocess.run(
            ["bash", "-c", ln], capture_output=True, text=True, timeout=30,
            env={"RECON_DIR": str(tmp_path / "recon-does-not-exist"),
                 "PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 0, f"{ln.strip()}: rc={proc.returncode}"
        assert proc.stderr == "", f"stderr leaked for: {ln.strip()}"
        assert proc.stdout.strip().endswith("0"), \
            f"missing file must count as 0: {proc.stdout!r}"


def test_live_urls_count_sites_use_leak_proof_redirect_order():
    """Every live/urls.txt wc -l counting site in recon_engine.sh must apply
    2>/dev/null BEFORE the input redirect (the v2.0.4 defect ordering)."""
    engine = REPO / "rhodawk" / "tools" / "recon_engine.sh"
    sites = [
        ln for ln in engine.read_text().splitlines()
        if "live/urls.txt" in ln and "wc -l" in ln
    ]
    assert sites, "expected the live/urls.txt counting sites to exist"
    for ln in sites:
        assert "wc -l 2>/dev/null <" in ln, \
            f"leaky redirect order on live/urls.txt count: {ln.strip()}"
