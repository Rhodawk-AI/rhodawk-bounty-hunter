"""Layer 1C packaging polish regression tests (Suite B follow-up).

Independent blank-container testing of Suite B install paths (pip, pipx,
uv tool, npm/npx) surfaced two defects this file pins:

1. Stale upstream provider key ``FLUXION_API_KEY`` still listed in
   rhodawk/tools/credentials.py — zero FLUXION references may remain in the
   shipped package tree.
2. ``npx -y @rhodawkai/bounty-hunter`` on a blank machine left npx's temp
   ``node_modules/.bin`` directory on the child ``PATH``, so ``pipx run``
   printed a confusing
   ``⚠️  rhodawk is already on your PATH ... Downloading and running anyway.``
   on EVERY invocation (the PATH entry pointed at the JS wrapper itself, not
   a Python rhodawk). The wrapper must strip its own directories from the
   child PATH, prefer ``uvx`` over ``pipx run`` on blank boxes, and print a
   clear install hint (uv tool install / pipx install) when no runner
   exists.

Node-dependent tests skip cleanly only when the ``node`` binary is absent.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CREDENTIALS = REPO / "rhodawk" / "tools" / "credentials.py"
WRAPPER = REPO / "npm" / "bin" / "rhodawk.js"
NODE = shutil.which("node")

STUB_SCRIPT = """#!/bin/bash
{ echo "PATH=$PATH"; echo "ARGS_COUNT=$#"; printf 'ARG:%s\\n' "$@"; } > "$STUB_OUT"
exit ${STUB_EXIT:-7}
"""


def _require_node() -> str:
    if NODE is None:
        pytest.skip("node binary not available")
    return NODE


# ── Issue #1: zero FLUXION leak gate ─────────────────────────────────────────

def test_no_fluxion_leak_in_credentials_py():
    assert CREDENTIALS.is_file()
    text = CREDENTIALS.read_text(encoding="utf-8")
    assert "FLUXION" not in text.upper(), \
        "stale upstream provider key FLUXION_API_KEY must be removed"


def test_no_fluxion_leak_in_rhodawk_package_tree():
    hits = []
    for path in (REPO / "rhodawk").rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {
            ".py", ".md", ".json", ".js", ".sh", ".toml", ".cfg", ".txt"
        }:
            continue
        if "fluxion" in path.read_text(encoding="utf-8", errors="ignore").lower():
            hits.append(str(path))
    assert hits == [], f"stale FLUXION references remain: {hits}"


# ── Version parity gate (all four manifests stay 2.0.5) ──────────────────────

def test_version_parity_across_manifests():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert m, "pyproject.toml [project] version not found"
    versions = {
        "pyproject.toml": m.group(1),
        "rhodawk/__init__.py": re.search(
            r'__version__\s*=\s*"([^"]+)"',
            (REPO / "rhodawk" / "__init__.py").read_text(encoding="utf-8"),
        ).group(1),
        "npm/package.json": json.loads(
            (REPO / "npm" / "package.json").read_text(encoding="utf-8")
        )["version"],
        ".claude-plugin/plugin.json": json.loads(
            (REPO / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
        )["version"],
    }
    assert set(versions.values()) == {"2.0.5"}, \
        f"version drift across manifests: {versions}"


# ── Issue #2: npm/bin/rhodawk.js behavioral tests ────────────────────────────

@pytest.fixture()
def npx_sandbox(tmp_path):
    """A faithful blank-box npx simulation: the wrapper reachable through a
    node_modules/.bin symlink whose directory sits FIRST on PATH, stub
    uvx/pipx runners that log their argv + received PATH, and a scratch dir
    for runner-less scenarios."""
    if NODE is None:
        pytest.skip("node binary not available")
    node_dir = Path(NODE).resolve().parent
    wrapper_dir = tmp_path / "npx-root" / "node_modules" / ".bin"
    wrapper_dir.mkdir(parents=True)
    # npm/npx place a SYMLINK in node_modules/.bin (copying would defeat the
    # realpath self-detection the wrapper relies on and make this fixture
    # unfaithful to the real layout).
    (wrapper_dir / "rhodawk").symlink_to(WRAPPER)
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name in ("uvx", "pipx"):
        stub = stubs / name
        stub.write_text(STUB_SCRIPT, encoding="utf-8")
        stub.chmod(0o755)
    scratch = tmp_path / "empty"
    scratch.mkdir()
    return {
        "tmp": tmp_path,
        "wrapper_dir": wrapper_dir,
        "wrapper_bin": wrapper_dir / "rhodawk",
        "stubs": stubs,
        "node_dir": node_dir,
        "scratch": scratch,
    }


def _run_wrapper(sb, argv, *, direct=True, extra_path_dirs=()):
    stub_out = sb["tmp"] / "stub.log"
    stub_out.unlink(missing_ok=True)
    if direct:
        cmd = [str(sb["wrapper_bin"]), *argv]
    else:
        cmd = [NODE, str(WRAPPER), *argv]
    path_dirs = [str(sb["wrapper_dir"]), str(sb["stubs"])] + \
        [str(d) for d in extra_path_dirs]
    if direct:
        # direct exec hits the wrapper's `#!/usr/bin/env node` shebang, so
        # node's directory must be on the child PATH (after the stubs, so a
        # real host uvx/pipx can never shadow the stubs).
        path_dirs.append(str(sb["node_dir"]))
    env = {
        "PATH": os.pathsep.join(path_dirs),
        "STUB_OUT": str(stub_out),
        "HOME": str(sb["tmp"]),
    }
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True,
                          timeout=60)
    return proc, stub_out


def _read_stub_log(stub_out: Path) -> dict:
    assert stub_out.is_file(), "stub runner was never invoked"
    lines = stub_out.read_text(encoding="utf-8").splitlines()
    path_line = next(ln for ln in lines if ln.startswith("PATH="))
    count_line = next(ln for ln in lines if ln.startswith("ARGS_COUNT="))
    args = [ln[4:] for ln in lines if ln.startswith("ARG:")]
    return {"path": path_line[5:], "count": int(count_line.split("=")[1]),
            "args": args}


def test_npm_wrapper_syntax_check():
    node = _require_node()
    proc = subprocess.run([node, "--check", str(WRAPPER)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_wrapper_sanitizes_path_and_invokes_uvx_first(npx_sandbox):
    sb = npx_sandbox
    proc, stub_out = _run_wrapper(sb, ["doctor", "--json"])
    assert proc.returncode == 7, \
        f"stub exit status must be forwarded verbatim: {proc.stderr[-300:]}"
    log = _read_stub_log(stub_out)
    # uvx preference on a blank box (no Python rhodawk on PATH)
    assert log["args"] == ["--from", "rhodawk-bounty-hunter", "rhodawk",
                           "doctor", "--json"], log["args"]
    assert log["count"] == 5
    # THE regression: the wrapper's own node_modules/.bin must NOT reach the
    # child PATH (pipx/uvx would see the wrapper as an installed rhodawk and
    # print the "already on your PATH" warning).
    assert str(sb["wrapper_dir"]) not in log["path"], \
        f"wrapper dir leaked into child PATH: {log['path']}"
    assert str(sb["stubs"]) in log["path"], "stub dir must stay on child PATH"


def test_wrapper_falls_back_to_pipx_when_uvx_absent(npx_sandbox):
    sb = npx_sandbox
    (sb["stubs"] / "uvx").unlink()
    proc, stub_out = _run_wrapper(sb, ["status"])
    assert proc.returncode == 7, proc.stderr
    log = _read_stub_log(stub_out)
    assert log["args"] == ["run", "--spec", "rhodawk-bounty-hunter", "rhodawk",
                           "status"], log["args"]
    assert str(sb["wrapper_dir"]) not in log["path"], \
        f"wrapper dir leaked into child PATH: {log['path']}"


def test_wrapper_chains_to_real_rhodawk_without_runners(npx_sandbox):
    sb = npx_sandbox
    (sb["stubs"] / "uvx").unlink()
    (sb["stubs"] / "pipx").unlink()
    real = sb["stubs"] / "rhodawk"
    real.write_text(STUB_SCRIPT.replace("exit ${STUB_EXIT:-7}", "exit 3"),
                    encoding="utf-8")
    real.chmod(0o755)
    proc, stub_out = _run_wrapper(sb, ["hunt", "target.example"])
    assert proc.returncode == 3, \
        f"chained binary exit status must be forwarded: {proc.stderr[-300:]}"
    log = _read_stub_log(stub_out)
    # args forwarded verbatim, no uvx/pipx wrapping (no recursion loop)
    assert log["args"] == ["hunt", "target.example"], log["args"]
    assert str(sb["wrapper_dir"]) not in log["path"], \
        f"wrapper dir leaked into child PATH: {log['path']}"


def test_wrapper_clear_hint_and_exit_1_when_nothing_installed(npx_sandbox):
    sb = npx_sandbox
    (sb["stubs"] / "uvx").unlink()
    (sb["stubs"] / "pipx").unlink()
    proc, stub_out = _run_wrapper(
        sb, ["doctor"], direct=False,
        # invoked via `node` with a PATH holding NOTHING but the wrapper dir
        # and an empty scratch dir (real host runners must not interfere)
        extra_path_dirs=(sb["scratch"],))
    assert proc.returncode == 1
    combined = proc.stdout + proc.stderr
    assert "uv tool install rhodawk-bounty-hunter" in combined
    assert "pipx install rhodawk-bounty-hunter" in combined
    assert not stub_out.exists(), "no runner stub may be invoked"


def test_wrapper_via_node_invocation_also_sanitizes_path(npx_sandbox):
    """Direct `node npm/bin/rhodawk.js` (no npx symlink) with a wrapper-copy
    dir on PATH: the realpath-match rule must strip that dir too."""
    sb = npx_sandbox
    proc, stub_out = _run_wrapper(sb, ["doctor"], direct=False)
    assert proc.returncode == 7, proc.stderr
    log = _read_stub_log(stub_out)
    assert log["args"][0] == "--from"  # uvx preferred, blank-box fallback
    assert str(sb["wrapper_dir"]) not in log["path"], \
        f"wrapper copy dir leaked into child PATH: {log['path']}"
