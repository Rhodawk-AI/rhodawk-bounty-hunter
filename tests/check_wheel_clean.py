#!/usr/bin/env python3
"""Wheel + sdist cleanliness gate (release audit R-01).

A wheel or sdist built from a source tree that has been used for testing or
hunting must never contain runtime artifacts: recon/, findings/, reports/,
targets/, hunt-memory/ (and stray lock/lead files under rhodawk/memory/).
Those files used to leak into distributions because package-data used a
"**/*" wildcard.

Usage:
    python tests/check_wheel_clean.py dist/*

Both distributions are covered in ONE pass:
  - .whl / .zip  archives via zipfile.ZipFile;
  - .tar.gz / .tgz sdists via tarfile.open(..., "r:gz").
(Since 2.0.1 the usage line really means <wheel-or-sdist>: passing an sdist
no longer crashes with zipfile.BadZipFile.)

Exit code 0 = clean, 1 = polluted/invalid archive (prints offending names),
2 = usage error.
"""
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

RUNTIME_DIR_NAMES = {"recon", "findings", "reports", "targets", "hunt-memory"}

ZIP_SUFFIXES = (".whl", ".zip")
TAR_GZ_SUFFIXES = (".tar.gz", ".tgz")


def _zip_member_names(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as zf:
        return list(zf.namelist())


def _targz_member_names(path: Path) -> list[str]:
    with tarfile.open(path, "r:gz") as tf:
        return [member.name for member in tf.getmembers()]


def archive_member_names(path: Path) -> list[str]:
    """Dispatch on the file extension: wheels/zips via zipfile, sdists via
    tarfile. Raises for anything that is neither."""
    name = path.name.lower()
    if name.endswith(ZIP_SUFFIXES):
        return _zip_member_names(path)
    if name.endswith(TAR_GZ_SUFFIXES):
        return _targz_member_names(path)
    raise ValueError(f"unsupported archive type: {path.name} "
                     f"(expected .whl/.zip or .tar.gz/.tgz)")


def offending_names(path: Path) -> list[str]:
    bad: list[str] = []
    for name in archive_member_names(path):
        parts = PurePosixPath(name).parts
        if any(part in RUNTIME_DIR_NAMES for part in parts[:-1]):
            bad.append(name)
            continue
        # strays written directly by the memory module (no dir marker).
        # Wheels are flat ("rhodawk/memory/..."), sdists carry a versioned
        # top-level dir ("rhodawk-2.0.1/rhodawk/memory/...") — find the
        # package dir wherever it sits.
        if "rhodawk" in parts:
            idx = parts.index("rhodawk")
            if idx + 1 < len(parts) and parts[idx + 1] == "memory":
                tail = PurePosixPath(name).name
                if tail.endswith((".jsonl", ".jsonl.lock")):
                    bad.append(name)
    return bad


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_wheel_clean.py <wheel-or-sdist> [...]", file=sys.stderr)
        return 2
    failures = 0
    for path in argv:
        whl = Path(path)
        if not whl.is_file():
            print(f"MISSING: {whl}")
            failures += 1
            continue
        try:
            bad = offending_names(whl)
        except (zipfile.BadZipFile, tarfile.TarError, OSError, ValueError) as exc:
            failures += 1
            print(f"ERROR: {whl} could not be inspected: {exc}")
            continue
        if bad:
            failures += 1
            print(f"POLLUTED: {whl} contains {len(bad)} runtime artifact(s):")
            for name in bad[:25]:
                print(f"  {name}")
            if len(bad) > 25:
                print(f"  ... and {len(bad) - 25} more")
        else:
            print(f"CLEAN: {whl}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
