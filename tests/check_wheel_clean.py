#!/usr/bin/env python3
"""Wheel cleanliness gate (release audit R-01).

A wheel built from a source tree that has been used for testing or hunting
must never contain runtime artifacts: recon/, findings/, reports/, targets/,
hunt-memory/ (and stray lock/lead files under rhodawk/memory/). Those files
used to leak into distributions because package-data used a "**/*" wildcard.

Usage:
    python tests/check_wheel_clean.py dist/*.whl

Exit code 0 = clean, 1 = polluted (prints offending names).
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path, PurePosixPath

RUNTIME_DIR_NAMES = {"recon", "findings", "reports", "targets", "hunt-memory"}


def offending_names(whl_path: Path) -> list[str]:
    bad: list[str] = []
    with zipfile.ZipFile(whl_path) as zf:
        for name in zf.namelist():
            parts = PurePosixPath(name).parts
            if any(part in RUNTIME_DIR_NAMES for part in parts[:-1]):
                bad.append(name)
                continue
            # strays written directly by the memory module (no dir marker)
            if len(parts) >= 2 and parts[0] == "rhodawk" and parts[1] == "memory":
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
        bad = offending_names(whl)
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
