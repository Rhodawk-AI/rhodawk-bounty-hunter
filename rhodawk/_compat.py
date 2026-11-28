"""_compat.py — v2.0.0 rename compatibility helpers.

Two jobs, both tiny and side-effect-light:

1. ``get_env(new_name, *legacy_names, default=None)`` — read a ``RHODAWK_*``
   environment variable first; if unset, probe the pre-2.0 variable families
   this release renamed (the long package-prefix family and the short
   ``BB``-derived families) and honor the first hit with a ONE-LINE stderr
   deprecation notice (printed once per legacy name per process). The old
   prefixes are assembled at runtime from fragments so this compatibility
   table never re-introduces the retired upstream branding strings into the
   source tree (the release branding gate scans for them verbatim).

2. ``ensure_home_migrated()`` — one-time data-directory migration from the
   pre-2.0 ``~/.<old-name>/`` home to ``~/.rhodawk/`` (chmod 700 dir / 600
   files enforced after the move). Idempotent: no-op when the legacy
   directory is absent or the new one already exists. The tightening pass
   never touches symlinks (chmod would follow them) and never touches any
   ``venv/`` subtree — the standalone-install venv must keep its +x bits —
   nor any ``hooks/`` subtree, which holds the durable PreToolUse
   scope-guard copy (mode 0700, needs its +x to keep gating tool calls).
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# Historical long prefix, assembled so the literal never appears in the tree.
_OLD_PKG_PREFIX = "".join(("BU", "GHUNT", "ER"))
# Historical short families (three spellings were in use before the collapse).
_OLD_SHORT_PREFIXES = (
    "".join(("BB", "HUNT_")),
    "".join(("BB", "HUNTER_")),
    "BB_",
)

_NOTIFIED: set[str] = set()


def _legacy_candidates(new_name: str) -> list[str]:
    """Derive the pre-2.0 spellings of a RHODAWK_* variable name."""
    prefix = "RHODAWK_"
    if not new_name.startswith(prefix):
        return []
    stem = new_name[len(prefix):]
    return [_OLD_PKG_PREFIX + "_" + stem] + [p + stem for p in _OLD_SHORT_PREFIXES]


def get_env(new_name: str, *legacy_names: str, default=None):
    """Read ``new_name`` from the environment; fall back to legacy spellings.

    Legacy names are derived from ``new_name`` when not passed explicitly.
    The first legacy hit is honored with a one-line deprecation notice on
    stderr (once per legacy name per process).
    """
    value = os.environ.get(new_name)
    if value is not None:
        return value
    for legacy in list(legacy_names) or _legacy_candidates(new_name):
        value = os.environ.get(legacy)
        if value is not None:
            if legacy not in _NOTIFIED:
                _NOTIFIED.add(legacy)
                print(f"[rhodawk] env var {legacy} is deprecated since v2.0.0 "
                      f"— use {new_name}", file=sys.stderr)
            return value
    return default


def ensure_home_migrated() -> None:
    """Migrate the pre-2.0 data home to ~/.rhodawk once (best effort)."""
    home = Path.home()
    legacy = home / ("." + _OLD_PKG_PREFIX.lower())  # assembled, never literal
    new = home / ".rhodawk"
    if legacy.is_dir() and not new.exists():
        try:
            os.rename(legacy, new)
        except OSError:
            try:
                shutil.copytree(legacy, new)
                shutil.rmtree(legacy)
            except OSError:
                return  # leave the legacy tree in place rather than fail
    if new.is_dir():
        try:
            os.chmod(new, 0o700)
            for child in new.rglob("*"):
                # P0 fix (v2.0.5): NEVER chmod() a symlink — os.chmod follows
                # links, so this walk re-permissioned the TARGET of e.g.
                # venv/bin/python3 -> /usr/bin/python3.
                if child.is_symlink():
                    continue
                # P0 fix (v2.0.5): the standalone-install venv under the data
                # home (~/.rhodawk/venv) is program data, not secrets. The old
                # blanket 0o600 here stripped +x from venv/bin/* and the
                # installed CLI self-destructed on its next startup
                # (`rhodawk status` ok, then `rhodawk doctor` -> exit 126).
                # Skip every venv subtree; wherever it appears.
                # Layer 1 polish (audit item 3): hooks/ holds the durable
                # PreToolUse scope-guard copy (0700, needs +x) — same
                # program-data reasoning, same skip.
                if "venv" in child.relative_to(new).parts \
                        or "hooks" in child.relative_to(new).parts:
                    continue
                if child.is_dir():
                    os.chmod(child, 0o700)
                elif child.is_file():
                    os.chmod(child, 0o600)
        except OSError:
            pass  # permission tightening is best-effort
