"""Regression tests for Claude Code plugin manifest.

Also guards release-audit findings R-02 (console entry points must exist in
pyproject and resolve to real callables) and R-10 (one version across all
release manifests).
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / ".claude-plugin" / "plugin.json"


def test_plugin_manifest_exists():
    assert MANIFEST.is_file(), "missing .claude-plugin/plugin.json"


def test_plugin_manifest_has_required_fields():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(data.get("name"), str) and data["name"]
    assert isinstance(data.get("description"), str) and data["description"]


def test_plugin_manifest_component_paths_exist():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for key in ("commands", "agents", "skills"):
        rel = data.get(key)
        assert rel, f"{key} path must be declared"
        path = REPO_ROOT / rel.removeprefix("./")
        assert path.exists(), f"{key} path does not exist: {path}"

    hooks = data.get("hooks")
    assert hooks, "hooks path must be declared"
    hooks_path = REPO_ROOT / hooks.removeprefix("./")
    assert hooks_path.is_file(), f"hooks path does not exist: {hooks_path}"


# ── Release audit R-02: console entry points ────────────────────────────────

def test_console_entry_points_declared_in_pyproject():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'rhodawk = "rhodawk.__main__:main"' in text, \
        "pyproject [project.scripts] must declare the rhodawk CLI"
    assert 'rhodawk-agent = "rhodawk.__main__:agent_main"' in text, \
        "pyproject [project.scripts] must declare the agent entry point"


def test_console_entry_points_resolve_to_real_callables():
    sys.path.insert(0, str(REPO_ROOT))
    for modpath in ("rhodawk.__main__:main", "rhodawk.__main__:agent_main"):
        mod_name, _, attr = modpath.partition(":")
        module = __import__(mod_name, fromlist=[attr])
        assert callable(getattr(module, attr, None)), \
            f"entry point target missing: {modpath}"


# ── Release audit R-10: one version across all release manifests ────────────

def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m, "pyproject.toml has no project version"
    return m.group(1)


def test_version_parity_across_manifests():
    expected = _pyproject_version()

    init = (REPO_ROOT / "rhodawk" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    assert m and m.group(1) == expected, \
        f"rhodawk/__init__.py __version__ must be {expected}"

    plugin = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert plugin.get("version") == expected, \
        f".claude-plugin/plugin.json version must be {expected}"

    npm = json.loads((REPO_ROOT / "npm" / "package.json").read_text(encoding="utf-8"))
    assert npm.get("version") == expected, \
        f"npm/package.json version must be {expected}"


def test_security_policy_tracks_current_major():
    text = (REPO_ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8")
    major = _pyproject_version().split(".", 1)[0]
    assert f"| {major}.x (latest) | Yes |" in text, \
        "SECURITY.md supported-versions table must track the released major"
    assert "v5.x" not in text, "SECURITY.md still references the retired 5.x line"
