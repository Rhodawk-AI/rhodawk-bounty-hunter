"""Shared fixtures for hunt memory and scope checker tests."""

import json
import os
import sys
import pytest

# Add both repo root and tools/ so tests can import either `tools.foo` or `foo`.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKG_ROOT = os.path.join(REPO_ROOT, "rhodawk")
TOOLS_ROOT = os.path.join(PKG_ROOT, "tools")
for path in (PKG_ROOT, TOOLS_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from memory.schemas import CURRENT_SCHEMA_VERSION


@pytest.fixture(autouse=True)
def _isolated_rhodawk_config(tmp_path, monkeypatch):
    """Pin every runtime-output location into tmp_path.

    RHODAWK_CONFIG_FILE: saved-provider config (brain.py LLMClient) points at
    a nonexistent path so a developer's real ~/.rhodawk/config.json can never
    leak into unit tests. Tests that exercise config loading override it
    themselves.

    RHODAWK_HOME / RECON_OUT_DIR / XDG_DATA_HOME (release audit R-01): all
    writable runtime output (recon, findings, targets, reports, hunt-memory)
    must land in tmp_path, never in the source tree — artifacts written into
    the package directory used to leak into built wheels. Any test needing a
    different home still overrides these itself (fixture ordering: this
    autouse fixture runs first).

    RHODAWK_ROOT_SECRETS_FILE (v2.0.5 test isolation): points the legacy
    /root/.secrets/h1_api fallback (credentials.legacy_root_secrets_file())
    at a nonexistent tmp_path location. On a production VPS that file holds
    LIVE HackerOne credentials — pytest must never read or print them (they
    leaked into assertion diffs before this guard). The env var (not just a
    module setattr) is used so subprocess-based tests inherit the isolation
    too. Tests that specifically exercise the legacy path re-point this var
    at their own tmp_path fixture file."""
    monkeypatch.setenv("RHODAWK_CONFIG_FILE",
                       str(tmp_path / "no-config.json"))
    # Note: the pinned directories are NOT pre-created — every writer in the
    # codebase mkdir(parents=True) its own output path, and pre-creating would
    # collide with test-local fixtures that mkdir the same layout themselves.
    monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "rhodawk-home"))
    monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "rhodawk-home" / "recon"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("RHODAWK_ROOT_SECRETS_FILE",
                       str(tmp_path / "no-host-root-secrets" / "h1_api"))


@pytest.fixture
def tmp_hunt_dir(tmp_path):
    """Create a temporary hunt-memory directory structure."""
    hunt_dir = tmp_path / "hunt-memory"
    hunt_dir.mkdir()
    (hunt_dir / "targets").mkdir()
    return hunt_dir


@pytest.fixture
def journal_path(tmp_hunt_dir):
    """Path to a temporary journal.jsonl file."""
    return tmp_hunt_dir / "journal.jsonl"


@pytest.fixture
def patterns_path(tmp_hunt_dir):
    """Path to a temporary patterns.jsonl file."""
    return tmp_hunt_dir / "patterns.jsonl"


@pytest.fixture
def sample_journal_entry():
    """A valid journal entry dict."""
    return {
        "ts": "2026-03-24T21:00:00Z",
        "target": "target.com",
        "action": "hunt",
        "vuln_class": "idor",
        "endpoint": "/api/v2/users/{id}/orders",
        "result": "confirmed",
        "severity": "high",
        "payout": 1500,
        "technique": "numeric_id_swap_with_put_method",
        "notes": "v1 had auth, v2 missing ownership check on PUT",
        "tags": ["api_version_diff", "method_swap"],
        "schema_version": CURRENT_SCHEMA_VERSION,
    }


@pytest.fixture
def sample_pattern_entry():
    """A valid pattern entry dict."""
    return {
        "ts": "2026-03-24T21:00:00Z",
        "target": "target.com",
        "vuln_class": "idor",
        "technique": "numeric_id_swap_with_put_method",
        "tech_stack": ["express", "postgresql"],
        "endpoint": "/api/v2/users/{id}/orders",
        "payout": 1500,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }


@pytest.fixture
def sample_target_profile():
    """A valid target profile dict."""
    return {
        "target": "target.com",
        "first_hunted": "2026-03-01T10:00:00Z",
        "last_hunted": "2026-03-24T21:00:00Z",
        "tech_stack": ["next.js", "graphql", "postgresql", "aws"],
        "scope_snapshot": {
            "in_scope": ["*.target.com", "api.target.com"],
            "out_of_scope": ["blog.target.com"],
            "excluded_classes": ["dos"],
            "fetched_at": "2026-03-24T20:00:00Z",
        },
        "tested_endpoints": [],
        "untested_endpoints": ["/api/v2/users/{id}/export"],
        "findings": [],
        "hunt_sessions": 3,
        "total_time_minutes": 120,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }


@pytest.fixture
def scope_domains():
    """Standard scope allowlist for testing."""
    return ["*.target.com", "api.target.com", "target.com"]


@pytest.fixture
def scope_excluded():
    """Standard scope exclusion list for testing."""
    return ["blog.target.com", "status.target.com"]
