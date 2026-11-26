"""Regression tests for the v2.0.3 pre-launch audit fixes (G1, G2, G3, G18).

Pins the negatives that motivated each fix:

- G1: the MCP runtime read/wrote recon/findings/reports under the package
  install tree while every other runtime writes under $RHODAWK_HOME — so
  CLI-generated artifacts were invisible to MCP tools. Every runtime path in
  adapters.py must resolve through _data_home(), never REPO.
- G2: MCP memory reads defaulted to a CWD-relative "hunt-memory" directory
  the writers never populate. They must resolve like
  memory/hunt_journal.default_memory_root().
- G3: `validate --auto` defaulted its output dir next to tools/ (site-packages
  under pipx). It must default under $RHODAWK_HOME/findings.
- G18: RHODAWK_GOOGLE_CLIENT_ID/_SECRET were read with plain os.environ.get,
  silently dropping the pre-2.0 BUGHUNTER_GOOGLE_* spellings. They must go
  through _compat.get_env like every other RHODAWK_* variable.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "rhodawk" / "mcp" / "rhodawk-mcp"
for path in (str(MCP), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

import adapters  # noqa: E402
from tools import validate as validate_mod  # noqa: E402
import tools.google_oauth as google_oauth  # noqa: E402


# ── G1: MCP state root ────────────────────────────────────────────────────────


class TestMcpDataHomeRoots:
    """adapters.py must mirror engine._data_home(): $RHODAWK_HOME else
    ~/.rhodawk, never the package install tree."""

    def test_roots_follow_rhodawk_home(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        assert adapters._data_home() == home
        assert adapters._recon_root() == home / "recon"
        assert adapters._findings_root() == home / "findings"
        assert adapters._reports_root() == home / "reports"

    def test_default_home_is_never_the_install_tree(self, monkeypatch):
        monkeypatch.delenv("RHODAWK_HOME", raising=False)
        # _compat.get_env also consults the pre-2.0 spellings — clear those too.
        for legacy in ("BUGHUNTER_HOME", "BBHUNT_HOME", "BBHUNTER_HOME", "BB_HOME"):
            monkeypatch.delenv(legacy, raising=False)
        assert adapters._data_home() == Path.home() / ".rhodawk"
        assert adapters._recon_root() != adapters.REPO / "recon"

    def test_recon_reads_resolve_under_data_home(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        subs = adapters._recon_root() / "target.com" / "subdomains"
        subs.mkdir(parents=True)
        (subs / "all.txt").write_text("api.target.com\n", encoding="utf-8")

        out = adapters.read_recon_file("target.com", "subdomains/all.txt")
        assert out["status"] == "completed"
        assert out["items"] == ["api.target.com"]
        assert str(adapters.REPO) not in out["path"]

        surface = adapters.attack_surface("target.com")
        assert surface["counts"].get("subdomains/all.txt") == 1

    def test_run_recon_pins_recon_out_dir_into_data_home(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(adapters.subprocess, "run", fake_run)
        out = adapters.run_recon("target.com")
        assert out["status"] == "completed"
        assert captured["kwargs"]["env"]["RECON_OUT_DIR"] == \
            str(home / "recon" / "target.com")
        # the script itself still comes from the CODE root
        assert captured["cmd"][1] == str(adapters.REPO / "tools" / "recon_engine.sh")

    def test_findings_reports_routing(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        fdir = adapters._findings_root() / "target.com"
        fdir.mkdir(parents=True)
        (fdir / "note.md").write_text("x", encoding="utf-8")
        rdir = adapters._reports_root() / "target.com"
        rdir.mkdir(parents=True)
        (rdir / "hackerone-report.md").write_text("y", encoding="utf-8")

        listed = adapters.list_findings("target.com")
        assert listed["findings"] == ["findings/target.com/note.md"]
        # the returned data-home-relative path must resolve, and must NOT
        # resolve under the install tree (the old split-brain)
        assert (adapters._data_home() / listed["findings"][0]).is_file()
        assert not (adapters.REPO / listed["findings"][0]).exists()

        stub = adapters.generate_report_stub("target.com")
        # the bundler collects *-report.md and *report*.md — the file matches
        # both globs, so dedupe before comparing (pre-existing behavior)
        assert sorted(set(stub["reports"])) == \
            ["reports/target.com/hackerone-report.md"]

    def test_prioritized_surface_reads_data_home_truth(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        base = adapters._recon_root() / "target.com"
        base.mkdir(parents=True)
        (base / "recon_truth.json").write_text(json.dumps({
            "hosts": [{"host": "api.target.com", "status_code": 200, "tech": ["nginx"]}],
        }), encoding="utf-8")

        out = adapters.prioritized_surface("target.com")
        assert out["sources"]["recon_truth"] is True
        assert out["items"][0]["host"] == "api.target.com"

    def test_adapters_source_has_no_install_tree_data_paths(self):
        """Static pin: the tree-rooted data paths must never come back."""
        src = Path(adapters.__file__).read_text(encoding="utf-8")
        for bad in ('REPO / "recon"', 'REPO / "findings"', 'REPO / "reports"'):
            assert bad not in src, f"adapters.py re-rooted runtime data at {bad}"

    def test_server_get_finding_resolves_against_data_home(self):
        """rhodawk_get_finding must read under the data home (it used to
        resolve paths against _REPO)."""
        src = (MCP / "server.py").read_text(encoding="utf-8")
        start = src.index("def rhodawk_get_finding")
        end = src.index("def rhodawk_validate")
        body = src[start:end]
        assert "adapters._data_home" in body
        assert "(_REPO / path)" not in body


# ── G2: MCP memory root ───────────────────────────────────────────────────────


class TestMcpMemoryRoot:
    def test_memory_root_defaults_under_data_home(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        monkeypatch.delenv("RHODAWK_MEMORY_DIR", raising=False)
        assert adapters._memory_root() == home / "hunt-memory"

    def test_memory_root_explicit_override_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("RHODAWK_MEMORY_DIR", str(tmp_path / "mem"))
        assert adapters._memory_root() == tmp_path / "mem"

    def test_memory_search_reads_journal_from_data_home(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        monkeypatch.delenv("RHODAWK_MEMORY_DIR", raising=False)
        mem = home / "hunt-memory"
        mem.mkdir(parents=True)
        row = {"schema_version": 1, "target": "target.com", "event": "note",
               "detail": "alpha finding"}
        (mem / "journal.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")

        out = adapters.memory_search("alpha", target="target.com")
        assert out["hits"], "memory_search must find journal rows under $RHODAWK_HOME"


# ── G3: validate --auto default output dir ────────────────────────────────────


class TestAutoOutDirDataHome:
    def test_default_auto_out_dir_under_rhodawk_home(self, monkeypatch, tmp_path):
        home = tmp_path / "custom-home"
        monkeypatch.setenv("RHODAWK_HOME", str(home))
        d = Path(validate_mod._default_auto_out_dir())
        assert d.is_relative_to(home / "findings")
        assert d.name.startswith("auto-")

    def test_default_auto_out_dir_legacy_home_env(self, monkeypatch, tmp_path):
        home = tmp_path / "legacy-home"
        monkeypatch.delenv("RHODAWK_HOME", raising=False)
        monkeypatch.setenv("BUGHUNTER_HOME", str(home))
        assert Path(validate_mod._default_auto_out_dir()).is_relative_to(
            home / "findings")

    def test_default_auto_out_dir_never_site_packages(self, monkeypatch):
        monkeypatch.delenv("RHODAWK_HOME", raising=False)
        for legacy in ("BUGHUNTER_HOME", "BBHUNT_HOME", "BBHUNTER_HOME", "BB_HOME"):
            monkeypatch.delenv(legacy, raising=False)
        pkg_parent = Path(validate_mod.__file__).resolve().parents[1]
        assert not Path(validate_mod._default_auto_out_dir()).is_relative_to(pkg_parent)


# ── G18: legacy Google OAuth env compat ───────────────────────────────────────

_OAUTH_ENV_VARS = (
    "RHODAWK_GOOGLE_CLIENT_ID", "RHODAWK_GOOGLE_CLIENT_SECRET",
    "BUGHUNTER_GOOGLE_CLIENT_ID", "BUGHUNTER_GOOGLE_CLIENT_SECRET",
    "BBHUNT_GOOGLE_CLIENT_ID", "BBHUNT_GOOGLE_CLIENT_SECRET",
    "BBHUNTER_GOOGLE_CLIENT_ID", "BBHUNTER_GOOGLE_CLIENT_SECRET",
    "BB_GOOGLE_CLIENT_ID", "BB_GOOGLE_CLIENT_SECRET",
)


@pytest.fixture
def oauth_module(monkeypatch):
    for var in _OAUTH_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield google_oauth
    # leave a defaults-initialized module behind (constants are evaluated at
    # import time, so a stale reload could leak test values into other tests)
    importlib.reload(google_oauth)


class TestGoogleOauthLegacyEnv:
    def test_legacy_bughunter_spellings_are_honored(self, oauth_module, monkeypatch):
        monkeypatch.setenv("BUGHUNTER_GOOGLE_CLIENT_ID", "legacy-id.apps.example.com")
        monkeypatch.setenv("BUGHUNTER_GOOGLE_CLIENT_SECRET", "legacy-secret")
        mod = importlib.reload(oauth_module)
        assert mod.OAUTH_CLIENT_ID == "legacy-id.apps.example.com"
        assert mod.OAUTH_CLIENT_SECRET == "legacy-secret"

    def test_rhodawk_spelling_wins_over_legacy(self, oauth_module, monkeypatch):
        monkeypatch.setenv("RHODAWK_GOOGLE_CLIENT_ID", "new-id.apps.example.com")
        monkeypatch.setenv("BUGHUNTER_GOOGLE_CLIENT_ID", "legacy-id.apps.example.com")
        mod = importlib.reload(oauth_module)
        assert mod.OAUTH_CLIENT_ID == "new-id.apps.example.com"

    def test_builtin_defaults_when_no_env(self, oauth_module):
        mod = importlib.reload(oauth_module)
        assert mod.OAUTH_CLIENT_ID == mod._DEFAULT_CID
        assert mod.OAUTH_CLIENT_SECRET == mod._DEFAULT_CSEC
