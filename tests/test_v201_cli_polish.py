"""v2.0.1 CLI polish — regression tests for the global-install fixes.

Covers the four user-facing breakages fixed in 2.0.1 (all network calls
mocked, zero secret leakage):

1. `rhodawk --help` / `rhodawk-agent --help` must present the installed
   command names: no `usage: engine.py`, no `./engine.py`, no
   `python3 agent.py` (pipx / npx users have no such files on their PATH).
2. `rhodawk doctor` fix hints must be runnable from ANY working directory:
   module invocations (`python3 -m rhodawk.tools.credentials ...`),
   installed command names (`rhodawk setup`, `rhodawk mcp doctor`), and
   repo-only scripts explicitly labeled as repo-checkout commands.
3. `scope-compile` loads HackerOne credentials from the data-home
   `$RHODAWK_HOME/.env` even when no H1 variable is exported in the shell,
   accepts the combined `H1_TOKEN=user:token` form, and reports WHY an
   authenticated REST attempt fell back to `keyless_public` — HTTP status
   code only, never the token.
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parents[1]

PKG_DIR = str(REPO / "rhodawk")
if PKG_DIR not in sys.path:
    sys.path.insert(0, PKG_DIR)

SECRET_TOKEN = "h1-api-token-DO-NOT-PRINT-v201"


def _import(name: str):
    return importlib.import_module(name)


# ── 1. --help program names & epilog examples ─────────────────────────────────

class TestHelpProgramNames:
    @pytest.fixture
    def isolated_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        return tmp_path

    def test_rhodawk_help_uses_installed_name(self, isolated_home, monkeypatch,
                                              capsys):
        engine = _import("engine")
        monkeypatch.setattr(sys, "argv", ["rhodawk", "--help"])
        with pytest.raises(SystemExit) as exc:
            engine.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "usage: rhodawk " in out
        assert "rhodawk setup" in out
        assert "rhodawk recon target.com" in out
        for banned in ("usage: engine.py", "./engine.py", "python3 agent.py"):
            assert banned not in out, banned

    def test_rhodawk_agent_help_uses_installed_name(self, isolated_home,
                                                    monkeypatch, capsys):
        agent = _import("agent")
        monkeypatch.setattr(sys, "argv", ["rhodawk-agent", "--help"])
        with pytest.raises(SystemExit):
            agent.main()
        out = capsys.readouterr().out
        assert "usage: rhodawk-agent" in out
        assert "rhodawk-agent --target example.com" in out
        assert "python3 agent.py" not in out


# ── 2. doctor fix hints are location-independent ──────────────────────────────

class TestDoctorPathHints:
    def test_doctor_fix_hints_are_location_independent(self, tmp_path,
                                                       monkeypatch, capsys):
        engine = _import("engine")
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
        monkeypatch.delenv("RTW_HOME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)
        monkeypatch.delenv("PDCP_API_KEY", raising=False)
        monkeypatch.delenv("CHAOS_API_KEY", raising=False)
        # No saved provider config -> the "LLM provider not configured" row
        # (and its fix hint) is emitted deterministically.
        monkeypatch.setattr(engine, "load_config", lambda: {})
        # Force the "core binaries missing" row so its fix hint is printed.
        import shutil  # noqa: PLC0415
        monkeypatch.setattr(shutil, "which", lambda name: None)

        with pytest.raises(SystemExit):
            engine.cmd_doctor(argparse.Namespace())
        out = capsys.readouterr().out

        # relative repo paths are gone from every fix hint
        assert "python3 rhodawk/tools/credentials.py" not in out
        assert "python3 rhodawk/engine.py" not in out
        assert "python3 rhodawk/mcp/" not in out
        # module-invocable / installed-command replacements are suggested
        assert "python3 -m rhodawk.tools.credentials --setup" in out
        assert "rhodawk setup" in out
        # repo-only scripts are clearly labeled
        for line in out.splitlines():
            if "install_tools.sh" in line or ("bash install.sh" in line):
                assert "repo checkout" in line, line


# ── 3. scope-compile credential auto-load + fallback reason ───────────────────

class TestScopeCompileCredentialAutoLoad:
    @pytest.fixture
    def clean_h1_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))  # no ~/.rhodawk vault here
        for var in ("H1_USERNAME", "H1_API_TOKEN", "H1_TOKEN",
                    "RHODAWK_CREDENTIALS_FILE"):
            monkeypatch.delenv(var, raising=False)
        return tmp_path

    @staticmethod
    def _write_data_home_env(home: Path, content: str) -> Path:
        data_home = home / "data-home"
        data_home.mkdir(parents=True, exist_ok=True)
        (data_home / ".env").write_text(content)
        return data_home

    def test_rest_mode_from_rhodawk_home_env_without_exported_vars(
            self, clean_h1_env, monkeypatch):
        scope_compiler = _import("tools.scope_compiler")
        data_home = self._write_data_home_env(
            clean_h1_env, 'H1_TOKEN="scopeuser:scope-token-123"\n')
        monkeypatch.setenv("RHODAWK_HOME", str(data_home))

        calls: list = []

        def fake_rest(url, auth=None):
            calls.append((url, auth))
            if "structured_scopes" not in url:
                return {"data": {"attributes": {"handle": "acme",
                                                "name": "Acme", "policy": ""}}}
            return {"data": [{"attributes": {
                        "asset_identifier": "acme.com", "asset_type": "URL",
                        "eligible_for_submission": True,
                        "eligible_for_bounty": True,
                        "instruction": "", "max_severity": ""}}],
                    "links": {"next": None}}

        fetched = scope_compiler.fetch_program_scope(
            "acme", rest_fn=fake_rest,
            graphql_fn=lambda q, v: (_ for _ in ()).throw(
                AssertionError("GraphQL must not run in authenticated mode")))

        assert fetched["auth_mode"] == "authenticated_rest"
        assert fetched["assets"][0].asset_identifier == "acme.com"
        url, auth = calls[0]
        assert auth and auth.startswith("Basic ")
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("ascii")
        # combined H1_TOKEN=user:token was split into the Basic-auth pair
        assert decoded == "scopeuser:scope-token-123"

    def test_rest_401_falls_back_with_redacted_reason(self, clean_h1_env,
                                                      monkeypatch):
        scope_compiler = _import("tools.scope_compiler")
        data_home = self._write_data_home_env(
            clean_h1_env,
            'H1_USERNAME="researcher"\n'
            f'H1_API_TOKEN="{SECRET_TOKEN}"\n')
        monkeypatch.setenv("RHODAWK_HOME", str(data_home))

        def denied(url, auth=None):
            raise scope_compiler.RestAuthError(
                "H1 REST API rejected credentials (HTTP 401)")

        fetched = scope_compiler.fetch_program_scope(
            "acme", rest_fn=denied,
            graphql_fn=lambda q, v: {"data": {"team": {
                "name": "Acme", "handle": "acme", "policy": "",
                "structured_scopes": {"nodes": [
                    {"asset_identifier": "acme.com",
                     "eligible_for_submission": True}]}}}})

        assert fetched["auth_mode"] == "keyless_public"
        assert fetched["assets"][0].asset_identifier == "acme.com"
        assert "HTTP 401" in fetched["auth_fallback_reason"]
        assert any("falling back" in n for n in fetched["notes"])
        # zero secret leakage through reason + notes
        assert SECRET_TOKEN not in fetched["auth_fallback_reason"]
        assert all(SECRET_TOKEN not in n for n in fetched["notes"])
        assert all("Authorization" not in n for n in fetched["notes"])

    def test_cli_warns_when_authenticated_rest_falls_back(
            self, clean_h1_env, monkeypatch, tmp_path, capsys):
        scope_compiler = _import("tools.scope_compiler")
        engine = _import("engine")
        data_home = self._write_data_home_env(
            clean_h1_env,
            'H1_USERNAME="researcher"\n'
            f'H1_API_TOKEN="{SECRET_TOKEN}"\n')
        monkeypatch.setenv("RHODAWK_HOME", str(data_home))
        monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "recon"))
        monkeypatch.setattr(sys, "argv",
                            ["engine.py", "scope-compile", "acme",
                             "--output", str(tmp_path / "out" / "m.json")])

        def denied(url, auth=None):
            if "structured_scopes" in url:
                raise scope_compiler.RestAuthError(
                    "H1 REST API rejected credentials (HTTP 401)")
            return {"data": {"attributes": {"handle": "acme", "name": "Acme",
                                            "policy": ""}}}

        def fake_gql(query, variables=None):
            return {"data": {"team": {
                "name": "Acme", "handle": "acme", "policy": "",
                "structured_scopes": {"nodes": [
                    {"asset_identifier": "acme.com",
                     "eligible_for_submission": True}]}}}}

        with patch("tools.scope_compiler._rest_request", side_effect=denied), \
             patch("tools.scope_compiler._graphql_request", side_effect=fake_gql):
            engine.main()

        out = capsys.readouterr().out
        # the fallback is announced, with the HTTP status and no token
        assert "H1 authenticated REST unusable" in out
        assert "HTTP 401" in out
        assert "keyless_public" in out
        assert SECRET_TOKEN not in out
        assert (tmp_path / "out" / "m.json").exists()
        assert SECRET_TOKEN not in (tmp_path / "out" / "m.json").read_text()
