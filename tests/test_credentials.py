"""Tests for rhodawk/tools/credentials.py — Commit 1 vault.

Covers the Commit-1 acceptance list:
- tool-to-credential table display,
- interactive wizard (mocked input/getpass) saving configured keys AND writing
  skipped keys as KEY="" in a 0o600 ~/.rhodawk/.env (dir 0o700),
- auto-loader ignoring blank KEY="" entries while exporting configured ones,
- tier-1 os.environ priority, H1_TOKEN=user:token parsing, loading an existing
  /root/.secrets/h1_api (env-style and bare user:token), and auto-tightening
  loose file permissions to 0o600,
- keyless fallback mode when every prompt is skipped,
- mocked HTTP 200 / HTTP 401 HackerOne verification with zero secret leakage.

Zero secret leakage is asserted directly: token values must never appear in
stdout/stderr of the wizard or the redacted --verify JSON.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

from tools import credentials

REPO = Path(__file__).resolve().parents[1]

SECRET_TOKEN = "h1-token-xyz-DO-NOT-PRINT"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def vault_home(tmp_path, monkeypatch):
    """Isolated HOME + clean managed env + isolated /root/.secrets path."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in credentials.ALL_MANAGED_VARS + ["H1_TOKEN",
                                               "RHODAWK_CREDENTIALS_FILE"]:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(credentials, "ROOT_SECRETS_FILE",
                        tmp_path / "root-secrets" / "h1_api")
    return tmp_path


def _write_vault(home: Path, content: str) -> Path:
    vault = home / ".rhodawk"
    vault.mkdir(parents=True, exist_ok=True)
    env_file = vault / ".env"
    env_file.write_text(content)
    return env_file


def _answers(answers: dict[str, str], fallback: str = ""):
    """Build input()/getpass() mocks that match on prompt substring."""
    def fake(prompt: str = "") -> str:
        for needle, value in answers.items():
            if needle in prompt:
                return value
        return fallback
    return fake


# ── Tool-to-credential table ──────────────────────────────────────────────────

class TestToolCredentialTable:
    def test_table_lists_every_group_and_variable(self, capsys):
        credentials.print_tool_credential_table()
        out = capsys.readouterr().out
        for group in credentials.CREDENTIAL_GROUPS:
            assert group["name"] in out
            assert group["tools"] in out
            for field in group["fields"]:
                assert field["var"] in out
        for tool in credentials.KEYLESS_TOOLS:
            assert tool["name"] in out

    def test_table_notes_keyless_tools_and_masked_input(self, capsys):
        credentials.print_tool_credential_table()
        out = capsys.readouterr().out.lower()
        assert "zero keys" in out
        assert "h1scope" in out
        assert "bounty-targets-data" in out
        assert "masked" in out or "getpass" in out

    def test_table_explains_blank_behaviour(self, capsys):
        credentials.print_tool_credential_table()
        out = capsys.readouterr().out
        assert "if blank" in out
        assert 'KEY=""' in out


# ── Interactive wizard ────────────────────────────────────────────────────────

class TestWizard:
    def test_wizard_saves_configured_and_blank_keys(
            self, vault_home, monkeypatch, capsys):
        """Configured keys saved; every skipped key written as KEY=""; vault
        0o600 inside a 0o700 ~/.rhodawk; H1 verdict printed; no leakage."""
        monkeypatch.setattr("builtins.input", _answers({"H1_USERNAME": "tester"}))
        monkeypatch.setattr(credentials.getpass, "getpass",
                            _answers({"H1_API_TOKEN": SECRET_TOKEN,
                                      "GROQ_API_KEY": "gsk_wizard_key"}))
        monkeypatch.setattr(credentials, "_http_request", lambda *a, **k: 200)

        values = credentials.run_interactive_onboarding()

        vault = vault_home / ".rhodawk" / ".env"
        assert vault.is_file()
        assert stat_mode(vault) == 0o600
        assert stat_mode(vault.parent) == 0o700

        stored = credentials.parse_env_text(vault.read_text())
        assert set(stored) == set(credentials.ALL_MANAGED_VARS)
        assert stored["H1_USERNAME"] == "tester"
        assert stored["H1_API_TOKEN"] == SECRET_TOKEN
        assert stored["GROQ_API_KEY"] == "gsk_wizard_key"
        for skipped in ("BUGCROWD_TOKEN", "BUGCROWD_EMAIL", "BUGCROWD_PASSWORD",
                        "BUGCROWD_OTP_SECRET", "INTIGRITI_TOKEN", "YWH_TOKEN",
                        "YWH_EMAIL", "YWH_PASSWORD", "YWH_OTP_SECRET",
                        "PDCP_API_KEY", "CHAOS_API_KEY", "OPENROUTER_API_KEY",
                        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                        "DEEPSEEK_API_KEY"):
            assert stored[skipped] == "", f"{skipped} must be stored blank"
        assert values["H1_API_TOKEN"] == SECRET_TOKEN

        captured = capsys.readouterr()
        assert "H1_AUTH: HTTP 200 (VALID)" in captured.out
        assert SECRET_TOKEN not in captured.out
        assert SECRET_TOKEN not in captured.err

    def test_wizard_h1_invalid_401(self, vault_home, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", _answers({"H1_USERNAME": "tester"}))
        monkeypatch.setattr(credentials.getpass, "getpass",
                            _answers({"H1_API_TOKEN": SECRET_TOKEN}))

        def deny(url, headers, timeout):
            raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)

        monkeypatch.setattr(credentials, "_http_request", deny)
        credentials.run_interactive_onboarding()
        out = capsys.readouterr().out
        assert "H1_AUTH: HTTP 401 (INVALID)" in out
        assert SECRET_TOKEN not in out

    def test_wizard_all_skipped_writes_blank_vault(self, vault_home, monkeypatch,
                                                   capsys):
        """Keyless fallback: Enter everywhere -> all-blank vault, no H1 call,
        summary shows SKIPPED (blank) + KEYLESS."""
        prompts: list[str] = []

        def record(prompt=""):
            prompts.append(prompt)
            return ""

        monkeypatch.setattr("builtins.input", record)
        monkeypatch.setattr(credentials.getpass, "getpass", record)
        monkeypatch.setattr(credentials, "_http_request",
                            lambda *a, **k: pytest.fail("H1 must not be called"))

        values = credentials.run_interactive_onboarding()

        assert all(v == "" for v in values.values())
        stored = credentials.parse_env_text(
            (vault_home / ".rhodawk" / ".env").read_text())
        assert all(v == "" for v in stored.values())
        out = capsys.readouterr().out
        assert out.count(credentials.STATUS_SKIPPED) == len(
            credentials.CREDENTIAL_GROUPS)
        assert out.count(credentials.STATUS_KEYLESS) == len(
            credentials.KEYLESS_TOOLS)
        assert "H1_AUTH" not in out
        assert prompts  # prompts did run

    def test_wizard_enter_keeps_existing_environment_value(
            self, vault_home, monkeypatch):
        monkeypatch.setenv("H1_USERNAME", "existing-user")
        monkeypatch.setattr("builtins.input", _answers({}))
        monkeypatch.setattr(credentials.getpass, "getpass", lambda prompt="": "")

        credentials.run_interactive_onboarding()

        stored = credentials.parse_env_text(
            (vault_home / ".rhodawk" / ".env").read_text())
        assert stored["H1_USERNAME"] == "existing-user"

    def test_wizard_eof_treated_as_skip(self, vault_home, monkeypatch):
        """Piped/closed stdin (EOFError) never crashes the wizard."""
        def eof(prompt=""):
            raise EOFError
        monkeypatch.setattr("builtins.input", eof)
        monkeypatch.setattr(credentials.getpass, "getpass", eof)

        values = credentials.run_interactive_onboarding()
        assert all(v == "" for v in values.values())


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


# ── 4-tier auto-loader ────────────────────────────────────────────────────────

class TestLoader:
    def test_exports_configured_ignores_blank(
            self, vault_home, monkeypatch):
        _write_vault(vault_home,
                     'H1_USERNAME="u1"\nH1_API_TOKEN="t1"\nBUGCROWD_TOKEN=""\n')
        result = credentials.load_credentials(interactive=False)

        assert os.environ["H1_USERNAME"] == "u1"
        assert os.environ["H1_API_TOKEN"] == "t1"
        assert not os.environ.get("BUGCROWD_TOKEN")
        assert result["auth_mode"] == "authenticated_rest"
        assert result["status"]["HackerOne"] == credentials.STATUS_READY
        assert result["status"]["Bugcrowd"] == credentials.STATUS_SKIPPED
        assert "BUGCROWD_TOKEN" in result["blank"]
        assert "H1_API_TOKEN" in result["configured"]

    def test_blank_key_never_reaches_environ(self, vault_home, monkeypatch):
        """KEY="" entries must stay unset even when the env var exists empty."""
        monkeypatch.setenv("INTIGRITI_TOKEN", "")
        _write_vault(vault_home, 'INTIGRITI_TOKEN=""\n')
        credentials.load_credentials()
        assert not os.environ.get("INTIGRITI_TOKEN")

    def test_tier1_environment_wins_over_file(self, vault_home, monkeypatch):
        monkeypatch.setenv("H1_API_TOKEN", "env-token")
        _write_vault(vault_home, 'H1_API_TOKEN="file-token"\n')
        credentials.load_credentials()
        assert os.environ["H1_API_TOKEN"] == "env-token"

    def test_rhodawk_credentials_file_override_first(
            self, vault_home, monkeypatch):
        override = vault_home / "override.env"
        override.write_text('H1_USERNAME="override-user"\n')
        _write_vault(vault_home, 'H1_USERNAME="vault-user"\n')
        monkeypatch.setenv("RHODAWK_CREDENTIALS_FILE", str(override))

        result = credentials.load_credentials()
        assert os.environ["H1_USERNAME"] == "override-user"
        assert str(override) in result["sources"][0]

    def test_h1_token_combined_form_parsed(self, vault_home, monkeypatch):
        monkeypatch.setenv("H1_TOKEN", "someuser:sometoken")
        result = credentials.load_credentials()
        assert os.environ["H1_USERNAME"] == "someuser"
        assert os.environ["H1_API_TOKEN"] == "sometoken"
        assert result["auth_mode"] == "authenticated_rest"

    def test_h1_token_bare_form_parsed(self, vault_home, monkeypatch):
        monkeypatch.delenv("H1_USERNAME", raising=False)
        monkeypatch.setenv("H1_TOKEN", "just-a-token")
        credentials.load_credentials()
        assert os.environ["H1_API_TOKEN"] == "just-a-token"
        assert not os.environ.get("H1_USERNAME")

    def test_root_secrets_h1_api_bare_user_token(
            self, vault_home, monkeypatch):
        root_file = vault_home / "root-secrets" / "h1_api"
        root_file.parent.mkdir(parents=True)
        root_file.write_text("rootuser:roottoken\n")
        os.chmod(root_file, 0o644)

        result = credentials.load_credentials()

        assert os.environ["H1_USERNAME"] == "rootuser"
        assert os.environ["H1_API_TOKEN"] == "roottoken"
        assert result["auth_mode"] == "authenticated_rest"
        assert str(root_file) in result["sources"]
        # Loose permissions auto-tightened on read.
        assert stat_mode(root_file) == 0o600

    def test_root_secrets_h1_api_env_style(self, vault_home, monkeypatch):
        root_file = vault_home / "root-secrets" / "h1_api"
        root_file.parent.mkdir(parents=True)
        root_file.write_text('H1_TOKEN="envuser:envtoken"\n')
        credentials.load_credentials()
        assert os.environ["H1_USERNAME"] == "envuser"
        assert os.environ["H1_API_TOKEN"] == "envtoken"

    def test_loader_tightens_loose_vault_perms(self, vault_home):
        env_file = _write_vault(vault_home, 'H1_USERNAME="u"\nH1_API_TOKEN="t"\n')
        os.chmod(env_file, 0o644)
        os.chmod(env_file.parent, 0o755)

        credentials.load_credentials()

        assert stat_mode(env_file) == 0o600
        assert stat_mode(env_file.parent) == 0o700

    def test_keyless_fallback_when_nothing_configured(self, vault_home):
        result = credentials.load_credentials(interactive=False)
        assert result["auth_mode"] == "keyless_public"
        assert result["configured"] == []
        assert result["sources"] == []
        assert all(status == credentials.STATUS_SKIPPED
                   for status in result["status"].values())

    def test_interactive_first_run_triggers_wizard(
            self, vault_home, monkeypatch):
        monkeypatch.setattr(credentials, "_stdin_isatty", lambda: True)
        monkeypatch.setattr("builtins.input", _answers({"H1_USERNAME": "wiz-user"}))
        monkeypatch.setattr(credentials.getpass, "getpass",
                            _answers({"H1_API_TOKEN": SECRET_TOKEN}))
        result = credentials.load_credentials(interactive=True)

        assert (vault_home / ".rhodawk" / ".env").is_file()
        assert os.environ["H1_USERNAME"] == "wiz-user"
        assert os.environ["H1_API_TOKEN"] == SECRET_TOKEN
        assert result["auth_mode"] == "authenticated_rest"
        assert result["vault_present"] is True

    def test_interactive_skipped_when_vault_exists(
            self, vault_home, monkeypatch):
        _write_vault(vault_home, 'H1_USERNAME="file-user"\nH1_API_TOKEN="t"\n')
        monkeypatch.setattr(credentials, "_stdin_isatty", lambda: True)

        def explode(prompt=""):
            raise AssertionError("wizard must not run when the vault exists")
        monkeypatch.setattr("builtins.input", explode)
        monkeypatch.setattr(credentials.getpass, "getpass", explode)

        credentials.load_credentials(interactive=True)
        assert os.environ["H1_USERNAME"] == "file-user"

    def test_interactive_skipped_without_tty(self, vault_home, monkeypatch):
        """pytest stdin is not a TTY, but force the flag off to be explicit."""
        monkeypatch.setattr(credentials, "_stdin_isatty", lambda: False)

        def explode(prompt=""):
            raise AssertionError("wizard must not run without a TTY")
        monkeypatch.setattr("builtins.input", explode)
        monkeypatch.setattr(credentials.getpass, "getpass", explode)

        result = credentials.load_credentials(interactive=True)
        assert result["auth_mode"] == "keyless_public"
        assert result["vault_present"] is False


# ── Status rows / group logic ─────────────────────────────────────────────────

class TestStatusRows:
    def test_ready_group_with_any_route(self):
        values = {"BUGCROWD_EMAIL": "a@b.c", "BUGCROWD_PASSWORD": "pw"}
        group = next(g for g in credentials.CREDENTIAL_GROUPS
                     if g["id"] == "bugcrowd")
        assert credentials.group_status(group, values) == credentials.STATUS_READY

    def test_incomplete_group_is_skipped(self):
        values = {"BUGCROWD_EMAIL": "a@b.c"}  # password missing
        group = next(g for g in credentials.CREDENTIAL_GROUPS
                     if g["id"] == "bugcrowd")
        assert credentials.group_status(group, values) == credentials.STATUS_SKIPPED

    def test_llm_any_single_key_is_ready(self):
        group = next(g for g in credentials.CREDENTIAL_GROUPS
                     if g["id"] == "llm_providers")
        assert credentials.group_status(group, {"GROQ_API_KEY": "gsk"}) \
            == credentials.STATUS_READY
        assert credentials.group_status(group, {}) == credentials.STATUS_SKIPPED

    def test_status_rows_cover_required_labels(self, vault_home):
        rows = {label: (status, detail)
                for label, status, detail in credentials.status_rows()}
        for label in ("HackerOne", "Bugcrowd", "Intigriti", "YesWeHack",
                      "PDCP", "Chaos", "LLM providers", "h1scope",
                      "bounty-targets-data"):
            assert label in rows
        assert rows["h1scope"][0] == credentials.STATUS_KEYLESS
        assert rows["bounty-targets-data"][0] == credentials.STATUS_KEYLESS

    def test_status_rows_redacted(self, vault_home):
        _write_vault(vault_home, f'H1_USERNAME="u1"\nH1_API_TOKEN="{SECRET_TOKEN}"\n')
        rows = credentials.status_rows()
        assert SECRET_TOKEN not in json.dumps(rows)


# ── HackerOne live verification ───────────────────────────────────────────────

class TestVerifyH1:
    def test_http_200_is_valid(self, monkeypatch):
        monkeypatch.setattr(credentials, "_http_request", lambda *a, **k: 200)
        assert credentials.verify_h1_auth("user", "token") == (200, "VALID")

    def test_http_401_is_invalid(self, monkeypatch):
        def deny(url, headers, timeout):
            raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)
        monkeypatch.setattr(credentials, "_http_request", deny)
        assert credentials.verify_h1_auth("user", "token") == (401, "INVALID")

    def test_network_error_is_invalid(self, monkeypatch):
        def dead(url, headers, timeout):
            raise OSError("network down")
        monkeypatch.setattr(credentials, "_http_request", dead)
        assert credentials.verify_h1_auth("user", "token") == (0, "INVALID")

    def test_missing_parts_never_hit_network(self, monkeypatch):
        monkeypatch.setattr(credentials, "_http_request",
                            lambda *a, **k: pytest.fail("must not call HTTP"))
        assert credentials.verify_h1_auth("", "token") == (0, "INVALID")
        assert credentials.verify_h1_auth("user", "") == (0, "INVALID")

    def test_verify_live_result_zero_leakage(self, vault_home, monkeypatch):
        _write_vault(vault_home,
                     f'H1_USERNAME="user1"\nH1_API_TOKEN="{SECRET_TOKEN}"\n')
        monkeypatch.setattr(credentials, "_http_request", lambda *a, **k: 200)
        result = credentials.load_credentials(verify_live=True)
        assert result["h1_auth"] == "HTTP 200 (VALID)"
        flat = json.dumps(result)
        assert SECRET_TOKEN not in flat
        assert base64.b64encode(b"user1:" + SECRET_TOKEN.encode()).decode() \
            not in flat


# ── CLI (--setup / --verify, redacted JSON only) ──────────────────────────────

class TestCLI:
    def test_verify_prints_redacted_json(self, vault_home, monkeypatch, capsys):
        _write_vault(vault_home,
                     f'H1_USERNAME="user1"\nH1_API_TOKEN="{SECRET_TOKEN}"\n'
                     'BUGCROWD_TOKEN=""\n')
        monkeypatch.setattr(credentials, "_http_request", lambda *a, **k: 200)
        assert credentials.main(["--verify"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["auth_mode"] == "authenticated_rest"
        assert data["status"]["HackerOne"] == credentials.STATUS_READY
        assert data["status"]["Bugcrowd"] == credentials.STATUS_SKIPPED
        assert "H1_API_TOKEN" in data["configured"]
        assert "BUGCROWD_TOKEN" in data["blank"]
        assert SECRET_TOKEN not in json.dumps(data)

    def test_setup_writes_vault(self, vault_home, monkeypatch):
        monkeypatch.setattr("builtins.input", _answers({"H1_USERNAME": "cli-user"}))
        monkeypatch.setattr(credentials.getpass, "getpass",
                            _answers({"H1_API_TOKEN": SECRET_TOKEN}))
        assert credentials.main(["--setup"]) == 0
        stored = credentials.parse_env_text(
            (vault_home / ".rhodawk" / ".env").read_text())
        assert stored["H1_USERNAME"] == "cli-user"
        assert stored["H1_API_TOKEN"] == SECRET_TOKEN

    def test_subprocess_verify_end_to_end(self, vault_home):
        """`python3 rhodawk/tools/credentials.py --verify` contract.

        Uses a non-H1 key so no live network call happens at all. The /root
        probe is guarded: on Python 3.12+ Path.is_file() raises
        PermissionError when a parent directory is unreadable."""
        root_readable = False
        try:
            root_readable = Path("/root/.secrets/h1_api").is_file()
        except OSError:
            root_readable = False  # unreadable -> tier 3 skips it
        if root_readable:
            pytest.skip("/root/.secrets/h1_api is readable on this host")
        _write_vault(vault_home, 'GROQ_API_KEY="gsk_sub_test"\n')
        env = {k: v for k, v in os.environ.items()
               if k not in credentials.ALL_MANAGED_VARS + ["H1_TOKEN",
                                                           "RHODAWK_CREDENTIALS_FILE"]}
        env["HOME"] = str(vault_home)
        proc = subprocess.run(
            [sys.executable, str(REPO / "rhodawk" / "tools" / "credentials.py"),
             "--verify"],
            capture_output=True, text=True, env=env, timeout=60, cwd=str(REPO))
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        assert data["auth_mode"] == "keyless_public"
        assert "GROQ_API_KEY" in data["configured"]
        assert "gsk_sub_test" not in proc.stdout
        assert "gsk_sub_test" not in proc.stderr


# ── Engine wiring ─────────────────────────────────────────────────────────────

class TestEngineWiring:
    def test_main_loads_vault_into_environ(self, vault_home, monkeypatch, capsys):
        """Every subcommand: main() exports the vault before dispatch."""
        import engine  # noqa: PLC0415  (pythonpath=rhodawk)

        _write_vault(vault_home,
                     f'H1_USERNAME="user1"\nH1_API_TOKEN="{SECRET_TOKEN}"\n'
                     'GROQ_API_KEY="gsk_engine_test"\n')
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("H1_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)
        monkeypatch.setattr(sys, "argv", ["engine.py"])

        engine.main()  # no command -> help, but the vault is already loaded

        assert os.environ["GROQ_API_KEY"] == "gsk_engine_test"
        assert os.environ["H1_USERNAME"] == "user1"
        assert os.environ["H1_API_TOKEN"] == SECRET_TOKEN
        captured = capsys.readouterr()
        assert "credential vault load failed" not in captured.out
        assert "credential vault load failed" not in captured.err

    def test_setup_runs_onboarding_on_tty(self, vault_home, monkeypatch, capsys):
        """`rhodawk setup` boots the credential wizard first (TTY path)."""
        import engine  # noqa: PLC0415

        monkeypatch.setattr(credentials, "_stdin_isatty", lambda: True)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
        monkeypatch.setattr("builtins.input",
                            _answers({"H1_USERNAME": "setup-user",
                                      "Enter number": "1"}))
        monkeypatch.setattr(credentials.getpass, "getpass",
                            _answers({"H1_API_TOKEN": SECRET_TOKEN}))
        monkeypatch.setattr(credentials, "_http_request", lambda *a, **k: 200)
        monkeypatch.setattr(engine, "CONFIG", vault_home / "config.json")
        monkeypatch.setattr(engine, "_import_brain",
                            lambda: (object, _FakeOllamaClient))
        monkeypatch.setattr(engine, "_print_banner", lambda: None)

        engine.cmd_setup(_setup_args())

        stored = credentials.parse_env_text(
            (vault_home / ".rhodawk" / ".env").read_text())
        assert stored["H1_USERNAME"] == "setup-user"
        assert stored["H1_API_TOKEN"] == SECRET_TOKEN
        assert json.loads((vault_home / "config.json").read_text())["provider"] \
            == "ollama"

    def test_setup_skips_onboarding_without_tty(self, vault_home, monkeypatch,
                                                capsys):
        import engine  # noqa: PLC0415

        def explode(prompt=""):
            raise AssertionError("wizard must not run without a TTY")
        monkeypatch.setattr("builtins.input", explode)
        monkeypatch.setattr(credentials.getpass, "getpass", explode)
        monkeypatch.setattr(engine, "CONFIG", vault_home / "config.json")
        monkeypatch.setattr(engine, "_import_brain",
                            lambda: (object, _FakeOllamaClient))
        monkeypatch.setattr(engine, "_print_banner", lambda: None)

        engine.cmd_setup(_setup_args())

        out = capsys.readouterr().out
        assert "Skipping interactive credential bootstrap" in out
        assert not (vault_home / ".rhodawk" / ".env").exists()

    def test_doctor_shows_tool_to_credential_status(self, vault_home, capsys):
        """doctor displays READY / SKIPPED (blank) / KEYLESS per group."""
        import engine  # noqa: PLC0415

        _write_vault(vault_home,
                     f'H1_USERNAME="user1"\nH1_API_TOKEN="{SECRET_TOKEN}"\n')
        monkeypatch = pytest.MonkeyPatch()
        # Keep the doctor fast: MCP module probe stays, LLM probe is skipped
        # because no provider is configured.
        monkeypatch.setenv("RHODAWK_CONFIG_FILE",
                           str(vault_home / "no-config.json"))

        with pytest.raises(SystemExit) as excinfo:
            engine.cmd_doctor(_setup_args())
        # Nothing FAILs in a bare sandbox beyond pre-existing env gaps; only
        # assert the section rendered and exit is a clean diagnostic.
        assert excinfo.value.code in (0, 1)
        out = capsys.readouterr().out
        for label in ("HackerOne", "Bugcrowd", "Intigriti", "YesWeHack",
                      "PDCP", "Chaos", "LLM providers", "h1scope",
                      "bounty-targets-data"):
            assert label in out, f"doctor must display {label}"
        assert credentials.STATUS_READY in out
        assert credentials.STATUS_KEYLESS in out
        monkeypatch.undo()


class _FakeOllamaClient:
    available = True
    description = "fake Ollama"

    def __init__(self, provider, model=None):
        assert provider == "ollama"

    def list_models(self):
        return ["qwen2.5:14b"]

    def chat(self, model, *args, **kwargs):
        assert model == "qwen2.5:14b"
        return "READY"


def _setup_args():
    from types import SimpleNamespace
    return SimpleNamespace(setup_provider="ollama", setup_model="qwen2.5:14b",
                           provider=None, model=None)


class TestVaultWriteHardening:
    """Release audit R-14 + L-10: atomic 0600 writes, newline rejection."""

    def test_newline_in_value_is_rejected(self, tmp_path):
        target = tmp_path / "vault.env"
        with pytest.raises(ValueError, match="newline"):
            credentials.write_env_file(
                {"H1_API_TOKEN": "tok\nEVIL_KEY=pwned"}, target)

    def test_carriage_return_in_value_is_rejected(self, tmp_path):
        target = tmp_path / "vault.env"
        with pytest.raises(ValueError, match="newline"):
            credentials.write_env_file(
                {"H1_API_TOKEN": "tok\rEVIL_KEY=pwned"}, target)

    def test_new_file_is_0600(self, tmp_path):
        target = tmp_path / "vault.env"
        credentials.write_env_file({"H1_API_TOKEN": "tok"}, target)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_preexisting_loose_file_replaced_atomically_to_0600(self, tmp_path):
        target = tmp_path / "vault.env"
        target.write_text("H1_API_TOKEN=old\n", encoding="utf-8")
        os.chmod(target, 0o664)
        credentials.write_env_file({"H1_API_TOKEN": "new"}, target)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert "EVIL" not in target.read_text(encoding="utf-8")

    def test_no_temp_files_left_behind(self, tmp_path):
        target = tmp_path / "vault.env"
        credentials.write_env_file({"H1_API_TOKEN": "tok"}, target)
        strays = [p.name for p in tmp_path.iterdir() if p.name.startswith(".vault-")]
        assert not strays, f"leftover temp files: {strays}"
