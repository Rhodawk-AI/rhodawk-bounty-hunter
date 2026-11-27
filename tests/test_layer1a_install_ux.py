"""Layer 1A first-run UX regressions (v2.0.5).

Covers the three CLI-side defects observed live on a fresh blank
Ubuntu 24.04 box at 8b75c56:

1. `rhodawk doctor` printed [PASS] MCP module while `rhodawk mcp doctor`
   exited 1 with "No module named 'mcp.server'" — the doctor check only
   imported the bundled mcp/rhodawk-mcp/cli.py, which imports the mcp SDK
   lazily, so a missing SDK was invisible to doctor.
2. `rhodawk doctor` credential rows suggested `python3 -m
   rhodawk.tools.credentials --setup` — a command that fails with
   ModuleNotFoundError for pipx / standalone-symlink installs running
   outside a venv or the repo checkout.
3. `rhodawk status` printed "[Brain] Ollama connection failed
   (http://localhost:11434): [Errno 111] Connection refused" straight above
   the clean "Provider: not configured" line on machines without a local
   Ollama — pure first-run noise.
"""

import argparse
import importlib
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

PKG_DIR = str(REPO / "rhodawk")
if PKG_DIR not in sys.path:
    sys.path.insert(0, PKG_DIR)

engine = importlib.import_module("engine")
brain = importlib.import_module("brain")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ── 1. doctor MCP check: cli.py import AND mcp SDK presence ──────────────────

class TestDoctorMcpSdkCheck:
    def test_missing_sdk_is_warn_not_pass(self, monkeypatch):
        """With no mcp SDK importable, doctor must report WARN (not PASS) and
        point at the SDK install — mirroring `rhodawk mcp doctor`'s verdict."""
        # sys.modules["mcp"] = None makes `import mcp` raise ImportError,
        # exactly like a box where the SDK was never installed.
        monkeypatch.setitem(sys.modules, "mcp", None)
        monkeypatch.setitem(sys.modules, "mcp.server", None)
        status, detail, fix = engine._doctor_mcp_check()
        assert status == "WARN", (status, detail, fix)
        assert "cli.py ok" in detail
        assert "'mcp' SDK missing" in detail
        assert "pip install 'mcp>=2.2.0'" in fix
        assert "rhodawk mcp doctor" in fix

    def test_sdk_available_is_pass(self):
        """In a dev/venv install with the SDK present the check stays PASS."""
        status, _detail, fix = engine._doctor_mcp_check()
        assert status == "PASS"
        assert fix == ""

    def test_full_doctor_output_warns_when_sdk_missing(self, capsys, monkeypatch,
                                                       tmp_path):
        """End-to-end: `rhodawk doctor` output carries the WARN row (and the
        MCP row is never PASS) when the SDK is absent."""
        monkeypatch.setitem(sys.modules, "mcp", None)
        monkeypatch.setitem(sys.modules, "mcp.server", None)
        monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
        monkeypatch.delenv("RTW_HOME", raising=False)
        monkeypatch.setenv("RTW_HOME", str(tmp_path / "no-reconftw"))
        with pytest.raises(SystemExit) as exc:
            engine.cmd_doctor(argparse.Namespace())
        assert exc.value.code == 0  # WARN, not FAIL
        out = ANSI_RE.sub("", capsys.readouterr().out)
        assert "[WARN] MCP module" in out
        assert "'mcp' SDK missing" in out
        assert "[PASS] MCP module" not in out


# ── 2. doctor credential fix hints: portable installed command ───────────────

class TestDoctorCredentialHints:
    def test_credential_hints_use_rhodawk_setup(self, capsys, monkeypatch,
                                                tmp_path):
        """Every non-READY credential row must suggest `rhodawk setup` (which
        works for pipx / uv / npm / venv / standalone installs alike) instead
        of the module invocation that breaks outside the repo checkout."""
        monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
        monkeypatch.delenv("RTW_HOME", raising=False)
        monkeypatch.setenv("RTW_HOME", str(tmp_path / "no-reconftw"))
        # Order-independence: the full suite runs other credential tests in
        # the same process — clear EVERY credential env var the vault knows
        # about (derived from the spec table, not a hardcoded list) and point
        # every vault file at nonexistent tmp paths, so all 7 credential rows
        # are deterministically SKIPPED (blank).
        creds = importlib.import_module("tools.credentials")
        for group in creds.CREDENTIAL_GROUPS:
            for field in group["fields"]:
                monkeypatch.delenv(field["var"], raising=False)
        monkeypatch.setenv("RHODAWK_CREDENTIALS_FILE",
                           str(tmp_path / "no-vault.env"))
        with pytest.raises(SystemExit):
            engine.cmd_doctor(argparse.Namespace())
        out = ANSI_RE.sub("", capsys.readouterr().out)
        # the 7 blank-vault credential rows (+ the LLM provider row) all hint
        # at the portable command
        assert out.count("fix: rhodawk setup") >= 7
        assert "python3 -m rhodawk.tools.credentials --setup" not in out


# ── 3. rhodawk status: zero Ollama probe noise on fresh machines ─────────────

class _DeadOllamaClient:
    """SDK-compatible stub whose every probe fails like a refused socket."""

    def __init__(self, host=None):
        self.host = host

    def list(self):
        raise OSError("[Errno 111] Connection refused")


def _patch_dead_ollama(monkeypatch):
    """Force the Ollama probe to fail deterministically regardless of whether
    the ollama package or a real daemon exists on the test host."""
    monkeypatch.setattr(brain, "_ollama_lib",
                        type("_StubOllamaModule", (), {"Client": _DeadOllamaClient}))
    monkeypatch.setattr(brain, "OLLAMA_HOST", "http://127.0.0.1:1")


class TestStatusQuietOllama:
    def test_status_prints_zero_ollama_noise(self, monkeypatch, capsys,
                                             tmp_path):
        """Fresh RHODAWK_HOME + unreachable Ollama → NO "[Brain] Ollama
        connection failed" noise, and the clean provider line still prints."""
        _patch_dead_ollama(monkeypatch)
        monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
        for env in set(brain.LLMClient.PROVIDER_KEY_ENV.values()):
            monkeypatch.delenv(env, raising=False)
        monkeypatch.setattr(engine, "RECON", tmp_path / "recon")
        monkeypatch.setattr(engine, "FINDINGS", tmp_path / "findings")
        monkeypatch.setattr(engine, "REPORTS", tmp_path / "reports")

        engine.cmd_status(argparse.Namespace())
        cap = capsys.readouterr()
        combined = cap.out + cap.err
        assert "Ollama connection failed" not in combined
        assert "Provider:" in cap.out
        assert "not configured" in cap.out
        assert "run: rhodawk setup" in cap.out

    def test_status_quiet_via_get_client_wiring(self, monkeypatch, capsys):
        """The suppression is wired through engine._get_client(quiet=True)."""
        _patch_dead_ollama(monkeypatch)
        monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
        for env in set(brain.LLMClient.PROVIDER_KEY_ENV.values()):
            monkeypatch.delenv(env, raising=False)
        client = engine._get_client(quiet=True)
        cap = capsys.readouterr()
        assert "Ollama connection failed" not in cap.out + cap.err
        assert client.available is False

    def test_interactive_path_still_surfaces_the_error(self, monkeypatch,
                                                       capsys):
        """Guard against over-suppression: a direct (interactive) client init
        still reports the connection failure on stderr."""
        _patch_dead_ollama(monkeypatch)
        monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
        for env in set(brain.LLMClient.PROVIDER_KEY_ENV.values()):
            monkeypatch.delenv(env, raising=False)
        client = brain.LLMClient("ollama")
        cap = capsys.readouterr()
        assert "Ollama connection failed" in cap.err
        assert client.available is False
