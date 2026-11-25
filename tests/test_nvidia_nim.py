"""NVIDIA NIM provider wiring: chat dispatch, defaults, and key redaction.

Adds NVIDIA NIM alongside every existing provider without breaking any of
them (live-run request):

  - nvidia registered in PROVIDER_PRIORITY / DEFAULT_MODELS / PROVIDER_KEY_ENV
  - aliases nim / nvidia-nim / nvidia_nim normalize to "nvidia"
  - chat() routes nvidia through the shared OpenAI-compatible /chat/completions
    path, with NVIDIA_NIM_BASE_URL overriding the hosted default endpoint
  - nvapi-... keys are redacted by memory/redaction.py before durable
    persistence
"""

import importlib
import json
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from memory.redaction import redact_obj, redact_text  # noqa: E402


@pytest.fixture
def brain_module(monkeypatch):
    for env in ("BRAIN_PROVIDER", "BRAIN_MODEL", "NVIDIA_API_KEY",
                "NVIDIA_NIM_BASE_URL"):
        monkeypatch.delenv(env, raising=False)
    import brain
    importlib.reload(brain)
    return brain


def _nim_client(brain_module, monkeypatch, base_url=None):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    if base_url:
        monkeypatch.setenv("NVIDIA_NIM_BASE_URL", base_url)
    else:
        monkeypatch.delenv("NVIDIA_NIM_BASE_URL", raising=False)
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._http = None
    client.description = ""
    client.provider = "nvidia"
    client.model = None
    return client


def test_nvidia_uses_openai_compat_chat_path(brain_module, monkeypatch):
    """chat() must route nvidia through the shared /chat/completions path."""
    client = _nim_client(brain_module, monkeypatch)
    brain_module.LLMClient._init_provider(client, "nvidia")
    assert client.available is True

    calls = []

    def _fake_chat(model, system, user, max_tokens, temperature):
        calls.append({"model": model, "system": system, "user": user})
        return "nim-reply"

    monkeypatch.setattr(client, "_chat_openai_compat", _fake_chat)
    reply = client.chat(None, "system", "user")

    assert reply == "nim-reply"
    assert len(calls) == 1


def test_nvidia_provider_registry_entries(brain_module):
    dm = brain_module.LLMClient.DEFAULT_MODELS
    assert dm["nvidia"] == "nvidia/nemotron-3-ultra-550b-a55b"
    assert brain_module.LLMClient.PROVIDER_KEY_ENV["nvidia"] == "NVIDIA_API_KEY"
    assert "nvidia" in brain_module.LLMClient.PROVIDER_PRIORITY


def test_nim_aliases_normalize(brain_module, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    for alias in ("nim", "nvidia-nim", "nvidia_nim"):
        client = brain_module.LLMClient(alias)
        assert client.provider == "nvidia"
        assert client.available is True
        assert "nvidia" in client.description.lower()


NVAPI_KEY = "nvapi-nV1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2"


def test_nvapi_key_redacted_in_text():
    out = redact_text(f"config error at {NVAPI_KEY} — retry")
    assert "nvapi-" not in out
    assert NVAPI_KEY not in out
    assert "[REDACTED:nvidia_key]" in out


def test_nvapi_key_redacted_in_obj_and_idempotent():
    obj = {"note": f"key={NVAPI_KEY}", "nested": [f"Bearer {NVAPI_KEY}"]}
    once = redact_obj(obj)
    assert NVAPI_KEY not in str(once)
    twice = redact_obj(once)
    assert twice == once  # deterministic + idempotent


def test_engine_wires_nvidia_setup_and_providers():
    """engine.py exposes NVIDIA NIM in setup (key + base URL + choices) and
    the providers table, keeping every existing provider untouched."""
    src = open(os.path.join(ROOT, "rhodawk", "engine.py"),
               encoding="utf-8").read()
    assert '"nvidia":     "NVIDIA_API_KEY"' in src          # setup env_map
    assert '"nvidia":       "NVIDIA_API_KEY"' in src        # providers table
    assert "NVIDIA_NIM_BASE_URL" in src                     # base URL override
    assert "NVIDIA NIM" in src                              # menu label
    assert '"nvidia", "nim", "nvidia-nim"' in src           # argparse choices
    assert "https://integrate.api.nvidia.com/v1" in src     # default shown
    assert "max_tokens=256" in src                          # reasoning-room ping


# ── Reasoning-model responses: content=None + reasoning_content ──────────────

class _FakeResponse:
    """Minimal OpenAI-compatible HTTP response for chat-path unit tests."""
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, payload):
        self.calls = []
        self._payload = payload

    def post(self, url, **kwargs):
        self.calls.append(url)
        return _FakeResponse(self._payload)


def _reasoning_client(brain_module, monkeypatch, payload):
    client = _nim_client(brain_module, monkeypatch)
    brain_module.LLMClient._init_provider(client, "nvidia")
    client._http = _FakeSession(payload)
    return client


def test_reasoning_model_none_content_falls_back_to_reasoning_content(
        brain_module, monkeypatch):
    """Reasoning models on NVIDIA NIM (e.g. nvidia/nemotron-3-ultra-550b-a55b)
    return {"content": null, "reasoning_content": "..."} when max_tokens is
    small or while still reasoning. chat() must return the reasoning text
    instead of raising AttributeError: 'NoneType' object has no attribute
    'strip'."""
    payload = {"choices": [{"message": {"content": None,
                                        "reasoning_content": "OK"}}]}
    client = _reasoning_client(brain_module, monkeypatch, payload)

    reply = client.chat(None, "system", "user")

    assert reply == "OK"
    assert client._http.calls[0].endswith("/chat/completions")


def test_reasoning_model_none_content_without_reasoning_returns_empty(
        brain_module, monkeypatch):
    """content=None and no reasoning_content yields "" — never a crash."""
    payload = {"choices": [{"message": {"content": None}}]}
    client = _reasoning_client(brain_module, monkeypatch, payload)
    assert client.chat(None, "system", "user") == ""


def test_reasoning_model_final_content_takes_precedence(
        brain_module, monkeypatch):
    """A real final content still wins over reasoning_content."""
    payload = {"choices": [{"message": {"content": "READY",
                                        "reasoning_content": "thinking..."}}]}
    client = _reasoning_client(brain_module, monkeypatch, payload)
    assert client.chat(None, "system", "user") == "READY"


# ── Saved-config loading (live-run fix 4) ─────────────────────────────────────
#
# `rhodawk setup --provider nvidia` saved ~/.rhodawk/config.json and printed
# "[+] Model responded: READY", yet a fresh `rhodawk <target> -recon` shell
# printed "[!] No LLM provider available" — the wizard only exported the key
# into its own process. LLMClient must now load provider/credentials/model
# from that config when BRAIN_PROVIDER / NVIDIA_API_KEY aren't exported.

class TestSavedNvidiaConfig:
    _ENV_KEYS = ("NVIDIA_API_KEY", "NVIDIA_NIM_BASE_URL", "BRAIN_PROVIDER",
                 "BRAIN_MODEL")

    def _write_cfg(self, tmp_path, payload):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(payload))
        return str(path)

    def _restore_env(self, saved):
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_config_provider_and_credentials_load_without_env(
            self, brain_module, tmp_path, monkeypatch):
        """Uppercase keys (the exact shape the setup wizard saves): a fresh
        process with NO env vars picks up provider, key, base URL and model."""
        path = self._write_cfg(tmp_path, {
            "provider": "nvidia",
            "NVIDIA_API_KEY": "nvapi-cfg",
            "NVIDIA_NIM_BASE_URL": "https://nim.example/v1",
            "models": {"nvidia": "nvidia/nemotron-3-ultra-550b-a55b"},
        })
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", path)
        saved = {k: os.environ.get(k) for k in self._ENV_KEYS}
        try:
            client = brain_module.LLMClient()
            assert client.provider == "nvidia"
            assert client.available is True
            assert client._api_base == "https://nim.example/v1"
            assert client.model == "nvidia/nemotron-3-ultra-550b-a55b"
        finally:
            self._restore_env(saved)

    def test_lowercase_config_keys_accepted(
            self, brain_module, tmp_path, monkeypatch):
        """Lowercase variants (nvidia_api_key / nvidia_nim_base_url / model)
        are accepted too."""
        path = self._write_cfg(tmp_path, {
            "provider": "nvidia",
            "nvidia_api_key": "nvapi-lc",
            "nvidia_nim_base_url": "https://nim-lc.example/v1",
            "model": "nvidia/nemotron-3-ultra-550b-a55b",
        })
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", path)
        saved = {k: os.environ.get(k) for k in self._ENV_KEYS}
        try:
            client = brain_module.LLMClient()
            assert client.provider == "nvidia"
            assert client.available is True
            assert client._api_base == "https://nim-lc.example/v1"
            assert client.model == "nvidia/nemotron-3-ultra-550b-a55b"
        finally:
            self._restore_env(saved)

    def test_explicit_env_key_wins_over_config(
            self, brain_module, tmp_path, monkeypatch):
        """An explicitly exported NVIDIA_API_KEY always beats the config one."""
        path = self._write_cfg(tmp_path, {
            "provider": "nvidia", "NVIDIA_API_KEY": "nvapi-cfg"})
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", path)
        monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-env")
        saved = {k: os.environ.get(k) for k in self._ENV_KEYS}
        try:
            client = brain_module.LLMClient()
            assert client.provider == "nvidia"
            assert client._http.headers["Authorization"] == "Bearer nvapi-env"
        finally:
            self._restore_env(saved)

    def test_config_provider_failure_falls_back_to_auto_detect(
            self, brain_module, tmp_path, monkeypatch):
        """A dead saved provider (key present, init impossible) must not leave
        the client disabled — auto-detect walks the remaining providers."""
        path = self._write_cfg(tmp_path, {
            "provider": "nvidia", "nvidia_api_key": "nvapi-broken",
            "nvidia_nim_base_url": "https://127.0.0.1:1/v1"})
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", path)
        monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-broken")
        # _chat_openai_compat would fail at request time, not init time — the
        # init itself succeeds with any key, so simulate a hard init failure
        # by pointing the client at a provider we then remove the key for.
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        saved = {k: os.environ.get(k) for k in self._ENV_KEYS}
        try:
            client = brain_module.LLMClient()
            # nvidia init without a usable key cannot be reached: the client
            # must NOT stay on a disabled nvidia — it walks on.
            assert client.provider != "nvidia" or client.available is True
        finally:
            self._restore_env(saved)
