"""Tests for LLMClient._auto_detect provider-priority reshuffling.

Users with only a cloud API key set (e.g. ANTHROPIC_API_KEY) should hit
the matching provider first. Without any key, the original ordering
(Ollama → Claude → OpenAI → Grok) still applies.
"""

import importlib
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)


@pytest.fixture
def brain_module(monkeypatch):
    for env in (
        "BRAIN_PROVIDER", "BRAIN_MODEL",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY",
        "OPENROUTER_API_KEY", "ORCAROUTER_API_KEY",
        "REQUESTY_API_KEY", "REQUESTY_BASE_URL",
        "NVIDIA_API_KEY", "NVIDIA_NIM_BASE_URL",
    ):
        monkeypatch.delenv(env, raising=False)
    import brain
    importlib.reload(brain)
    return brain


class _Tracker:
    """Records _init_provider calls; marks a chosen provider available."""

    def __init__(self, available_provider: str | None = None):
        self.calls: list[str] = []
        self.available_provider = available_provider

    def bind(self, client):
        def _init(provider: str) -> None:
            self.calls.append(provider)
            client.available = provider == self.available_provider
        client._init_provider = _init


def test_anthropic_key_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="claude")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "claude"
    assert tracker.calls[0] == "claude", "claude must be probed first when its key is set"


def test_openai_and_grok_keys_both_front_nothing_available(brain_module, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("XAI_API_KEY", "xai-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider=None)
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "ollama"
    assert set(tracker.calls[:2]) == {"openai", "grok"}, \
        "key-bearing providers must be probed before the rest"
    rest = [p for p in brain_module.LLMClient.PROVIDER_PRIORITY
            if p not in ("openai", "grok")]
    assert tracker.calls[2:] == rest, \
        "providers without keys keep their original relative order"


def test_no_keys_falls_back_to_default_priority(brain_module):
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider=None)
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "ollama"
    assert tracker.calls == list(brain_module.LLMClient.PROVIDER_PRIORITY)


def test_key_set_but_provider_unavailable_falls_through(brain_module, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="ollama")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "ollama"
    assert tracker.calls[0] == "claude"
    assert "ollama" in tracker.calls


def test_openrouter_key_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="openrouter")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "openrouter"
    assert tracker.calls[0] == "openrouter"


def test_openrouter_init_sets_api_base(brain_module, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._ollama = None
    client._http = None
    client.description = ""
    client.provider = "openrouter"

    brain_module.LLMClient._init_provider(client, "openrouter")

    assert client.available is True
    assert client._api_base == "https://openrouter.ai/api/v1"
    assert "openrouter" in client.description.lower()
    assert brain_module.LLMClient.DEFAULT_MODELS["openrouter"] == "anthropic/claude-sonnet-4.6"
    assert "anthropic/claude-sonnet-4.6" in brain_module.LLMClient.list_models(client)


def test_orcarouter_key_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="orcarouter")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "orcarouter"
    assert tracker.calls[0] == "orcarouter"


def test_orcarouter_init_sets_api_base(brain_module, monkeypatch):
    monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._ollama = None
    client._http = None
    client.description = ""
    client.provider = "orcarouter"

    brain_module.LLMClient._init_provider(client, "orcarouter")

    assert client.available is True
    assert client._api_base == "https://api.orcarouter.ai/v1"
    assert "orcarouter" in client.description.lower()
    assert brain_module.LLMClient.DEFAULT_MODELS["orcarouter"] == "openai/gpt-4o"
    assert "orcarouter/auto" in brain_module.LLMClient.list_models(client)
def test_requesty_key_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("REQUESTY_API_KEY", "rqsty-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="requesty")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "requesty"
    assert tracker.calls[0] == "requesty"


def test_requesty_init_sets_api_base(brain_module, monkeypatch):
    monkeypatch.setenv("REQUESTY_API_KEY", "rqsty-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._ollama = None
    client._http = None
    client.description = ""
    client.provider = "requesty"

    brain_module.LLMClient._init_provider(client, "requesty")

    assert client.available is True
    assert client._api_base == "https://router.requesty.ai/v1"
    assert "requesty" in client.description.lower()
    assert brain_module.LLMClient.DEFAULT_MODELS["requesty"] == "anthropic/claude-sonnet-4-6"
    assert "anthropic/claude-sonnet-4-6" in brain_module.LLMClient.list_models(client)


def test_requesty_base_url_override(brain_module, monkeypatch):
    monkeypatch.setenv("REQUESTY_API_KEY", "rqsty-test")
    monkeypatch.setenv("REQUESTY_BASE_URL", "https://router.eu.requesty.ai/v1/")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._http = None
    client.description = ""

    brain_module.LLMClient._init_provider(client, "requesty")

    assert client._api_base == "https://router.eu.requesty.ai/v1"


def test_requesty_is_opt_in_only(brain_module):
    assert "requesty" not in brain_module.LLMClient.PROVIDER_PRIORITY


def test_nvidia_key_jumps_to_front(brain_module, monkeypatch):
    """NVIDIA_API_KEY set → the nvidia (NIM) provider is probed first."""
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="nvidia")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "nvidia"
    assert tracker.calls[0] == "nvidia"


def test_nvidia_init_sets_default_api_base(brain_module, monkeypatch):
    """Default NIM endpoint is NVIDIA's hosted integrate.api.nvidia.com/v1."""
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.delenv("NVIDIA_NIM_BASE_URL", raising=False)
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._ollama = None
    client._http = None
    client.description = ""
    client.provider = "nvidia"

    brain_module.LLMClient._init_provider(client, "nvidia")

    assert client.available is True
    assert client._api_base == "https://integrate.api.nvidia.com/v1"
    assert "nvidia" in client.description.lower()
    assert brain_module.LLMClient.DEFAULT_MODELS["nvidia"] == "nvidia/nemotron-3-ultra-550b-a55b"
    assert "nvidia/nemotron-3-ultra-550b-a55b" in brain_module.LLMClient.list_models(client)


def test_nvidia_base_url_override(brain_module, monkeypatch):
    """NVIDIA_NIM_BASE_URL overrides the endpoint (self-hosted NIM)."""
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.setenv("NVIDIA_NIM_BASE_URL", "http://nim.lab.internal:8000/v1/")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._http = None
    client.description = ""

    brain_module.LLMClient._init_provider(client, "nvidia")

    assert client._api_base == "http://nim.lab.internal:8000/v1"


def test_nvidia_in_priority_with_nim_aliases(brain_module, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    assert "nvidia" in brain_module.LLMClient.PROVIDER_PRIORITY
    for alias in ("nim", "nvidia-nim", "nvidia_nim"):
        client = brain_module.LLMClient(alias)
        assert client.provider == "nvidia"
        assert client.available is True
