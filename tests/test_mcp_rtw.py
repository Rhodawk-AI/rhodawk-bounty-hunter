"""Tests for the MCP runtime's reconFTW delegation (Fix 3).

`rhodawk mcp serve` is the 4th runtime. run_rtw_capability must:
- go through the SAME PolicyEngine gate as every other active MCP tool
  (scope required → fail-closed BLOCK without scope; REQUIRE_APPROVAL without
  approve=true; BLOCK for out-of-scope targets);
- delegate through tools/rtw_adapter.py, producing the SAME rtw_manifest.json
  schema the engine (Phase 1.5/5.5), ReAct agent, and harness runtimes write.
"""

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_DIR = REPO_ROOT / "rhodawk" / "mcp" / "rhodawk-mcp"
for path in (str(REPO_ROOT / "rhodawk"), str(REPO_ROOT / "rhodawk" / "tools"),
             str(MCP_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from policy import PolicyEngine  # noqa: E402
from policy.tool_meta import TOOL_META  # noqa: E402
import adapters  # noqa: E402

SCOPE = ["*.goodscope.example"]
TARGET = "target.goodscope.example"

STUB_RECONFTW = """#!/bin/bash
while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done
mkdir -p "$out/subdomains"
echo "mcp-found.goodscope.example" > "$out/subdomains/rtw_stub.txt"
exit 0
"""


@pytest.fixture(autouse=True)
def isolated_homes(tmp_path, monkeypatch):
    home = tmp_path / "rhodawk-home"
    home.mkdir()
    monkeypatch.setenv("RHODAWK_HOME", str(home))
    monkeypatch.setenv("RHODAWK_CAPABILITIES_FILE", str(home / "capabilities.json"))
    monkeypatch.setenv("HOME", str(tmp_path))
    repo = tmp_path / "rtw"
    repo.mkdir()
    script = repo / "reconftw.sh"
    script.write_text(STUB_RECONFTW)
    script.chmod(0o755)
    monkeypatch.setenv("RTW_HOME", str(repo))
    (home / "capabilities.json").write_text(json.dumps(
        {cap: "RTW_AVAILABLE"
         for cap in ("CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE",
                     "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                     "CAP_FAVICON")}))
    # G1: runtime data now resolves under $RHODAWK_HOME (set above); keep REPO
    # sandboxed anyway since adapters use it for the CODE root (scripts, tools).
    monkeypatch.setattr(adapters, "REPO", tmp_path / "mcp-repo")
    return home


class TestPolicyGate:
    def test_registered_with_recon_posture(self):
        meta = TOOL_META["rhodawk_run_rtw_capability"]
        assert meta.requires_scope and meta.active_testing
        assert meta.network_access and meta.requires_approval
        assert not meta.read_only

    def test_requires_scope_fail_closed(self):
        """No scope configured → policy BLOCKS before the adapter is reached."""
        engine = PolicyEngine()
        decision = engine.authorize_tool("rhodawk_run_rtw_capability",
                                         {"target": TARGET, "approve": True})
        assert decision.kind.value == "block"
        assert not decision.allowed

    def test_requires_approval(self):
        """Scope set but approve missing → REQUIRE_APPROVAL (not silent run)."""
        engine = PolicyEngine(domains=SCOPE)
        decision = engine.authorize_tool("rhodawk_run_rtw_capability",
                                         {"target": TARGET})
        assert not decision.allowed
        assert "approval" in decision.reason.lower() or "APPROVAL" in (decision.error_code or "")

    def test_out_of_scope_blocked(self):
        engine = PolicyEngine(domains=SCOPE)
        decision = engine.authorize_tool("rhodawk_run_rtw_capability",
                                         {"target": "evil.example", "approve": True})
        assert not decision.allowed

    def test_in_scope_with_approval_allowed(self):
        engine = PolicyEngine(domains=SCOPE)
        decision = engine.authorize_tool("rhodawk_run_rtw_capability",
                                         {"target": TARGET, "approve": True})
        assert decision.allowed


class TestMcpRuntimeDelegation:
    def test_delegates_through_adapter_with_shared_manifest(self, isolated_homes):
        """The MCP path produces the SAME manifest schema as every other
        runtime (parity check) and scope-filters via the policy checker."""
        engine = PolicyEngine(domains=SCOPE)
        assert engine._checker is not None
        result = adapters.run_rtw_capability("CAP_ASN_ENUM", TARGET,
                                             scope_checker=engine._checker)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        entry = result["entry"]
        for key in ("capability_id", "rtw_function", "target", "input_hash",
                    "status", "started", "finished"):
            assert key in entry, f"manifest schema missing {key}"
        manifest = json.loads(
            (isolated_homes / "recon" / TARGET / "rtw_manifest.json").read_text())
        assert manifest["version"] == 1 and manifest["ttl_days"] == 7
        assert manifest["entries"][-1] == entry

    def test_out_of_scope_never_spawns(self, isolated_homes):
        engine = PolicyEngine(domains=SCOPE)
        result = adapters.run_rtw_capability("CAP_ASN_ENUM", "evil.example",
                                             scope_checker=engine._checker)
        assert result["status"] == "SKIPPED" and result["blocked"] is True
        audit = (isolated_homes / "hunt-memory" / "audit.jsonl")
        assert audit.is_file()
        assert json.loads(audit.read_text().splitlines()[-1])["scope_check"] == "fail"

    def test_unsafe_target_rejected(self, isolated_homes):
        engine = PolicyEngine(domains=SCOPE)
        result = adapters.run_rtw_capability("CAP_ASN_ENUM", "../../etc",
                                             scope_checker=engine._checker)
        assert result["status"] == "failed"
        assert result["error"] == "INVALID_TARGET"

    def test_server_module_registers_tool(self):
        """server.py registers the tool (4-runtime parity: same tool name,
        capability IDs, capabilities.json reference). Live import requires the
        mcp>=2.2 MCPServer API; when that's unavailable (upstream exits with
        its own guarded error), fall back to source-level verification."""
        src = (MCP_DIR / "server.py").read_text()
        assert "@mcp.tool" in src and "rhodawk_run_rtw_capability" in src
        for cap in ("CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE",
                    "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                    "CAP_FAVICON"):
            assert cap in src, f"server.py docstring missing canonical ID {cap}"
        assert "capabilities.json" in src
        assert "adapters.run_rtw_capability" in src
        assert '_gate("rhodawk_run_rtw_capability"' in src
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("rtw_mcp_server",
                                                          MCP_DIR / "server.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            assert hasattr(mod, "rhodawk_run_rtw_capability")
        except SystemExit:
            pytest.skip("mcp MCPServer API unavailable in this environment — "
                        "static wiring verified instead")
