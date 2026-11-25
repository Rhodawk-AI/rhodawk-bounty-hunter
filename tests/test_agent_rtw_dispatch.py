"""Tests for the ReAct-agent runtime's run_rtw_capability dispatch (Fix 3
parity: runtime 2 of 4). The dispatcher must:

- route run_rtw_capability through the same AutopilotGuard scope gate as every
  other network tool (fail-closed BLOCK with no checker, before the adapter);
- delegate through tools/rtw_adapter.py and write the SAME rtw_manifest.json
  schema the engine/harness/MCP runtimes produce;
- expose the tool schema with exactly the 7 canonical capability IDs, and the
  AGENT_SYSTEM rule worded identically to the harness docs.
"""

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_ROOT = REPO_ROOT / "rhodawk"
for path in (str(PKG_ROOT), str(PKG_ROOT / "tools")):
    if path not in sys.path:
        sys.path.insert(0, path)

import agent  # noqa: E402
from agent import HuntMemory, ToolDispatcher  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402

SCOPE = ["*.goodscope.example"]
TARGET = "target.goodscope.example"

STUB_RECONFTW = """#!/bin/bash
while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done
mkdir -p "$out/subdomains"
echo "agent-found.goodscope.example" > "$out/subdomains/rtw_stub.txt"
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
    return home


@pytest.fixture
def memory(tmp_path):
    return HuntMemory(str(tmp_path / "agent_session.json"))


class TestReActDispatch:
    def test_tool_schema_lists_canonical_ids(self):
        rtw_tools = [t for t in agent.TOOLS
                     if t["function"]["name"] == "run_rtw_capability"]
        assert len(rtw_tools) == 1
        enum = rtw_tools[0]["function"]["parameters"]["properties"]["capability_id"]["enum"]
        assert set(enum) == {"CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE",
                             "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                             "CAP_FAVICON"}

    def test_agent_system_rule_wording_parity(self):
        canonical = ("If recon_summary flags a capability gap and capabilities.json "
                     "marks it RTW_AVAILABLE, call run_rtw_capability before proceeding.")
        assert canonical in agent.AGENT_SYSTEM
        # Identical wording in the harness docs (worded identically across every
        # prompt layer, per the build brief).
        for doc in ("commands/recon.md", "rhodawk/agents/recon-agent.md",
                    "skills/web2-recon/SKILL.md"):
            assert canonical in (REPO_ROOT / doc).read_text(), \
                f"{doc} must carry the identical rule wording"

    def test_dispatch_writes_shared_manifest_schema(self, memory):
        """In-scope dispatch → real adapter run → shared manifest schema."""
        dispatcher = ToolDispatcher(TARGET, memory, scope_checker=ScopeChecker(SCOPE))
        obs = dispatcher.dispatch("run_rtw_capability",
                                  {"capability_id": "CAP_ASN_ENUM"})
        assert "COMPLETED_WITH_FINDINGS" in obs
        home = Path(os.environ["RHODAWK_HOME"])
        manifest = json.loads((home / "recon" / TARGET / "rtw_manifest.json").read_text())
        entry = manifest["entries"][-1]
        for key in ("capability_id", "rtw_function", "target", "input_hash",
                    "status", "started", "finished"):
            assert key in entry
        assert entry["rtw_function"] == "sub_asn"

    def test_dispatch_blocked_without_scope_checker(self, memory):
        """fail_closed guard: no checker → the dispatch blocks BEFORE the
        adapter runs (no manifest entry for the capability)."""
        dispatcher = ToolDispatcher(TARGET, memory)  # no scope_checker
        obs = dispatcher.dispatch("run_rtw_capability",
                                  {"capability_id": "CAP_ASN_ENUM"})
        assert "BLOCKED" in obs or "blocked" in obs
        home = Path(os.environ["RHODAWK_HOME"])
        manifest_path = home / "recon" / TARGET / "rtw_manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            assert manifest["entries"] == []  # nothing ran

    def test_dispatch_out_of_scope_blocked_before_subprocess(self, memory, monkeypatch):
        dispatcher = ToolDispatcher(TARGET, memory, scope_checker=ScopeChecker(SCOPE))
        guard = {"calls": 0}
        real_run = __import__("tools.rtw_adapter", fromlist=["subprocess"]).subprocess.run

        def counting_run(argv, **kwargs):
            guard["calls"] += 1
            return real_run(argv, **kwargs)

        monkeypatch.setattr("tools.rtw_adapter.subprocess.run", counting_run)
        obs = dispatcher.dispatch("run_rtw_capability",
                                  {"capability_id": "CAP_ASN_ENUM",
                                   "force": True})
        # Adapter-level gate SKIPS (already guarded at dispatch level, but the
        # adapter must still refuse an out-of-scope domain passed directly).
        dispatcher2 = ToolDispatcher("evil.example", memory,
                                     scope_checker=ScopeChecker(SCOPE))
        guard["calls"] = 0  # first dispatch above legitimately ran the stub (in scope)
        obs2 = dispatcher2.dispatch("run_rtw_capability",
                                    {"capability_id": "CAP_ASN_ENUM",
                                     "force": True})
        assert "SKIPPED" in obs2 or "blocked" in obs2.lower()
        # The AutopilotGuard blocks BEFORE the adapter is reached, so no
        # reconFTW subprocess can ever spawn on this path. The adapter's own
        # fail-closed gate + audit.jsonl logging fires when it IS reached
        # directly (engine Phase 1.5/5.5, MCP) — covered by
        # test_recon_engine_rtw.py and test_mcp_rtw.py.
        assert guard["calls"] == 0, "reconFTW subprocess spawned after guard block"
