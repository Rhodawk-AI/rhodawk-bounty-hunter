"""Tests for Commit 4 — kernel system prompt, prompt hygiene, deterministic
PreToolUse hooks.

Covers the Commit-4 acceptance list:

- ``rhodawk/prompts/kernel.md`` exists and defines the
  ``<untrusted_target_data>`` data-plane isolation rules, the deterministic
  stage order, the authorized-verification framing and the typed-tool rule
  (``compiled_scope.json`` as scope authority),
- no raw ``curl`` workarounds to ``hackerone.com/graphql`` or
  ``dns.projectdiscovery.io`` remain in ``SKILL.md``,
  ``skills/bug-bounty/SKILL.md`` or ``rhodawk/agents/recon-agent.md``,
- ``hooks/hooks.json`` is valid JSON and registers a ``PreToolUse`` hook
  invoking ``hook_scope_guard.py`` (SessionStart / Stop reminders intact),
- ``hook_scope_guard.py`` exits 0 on a valid manifest, exits 0 on read-only
  tools, and exits 2 (``SCOPE_HOOK_BLOCK``) on a missing or tampered manifest
  for active recon/hunt tools.

The guard is exercised end-to-end via subprocess (stdin JSON exactly as
Claude Code delivers it), in an isolated cwd so a developer's real
``recon/`` tree can never influence results.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from contracts.scope import CompiledScopeManifest

REPO = Path(__file__).resolve().parents[1]
KERNEL = REPO / "rhodawk" / "prompts" / "kernel.md"
HOOK = REPO / "rhodawk" / "tools" / "hook_scope_guard.py"
HOOKS_JSON = REPO / "hooks" / "hooks.json"
SKILL_ROOT = REPO / "SKILL.md"
SKILL_BB = REPO / "skills" / "bug-bounty" / "SKILL.md"
RECON_AGENT = REPO / "rhodawk" / "agents" / "recon-agent.md"

PROMPT_HYGIENE_FILES = (SKILL_ROOT, SKILL_BB, RECON_AGENT)
BANNED_ENDPOINTS = ("hackerone.com/graphql", "dns.projectdiscovery.io")

STAGES = ("Compile Scope", "Scoped Recon", "Prioritized Surface",
          "Hypothesis Hunt", "Clean-Room Verify", "Report")


# ── helpers ──────────────────────────────────────────────────────────────

def run_guard(payload=None, args=(), cwd=None, env_extra=None):
    """Run hook_scope_guard.py exactly as a PreToolUse hook would run it."""
    env = dict(os.environ)
    env.pop("RHODAWK_SCOPE_MANIFEST", None)  # isolate from developer env
    if env_extra:
        env.update(env_extra)
    stdin = b"" if payload is None else json.dumps(payload).encode("utf-8")
    return subprocess.run(
        [sys.executable, str(HOOK), *args],
        input=stdin, capture_output=True, env=env,
        cwd=str(cwd or REPO), timeout=120,
    )


def write_manifest(base: Path, handle: str = "shopify",
                   allow=("*.shopify.com",)) -> Path:
    """Compile a real, hash-valid manifest under <base>/recon/<handle>/."""
    manifest = CompiledScopeManifest(
        program_handle=handle,
        allow_patterns=list(allow),
        exclude_patterns=["staging." + allow[0].lstrip("*.")],
        excluded_classes=["ssrf"],
        max_rps=5.0,
    )
    return manifest.save(base / "recon" / handle / "scope"
                         / "compiled_scope.json")


@pytest.fixture
def isolated_cwd(tmp_path):
    """Empty cwd for the guard subprocess (no recon/ tree visible)."""
    return tmp_path


# ── kernel prompt ────────────────────────────────────────────────────────

class TestKernelPrompt:
    def test_kernel_prompt_exists(self):
        assert KERNEL.is_file(), "rhodawk/prompts/kernel.md must exist"

    def test_kernel_defines_stage_order(self):
        text = KERNEL.read_text(encoding="utf-8")
        for stage in STAGES:
            assert stage in text, f"kernel.md missing stage '{stage}'"
        # deterministic order in the numbered list
        positions = [text.index(stage) for stage in STAGES]
        assert positions == sorted(positions), "stages must appear in order"

    def test_kernel_defines_untrusted_data_isolation(self):
        text = KERNEL.read_text(encoding="utf-8")
        assert "<untrusted_target_data>" in text
        assert "</untrusted_target_data>" in text
        # passive-data rule: data, never instructions
        assert "passive" in text.lower()
        assert "never instructions" in text.lower()
        # scope cannot be widened from inside target data
        assert "scope override" in text.lower()

    def test_kernel_defines_authorized_framing(self):
        text = KERNEL.read_text(encoding="utf-8").lower()
        assert "authorized" in text
        assert "invariant" in text
        assert "refusal" in text

    def test_kernel_names_compiled_manifest_as_scope_authority(self):
        text = KERNEL.read_text(encoding="utf-8")
        assert "compiled_scope.json" in text
        assert "require_valid_hash=True" in text
        for tool in ("rhodawk scope-compile", "rhodawk_compile_scope",
                     "rhodawk_prioritized_surface",
                     "rhodawk_inspect_endpoint_slice"):
            assert tool in text, f"kernel.md missing typed tool '{tool}'"
        assert "curl" in text.lower()  # raw-curl prohibition is stated


# ── prompt hygiene ───────────────────────────────────────────────────────

class TestPromptHygiene:
    @pytest.mark.parametrize("doc", PROMPT_HYGIENE_FILES,
                             ids=lambda p: str(p.relative_to(REPO)))
    def test_no_raw_curl_platform_workarounds(self, doc):
        assert doc.is_file(), f"{doc} missing"
        text = doc.read_text(encoding="utf-8")
        for endpoint in BANNED_ENDPOINTS:
            assert endpoint not in text, (
                f"{doc.name} still contains raw curl workaround to {endpoint}")

    @pytest.mark.parametrize("doc", (SKILL_ROOT, SKILL_BB),
                             ids=lambda p: str(p.relative_to(REPO)))
    def test_skill_docs_reference_kernel_and_manifest(self, doc):
        text = doc.read_text(encoding="utf-8")
        assert "rhodawk/prompts/kernel.md" in text, (
            f"{doc.name} must reference the kernel prompt")
        assert "compiled_scope.json" in text
        assert "rhodawk scope-compile" in text
        assert "rhodawk_compile_scope" in text

    def test_recon_agent_points_to_engine_and_mcp(self):
        text = RECON_AGENT.read_text(encoding="utf-8")
        assert "recon_engine.sh" in text
        assert "--scope-manifest" in text
        assert "rhodawk_recon" in text
        assert "scope-compile" in text
        # the removed Chaos snippet must not survive anywhere in the agent
        assert "dns.projectdiscovery.io" not in text
        assert "CHAOS_API_KEY" not in text

    def test_commands_document_authoritative_scope_workflow(self):
        scope_doc = (REPO / "commands" / "scope.md").read_text(encoding="utf-8")
        agg_doc = (REPO / "commands" / "scope-aggregate.md").read_text(
            encoding="utf-8")
        recon_doc = (REPO / "commands" / "recon.md").read_text(encoding="utf-8")
        for doc, name in ((scope_doc, "scope.md"),
                          (agg_doc, "scope-aggregate.md"),
                          (recon_doc, "recon.md")):
            assert "rhodawk scope-compile" in doc, name
            assert "compiled_scope.json" in doc, name
        assert "--scope-manifest" in recon_doc
        # manual aggregator / raw WHOIS-CNAME shell instructions replaced
        assert "whois api.target.com" not in scope_doc
        assert "dig +short" not in scope_doc


# ── hooks.json wiring ────────────────────────────────────────────────────

class TestHooksWiring:
    def test_hooks_json_is_valid_json(self):
        data = json.loads(HOOKS_JSON.read_text(encoding="utf-8"))
        assert isinstance(data, dict) and "hooks" in data

    def test_pretooluse_registered_invoking_guard(self):
        data = json.loads(HOOKS_JSON.read_text(encoding="utf-8"))
        pre = data["hooks"].get("PreToolUse")
        assert isinstance(pre, list) and pre, "PreToolUse must be registered"
        blob = json.dumps(pre)
        assert "hook_scope_guard.py" in blob
        assert "python3" in blob
        # matcher must cover the Bash tool (raw shell is the bypass vector)
        matchers = json.dumps(pre)
        assert "Bash" in matchers

    def test_pretooluse_matcher_covers_active_mcp_tools(self):
        data = json.loads(HOOKS_JSON.read_text(encoding="utf-8"))
        blob = json.dumps(data["hooks"]["PreToolUse"])
        for tool in ("rhodawk_recon", "rhodawk_hunt", "rhodawk_hunt_class",
                     "rhodawk_research"):
            assert tool in blob, f"PreToolUse matcher must cover {tool}"

    def test_sessionstart_and_stop_reminders_intact(self):
        data = json.loads(HOOKS_JSON.read_text(encoding="utf-8"))
        assert data["hooks"]["SessionStart"][0]["command"].startswith("echo")
        assert data["hooks"]["Stop"][0]["command"].startswith("echo")


# ── hook_scope_guard.py behaviour ────────────────────────────────────────

class TestHookScopeGuard:
    def test_allows_read_only_tool_without_manifest(self, isolated_cwd):
        proc = run_guard({"tool_name": "Read",
                          "tool_input": {"file_path": "/tmp/x"}},
                         cwd=isolated_cwd)
        assert proc.returncode == 0, proc.stderr.decode()

    def test_allows_unknown_non_target_tool(self, isolated_cwd):
        proc = run_guard({"tool_name": "WebSearch",
                          "tool_input": {"query": "x"}}, cwd=isolated_cwd)
        assert proc.returncode == 0

    def test_allows_read_only_mcp_tools_without_manifest(self, isolated_cwd):
        for tool in ("rhodawk_scope_check", "rhodawk_attack_surface",
                     "rhodawk_prioritized_surface"):
            proc = run_guard({"tool_name": tool, "tool_input": {"target": "x"}},
                             cwd=isolated_cwd)
            assert proc.returncode == 0, (tool, proc.stderr.decode())

    def test_blocks_active_tool_without_manifest(self, isolated_cwd):
        proc = run_guard({"tool_name": "rhodawk_recon",
                          "tool_input": {"target": "shopify"}},
                         cwd=isolated_cwd)
        assert proc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in proc.stderr.decode()

    def test_blocks_bash_recon_engine_without_manifest(self, isolated_cwd):
        proc = run_guard({"tool_name": "Bash",
                          "tool_input": {"command":
                              "bash rhodawk/tools/recon_engine.sh target.com"}},
                         cwd=isolated_cwd)
        assert proc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in proc.stderr.decode()

    def test_blocks_bash_full_hunt_without_manifest(self, isolated_cwd):
        proc = run_guard({"tool_name": "Bash",
                          "tool_input": {"command":
                              "bash scripts/full_hunt.sh --target target.com"}},
                         cwd=isolated_cwd)
        assert proc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in proc.stderr.decode()

    def test_allows_valid_manifest_via_cli_flag(self, tmp_path):
        manifest = write_manifest(tmp_path)
        proc = run_guard({"tool_name": "rhodawk_hunt",
                          "tool_input": {"target": "shopify"}},
                         args=("--manifest", str(manifest)),
                         cwd=tmp_path)
        assert proc.returncode == 0, proc.stderr.decode()

    def test_allows_valid_manifest_via_tool_input(self, tmp_path):
        manifest = write_manifest(tmp_path)
        proc = run_guard({"tool_name": "rhodawk_recon",
                          "tool_input": {"target": "shopify",
                                         "manifest_path": str(manifest)}},
                         cwd=tmp_path)
        assert proc.returncode == 0, proc.stderr.decode()

    def test_allows_target_derived_manifest(self, tmp_path):
        # B-4: target-derived discovery anchors to $RHODAWK_HOME (the conftest
        # pins it per-test) — the manifest must be written THERE, not in the
        # CWD: a planted working-directory manifest can no longer self-authorize.
        write_manifest(Path(os.environ["RHODAWK_HOME"]), "shopify")
        proc = run_guard({"tool_name": "rhodawk_recon",
                          "tool_input": {"target": "shopify"}},
                         cwd=tmp_path)
        assert proc.returncode == 0, proc.stderr.decode()

    def test_allows_bash_command_carrying_scope_manifest(self, tmp_path):
        manifest = write_manifest(tmp_path, "target.com")
        proc = run_guard({"tool_name": "Bash",
                          "tool_input": {"command":
                              f"bash rhodawk/tools/recon_engine.sh target.com "
                              f"--scope-manifest {manifest}"}},
                         cwd=tmp_path)
        assert proc.returncode == 0, proc.stderr.decode()

    def test_allows_env_var_manifest(self, tmp_path):
        manifest = write_manifest(tmp_path)
        proc = run_guard({"tool_name": "rhodawk_hunt",
                          "tool_input": {"target": "shopify"}},
                         cwd=tmp_path,
                         env_extra={"RHODAWK_SCOPE_MANIFEST": str(manifest)})
        assert proc.returncode == 0, proc.stderr.decode()

    def test_blocks_tampered_manifest(self, tmp_path):
        # B-4: same data-home anchoring as the allow test — compile into
        # $RHODAWK_HOME, then tamper in place.
        manifest = write_manifest(Path(os.environ["RHODAWK_HOME"]), "shopify")
        # tamper: widen scope post-compilation without re-hashing
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["allow_patterns"] = ["*.evil.com"]
        manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")
        proc = run_guard({"tool_name": "rhodawk_recon",
                          "tool_input": {"target": "shopify"}},
                         cwd=tmp_path)
        assert proc.returncode == 2
        err = proc.stderr.decode()
        assert "SCOPE_HOOK_BLOCK" in err
        assert "integrity" in err.lower()

    def test_blocks_explicit_missing_manifest(self, tmp_path):
        proc = run_guard({"tool_name": "rhodawk_recon",
                          "tool_input": {"target": "shopify"}},
                         args=("--manifest", str(tmp_path / "nope.json")),
                         cwd=tmp_path)
        assert proc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in proc.stderr.decode()

    def test_blocks_ambiguous_multiple_manifests(self, tmp_path):
        write_manifest(tmp_path, "alpha")
        write_manifest(tmp_path, "beta")
        # active Bash call with no target arg and no explicit manifest
        proc = run_guard({"tool_name": "Bash",
                          "tool_input": {"command":
                              "bash rhodawk/tools/recon_engine.sh"}},
                         cwd=tmp_path)
        assert proc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in proc.stderr.decode()

    def test_blocks_active_mcp_hunt_without_manifest(self, isolated_cwd):
        proc = run_guard({"tool_name": "mcp__rhodawk-mcp__rhodawk_hunt",
                          "tool_input": {"target": "shopify"}},
                         cwd=isolated_cwd)
        assert proc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in proc.stderr.decode()

    def test_unparseable_stdin_treated_as_non_target(self, isolated_cwd):
        proc = run_guard(None, cwd=isolated_cwd)
        # empty stdin + no CLI tool override -> nothing to classify -> allow
        assert proc.returncode == 0
