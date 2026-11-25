"""MCP self-authorization transparency (DD follow-up).

rhodawk_run_rtw_capability lets the MCP CALLER supply scope_domains
(server.py POLICY.set_scope(scope_domains or [target])) — the server
trusts the caller's scope declaration. Behavior is unchanged by design,
but the caller-supplied scope must be (a) documented and (b) logged to
the audit log.
"""

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_DIR = REPO_ROOT / "rhodawk" / "mcp" / "rhodawk-mcp"


def _load_server():
    for p in (str(REPO_ROOT), str(MCP_DIR)):
        if p not in sys.path:
            sys.path.insert(0, p)
    # unique module name: other MCP tests import a *different* server.py
    # (hackerone-mcp) under the plain "server" name — never reuse that cache
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rhodawk_mcp_server", MCP_DIR / "server.py")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit as exc:
        # server.py exits with its own guarded error when the installed
        # `mcp` SDK predates the MCPServer API (repo pins mcp>=2.2.0). That
        # is purely an upstream SDK-version mismatch, not a bug in the code
        # under test — skip (same pattern as tests/test_mcp_rtw.py) instead
        # of failing. The audited function is a pure audit-log writer.
        pytest.skip(f"mcp MCPServer API unavailable in this environment: {exc}")
    return mod


def test_docs_mcp_documents_caller_supplied_scope():
    docs = (REPO_ROOT / "docs" / "mcp.md").read_text()
    assert "scope_domains" in docs
    assert "caller" in docs.lower()
    assert "self-author" in docs.lower() or "trusts the caller" in docs.lower()


def test_caller_supplied_scope_logged_to_audit(tmp_path, monkeypatch):
    server = _load_server()
    audit = tmp_path / "hunt-memory" / "audit.jsonl"
    monkeypatch.setenv("RHODAWK_AUDIT_FILE", str(audit))
    server._audit_caller_scope(
        "rhodawk_run_rtw_capability", "CAP_DNS_PERMUT",
        "target.goodscope.example", ["*.goodscope.example"])
    entry = json.loads(audit.read_text().splitlines()[-1])
    assert entry["caller_scope_domains"] == ["*.goodscope.example"]
    assert entry["capability_id"] == "CAP_DNS_PERMUT"
    assert "rhodawk_run_rtw_capability" in entry["error"]


def test_audit_failure_never_raises(tmp_path, monkeypatch):
    server = _load_server()
    monkeypatch.setenv("RHODAWK_AUDIT_FILE",
                       str(tmp_path / "nope" / "dir" / "audit.jsonl"))
    # parent dir does not exist and cannot be created (file in the way)
    blocker = tmp_path / "nope"
    blocker.write_text("not a dir")
    server._audit_caller_scope("t", "CAP_X", "x.example", ["*.x.example"])
