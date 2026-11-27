"""Fix 3 red-to-green: the spray modules enforce a scope contract themselves.

Defect (rhodawk-blueprint.md gap #5 / mission item 3, README "Honest
Limitations"): `_spray_oauth.py` / `_spray_http_form.py` POST credentials to
whatever URL they are handed — spray_orchestrator.sh gates before spawning,
but the modules were byte-identical to upstream and runnable standalone with
NO internal scope check whatsoever.

Contract after the fix (strictly stronger than before, never weaker):
  - RHODAWK_SPRAY_SCOPE_MANIFEST / RHODAWK_SCOPE_MANIFEST (SHA-256 verified)
    must cover the target — out-of-scope ⇒ exit 3, ZERO requests;
  - no manifest ⇒ refuse (exit 3, 0 requests) unless RHODAWK_SPRAY_UNSAFE=1
    is explicitly set by the operator;
  - a tampered manifest ⇒ exit 3 (ScopeChecker.from_manifest fail-closed).
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from contracts.scope import CompiledScopeManifest  # noqa: E402

FORM_TOOL = REPO / "rhodawk" / "tools" / "_spray_http_form.py"
OAUTH_TOOL = REPO / "rhodawk" / "tools" / "_spray_oauth.py"

HITS = {"count": 0}


class _CountingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<form><input name="csrf" value="t"></form>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        HITS["count"] += 1
        body = b'{"access_token": "ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def target_server(tmp_path):
    HITS["count"] = 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/login"
    srv.shutdown()


def _manifest(tmp_path: Path, patterns: list[str]) -> str:
    m = CompiledScopeManifest(program_handle="t", allow_patterns=patterns)
    return str(m.save(str(tmp_path / "compiled_scope.json")))


def _run_spray(tool: Path, tmp_path: Path, url: str, extra_env: dict) -> subprocess.CompletedProcess:
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    users.write_text("victim@example.test\n", encoding="utf-8")
    passes.write_text("Winter2026!\n", encoding="utf-8")
    audit = tmp_path / "audit.jsonl"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SPRAY_TARGET_URL": url,
        "SPRAY_USERS_FILE": str(users),
        "SPRAY_PASSES_FILE": str(passes),
        "AUDIT_LOG": str(audit),
        "SPRAY_DELAY": "0",
        "SPRAY_JITTER": "0",
        "RHODAWK_HOME": str(tmp_path / "home"),
        "HOME": str(tmp_path / "home"),
    }
    env.update(extra_env)
    return subprocess.run([sys.executable, str(tool)], env=env,
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("tool", [FORM_TOOL, OAUTH_TOOL], ids=["http-form", "oauth"])
def test_no_manifest_no_optout_refused_zero_requests(tool, target_server, tmp_path):
    """THE defect: previously the module sprayed with no check at all."""
    proc = _run_spray(tool, tmp_path, target_server, {})
    assert proc.returncode == 3
    assert "SCOPE BLOCK" in proc.stderr
    assert HITS["count"] == 0, "spray fired WITHOUT any scope authority"


@pytest.mark.parametrize("tool", [FORM_TOOL, OAUTH_TOOL], ids=["http-form", "oauth"])
def test_in_scope_manifest_allows_run(tool, target_server, tmp_path):
    manifest = _manifest(tmp_path, ["127.0.0.1"])
    proc = _run_spray(tool, tmp_path, target_server,
                      {"RHODAWK_SPRAY_SCOPE_MANIFEST": manifest})
    assert proc.returncode == 0, f"stderr: {proc.stderr[-400:]}"
    assert "Scope gate: target inside verified manifest" in proc.stdout
    assert HITS["count"] > 0


@pytest.mark.parametrize("tool", [FORM_TOOL, OAUTH_TOOL], ids=["http-form", "oauth"])
def test_out_of_scope_manifest_blocks_zero_requests(tool, target_server, tmp_path):
    manifest = _manifest(tmp_path, ["example.test"])  # NOT 127.0.0.1
    proc = _run_spray(tool, tmp_path, target_server,
                      {"RHODAWK_SPRAY_SCOPE_MANIFEST": manifest})
    assert proc.returncode == 3
    assert "outside the verified scope manifest" in proc.stderr
    assert HITS["count"] == 0


@pytest.mark.parametrize("tool", [FORM_TOOL, OAUTH_TOOL], ids=["http-form", "oauth"])
def test_tampered_manifest_blocks(tool, target_server, tmp_path):
    manifest = _manifest(tmp_path, ["127.0.0.1"])
    raw = json.loads(Path(manifest).read_text(encoding="utf-8"))
    raw["allow_patterns"].append("evil.example.com")
    Path(manifest).write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
    proc = _run_spray(tool, tmp_path, target_server,
                      {"RHODAWK_SPRAY_SCOPE_MANIFEST": manifest})
    assert proc.returncode == 3
    assert HITS["count"] == 0


@pytest.mark.parametrize("tool", [FORM_TOOL, OAUTH_TOOL], ids=["http-form", "oauth"])
def test_explicit_unsafe_optout_runs_but_warns(tool, target_server, tmp_path):
    """RHODAWK_SPRAY_UNSAFE=1 keeps the tool usable without a manifest — an
    explicit, logged operator decision (strictly stronger than the old
    check-free behavior, never weaker)."""
    proc = _run_spray(tool, tmp_path, target_server,
                      {"RHODAWK_SPRAY_UNSAFE": "1"})
    assert proc.returncode == 0, f"stderr: {proc.stderr[-400:]}"
    assert "RHODAWK_SPRAY_UNSAFE=1" in proc.stderr
    assert HITS["count"] > 0


def test_orchestrator_forwards_verified_manifest(tmp_path):
    """Defense in depth: spray_orchestrator.sh exports the verified manifest
    so spawned modules re-verify it themselves."""
    src = (REPO / "rhodawk" / "tools" / "spray_orchestrator.sh").read_text(encoding="utf-8")
    assert 'export RHODAWK_SPRAY_SCOPE_MANIFEST="$_SCOPE_GATE_MANIFEST"' in src
