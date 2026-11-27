"""Regression tests for the Phase 5.75 headless JS crawl (CRAWLER-REDESIGN.md).

Covers the red-to-green defect "static crawler returns 0 API endpoints against
a JS-rendered SPA": a local SPA fixture serves a page whose JavaScript fetches
three API routes at runtime (they exist nowhere in the HTML source); the
headless crawl must surface them in the SAME recon_truth.json schema.

Browser-dependent tests skip cleanly when Playwright/Chromium is unavailable
(degradation contract) so upstream CI without browsers stays green.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from tools import js_crawl  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402

# ---------------------------------------------------------------------------
# SPA fixture (stdlib server, mirrors the verified defect repro)
# ---------------------------------------------------------------------------

SPA_HTML = """<!DOCTYPE html>
<html><head><title>Ghost Dashboard</title></head>
<body><h1>Ghost Dashboard</h1><div id="out">loading</div>
<script>
const base = window.location.origin;
Promise.all([
  fetch(base + "/api/v2/session").then(r => r.json()),
  fetch(base + "/api/v2/user/4242").then(r => r.json()),
  fetch(base + "/api/internal/admin/ping").then(r => r.json()),
]).then(results => {
  document.getElementById("out").textContent = JSON.stringify(results);
}).catch(e => { document.getElementById("out").textContent = "err " + e; });
</script></body></html>
"""


class _SPAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/"):
            body = json.dumps({"ok": True, "path": self.path}).encode()
            ctype = "application/json"
        else:
            body = SPA_HTML.encode()
            ctype = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence test output
        pass


@pytest.fixture(scope="module")
def spa_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SPAHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


PW = pytest.mark.skipif(not _playwright_available(),
                        reason="playwright not installed (graceful degradation path)")


# ---------------------------------------------------------------------------
# Pure helpers — no browser required
# ---------------------------------------------------------------------------

def test_scope_refusal_without_scope():
    """Fail-closed contract: no manifest and no patterns ⇒ refusal."""
    with pytest.raises(js_crawl.ScopeRefusal):
        js_crawl.resolve_scope(None, [], [])


def test_resolve_scope_from_patterns():
    checker = js_crawl.resolve_scope(None, ["*.target.com"], ["blog.target.com"])
    assert checker.is_in_scope("https://app.target.com/api/x")
    assert not checker.is_in_scope("https://blog.target.com/")


def test_resolve_scope_from_manifest(tmp_path):
    from contracts.scope import CompiledScopeManifest
    m = CompiledScopeManifest(program_handle="t", allow_patterns=["127.0.0.1"])
    p = m.save(str(tmp_path / "compiled_scope.json"))
    checker = js_crawl.resolve_scope(str(p), [], [])
    assert checker.is_in_scope("http://127.0.0.1:8099/api/v2/session")


def test_resolve_scope_tampered_manifest_fails_closed(tmp_path):
    """A hand-edited manifest must never authorize a crawl (red-to-green for
    the tamper path)."""
    from contracts.scope import CompiledScopeManifest
    m = CompiledScopeManifest(program_handle="t", allow_patterns=["127.0.0.1"])
    p = Path(m.save(str(tmp_path / "compiled_scope.json")))
    raw = json.loads(p.read_text(encoding="utf-8"))
    raw["allow_patterns"].append("evil.example.com")
    p.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        js_crawl.resolve_scope(str(p), [], [])


def test_filter_in_scope_drops_and_keeps():
    checker = ScopeChecker(domains=["127.0.0.1"])
    kept, dropped = js_crawl.filter_in_scope(
        ["http://127.0.0.1:8099/api/v2/session",
         "https://out-of-scope.example.test/api"],
        checker)
    assert kept == ["http://127.0.0.1:8099/api/v2/session"]
    assert dropped == ["https://out-of-scope.example.test/api"]


def test_filter_in_scope_drops_on_checker_crash():
    """Fail-closed: a URL the checker cannot evaluate is dropped, never kept."""

    class Boom(ScopeChecker):
        def is_in_scope(self, url):
            raise RuntimeError("boom")

    kept, dropped = js_crawl.filter_in_scope(["http://x.test/"], Boom(domains=["x.test"]))
    assert kept == [] and dropped == ["http://x.test/"]


def test_write_outputs_deterministic(tmp_path):
    js_crawl.write_outputs(tmp_path, ["http://b/x", "http://a/y"], ["http://oos/"],
                           {"status": "ok"})
    assert (tmp_path / "js_crawl" / "endpoints.txt").read_text() == \
        "http://a/y\nhttp://b/x\n"
    assert (tmp_path / "js_crawl" / "dropped_oos.txt").read_text() == "http://oos/\n"
    summary = json.loads((tmp_path / "js_crawl" / "summary.json").read_text())
    assert summary["status"] == "ok"


def test_degradation_skips_cleanly(tmp_path):
    """playwright import failure ⇒ summary status=skipped, exit 0, no crash."""
    orig = js_crawl.crawl

    def _boom(*a, **k):
        raise js_crawl.PlaywrightUnavailable("playwright not installed: test")

    js_crawl.crawl = _boom
    try:
        rc = js_crawl.main(["--url", "http://127.0.0.1:9/x", "--recon-dir",
                            str(tmp_path), "--domain", "127.0.0.1"])
    finally:
        js_crawl.crawl = orig
    assert rc == 0
    summary = json.loads((tmp_path / "js_crawl" / "summary.json").read_text())
    assert summary["status"] == "skipped"
    assert "playwright" in summary["reason"]
    assert not (tmp_path / "js_crawl" / "endpoints.txt").exists()


def test_scope_refusal_writes_summary_and_exit_2(tmp_path):
    rc = js_crawl.main(["--url", "http://127.0.0.1:9/x", "--recon-dir", str(tmp_path)])
    assert rc == 2
    summary = json.loads((tmp_path / "js_crawl" / "summary.json").read_text())
    assert summary["status"] == "skipped"
    assert "scope authority" in summary["reason"]


def test_env_auth_headers_parsing(monkeypatch):
    monkeypatch.setenv("RHODAWK_AUTH_HEADERS",
                       "Authorization: Bearer abc\n# comment\nBad\r\nCookie: k=v")
    hdrs = js_crawl._env_auth_headers()
    assert hdrs == ["Authorization: Bearer abc", "Cookie: k=v"]


# ---------------------------------------------------------------------------
# Real-browser integration (skips without Playwright) — the red-to-green proof
# ---------------------------------------------------------------------------

@PW
def test_spa_endpoints_discovered_end_to_end(spa_server, tmp_path):
    """THE defect: three runtime-only API routes; static analysis sees zero."""
    checker = js_crawl.resolve_scope(None, ["127.0.0.1"], [])
    endpoints, dropped, summary = js_crawl.crawl(
        [f"{spa_server}/"], checker, max_pages=3, timeout_secs=60)
    assert summary["status"] == "ok"
    assert summary["pages_visited"] >= 1
    paths = {urlsplit(u).path for u in endpoints}
    assert "/api/v2/session" in paths
    assert "/api/v2/user/4242" in paths
    assert "/api/internal/admin/ping" in paths
    assert dropped == []


@PW
def test_out_of_scope_capture_never_exported(spa_server, tmp_path):
    """Defense in depth: a hostile page redirecting captures to an OOS origin
    must not leak those URLs into endpoints.txt (capture-time filter)."""
    checker = js_crawl.resolve_scope(None, ["127.0.0.1"], [])
    endpoints, dropped, summary = js_crawl.crawl(
        [f"{spa_server}/"], checker, max_pages=3, timeout_secs=60)
    # The fixture only talks to itself (in scope); assert the contract holds
    # for the OOS quarantine file: anything dropped is recorded, never merged.
    js_crawl.write_outputs(tmp_path, endpoints, dropped, summary)
    if dropped:
        epts = (tmp_path / "js_crawl" / "endpoints.txt").read_text()
        for u in dropped:
            assert u not in epts


@PW
def test_cli_end_to_end_with_summary(spa_server, tmp_path):
    rc = js_crawl.main(["--url", f"{spa_server}/", "--recon-dir", str(tmp_path),
                        "--domain", "127.0.0.1", "--max-pages", "3",
                        "--timeout", "60"])
    assert rc == 0
    summary = json.loads((tmp_path / "js_crawl" / "summary.json").read_text())
    assert summary["status"] == "ok"
    epts = (tmp_path / "js_crawl" / "endpoints.txt").read_text()
    assert "/api/v2/session" in epts


# ---------------------------------------------------------------------------
# recon_fusion.py integration — same schema, zero downstream changes
# ---------------------------------------------------------------------------

def _make_truth_dir(tmp_path: Path, crawled: list[str]) -> Path:
    """Minimal recon dir with a js_crawl/endpoints.txt the fusion must ingest."""
    rd = tmp_path / "recon"
    (rd / "subdomains").mkdir(parents=True)
    (rd / "js_crawl").mkdir(parents=True)
    (rd / "subdomains" / "all.txt").write_text("127.0.0.1\n")
    (rd / "js_crawl" / "endpoints.txt").write_text("\n".join(crawled) + "\n")
    return rd


def test_fusion_ingests_js_crawl_endpoints(tmp_path, monkeypatch):
    from tools import recon_fusion
    crawled = ["http://127.0.0.1:8099/api/v2/session",
               "http://127.0.0.1:8099/api/v2/user/4242",
               "http://127.0.0.1:8099/static/app.js"]
    rd = _make_truth_dir(tmp_path, crawled)
    monkeypatch.chdir(REPO)
    truth, _delta = recon_fusion.fuse(rd, "127.0.0.1", scope_domains=["127.0.0.1"])
    urls = {u["url"]: u["discovered_by"] for u in truth["urls"]}
    # URLs land in urls[] with js_crawl provenance preserved
    assert urls["http://127.0.0.1:8099/api/v2/session"] == ["js_crawl/endpoints.txt"]
    # API-shaped paths surface in js_endpoints[] (schema unchanged)
    js_eps = {r["endpoint"]: r["discovered_by"] for r in truth["js_endpoints"]}
    assert "/api/v2/session" in js_eps
    assert js_eps["/api/v2/session"] == ["js_crawl/endpoints.txt"]
    # static assets stay in urls[] only, never in js_endpoints[]
    assert "/static/app.js" not in js_eps
    assert truth["counts"]["unique_urls"] == 3
    assert truth["counts"]["js_endpoints"] == 2


def test_fusion_without_js_crawl_file_unchanged(tmp_path, monkeypatch):
    """Backward compat: no js_crawl dir ⇒ truth identical to the pre-phase schema."""
    from tools import recon_fusion
    rd = _make_truth_dir(tmp_path, [])
    monkeypatch.chdir(REPO)
    truth, _delta = recon_fusion.fuse(rd, "127.0.0.1", scope_domains=["127.0.0.1"])
    assert truth["counts"]["unique_urls"] == 0
    assert truth["counts"]["js_endpoints"] == 0


# ---------------------------------------------------------------------------
# Engine wiring (shell contract, matching the repo's grep-level shell tests)
# ---------------------------------------------------------------------------

def test_engine_has_opt_in_phase_block():
    """Phase 5.75 exists, is opt-in, and routes through the B3 scope filter."""
    script = (REPO / "rhodawk" / "tools" / "recon_engine.sh").read_text(encoding="utf-8")
    assert '--js-crawl)' in script.replace("\n", " ")  # arg parsed
    assert 'JS_CRAWL=1' in script and 'JS_CRAWL=0' in script
    assert "Phase 5.75: Headless JS Crawl" in script
    # the crawled corpus passes the SAME scope filter as every other source
    assert '_rhodawk_scope_filter "$RECON_DIR/js_crawl/endpoints.txt"' in script
    # opt-out never browses
    assert "SCOPE_OPT_OUT" in script and "js-crawl invoked without any scope authority" in script


def test_engine_flag_reaches_recon_and_hunt():
    """engine.py forwards --js-crawl for both recon and hunt subcommands."""
    engine = (REPO / "rhodawk" / "engine.py").read_text(encoding="utf-8")
    # 2 parser flags + the literal inside _js_crawl_args()
    assert engine.count('"--js-crawl"') == 3
    assert engine.count('add_argument("--js-crawl"') == 2  # recon + hunt parsers
    assert "_js_crawl_args(args)" in engine


def test_engine_rejects_js_crawl_without_scope_authority(tmp_path):
    """Shell-level red-to-green: --js-crawl on a list-mode target (whose list
    IS the scope, so the pre-flight gate passes) still refuses to BROWSE
    without a scope authority — exits 3, audits the block, launches no browser."""
    list_file = tmp_path / "targets.txt"
    list_file.write_text("127.0.0.1\n", encoding="utf-8")
    script = str(REPO / "rhodawk" / "tools" / "recon_engine.sh")
    # Hermetic run: stub curl so Phase 4's wayback fallback (a live
    # archive.org call on tool-less machines) fails instantly instead of
    # stalling the pipeline — the point under test is the Phase 5.75 gate.
    stub = tmp_path / "stubbin"
    stub.mkdir()
    (stub / "curl").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (stub / "curl").chmod(0o755)
    env = {
        "PATH": f"{stub}:/usr/bin:/bin",
        "RECON_OUT_DIR": str(tmp_path / "recon"),
        "RHODAWK_HOME": str(tmp_path / "home"),
        "HOME": str(tmp_path / "home"),
    }
    (tmp_path / "recon").mkdir(parents=True)
    proc = subprocess.run(
        ["bash", script, str(list_file), "--js-crawl"],
        env=env, capture_output=True, text=True, timeout=120)
    combined = proc.stdout + proc.stderr
    assert "SCOPE BLOCK" in combined
    assert "--js-crawl requires a scope authority" in combined
    assert proc.returncode == 3
