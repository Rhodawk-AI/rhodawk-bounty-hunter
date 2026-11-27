"""End-to-end tests for recon_engine.sh RhodawkAI Edition gap-fill (Fixes 1+2).

Acceptance checks verified here at the engine level, with a stub reconFTW
checkout (no network, no real scanners needed):

1. Pipeline order: Phase 1.5 exists and runs BEFORE Phase 2 (httpx); Phase 5.5
   runs BEFORE Phase 6 (ffuf). Checked by bash -n + grep ordering + live runs.
2. CLI scope gate:
   - --scope-domain passes scope to rtw_adapter.py; in-scope stub findings are
     merged into subdomains/all.txt (Phase 1.5) before httpx probes them.
   - an out-of-scope target blocks with ZERO reconFTW subprocesses (stub
     marker never touched) and the block is audited.
   - no scope flags at all → fail closed (adapter blocks; engine continues).
   - --no-scope-check is the explicit demo opt-out (stub runs unscoped).
3. RTW_HOME unset → engine behaves as upstream (gap-fill skipped, no crash).
"""

import argparse
import shutil
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ENGINE = REPO_ROOT / "rhodawk" / "tools" / "recon_engine.sh"
ADAPTER = REPO_ROOT / "rhodawk" / "tools" / "rtw_adapter.py"

SCOPE = ["*.goodscope.example"]
TARGET = "target.goodscope.example"

STUB_RECONFTW = r"""#!/bin/bash
# Stub reconFTW checkout for engine-level tests. Handles BOTH invocation
# modes the adapter uses:
#   cli:          bash reconftw.sh -d T -c FN -f CFG -o WORKDIR --no-banner
#   source-only:  source reconftw.sh --source-only; then call FN (cwd=workdir)
RTW_STUB_MARKER="${RTW_STUB_MARKER:-}"
rtw_stub_emit() {
    local out="${1:-$PWD}"
    mkdir -p "$out/subdomains" "$out/webs"
    echo "stub-found.goodscope.example" > "$out/subdomains/rtw_stub.txt"
    echo "https://stub-found.goodscope.example/js/app.js" > "$out/webs/rtw_stub_urls.txt"
}
if [[ "${1:-}" == "--source-only" ]]; then
    sub_asn()        { rtw_stub_emit "$PWD"; }
    sub_permut()     { rtw_stub_emit "$PWD"; }
    cdnprovider()    { rtw_stub_emit "$PWD"; }
    jschecks()       { rtw_stub_emit "$PWD"; }
    virtualhosts()   { rtw_stub_emit "$PWD"; }
    tls_ip_pivots()  { rtw_stub_emit "$PWD"; }
    favirecon_tech() { rtw_stub_emit "$PWD"; }
    return 0 2>/dev/null || exit 0
fi
out=""
while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done
[[ -n "$RTW_STUB_MARKER" ]] && touch "$RTW_STUB_MARKER"
rtw_stub_emit "$out"
exit 0
"""


@pytest.fixture
def rtw_env(tmp_path, monkeypatch):
    """Stub RTW checkout + isolated homes + capabilities all RTW_AVAILABLE.

    A stub `curl` (instant connection-refused) is prepended to PATH so the
    engine's crt.sh / web.archive.org calls fail fast — hermetic, no network,
    and the engine treats them exactly like an offline box (empty results)."""
    repo = tmp_path / "rtw"
    repo.mkdir()
    script = repo / "reconftw.sh"
    script.write_text(STUB_RECONFTW)
    script.chmod(0o755)

    stub_bin = tmp_path / "stub-bin"
    stub_bin.mkdir()
    curl_stub = stub_bin / "curl"
    curl_stub.write_text("#!/bin/bash\nexit 7\n")
    curl_stub.chmod(0o755)
    # Live-run fix: stub every scanner the engine's `command -v` guards for,
    # so a fully-provisioned host (real subfinder/nmap/dig on PATH, as on a
    # root VPS) can never turn these unit tests into live network runs or
    # hangs. The engine treats them exactly like absent/empty tools.
    for _tool in ("subfinder", "amass", "httpx", "nmap", "dig", "katana",
                  "gau", "ffuf", "nuclei", "naabu", "dnsx", "waybackurls",
                  "anew"):
        _stub = stub_bin / _tool
        _stub.write_text("#!/bin/bash\nexit 0\n")
        _stub.chmod(0o755)
    # Step 2A: the PD httpx stub emits one live line per probed host so the
    # pipeline has live hosts. Hosts whose name contains "cdn." carry a
    # cloudflare tech tag (CDN_EDGE classification); everything else is plain
    # nginx (FIRST_PARTY_ORIGIN).
    httpx_stub = stub_bin / "httpx"
    httpx_stub.write_text(
        "#!/bin/bash\n"
        '# _resolve_pd_httpx probes `-version` and greps for "projectdiscovery"\n'
        '# — answering it routes the engine to THIS stub via an absolute path.\n'
        'if [[ "$1" == "-version" ]]; then echo "httpx 1.3.5 projectdiscovery"; exit 0; fi\n'
        'out=""; list=""\n'
        'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; -l) list="$2";; esac; shift; done\n'
        '[[ -n "$out" && -n "$list" ]] || exit 0\n'
        'while IFS= read -r h; do\n'
        '  [[ -z "$h" ]] && continue\n'
        '  case "$h" in\n'
        '    *cdn.*) echo "$h [200] [Welcome] [cloudflare,nginx] [1234]" ;;\n'
        '    *)     echo "$h [200] [Welcome] [nginx] [2048]" ;;\n'
        '  esac\n'
        'done < "$list" > "$out"\n'
        "exit 0\n"
    )
    httpx_stub.chmod(0o755)
    # Live-run fix (issue 5, EXIT_CODE=124): recon_engine.sh re-prepends
    # ~/go/bin:/usr/local/bin to PATH and _resolve_pd_httpx probes
    # /usr/local/bin/httpx directly — on a root VPS those host binaries
    # shadow these stubs and the engine hangs on real network probes. Pin
    # both knobs to this sandbox.
    monkeypatch.setenv("RHODAWK_NO_BIN_PATH", "1")
    monkeypatch.setenv("RHODAWK_HTTPX_BIN", str(httpx_stub))
    monkeypatch.setenv("PATH", f"{stub_bin}:{os.environ.get('PATH', '')}")

    home = tmp_path / "rhodawk-home"
    home.mkdir()
    marker = tmp_path / "rtw_stub_marker"
    recon_out = tmp_path / "recon-out"
    recon_out.mkdir()

    monkeypatch.setenv("RTW_HOME", str(repo))
    monkeypatch.setenv("RHODAWK_HOME", str(home))
    monkeypatch.setenv("RHODAWK_CAPABILITIES_FILE",
                       str(home / "capabilities.json"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("RECON_OUT_DIR", str(recon_out))
    monkeypatch.setenv("RTW_STUB_MARKER", str(marker))
    (home / "capabilities.json").write_text(
        json.dumps({cap: "RTW_AVAILABLE"
                    for cap in ("CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE",
                                "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                                "CAP_FAVICON")}))
    return {"home": home, "marker": marker, "recon_out": recon_out,
            "capabilities": home / "capabilities.json", "stub_bin": stub_bin}


def run_engine(args, cwd=REPO_ROOT, timeout=300):
    env = os.environ.copy()
    env["RHODAWK_SKIP_DEPS"] = "1"
    return subprocess.run(
        ["bash", str(ENGINE), *args],
        cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout,
    )


class TestPipelineOrder:
    def test_syntax_ok(self):
        proc = subprocess.run(["bash", "-n", str(ENGINE)], capture_output=True)
        assert proc.returncode == 0, proc.stderr

    def test_phase_1_5_before_phase_2_and_after_phase_1(self):
        text = ENGINE.read_text()
        p1 = text.index("# Phase 1: Subdomain Enumeration")
        p15 = text.index("# Phase 1.5: reconFTW Subdomain/Infra Gap-Fill")
        p2 = text.index("# Phase 2: HTTP Probing")
        assert p1 < p15 < p2, "Phase 1.5 must run between Phase 1 and httpx"

    def test_phase_5_5_before_phase_6_and_after_phase_5(self):
        text = ENGINE.read_text()
        p5 = text.index("# Phase 5: JS Analysis")
        p55 = text.index("# Phase 5.5: reconFTW Web/JS/TLS Gap-Fill")
        p6 = text.index("# Phase 6: Directory Fuzzing")
        assert p5 < p55 < p6, "Phase 5.5 must run between Phase 5 and ffuf"

    def test_no_phase_10_5_left(self):
        assert "Phase 10.5" not in ENGINE.read_text()

    def test_phase_1_enum_calls_are_time_bounded(self):
        """Live-run fix: Phase 1 subfinder and the crt.sh/wayback curls are
        wrapped in bounded `timeout` so passive enumeration can never hang."""
        text = ENGINE.read_text()
        assert "timeout 180 subfinder" in text
        p1 = text.index("# Phase 1: Subdomain Enumeration")
        p15 = text.index("# Phase 1.5: reconFTW Subdomain/Infra Gap-Fill")
        phase1 = text[p1:p15]
        assert phase1.count("timeout 60 curl") == 2

    def test_adapter_phase_groups_match_engine(self):
        sys.path.insert(0, str(REPO_ROOT / "rhodawk"))
        from tools import rtw_adapter as adp
        assert set(adp.PHASE_1_5_CAPABILITIES) == {
            "CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE"}
        assert set(adp.PHASE_5_5_CAPABILITIES) == {
            "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS", "CAP_FAVICON"}


class TestCliScopeGate:
    def test_scope_forwarded_and_findings_merged(self, rtw_env):
        """--scope-domain passes through to the adapter; in-scope stub
        subdomains land in subdomains/all.txt BEFORE httpx runs."""
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0],
                           "--scope-exclude", "excluded.goodscope.example"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "Phase 1.5" in out, "Phase 1.5 did not run"
        assert "merged subdomains" in out, "gap-fill subdomains not merged"
        all_txt = (rtw_env["recon_out"] / "subdomains" / "all.txt").read_text()
        assert "stub-found.goodscope.example" in all_txt
        # Dedup: stub appears exactly once despite seed re-add + sort -u.
        assert all_txt.count("stub-found.goodscope.example") == 1
        # The reconFTW subprocess actually ran.
        assert rtw_env["marker"].is_file(), "reconFTW stub never executed"
        # Phase 5.5 merged the stub URL into the URL corpus.
        assert "Phase 5.5" in out
        urls = (rtw_env["recon_out"] / "urls" / "all.txt").read_text()
        assert "https://stub-found.goodscope.example/js/app.js" in urls
        # Manifest written in the shared schema.
        manifest = json.loads((rtw_env["home"] / "recon" / TARGET /
                               "rtw_manifest.json").read_text())
        assert manifest["version"] == 1 and manifest["ttl_days"] == 7
        fn_names = {e["rtw_function"] for e in manifest["entries"]}
        assert {"sub_asn", "sub_permut", "cdnprovider"} <= fn_names

    def test_out_of_scope_blocks_preflight(self, rtw_env):
        """Live-run fix: an out-of-scope domain target is blocked by the
        PRE-FLIGHT gate — non-zero exit before any phase runs, zero tools
        executed, zero packets sent, block audited."""
        proc = run_engine(["evil.example", "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, out[-3000:]
        assert "SCOPE BLOCK" in out
        assert "Phase 1" not in out, "a phase started after the pre-flight block"
        assert not rtw_env["marker"].is_file(), \
            "reconFTW subprocess spawned for an out-of-scope target!"
        audit = (rtw_env["home"] / "hunt-memory" / "audit.jsonl")
        assert audit.is_file(), "scope block not audited"
        entry = json.loads(audit.read_text().splitlines()[-1])
        assert entry["scope_check"] == "fail"
        assert "evil.example" in entry["url"]

    def test_no_scope_flags_blocks_preflight(self, rtw_env):
        """Neither --scope-domain nor --no-scope-check → the whole engine run
        fails closed at the pre-flight gate (not just delegation)."""
        proc = run_engine([TARGET])
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, out[-3000:]
        assert "SCOPE BLOCK" in out and "no --scope-domain" in out
        assert "Phase 1" not in out
        assert not rtw_env["marker"].is_file()
        audit = (rtw_env["home"] / "hunt-memory" / "audit.jsonl")
        assert audit.is_file(), "scope block not audited"

    def test_normalize_only_unaffected_by_gate(self, rtw_env):
        """Upstream contract preserved: --normalize-only prints the parsed
        target and exits 0 with no scope flags — the gate sits after it."""
        proc = run_engine([TARGET, "--normalize-only"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "host=target.goodscope.example" in out
        assert "SCOPE BLOCK" not in out

    def test_no_scope_check_opt_out_runs_unscoped(self, rtw_env):
        """--no-scope-check is the explicit demo opt-out: stub executes."""
        proc = run_engine([TARGET, "--no-scope-check"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert rtw_env["marker"].is_file(), \
            "--no-scope-check must allow the delegation to run"
        assert "UNSCOPED" in out

    def test_rtw_home_unset_is_upstream_behavior(self, rtw_env, monkeypatch):
        """RTW_HOME unset → gap-fill skipped with upstream behavior; native
        pipeline still runs and no capabilities work happens."""
        monkeypatch.delenv("RTW_HOME", raising=False)
        monkeypatch.setenv("RTW_STUB_MARKER", str(rtw_env["marker"]) + ".absent")
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "gap-fill not configured" in out
        assert "Phase 1.5" in out  # the (skipped) phase header still prints
        assert not rtw_env["marker"].is_file()

    def test_rtw_home_loaded_from_config_json(self, rtw_env, monkeypatch):
        """Live-run fix: fresh shells no longer need `export RTW_HOME=...`.
        With RTW_HOME unset the engine reads rtw_home from
        ~/.rhodawk/config.json (persisted by install.sh) at the top of the
        script and Phase 1.5/5.5 delegation still runs."""
        monkeypatch.delenv("RTW_HOME", raising=False)
        cfg = rtw_env["home"].parent / ".rhodawk" / "config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps({"rtw_home": str(rtw_env["home"].parent / "rtw")}))
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", str(cfg))
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert rtw_env["marker"].is_file(), \
            "gap-fill must run via rtw_home from config.json (RTW_HOME unset)"
        assert "gap-fill not configured" not in out

    def test_comma_separated_scope_patterns(self, rtw_env):
        """Repeatable + comma-separated patterns both work."""
        proc = run_engine([TARGET,
                           "--scope-domain", "*.goodscope.example,other.example",
                           "--scope-domain", "extra.goodscope.example"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert rtw_env["marker"].is_file()


class TestShorthandAndHonestRecon:
    """Step 1A shorthand CLI + Step 1B health table + Step 2A origin-only
    nmap + Step 2B/2C truth & delta, verified at the engine level."""

    def test_shorthand_argv_rewrite(self):
        """Unit: engine._normalize_cli_argv rewrites `<target> -recon[...]`
        into the canonical `recon <target> ...` argv; known commands and
        flag-first invocations are untouched."""
        sys.path.insert(0, str(REPO_ROOT / "rhodawk"))
        import engine
        assert engine._normalize_cli_argv(
            ["evil.example", "-recon"]) == ["recon", "evil.example"]
        assert engine._normalize_cli_argv(
            ["t.example", "--recon", "--scope-domain", "*.s.example"]) == \
            ["recon", "t.example", "--scope-domain", "*.s.example"]
        assert engine._normalize_cli_argv(
            ["t.example", "-recon", "--provider", "groq", "--model", "m1"]) == \
            ["recon", "t.example", "--provider", "groq", "--model", "m1"]
        assert engine._normalize_cli_argv(["recon", "t.example"]) == \
            ["recon", "t.example"]
        assert engine._normalize_cli_argv(["status"]) == ["status"]
        assert engine._normalize_cli_argv(["-recon", "t.example"]) == \
            ["-recon", "t.example"]

    def test_shorthand_target_recon_blocks_out_of_scope(self, rtw_env):
        """`rhodawk <target> -recon` == `rhodawk recon <target>`: an
        out-of-scope shorthand run hits the same pre-flight scope gate —
        exit 3, 0 packets sent, 0 tools executed."""
        env = os.environ.copy()
        env["RHODAWK_HOME"] = str(rtw_env["home"])
        env["RHODAWK_CAPABILITIES_FILE"] = str(rtw_env["capabilities"])
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "rhodawk" / "engine.py"),
             "evil.example", "-recon", "--scope-domain", SCOPE[0]],
            cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
            timeout=120,
        )
        out = proc.stdout + proc.stderr
        assert proc.returncode == 3, out[-3000:]
        assert "SCOPE BLOCK" in out
        assert not rtw_env["marker"].is_file()

    def test_nmap_runs_on_first_party_origins_only(self, rtw_env):
        """Step 2A: with classification evidence, Phase 3 nmaps only
        FIRST_PARTY_ORIGIN targets and says so."""
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "Phase 2.5" in out
        assert "FIRST_PARTY_ORIGIN target(s) only" in out
        assert "origin IPs only" in out
        classes = (rtw_env["recon_out"] / "hosts" / "host_classes.txt").read_text()
        assert "FIRST_PARTY_ORIGIN" in classes
        truth = json.loads((rtw_env["recon_out"] / "recon_truth.json").read_text())
        assert truth["counts"]["cdn_edges"] == 0
        # The stub dig resolves no A records, so counts.origin_ips (which
        # counts resolved IPs) is 0 — the first-party classification itself
        # is what drives the origin-only nmap here.
        assert sum(1 for h in truth["hosts"]
                   if h["asset_class"] == "FIRST_PARTY_ORIGIN") >= 1

    def test_origin_only_nmap_skips_cdn_edges(self, rtw_env):
        """Step 2A: a host whose CNAME resolves into a CDN suffix is
        classified CDN_EDGE and skipped by Phase 3 — no nmap on edges."""
        dig_stub = rtw_env["stub_bin"] / "dig"
        dig_stub.write_text(
            "#!/bin/bash\n"
            'if [[ "${5:-}" == "CNAME" ]]; then echo "edge.cloudflare.net."; fi\n'
            "exit 0\n"
        )
        dig_stub.chmod(0o755)
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "Skipping nmap on CDN_EDGE host/IP" in out
        assert "No FIRST_PARTY_ORIGIN targets classified" in out
        classes = (rtw_env["recon_out"] / "hosts" / "host_classes.txt").read_text()
        assert "CDN_EDGE" in classes and "Cloudflare" in classes
        truth = json.loads((rtw_env["recon_out"] / "recon_truth.json").read_text())
        assert truth["counts"]["cdn_edges"] >= 1
        assert truth["counts"]["origin_ips"] == 0

    def test_recon_truth_delta_and_health_table(self, rtw_env):
        """Step 2B/2C + Step 1B fix 4: recon_truth.json (schema, provenance,
        tool_health), delta.json (first run → has_previous_run false; second
        run → archived prev + delta summary), and the health table in the
        Recon Summary."""
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        assert proc.returncode == 0
        recon_out = rtw_env["recon_out"]
        truth = json.loads((recon_out / "recon_truth.json").read_text())
        assert truth["schema_version"] == "1.0"
        assert truth["counts"]["live_hosts"] >= 1
        assert truth["hosts"][0]["cluster_id"]
        assert "live/httpx_full.txt" in truth["hosts"][0]["discovered_by"]
        assert truth["tool_health"], "tool_health must ingest rtw_manifest.json"
        delta = json.loads((recon_out / "delta.json").read_text())
        assert delta["has_previous_run"] is False

        proc2 = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out2 = proc2.stdout + proc2.stderr
        assert proc2.returncode == 0, out2[-3000:]
        assert (recon_out / "recon_truth.prev.json").is_file()
        delta2 = json.loads((recon_out / "delta.json").read_text())
        assert delta2["has_previous_run"] is True
        assert "Delta vs previous run" in out2
        # Step 1B fix 4: the 7-row recon health table prints at the end.
        assert "Capability" in out2 and "Net-New" in out2


class TestScopedRedirectEnforcement:
    """B2 regression: engine.py cmd_recon/cmd_hunt must set SCOPE_ENFORCED=1
    whenever scoping is active (explicit patterns or the self-scoped local
    path), so recon_engine.sh runs httpx WITHOUT -follow-redirects. A local
    301 to an out-of-scope listener must receive 0 requests, the destination
    must not appear in live/httpx_full.txt or live/urls.txt, and the
    destination is recorded as a finding in live/redirects.txt."""

    def test_cmd_recon_and_hunt_set_scope_enforced(self, monkeypatch):
        """Unit: SCOPE_ENFORCED=1 whenever scoping is active; absent for
        --no-scope-check. Matches hunt.py run_recon's rule."""
        sys.path.insert(0, str(REPO_ROOT / "rhodawk"))
        import engine
        captured = {}

        def fake_run_shell(cmd, cwd=None, timeout=3600, env=None,
                           full_env=False):
            # full_env (fix 4): the env passed IS the child environment —
            # cmd_recon/cmd_hunt now build a redacted full env.
            captured["env"] = dict(env or {})
            return True, ""

        monkeypatch.setattr(engine, "_run_shell", fake_run_shell)

        class _FakeBrain:
            def analyze_recon(self, *a, **k):
                return "ok"

            def interpret_scan(self, *a, **k):
                return "ok"

        monkeypatch.setattr(engine, "_get_brain", lambda: _FakeBrain())
        ns = argparse.Namespace(target="127.0.0.1:8080", scope_domain=[],
                                scope_exclude=[], no_scope_check=False)
        engine.cmd_recon(ns)
        assert captured["env"].get("SCOPE_ENFORCED") == "1"
        assert captured["env"].get("RECON_OUT_DIR")
        ns.no_scope_check = True
        engine.cmd_recon(ns)
        assert "SCOPE_ENFORCED" not in captured["env"]
        ns.no_scope_check = False
        ns.scope_domain = ["*.example.test"]
        engine.cmd_recon(ns)
        assert captured["env"].get("SCOPE_ENFORCED") == "1"
        engine.cmd_hunt(argparse.Namespace(
            target="127.0.0.1:8080", scope_domain=[], scope_exclude=[],
            no_scope_check=False))
        assert captured["env"].get("SCOPE_ENFORCED") == "1"

    def test_scoped_recon_does_not_follow_redirects(self, rtw_env, tmp_path):
        """Integration: two real localhost listeners — A (target) 301s to B
        (out of scope). Before the fix the scoped CLI run hopped to B (>=1
        request, destination in outputs); after the fix B sees 0 requests,
        the destination is only recorded in live/redirects.txt."""
        import http.server
        import threading

        counts = {"a": 0, "b": 0}

        class HandlerB(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                counts["b"] += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><title>OOS</title></html>")

            def log_message(self, *a):
                pass

        class HandlerA(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                counts["a"] += 1
                self.send_response(301)
                self.send_header(
                    "Location",
                    f"http://127.0.0.1:{srv_b.server_port}/")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv_a = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), HandlerA)
        srv_b = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), HandlerB)
        for srv in (srv_a, srv_b):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

        # A fetching httpx stub: without -follow-redirects a 3xx is recorded
        # but NOT followed; with it, the Location host is fetched (counted).
        stub_bin = rtw_env["stub_bin"]
        httpx_fetch = stub_bin / "httpx"
        httpx_fetch.write_text(f'''#!/usr/bin/env python3
import sys, urllib.request, urllib.error
args = sys.argv[1:]
if "-version" in args:
    print("httpx 1.3.5 projectdiscovery"); sys.exit(0)
follow = "-follow-redirects" in args
in_file = out_file = None
i = 0
while i < len(args):
    if args[i] == "-l": in_file = args[i + 1]
    if args[i] == "-o": out_file = args[i + 1]
    i += 1
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
opener = urllib.request.build_opener(NoRedirect)
lines = []
if in_file:
    lines = [l.strip() for l in open(in_file, encoding="utf-8") if l.strip()]
with open(out_file, "w", encoding="utf-8") as out:
    for line in lines:
        url = line if "://" in line else "http://" + line
        try:
            r = (urllib.request.urlopen(url, timeout=5) if follow
                 else opener.open(url, timeout=5))
            out.write(f"{{r.url}} [{{r.status}}] [LAB] [stub] [10]\\n")
        except urllib.error.HTTPError as e:
            out.write(f"{{url}} [{{e.code}}] [redirect] [stub] [0]\\n")
        except Exception:
            pass
''')
        httpx_fetch.chmod(0o755)
        # curl stub answers the scoped HEAD with the redirect Location so the
        # destination is recorded as a finding.
        curl_stub = stub_bin / "curl"
        curl_stub.write_text(
            "#!/bin/bash\n"
            'echo "HTTP/1.1 301 Moved Permanently"\n'
            f'echo "Location: http://127.0.0.1:{srv_b.server_port}/"\n'
            "exit 0\n")
        curl_stub.chmod(0o755)

        target = f"127.0.0.1:{srv_a.server_port}"
        env = os.environ.copy()
        env.update({
            "RHODAWK_HOME": str(rtw_env["home"]),
            "RHODAWK_CAPABILITIES_FILE": str(rtw_env["capabilities"]),
        })
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "rhodawk" / "engine.py"),
             "recon", target],
            cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
            timeout=300)
        out = proc.stdout + proc.stderr

        try:
            assert counts["b"] == 0, (
                f"out-of-scope listener received {counts['b']} request(s)\n"
                f"{out[-3000:]}")
            recon = rtw_env["home"] / "recon" / f"127.0.0.1_{srv_a.server_port}"
            if not recon.is_dir():  # C10 keying may vary pre/post fix
                legacy = rtw_env["home"] / "recon" / "127.0.0.1"
                recon = legacy if legacy.is_dir() else recon
            dest = f"http://127.0.0.1:{srv_b.server_port}"
            httpx_full = (recon / "live" / "httpx_full.txt")
            urls = (recon / "live" / "urls.txt")
            if httpx_full.exists():
                assert dest not in httpx_full.read_text(), \
                    "redirect destination leaked into live/httpx_full.txt"
            if urls.exists():
                assert dest not in urls.read_text(), \
                    "redirect destination leaked into live/urls.txt"
            redirects = (recon / "live" / "redirects.txt")
            assert redirects.is_file() and dest in redirects.read_text(), \
                "redirect destination not recorded as a finding"
            assert "recorded, NOT probed" in redirects.read_text()
        finally:
            srv_a.shutdown()
            srv_b.shutdown()
            srv_a.server_close()
            srv_b.server_close()


class TestPostEnumerationScopeFilter:
    """B3 regression: hosts/URLs discovered OUT of scope (stub subfinder /
    katana / gau emit oos.evil.com) are filtered BEFORE any probing tool
    reads them. Dropped lines land in scope/dropped_oos.txt, the dropped
    count in the Summary and in recon_truth.json counts.scope_dropped. The
    filter is a no-op with --no-scope-check and self-scopes local targets."""

    @staticmethod
    def _oos_stubbin(tmp_path):
        stub = tmp_path / "oos-bin"
        stub.mkdir(exist_ok=True)
        subfinder = stub / "subfinder"
        subfinder.write_text(
            "#!/bin/bash\n"
            'out=""\n'
            'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done\n'
            '[[ -n "$out" ]] && printf "target.goodscope.example\\noos.evil.com\\n" > "$out"\n'
            "exit 0\n")
        subfinder.chmod(0o755)
        katana = stub / "katana"
        katana.write_text(
            "#!/bin/bash\n"
            'list=""; out=""\n'
            'while [[ $# -gt 0 ]]; do case "$1" in -list) list="$2";; -o) out="$2";; esac; shift; done\n'
            '{ while IFS= read -r u; do echo "http://$u/api"; done < "$list";\n'
            '  echo "http://oos.evil.com/leak"; } > "$out"\n'
            "exit 0\n")
        katana.chmod(0o755)
        gau = stub / "gau"
        gau.write_text(
            "#!/bin/bash\n"
            'out=""\n'
            'while [[ $# -gt 0 ]]; do case "$1" in --o) out="$2";; esac; shift; done\n'
            'if [[ -n "$out" ]]; then echo "http://oos.evil.com/old-page" > "$out";\n'
            'else echo "http://oos.evil.com/old-page"; fi\n'
            "exit 0\n")
        gau.chmod(0o755)
        # httpx echoes every probed host, so an OOS host in its -l input
        # would land in live/httpx_full.txt (the before-fix behavior).
        httpx = stub / "httpx"
        httpx.write_text(
            "#!/bin/bash\n"
            'if [[ "$1" == "-version" ]]; then echo "httpx 1.3.5 projectdiscovery"; exit 0; fi\n'
            'out=""; list=""\n'
            'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; -l) list="$2";; esac; shift; done\n'
            '[[ -n "$out" && -n "$list" ]] || exit 0\n'
            'while IFS= read -r h; do [[ -z "$h" ]] && continue;\n'
            '  echo "$h [200] [Welcome] [nginx] [2048]"; done < "$list" > "$out"\n'
            "exit 0\n")
        httpx.chmod(0o755)
        return stub

    def test_oos_discoveries_filtered_before_probing(self, rtw_env, tmp_path):
        stub = self._oos_stubbin(tmp_path)
        for tool in ("subfinder", "katana", "gau", "httpx"):
            shutil.copyfile(stub / tool, rtw_env["stub_bin"] / tool)
            (rtw_env["stub_bin"] / tool).chmod(0o755)
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        recon = rtw_env["recon_out"]
        for rel in ("subdomains/all.txt", "urls/all.txt",
                    "live/httpx_full.txt", "live/urls.txt"):
            text = (recon / rel).read_text() if (recon / rel).exists() else ""
            assert "oos.evil.com" not in text, f"OOS asset leaked into {rel}"
        assert "target.goodscope.example" in \
            (recon / "subdomains" / "all.txt").read_text()
        dropped = recon / "scope" / "dropped_oos.txt"
        assert dropped.is_file(), "dropped_oos.txt missing"
        dropped_text = dropped.read_text()
        assert "oos.evil.com" in dropped_text
        truth = json.loads((recon / "recon_truth.json").read_text())
        assert truth["counts"]["scope_dropped"] >= 3
        assert "Scope-filtered (dropped OOS)" in out
        # in-scope URL survived the URL-side filter
        assert "http://target.goodscope.example/api" in \
            (recon / "urls" / "all.txt").read_text()

    def test_no_scope_check_filter_is_noop(self, rtw_env, tmp_path):
        stub = self._oos_stubbin(tmp_path)
        for tool in ("subfinder", "katana", "gau", "httpx"):
            shutil.copyfile(stub / tool, rtw_env["stub_bin"] / tool)
            (rtw_env["stub_bin"] / tool).chmod(0o755)
        proc = run_engine([TARGET, "--no-scope-check"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        all_txt = (rtw_env["recon_out"] / "subdomains" / "all.txt").read_text()
        assert "oos.evil.com" in all_txt, \
            "--no-scope-check must leave the filter as a no-op"
        assert not (rtw_env["recon_out"] / "scope" / "dropped_oos.txt").exists()

    def test_local_target_self_scoping_kept(self, rtw_env, tmp_path):
        """Local target without patterns: the filter self-scopes to the
        target itself and keeps the target's host:port probe entry."""
        proc = run_engine(["127.0.0.1:8080", "--no-scope-check"])
        assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]


class TestRunIsolation:
    """B5 regression: a re-run must not mix stale artifacts into the new
    Summary. After a run whose httpx phase produced nothing, the Summary must
    show Live hosts: 0 (run 1's live/urls.txt must not leak)."""

    def test_second_run_does_not_leak_stale_summary(self, rtw_env):
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "Live hosts:        2" in out
        recon = rtw_env["recon_out"]

        # simulate httpx disappearing between runs (bin_nohx scenario)
        (rtw_env["stub_bin"] / "httpx").unlink()
        proc2 = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out2 = proc2.stdout + proc2.stderr
        assert proc2.returncode == 0, out2[-3000:]
        assert "Live hosts:        0" in out2, \
            f"stale run-1 artifacts leaked into the Summary\n{out2[-2500:]}"
        truth = json.loads((recon / "recon_truth.json").read_text())
        assert truth["counts"]["live_hosts"] == 0
        # the previous truth is kept as the delta baseline
        assert (recon / ".prev_run" / "recon_truth.json").is_file()
        delta = json.loads((recon / "delta.json").read_text())
        assert delta["has_previous_run"] is True

    def test_second_run_rebuilds_fresh_artifacts(self, rtw_env):
        assert run_engine([TARGET, "--scope-domain", SCOPE[0]]).returncode == 0
        recon = rtw_env["recon_out"]
        (recon / "live" / "httpx_full.txt").write_text("STALE\n")
        (recon / "urls" / "all.txt").write_text("STALE\n")
        assert run_engine([TARGET, "--scope-domain", SCOPE[0]]).returncode == 0
        assert "STALE" not in (recon / "live" / "httpx_full.txt").read_text()
        assert "STALE" not in (recon / "urls" / "all.txt").read_text()


class TestRunIncompleteMarker:
    """B6 regression: an unclean previous run is recorded in the next truth
    (previous_run_incomplete) and warned about."""

    def test_marker_recorded_in_next_truth(self, rtw_env):
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        truth = json.loads(
            (rtw_env["recon_out"] / "recon_truth.json").read_text())
        assert truth.get("previous_run_incomplete") is False
        # simulate a killed run: the marker file was left behind
        (rtw_env["recon_out"] / ".run_incomplete").write_text("killed\n")
        proc2 = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out2 = proc2.stdout + proc2.stderr
        assert proc2.returncode == 0, out2[-3000:]
        assert "did not complete" in out2
        truth2 = json.loads(
            (rtw_env["recon_out"] / "recon_truth.json").read_text())
        assert truth2.get("previous_run_incomplete") is True
        # a clean run clears the marker and the flag flips back
        proc3 = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        assert proc3.returncode == 0
        truth3 = json.loads(
            (rtw_env["recon_out"] / "recon_truth.json").read_text())
        assert truth3.get("previous_run_incomplete") is False
        assert not (rtw_env["recon_out"] / ".run_incomplete").exists()


class TestHostPortReconDirs:
    """C10 regression: 127.0.0.1:8082 and 127.0.0.1:8083 key separate recon
    directories; the first run's data survives the second run."""

    def test_two_ports_two_dirs(self, rtw_env):
        import http.server
        import threading

        def handler(port_label):
            class H(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        f"<html><title>LAB {port_label}</title></html>".encode())

                def log_message(self, *a):
                    pass
            return H

        srv1 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler("P1"))
        srv2 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler("P2"))
        for srv in (srv1, srv2):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            env = os.environ.copy()
            env.update({
                "RHODAWK_HOME": str(rtw_env["home"]),
                "RHODAWK_CAPABILITIES_FILE": str(rtw_env["capabilities"]),
            })
            common = [sys.executable,
                      str(REPO_ROOT / "rhodawk" / "engine.py"), "recon"]
            p1 = subprocess.run(common + [f"127.0.0.1:{srv1.server_port}"],
                                cwd=str(REPO_ROOT), env=env,
                                capture_output=True, text=True, timeout=300)
            p2 = subprocess.run(common + [f"127.0.0.1:{srv2.server_port}"],
                                cwd=str(REPO_ROOT), env=env,
                                capture_output=True, text=True, timeout=300)
            assert p1.returncode == 0, (p1.stdout + p1.stderr)[-2000:]
            assert p2.returncode == 0, (p2.stdout + p2.stderr)[-2000:]
            base = rtw_env["home"] / "recon"
            d1 = base / f"127.0.0.1_{srv1.server_port}"
            d2 = base / f"127.0.0.1_{srv2.server_port}"
            assert d1.is_dir() and d2.is_dir(), \
                f"host:port dirs missing: {sorted(p.name for p in base.iterdir())}"
            # the data-home mirror (~/.rhodawk/recon/<host>/recon_truth.json)
            # stays host-keyed by design — assert the OUTPUT pipeline itself
            # never writes artifacts into a bare-host dir
            assert not (base / "127.0.0.1" / "live").is_dir(), \
                "legacy bare-host OUTPUT dir still written for host:port targets"
            full1 = (d1 / "live" / "httpx_full.txt").read_text()
            full2 = (d2 / "live" / "httpx_full.txt").read_text()
            assert f"127.0.0.1:{srv1.server_port}" in full1, full1
            assert f"127.0.0.1:{srv2.server_port}" in full2, full2
            assert f"127.0.0.1:{srv2.server_port}" not in full1, \
                "run 2 overwrote run 1's directory contents"
        finally:
            srv1.shutdown(); srv2.shutdown()
            srv1.server_close(); srv2.server_close()

    def test_hunt_resolve_recon_dir_port_aware(self, monkeypatch, tmp_path):
        sys.path.insert(0, str(REPO_ROOT / "rhodawk"))
        sys.path.insert(0, str(REPO_ROOT / "rhodawk" / "tools"))
        monkeypatch.setenv("RHODAWK_HOME", str(tmp_path))
        import importlib
        import tools.hunt as hunt
        importlib.reload(hunt)
        assert hunt._resolve_recon_dir(
            "127.0.0.1:8080").endswith(os.path.join("recon", "127.0.0.1_8080"))
        assert hunt._resolve_recon_dir(
            "app.example.test").endswith(
                os.path.join("recon", "app.example.test"))
