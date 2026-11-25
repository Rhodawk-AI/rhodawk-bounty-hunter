"""Sprint 2 negative regression tests — P1 scope-safety fixes.

Every test here proves a *negative*: a dangerous action is REFUSED, not
merely warned about. Coverage map (audit IDs):

  R-05  verifier spine + PoC bundler enforce scope/SSRF at hop 0
  R-05  validate_core evidence-gated status + is_report_ready requirements
  R-05  swarm scope config fail-closed (no exception swallowing)
  R-05  xss verifier refuses out-of-scope URLs BEFORE the browser launches
  R-06  scope_checker CLI exit codes 0 / 2 / 3 + --check/--filter-file
  R-11  hook_scope_guard fail-closed on malformed stdin; quoted plugin root
  R-16  shell tools carry the manifest preflight gate
  R-18  secret/PII-writing shell tools run under umask 077
  R-19  hunt.py kills the whole process group on timeout; argv-list commands
  R-20  target_selector never silently widens path-scoped assets
  R-21  zero_day_fuzzer refuses to run without a verified manifest

All tests are offline: no real network traffic, no writes into the source
tree (runtime paths are pinned by the conftest autouse fixture).
"""

import json
import subprocess
import sys
import time
import urllib.error
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "rhodawk" / "tools"
REPO = TOOLS.parent.parent

from tools.scope_checker import ScopeChecker, ScopeError


# ---------------------------------------------------------------------------
# R-05 — verifier spine: fetch() hop-0 SSRF + scope gate
# ---------------------------------------------------------------------------

class TestFetchHopZeroGate:
    def test_metadata_host_blocked_even_with_scope_and_seam(self):
        from verifiers.base import fetch

        checker = ScopeChecker(["169.254.169.254"])  # even "in scope" is blocked
        ex, body = fetch(
            "http://169.254.169.254/latest/meta-data/",
            scope_checker=checker,
            allow_localhost_testing=True,  # the seam must NOT reach metadata
        )
        assert ex.status is None
        assert body == b""
        assert "blocked" in (ex.note or "").lower()
        assert "ssrf" in (ex.note or "").lower()

    def test_loopback_blocked_without_seam(self):
        from verifiers.base import fetch

        ex, body = fetch("http://127.0.0.1:9/x", note="probe")
        assert ex.status is None
        assert body == b""
        assert "blocked" in (ex.note or "").lower()

    def test_out_of_scope_public_host_blocked_fail_closed(self):
        from verifiers.base import fetch

        checker = ScopeChecker(["*.example.com"])
        ex, body = fetch("https://evil.com/steal", scope_checker=checker)
        assert ex.status is None
        assert body == b""
        assert "out of scope" in (ex.note or "").lower()

    def test_missing_scope_checker_blocks_public_host(self):
        from verifiers.base import fetch

        ex, _ = fetch("https://target.example/")
        assert ex.status is None
        assert "no scope_checker" in (ex.note or "").lower()

    def test_localhost_seam_allows_loopback_only(self):
        # Explicit unit-test seam: loopback is allowed WITHOUT a checker;
        # the connection itself fails fast (port 9 / discard) which is fine —
        # the assertion is that the gate let it through (no "blocked" note).
        from verifiers.base import fetch

        ex, _ = fetch("http://127.0.0.1:9/x", allow_localhost_testing=True)
        assert "blocked" not in (ex.note or "").lower()

    def test_localhost_seam_never_allows_public_hosts(self):
        from verifiers.base import fetch

        ex, _ = fetch("https://target.example/", allow_localhost_testing=True)
        assert ex.status is None
        assert "no scope_checker" in (ex.note or "").lower()


# ---------------------------------------------------------------------------
# R-05 — poc_bundler.capture() hop-0 gate
# ---------------------------------------------------------------------------

class TestCaptureHopZeroGate:
    def test_metadata_capture_refused_with_zero_packets(self):
        import poc_bundler as pb

        checker = ScopeChecker(["169.254.169.254"])
        with pytest.raises(urllib.error.URLError) as excinfo:
            pb.capture("http://169.254.169.254/latest/meta-data/", "GET",
                       [], None, 5, scope_checker=checker,
                       allow_localhost_testing=True)
        assert "ssrf" in str(excinfo.value).lower()

    def test_capture_without_scope_checker_refused(self):
        import poc_bundler as pb

        with pytest.raises(urllib.error.URLError) as excinfo:
            pb.capture("https://target.example/x", "GET", [], None, 5)
        assert "scope" in str(excinfo.value).lower()

    def test_capture_out_of_scope_refused(self):
        import poc_bundler as pb

        checker = ScopeChecker(["*.example.com"])
        with pytest.raises(urllib.error.URLError) as excinfo:
            pb.capture("https://evil.com/x", "GET", [], None, 5,
                       scope_checker=checker)
        assert "out of scope" in str(excinfo.value).lower()

    def test_capture_loopback_seam(self):
        import poc_bundler as pb

        # Port 9 (discard): the gate must LET it through; the socket then
        # fails instantly. No "blocked" URLError is the assertion.
        try:
            pb.capture("http://127.0.0.1:9/x", "GET", [], None, 2,
                       allow_localhost_testing=True)
        except urllib.error.URLError as exc:
            assert "blocked" not in str(exc).lower()

    def test_capture_blocked_reason_helper(self):
        import poc_bundler as pb

        assert pb.capture_blocked_reason(
            "http://127.0.0.1/", allow_localhost_testing=True) is None
        reason = pb.capture_blocked_reason("http://127.0.0.1/")
        assert reason and "ssrf" in reason.lower()


# ---------------------------------------------------------------------------
# R-05 — validate_core evidence + scope gating
# ---------------------------------------------------------------------------

class TestReportGate:
    def _payload(self, **over):
        payload = {
            "status": "validated_finding",
            "scope_enforced": True,
            "evidence_linked": True,
            "evidence_id": "EV-123",
            "verifier": {"confirmed": True},
        }
        payload.update(over)
        return payload

    def test_report_ready_requires_all_conditions(self):
        from tools.validate_core import is_report_ready

        assert is_report_ready(self._payload()) is True

    def test_no_evidence_is_never_report_ready(self):
        from tools.validate_core import is_report_ready

        assert is_report_ready(self._payload(evidence_linked=False,
                                             evidence_id=None)) is False

    def test_unscoped_run_is_never_report_ready(self):
        from tools.validate_core import is_report_ready

        assert is_report_ready(self._payload(scope_enforced=False)) is False
        # legacy payload without the field at all
        p = self._payload()
        del p["scope_enforced"]
        assert is_report_ready(p) is False

    def test_rejected_or_skipped_verifier_not_report_ready(self):
        from tools.validate_core import is_report_ready

        assert is_report_ready(self._payload(verifier={"confirmed": False})) is False
        assert is_report_ready(self._payload(status="scanner_hit")) is False

    def test_programmatic_gate_without_session_dir_never_validates(self):
        # session_dir=None -> no evidence record possible -> scanner_hit,
        # even when a (fake) verifier confirms.
        from tools import validate_core

        class FakeResult:
            confirmed = True
            skipped = False
            oracle = "fake oracle"
            error = None
            trace = []

            def to_dict(self):
                return {"confirmed": True, "skipped": False,
                        "vuln_class": "sqli", "oracle": "fake oracle",
                        "evidence": "", "error": None, "skipped2": None,
                        "trace": []}

        from tools.verifiers import normalize_class

        monkey_findings = {
            "vuln_class": "sqli", "url": "https://sub.example.com/x",
            "param": "q", "target": "example.com",
            "error_signature": "SQL syntax", "breaker_payload": "'",
            "benign_value": "1",
        }
        import tools.validate_core as vc

        original = vc.verify_finding
        vc.verify_finding = lambda f, scope_checker=None, **kw: FakeResult()
        try:
            res = vc.verify_finding_programmatic(
                monkey_findings, scope_checker=ScopeChecker(["*.example.com"]),
                session_dir=None, log_research=False,
            )
        finally:
            vc.verify_finding = original
        assert res["status"] == "scanner_hit"
        assert res["technically_confirmed"] is True
        assert res["scope_enforced"] is True
        assert any("evidence" in r.lower() for r in res["rejection_reasons"])


# ---------------------------------------------------------------------------
# R-05 — swarm scope fail-closed
# ---------------------------------------------------------------------------

class TestSwarmScopeFailClosed:
    def test_public_suffix_wildcard_raises(self):
        from tools.swarm import _scope_checker

        with pytest.raises(ScopeError):
            _scope_checker(["*.com"])  # dangerous pattern -> raise, not None

    def test_invalid_wildcard_placement_raises(self):
        from tools.swarm import _scope_checker

        with pytest.raises(ScopeError):
            _scope_checker(["a.*.b.example.com"])

    def test_valid_config_still_builds(self):
        from tools.swarm import _scope_checker

        checker = _scope_checker(["*.example.com"])
        assert checker is not None
        assert checker.is_in_scope("https://sub.example.com/")

    def test_coordinate_refuses_unscoped_wave(self):
        from tools.swarm import coordinate

        report = coordinate("example.com", scope_domains=[])
        assert report["dispatched"] == 0
        assert report.get("scope_error")

    def test_coordinate_refuses_invalid_scope_config(self):
        from tools.swarm import coordinate

        report = coordinate("example.com", scope_domains=["*.com"])
        assert report["dispatched"] == 0
        assert report.get("scope_error")
        assert "unusable" in report["summary"]["error"].lower()


# ---------------------------------------------------------------------------
# R-05 — xss verifier: scope gate BEFORE browser launch
# ---------------------------------------------------------------------------

class TestXssPreBrowserGate:
    def test_out_of_scope_url_never_reaches_playwright(self, monkeypatch):
        from verifiers import xss as xss_v

        def _boom(*a, **k):
            raise AssertionError("browser launched for an out-of-scope URL")

        monkeypatch.setattr(xss_v.dom_xss_harness, "run", _boom)
        checker = ScopeChecker(["*.example.com"])
        res = xss_v.verify({"url": "https://evil.com/?q=<svg>"}, scope_checker=checker)
        assert res.skipped is True
        assert "scope" in (res.oracle or "").lower()

    def test_missing_scope_checker_skips_before_browser(self, monkeypatch):
        from verifiers import xss as xss_v

        def _boom(*a, **k):
            raise AssertionError("browser launched without a scope checker")

        monkeypatch.setattr(xss_v.dom_xss_harness, "run", _boom)
        res = xss_v.verify({"url": "https://sub.example.com/?q=1"})
        assert res.skipped is True
        assert "scope" in (res.oracle or "").lower()


# ---------------------------------------------------------------------------
# R-06 — scope_checker CLI exit codes + aliases
# ---------------------------------------------------------------------------

class TestScopeCheckerCli:
    @pytest.fixture()
    def manifest(self, tmp_path):
        # Compiled through the REAL contract so manifest_sha256 matches the
        # canonical-hash algorithm the checker verifies against.
        from contracts.scope import CompiledScopeManifest

        m = CompiledScopeManifest(
            allow_patterns=["*.example.com"],
            exclude_patterns=[],
            excluded_classes=[],
        )
        path = tmp_path / "compiled_scope.json"
        m.save(str(path))
        return path

    def _cli(self, *args, stdin=None):
        return subprocess.run(
            [sys.executable, str(TOOLS / "scope_checker.py"), *args],
            capture_output=True, text=True, timeout=60,
            input=stdin, cwd=str(REPO),
        )

    def test_in_scope_exit_zero(self, manifest):
        rc = self._cli("--manifest", str(manifest), "--check",
                       "https://sub.example.com/a")
        assert rc.returncode == 0, rc.stderr

    def test_out_of_scope_exit_two(self, manifest):
        rc = self._cli("--manifest", str(manifest), "--check",
                       "https://other.com/")
        assert rc.returncode == 2

    def test_apex_not_covered_by_wildcard(self, manifest):
        rc = self._cli("--manifest", str(manifest), "--check",
                       "https://example.com/")
        assert rc.returncode == 2

    def test_tampered_manifest_exit_three(self, manifest, tmp_path):
        bad = tmp_path / "tampered.json"
        bad.write_text(manifest.read_text(encoding="utf-8").replace(
            "*.example.com", "*.EVERYTHING.com"), encoding="utf-8")
        rc = self._cli("--manifest", str(bad))
        assert rc.returncode == 3
        assert "SCOPE BLOCK" in rc.stderr

    def test_missing_manifest_exit_three(self, tmp_path):
        rc = self._cli("--manifest", str(tmp_path / "nope.json"),
                       "--check", "https://sub.example.com/")
        assert rc.returncode == 3

    def test_filter_file_alias_filters_in_place(self, manifest, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("https://sub.example.com/ok\nhttps://evil.com/no\n",
                     encoding="utf-8")
        rc = self._cli("--manifest", str(manifest), "--filter-file", str(f))
        assert rc.returncode == 0
        lines = f.read_text(encoding="utf-8").splitlines()
        assert lines == ["https://sub.example.com/ok"]


# ---------------------------------------------------------------------------
# R-21 — zero_day_fuzzer requires a verified manifest
# ---------------------------------------------------------------------------

class TestZeroDayFuzzerScopeGate:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(TOOLS / "zero_day_fuzzer.py"), *args],
            capture_output=True, text=True, timeout=60, cwd=str(REPO),
        )

    def test_refuses_without_any_manifest(self):
        rc = self._run("https://sub.example.com")
        assert rc.returncode == 3
        assert "SCOPE BLOCK" in rc.stderr

    def test_refuses_tampered_manifest(self, tmp_path):
        bad = tmp_path / "compiled_scope.json"
        bad.write_text('{"allow_patterns": ["*.example.com"], '
                       '"manifest_sha256": "deadbeef"}', encoding="utf-8")
        rc = self._run("https://sub.example.com", "--manifest", str(bad))
        assert rc.returncode == 3

    def test_missing_manifest_file_refuses(self, tmp_path):
        rc = self._run("https://sub.example.com",
                       "--manifest", str(tmp_path / "absent.json"))
        assert rc.returncode == 3

    def test_rate_limit_helper_shapes_sleep(self):
        import time as _time

        import zero_day_fuzzer as zdf

        zdf.set_rate_limit(0)  # unlimited -> returns immediately
        t0 = _time.monotonic()
        zdf.rate_limit_sleep_for("https://a.example/")
        assert _time.monotonic() - t0 < 0.5

        zdf.set_rate_limit(1)  # 1 rps -> first call no sleep, second ~1s
        zdf.rate_limit_sleep_for("https://b.example/")
        t1 = _time.monotonic()
        zdf.rate_limit_sleep_for("https://b.example/")
        slept = _time.monotonic() - t1
        zdf.set_rate_limit(0)
        assert slept >= 0.5

    def test_url_blocked_rejects_metadata_and_oos(self):
        import zero_day_fuzzer as zdf

        checker = ScopeChecker(["*.example.com"])
        assert "SSRF" in zdf.url_blocked("http://169.254.169.254/", checker)
        assert "out of scope" in zdf.url_blocked("https://evil.com/", checker)
        assert zdf.url_blocked("https://sub.example.com/", checker) is None


# ---------------------------------------------------------------------------
# R-11 — hook fail-closed stdin + quoted plugin root
# ---------------------------------------------------------------------------

class TestHookScopeGuard:
    def _run(self, stdin_text):
        return subprocess.run(
            [sys.executable, str(TOOLS / "hook_scope_guard.py")],
            input=stdin_text, capture_output=True, text=True, timeout=60,
            cwd=str(REPO),
        )

    def test_malformed_json_blocked_exit_two(self):
        rc = self._run("this is not json {{{")
        assert rc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in rc.stderr

    def test_non_object_json_blocked_exit_two(self):
        rc = self._run('["array", "not", "object"]')
        assert rc.returncode == 2
        assert "SCOPE_HOOK_BLOCK" in rc.stderr

    def test_readonly_tool_with_object_payload_allows(self):
        payload = json.dumps({"tool_name": "Read",
                              "tool_input": {"file_path": "/tmp/x"}})
        rc = self._run(payload)
        assert rc.returncode == 0

    def test_active_bash_tool_without_manifest_blocked(self):
        payload = json.dumps({"tool_name": "Bash",
                              "tool_input": {"command": "bash tools/recon_engine.sh evil.com"}})
        rc = self._run(payload)
        assert rc.returncode == 2

    def test_hooks_json_quoted_plugin_root(self):
        data = json.loads((REPO / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        cmd = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert cmd == 'python3 "${CLAUDE_PLUGIN_ROOT}/rhodawk/tools/hook_scope_guard.py"'
        # quoted (word-splitting safe) but NO :-fallback (keeps Claude Code's
        # built-in missing-plugin-root protection)
        assert '"${CLAUDE_PLUGIN_ROOT}' in cmd
        assert ":-" not in cmd


# ---------------------------------------------------------------------------
# R-16 / R-18 — shell tools carry the gate; secret writers use umask 077
# ---------------------------------------------------------------------------

class TestShellToolGates:
    _GATED = [
        "takeover_scanner.sh", "secrets_hunter.sh", "bypass_403.sh",
        "cve_scan.sh", "graphql_audit.sh", "param_discovery.sh",
        "cloud_recon.sh", "wordlist_engine.sh", "osint_employees.sh",
        "spray_orchestrator.sh",
    ]

    def test_every_downstream_tool_sources_the_gate(self):
        for name in self._GATED:
            src = (TOOLS / name).read_text(encoding="utf-8")
            assert "_scope_gate.sh" in src, f"{name}: gate not sourced"
            assert "rhodawk_scope_gate_init" in src, f"{name}: gate not called"

    def test_vuln_scanner_gate_filter_and_mktemp(self):
        src = (TOOLS / "vuln_scanner.sh").read_text(encoding="utf-8")
        assert "rhodawk_scope_gate_init" in src
        assert "rhodawk_scope_gate_filter" in src
        assert '"/tmp/$canary"' not in src  # predictable path gone
        assert "mktemp" in src and "trap" in src

    def test_secret_writers_use_umask_077(self):
        for name in ("secrets_hunter.sh", "osint_employees.sh",
                     "spray_orchestrator.sh"):
            src = (TOOLS / name).read_text(encoding="utf-8")
            assert "umask 077" in src, f"{name}: umask 077 missing"

    def test_full_hunt_filters_enumeration_before_probing(self):
        src = (REPO / "scripts" / "full_hunt.sh").read_text(encoding="utf-8")
        # the filter must sit between the all_subs merge and the httpx probe
        merge = src.index("all_subs.txt")
        flt = src.index("Post-enumeration scope filter")
        probe = src.index("Probing live subdomains")
        assert merge < flt < probe

    def test_gate_helper_rejects_tampered_manifest(self, tmp_path):
        home = tmp_path / "home"
        (home / "recon" / "sub.example.com" / "scope").mkdir(parents=True)
        (home / "recon" / "sub.example.com" / "scope" / "compiled_scope.json").write_text(
            '{"allow_patterns":["*.example.com"],"manifest_sha256":"nope"}',
            encoding="utf-8")
        script = (
            f"export RHODAWK_HOME={home}; "
            f"source {TOOLS}/_scope_gate.sh; "
            f'_SCOPE_GATE_TOOL=t; '
            f'rhodawk_scope_gate_init "" "sub.example.com"'
        )
        rc = subprocess.run(["bash", "-c", script], capture_output=True,
                            text=True, timeout=60)
        assert rc.returncode == 3
        assert "SCOPE BLOCK" in rc.stderr
        # and the block was audited to hunt-memory/audit.jsonl
        audit = home / "hunt-memory" / "audit.jsonl"
        assert audit.exists()
        assert '"scope_check":"fail"' in audit.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# R-19 — hunt.py process-group kill + argv-list commands
# ---------------------------------------------------------------------------

class TestHuntProcessHardening:
    def test_timeout_kills_child_and_grandchild(self):
        import hunt

        # Distinctive duration so pgrep cannot match an unrelated process.
        cmd = "bash -c 'sleep 246 & wait'"
        ok, out = hunt.run_cmd(cmd, timeout=1)
        assert ok is False
        assert "timed out" in out.lower()
        # the grandchild `sleep 246` must be gone: poll briefly
        deadline = time.time() + 6
        alive = True
        while time.time() < deadline:
            probe = subprocess.run(["pgrep", "-fx", "sleep 246"],
                                   capture_output=True, text=True)
            if not probe.stdout.strip():
                alive = False
                break
            time.sleep(0.5)
        assert not alive, "grandchild survived the process-group kill"

    def test_select_targets_uses_argv_list(self, monkeypatch):
        import hunt

        captured = {}

        def fake_run_cmd(cmd, cwd=None, timeout=600):
            captured["cmd"] = cmd
            return True, ""

        monkeypatch.setattr(hunt, "run_cmd", fake_run_cmd)
        hunt.select_targets(top_n=7)
        cmd = captured["cmd"]
        assert isinstance(cmd, list), "select_targets must not use a shell string"
        assert cmd[0] == "python3" and "--top" in cmd and "7" in cmd

    def test_run_swarm_uses_argv_list_with_scope_flags(self, monkeypatch):
        import hunt

        captured = {}

        def fake_run_cmd(cmd, cwd=None, timeout=600):
            captured["cmd"] = cmd
            return True, ""

        monkeypatch.setattr(hunt, "run_cmd", fake_run_cmd)
        hunt.set_scope_checker(None)
        hunt.run_swarm("target.example", workers=3)
        cmd = captured["cmd"]
        assert isinstance(cmd, list), "run_swarm must not use a shell string"
        assert "--scope-domain" in cmd and "target.example" in cmd

    def test_show_status_survives_corrupt_targets_json(self, monkeypatch, tmp_path):
        import hunt

        tf = Path(hunt.TARGETS_DIR) / "selected_targets.json"
        original = tf.read_text(encoding="utf-8") if tf.exists() else None
        Path(hunt.TARGETS_DIR).mkdir(parents=True, exist_ok=True)
        tf.write_text("{corrupt json!!", encoding="utf-8")
        try:
            hunt.show_status()  # must not raise
        finally:
            if original is None:
                tf.unlink(missing_ok=True)
            else:
                tf.write_text(original, encoding="utf-8")


# ---------------------------------------------------------------------------
# R-20 — target_selector non-widening
# ---------------------------------------------------------------------------

class TestTargetSelectorNonWidening:
    def test_path_scoped_asset_not_widened(self, capsys):
        import target_selector as ts

        prog = {"assets": ["target.com/api/", "plain.example.com"]}
        domains = ts.extract_scope_domains(prog)
        assert "target.com" not in domains
        assert "plain.example.com" in domains
        err = capsys.readouterr().err.lower()
        assert "not widening" in err and "path" in err

    def test_url_scoped_asset_not_widened(self, capsys):
        import target_selector as ts

        domains = ts.extract_scope_domains({"assets": ["https://api.target.com/v2"]})
        assert "api.target.com" not in domains
        assert "target.com" not in domains

    def test_wildcard_kept_verbatim(self):
        import target_selector as ts

        domains = ts.extract_scope_domains({"assets": ["*.wild.example.com"]})
        assert domains == ["*.wild.example.com"]  # NOT reduced to the apex

    def test_wildcard_not_reduced_to_apex(self):
        import target_selector as ts

        domains = ts.extract_scope_domains({"assets": ["*.target.example"]})
        assert "target.example" not in domains

    def test_plain_domain_passes_through(self):
        import target_selector as ts

        domains = ts.extract_scope_domains(
            {"assets": ["a.example.com", "b.example.com", "a.example.com"]})
        assert domains == ["a.example.com", "b.example.com"]
