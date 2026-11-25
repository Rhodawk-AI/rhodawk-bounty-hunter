"""Tests for the RhodawkAI Edition reconFTW delegation layer.

Covers capability_registry.py (boot-time tool binding) and rtw_adapter.py
(deterministic six-step delegation), including the acceptance criteria from
the build brief + the three structural fixes:

- capabilities.json reports RTW_AVAILABLE only when RTW_HOME/reconftw.sh is
  executable AND the capability's backing binaries are present (Fix 1/§3).
- Fail-closed scope: no scope patterns → no reconFTW subprocess, block audited
  (Fix 2); --no-scope-check / allow_unscoped is the explicit demo opt-out.
- Out-of-scope target: zero subprocess spawned, block logged to audit.jsonl.
- Dedup: second call inside the 7-day TTL short-circuits with zero subprocess.
- Split phases: Phase 1.5 group vs Phase 5.5 group (Fix 1).
- Standardized merge outputs rtw_subdomains.txt / rtw_urls.txt (Fix 1b).
"""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_ROOT = REPO_ROOT / "rhodawk"
for path in (str(PKG_ROOT), str(PKG_ROOT / "tools")):
    if path not in sys.path:
        sys.path.insert(0, path)

from tools import capability_registry as reg  # noqa: E402
from tools import rtw_adapter as adp  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402

SCOPE = ["*.goodscope.example"]
TARGET = "target.goodscope.example"


@pytest.fixture(autouse=True)
def isolated_homes(tmp_path, monkeypatch):
    """Point every home/path knob the two modules read at a tmp sandbox.

    Live-run fix: HOME and RTW_HOME are both pinned to the tmp sandbox so a
    host checkout (/root/Tools/reconftw when running as root on a VPS) can
    never leak into availability results — including the RTW_HOME-unset tests,
    whose default ~/.Tools/reconftw lookup then resolves inside tmp_path."""
    home = tmp_path / "rhodawk-home"
    home.mkdir()
    monkeypatch.setenv("RHODAWK_HOME", str(home))
    monkeypatch.setenv("RHODAWK_CAPABILITIES_FILE", str(home / "capabilities.json"))
    monkeypatch.setenv("RTW_HOME", str(tmp_path / "rtw"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    # Keep the developer's real config.json out of scope-gate results. NOTE:
    # os.access(p, os.X_OK) is True for root on Linux even for mode-0644 files,
    # so the registry's executable check uses mode bits (os.stat().st_mode);
    # HOME pinning alone would not be sufficient on a root VPS.
    monkeypatch.setenv("HOME", str(tmp_path))
    return home


@pytest.fixture
def rtw_repo(tmp_path):
    """A stub reconFTW checkout: executable reconftw.sh that parses -o and
    emits one in-scope finding so runs complete with findings."""
    repo = tmp_path / "rtw"
    repo.mkdir()
    script = repo / "reconftw.sh"
    script.write_text(
        "#!/bin/bash\n"
        "# test stub — records invocation, writes one finding, exits 0\n"
        'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done\n'
        'mkdir -p "$out/subdomains"\n'
        'echo "found.goodscope.example" > "$out/subdomains/rtw_stub.txt"\n'
        "exit 0\n"
    )
    script.chmod(0o755)
    return repo


@pytest.fixture
def full_state():
    """capabilities.json marking every capability RTW_AVAILABLE."""
    state = {cap: "RTW_AVAILABLE" for cap in reg.CAPABILITIES}
    Path(os.environ["RHODAWK_CAPABILITIES_FILE"]).write_text(json.dumps(state) + "\n")
    return state


class NoSubprocess:
    """Guard asserting ZERO subprocess spawn in tests that must not execute."""

    def __init__(self):
        self.calls = 0

    def run(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("subprocess spawned in a no-spawn test path")


# ── capability_registry ───────────────────────────────────────────────────────

class TestRegistry:
    def test_seven_canonical_capabilities_exist(self):
        assert len(reg.CAPABILITIES) == 7
        for cap in ("CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE",
                    "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                    "CAP_FAVICON"):
            assert cap in reg.CAPABILITIES
            assert reg.CAPABILITIES[cap].rtw_function

    def test_phase_groups_cover_all_seven(self):
        all_ids = set(reg.CAPABILITIES)
        assert set(adp.PHASE_1_5_CAPABILITIES) | set(adp.PHASE_5_5_CAPABILITIES) == all_ids
        assert not set(adp.PHASE_1_5_CAPABILITIES) & set(adp.PHASE_5_5_CAPABILITIES)
        # Phase 1.5 = subdomain/infra gap-fill, runs BEFORE httpx (Phase 2).
        assert adp.PHASE_1_5_CAPABILITIES == ("CAP_ASN_ENUM", "CAP_DNS_PERMUT",
                                              "CAP_CDN_ISOLATE")
        # Phase 5.5 = web/JS/TLS gap-fill, runs BEFORE ffuf (Phase 6).
        assert adp.PHASE_5_5_CAPABILITIES == ("CAP_JS_SOURCEMAPS", "CAP_VHOSTS",
                                              "CAP_TLS_PIVOTS", "CAP_FAVICON")

    def test_missing_deps_state_without_rtw(self):
        """No reconftw checkout → every capability RTW_MISSING_DEPS (never a
        blanket available flag)."""
        mapping = reg.rebuild(write=True)
        assert set(mapping.values()) == {"RTW_MISSING_DEPS"}
        on_disk = json.loads(Path(os.environ["RHODAWK_CAPABILITIES_FILE"]).read_text())
        assert on_disk == mapping

    def test_available_requires_executable_script_and_binaries(self, rtw_repo, monkeypatch):
        """Acceptance: RTW_AVAILABLE only when reconftw.sh is executable AND
        the specific capability's binaries are on PATH."""
        monkeypatch.setattr(reg, "which_tool", lambda t: "/usr/bin/fake")
        # Script absent → missing deps.
        assert reg.evaluate_capability("CAP_ASN_ENUM")["state"] == "RTW_MISSING_DEPS"
        # Script present but no PDCP_API_KEY → still missing deps (sub_asn
        # hard-requires it upstream).
        (rtw_repo / "reconftw.sh").chmod(0o755)
        ev = reg.evaluate_capability("CAP_ASN_ENUM")
        assert ev["state"] == "RTW_MISSING_DEPS"
        assert "PDCP_API_KEY" in ev["missing_env"]
        # Key set → available.
        monkeypatch.setenv("PDCP_API_KEY", "test-key")
        assert reg.evaluate_capability("CAP_ASN_ENUM")["state"] == "RTW_AVAILABLE"
        # Drop one backing binary → back to missing deps, per-capability.
        monkeypatch.setattr(reg, "which_tool",
                            lambda t: None if t == "asnmap" else "/usr/bin/fake")
        ev = reg.evaluate_capability("CAP_ASN_ENUM")
        assert ev["state"] == "RTW_MISSING_DEPS"
        assert ev["missing_tools"] == ["asnmap"]
        # A different capability without that binary stays available.
        assert reg.evaluate_capability("CAP_CDN_ISOLATE")["state"] == "RTW_AVAILABLE"

    def test_pinned_install_commands(self, monkeypatch):
        """Install routing: pinned go-install per capability — never reconFTW's
        own installer, never brew floats."""
        monkeypatch.setattr(reg, "which_tool", lambda t: None)
        monkeypatch.setattr(reg.shutil, "which", lambda t: "/usr/bin/go" if t == "go" else None)
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr(reg.subprocess, "run", fake_run)
        rc = reg.install_capability("CAP_ASN_ENUM")
        assert rc == 0
        installs = [c[-1] for c in captured if c[:2] == ["go", "install"]]
        assert installs, "expected go install commands"
        for pin in installs:
            assert "@" in pin, f"unpinned install: {pin}"
            assert pin.startswith(("github.com/", "cramppet/")), pin
        assert reg.RTW_TOOL_PINS.get("puredns") == "github.com/d3mondev/puredns/v2@v2.1.1"
        assert reg.RTW_TOOL_PINS.get("tlsx") == "github.com/projectdiscovery/tlsx/cmd/tlsx@v1.1.7"

    def test_banner_lists_required_and_optional_keys(self, capsys):
        reg.print_banner(reg.rebuild(write=False))
        out = capsys.readouterr().out
        assert "PDCP_API_KEY" in out
        assert "chaos_api_key" in out
        assert "h1_api_token" in out
        assert "[Req]" in out and "[Opt]" in out
        for cap in reg.CAPABILITIES:
            assert cap in out

    def test_banner_evaluates_live_environment(self, capsys, monkeypatch):
        """Step 1D: --banner without --rebuild evaluates the CURRENT process
        environment — a stale cached capabilities.json must never make the
        banner show "CAP_ASN_ENUM RTW_AVAILABLE" next to a live
        "PDCP_API_KEY MISSING" row (or vice versa)."""
        # Stale cache claims everything is available (written long ago)…
        state = {cap: "RTW_AVAILABLE" for cap in reg.CAPABILITIES}
        Path(os.environ["RHODAWK_CAPABILITIES_FILE"]).write_text(json.dumps(state))
        # …but the live env cannot support delegation: no key, no checkout.
        monkeypatch.delenv("PDCP_API_KEY", raising=False)
        reg.main(["--banner"])
        out = capsys.readouterr().out
        row = next(line for line in out.splitlines()
                   if line.strip().startswith("CAP_ASN_ENUM"))
        assert "RTW_MISSING_DEPS" in row
        assert "RTW_AVAILABLE" not in row

        # Live env satisfied (key set, executable checkout, binaries on PATH)
        # → the banner reports availability without any --rebuild.
        monkeypatch.setenv("PDCP_API_KEY", "test-key")
        monkeypatch.setattr(reg, "which_tool", lambda t: "/usr/bin/fake")
        repo = Path(os.environ["RTW_HOME"])
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "reconftw.sh").write_text("#!/bin/bash\nexit 0\n")
        (repo / "reconftw.sh").chmod(0o755)
        reg.main(["--banner"])
        out = capsys.readouterr().out
        row = next(line for line in out.splitlines()
                   if line.strip().startswith("CAP_ASN_ENUM"))
        assert "RTW_AVAILABLE" in row
        assert "RTW_MISSING_DEPS" not in row


# ── CLI-mode delegation (Step 1B fix 1: no more --source-only subshells) ──────

class TestCliModeDelegation:
    def test_all_seven_capabilities_use_cli_mode(self):
        """Step 1B fix 1: ALL 7 capabilities invoke reconFTW through the CLI
        interface — the brittle `--source-only` subshells (which silently
        no-op'd for sub_permut/cdnprovider/jschecks) are gone entirely."""
        for cap_id, spec in reg.CAPABILITIES.items():
            assert spec.rtw_mode == "cli", f"{cap_id} must delegate via CLI mode"
        assert not hasattr(adp, "build_source_script")
        assert not hasattr(adp, "build_source_command")

    def test_cli_invocation_shape_with_no_banner(self, tmp_path):
        """`bash <RTW_HOME>/reconftw.sh -d <target> -c <fn> -f <cfg>
        -o <workdir> --no-banner` — the exact single-function interface,
        always a subprocess, never sourced into our process."""
        spec = reg.CAPABILITIES["CAP_DNS_PERMUT"]
        workdir = tmp_path / "wd"
        cfg = adp.write_override_cfg(workdir, spec)
        argv = adp.build_cli_command(spec, TARGET, workdir, cfg)
        assert argv[:2] == ["bash", str(adp.rtw_script())]
        assert argv[-1] == "--no-banner"
        for flag, val in (("-d", TARGET), ("-c", "sub_permut"),
                          ("-f", str(cfg)), ("-o", str(workdir))):
            i = argv.index(flag)
            assert argv[i + 1] == val
        assert "source" not in " ".join(argv)

    def test_override_cfg_enables_requested_function_flags(self, tmp_path):
        """The ephemeral cfg explicitly enables the requested function's gate
        flag(s) while VULNS_GENERAL / CDN_BYPASS / NOTIFICATION stay
        hard-locked to false."""
        cfg = adp.write_override_cfg(tmp_path / "wd1",
                                     reg.CAPABILITIES["CAP_DNS_PERMUT"])
        text = cfg.read_text()
        assert "SUBPERMUTE=true" in text
        assert "Requested function: sub_permut" in text
        assert "VULNS_GENERAL=false" in text
        assert "CDN_BYPASS=false" in text
        assert "NOTIFICATION=false" in text
        assert "TLSX_THREADS=25" in text  # reconFTW default is 1000 — capped

        cfg2 = adp.write_override_cfg(tmp_path / "wd2",
                                      reg.CAPABILITIES["CAP_TLS_PIVOTS"])
        text2 = cfg2.read_text()
        assert "TLSX_PORTS=true" in text2 and "TLS_IP_PIVOTS=true" in text2
        assert "Requested function: tls_ip_pivots" in text2

    def test_failed_function_publishes_no_findings(self, full_state, tmp_path):
        """rc != 0 → FAILED: findings_count == 0, net_new_count == 0 and
        published == [] — the pre-seeded inputs are never counted or copied."""
        repo = tmp_path / "rtw"          # matches isolated_homes' RTW_HOME
        repo.mkdir(exist_ok=True)
        script = repo / "reconftw.sh"
        script.write_text(
            "#!/bin/bash\n"
            "# stub: CLI single-function mode — emits one line, then fails\n"
            'out=""\n'
            'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done\n'
            'mkdir -p "$out/subdomains"\n'
            'echo "candidate.goodscope.example" > "$out/subdomains/rtw_out.txt"\n'
            "exit 3\n"
        )
        script.chmod(0o755)

        recon_dir = tmp_path / "recon"
        (recon_dir / "subdomains").mkdir(parents=True)
        (recon_dir / "subdomains" / "all.txt").write_text("seed.goodscope.example\n")

        result = adp.run_capability("CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE)
        assert result["status"] == "FAILED"
        entry = result["entry"]
        assert entry["returncode"] == 3
        assert entry["findings_count"] == 0
        assert entry["net_new_count"] == 0
        assert entry["published"] == []
        # and nothing reached Rhodawk's recon dir either
        assert not (recon_dir / "rtw" / "sub_permut").exists()

    def test_subprocess_env_pins_scriptpath_to_rtw_home(self, full_state, tmp_path):
        """Live-run fix: reconftw.sh resolves its lib/ + modules/ base from
        $SCRIPTPATH — with a stale inherited value, sub_permut and
        tls_ip_pivots sourced /opt/reconftw/modules/utils.sh instead of the
        RTW_HOME checkout. The adapter must pin SCRIPTPATH=$RTW_HOME on every
        delegated subprocess. (The stub records the value OUTSIDE the
        harvested workdir — the post-call scope filter would strip a raw
        filesystem path from harvested outputs, which is correct behavior.)"""
        repo = tmp_path / "rtw"          # matches isolated_homes' RTW_HOME
        repo.mkdir(exist_ok=True)
        script = repo / "reconftw.sh"
        script.write_text(
            "#!/bin/bash\n"
            "# stub: records the SCRIPTPATH the adapter handed us, outside the\n"
            "# harvested workdir so the scope filter does not sanitize it\n"
            'if [ -n "$SCRIPTPATH" ]; then\n'
            '    printf "%s" "$SCRIPTPATH" > "$SCRIPTPATH/.sp_record"\n'
            "fi\n"
            'out=""\n'
            'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done\n'
            'mkdir -p "$out/subdomains"\n'
            'echo "found.goodscope.example" > "$out/subdomains/rtw_out.txt"\n'
            "exit 0\n"
        )
        script.chmod(0o755)

        recon_dir = tmp_path / "recon" / "t.goodscope.example"
        (recon_dir / "subdomains").mkdir(parents=True)
        (recon_dir / "subdomains" / "all.txt").write_text("seed.goodscope.example\n")

        result = adp.run_capability("CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE, force=True)
        rtw_home = Path(os.environ["RTW_HOME"])
        recorded = (rtw_home / ".sp_record")
        assert recorded.is_file(), "stub never saw SCRIPTPATH in its subprocess env"
        assert recorded.read_text() == str(rtw_home)


# ── honest accounting (Step 1B fixes 2-4): seed diffing, skips, health table ──

class TestHonestAccounting:
    STUB_HEAD = (
        "#!/bin/bash\n"
        "# stub: CLI single-function mode\n"
        'out=""\n'
        'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done\n'
    )

    def _seed_recon(self, tmp_path):
        """recon dir with 2 seeded subdomains + 1 seeded live URL."""
        recon_dir = tmp_path / "recon" / "t.goodscope.example"
        (recon_dir / "subdomains").mkdir(parents=True)
        (recon_dir / "live").mkdir()
        (recon_dir / "subdomains" / "all.txt").write_text(
            "seed1.goodscope.example\nseed2.goodscope.example\n")
        (recon_dir / "live" / "urls.txt").write_text(
            "https://seed1.goodscope.example\n")
        return recon_dir

    def _stub(self, tmp_path, body):
        repo = tmp_path / "rtw"      # matches isolated_homes' RTW_HOME
        repo.mkdir(exist_ok=True)
        script = repo / "reconftw.sh"
        script.write_text(self.STUB_HEAD + body)
        script.chmod(0o755)

    def test_net_new_count_excludes_seeded_lines(self, full_state, tmp_path):
        """Live-run bug fixed: the stub echoes both seeded lines back plus one
        new host — findings_count / net_new_count must be 1 (net-new only),
        NOT 3, and published files carry the net-new line only."""
        self._stub(tmp_path,
                   'mkdir -p "$out/subdomains"\n'
                   'printf "seed1.goodscope.example\\nseed2.goodscope.example\\n'
                   'new.goodscope.example\\n" > "$out/subdomains/rtw_out.txt"\n'
                   "exit 0\n")
        recon_dir = self._seed_recon(tmp_path)
        result = adp.run_capability("CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE, force=True)
        entry = result["entry"]
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        assert entry["net_new_count"] == 1
        assert entry["findings_count"] == 1
        assert entry["seed_lines"] == 2  # CAP_DNS_PERMUT seeds subdomains/all.txt only
        published_texts = [Path(p).read_text() for p in entry["published"]]
        assert published_texts, "expected at least one published output"
        assert all("seed1" not in t and "seed2" not in t
                   for t in published_texts)
        assert any("new.goodscope.example" in t for t in published_texts)

    def test_seeded_only_output_is_completed_empty(self, full_state, tmp_path):
        """rc == 0 and net_new_count == 0 (the function only echoed the seeds
        back) → COMPLETED_EMPTY with findings_count 0 — never
        COMPLETED_WITH_FINDINGS. This is exactly the rhodawkai.com 0.1s
        no-op that used to report findings_count: 2."""
        self._stub(tmp_path,
                   'mkdir -p "$out/subdomains"\n'
                   'printf "seed1.goodscope.example\\nseed2.goodscope.example\\n" '
                   '> "$out/subdomains/rtw_out.txt"\n'
                   "exit 0\n")
        recon_dir = self._seed_recon(tmp_path)
        result = adp.run_capability("CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE, force=True)
        assert result["status"] == "COMPLETED_EMPTY"
        entry = result["entry"]
        assert entry["net_new_count"] == 0
        assert entry["findings_count"] == 0

    def test_silent_skip_detected_from_output(self, full_state, tmp_path):
        """rc == 0 but the function printed a reconFTW skip marker →
        SKIPPED_SILENT with the exact extracted reason."""
        self._stub(tmp_path,
                   'echo "SKIP: sub_permut — reason: config flag disabled"\n'
                   "exit 0\n")
        recon_dir = self._seed_recon(tmp_path)
        result = adp.run_capability("CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE, force=True)
        assert result["status"] == "SKIPPED_SILENT"
        assert result["entry"]["net_new_count"] == 0
        assert "skip marker" in result["reason"]
        assert result["entry"]["reason"].startswith("skip marker")

    def test_skip_marker_with_net_new_output_is_degraded(self, full_state, tmp_path):
        """Skip markers in the output but net-new lines still landed →
        DEGRADED (partial success is reported honestly)."""
        self._stub(tmp_path,
                   'echo "SKIP: legacy path unavailable"\n'
                   'mkdir -p "$out/subdomains"\n'
                   'echo "bonus.goodscope.example" > "$out/subdomains/rtw_out.txt"\n'
                   "exit 0\n")
        recon_dir = self._seed_recon(tmp_path)
        result = adp.run_capability("CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE, force=True)
        assert result["status"] == "DEGRADED"
        assert result["entry"]["net_new_count"] == 1

    def test_format_health_table(self):
        """Step 1B fix 4: Capability | Function | Status | Duration | Net-New |
        Reason — one row per capability, latest entry wins."""
        manifest = {"entries": [
            {"capability_id": "CAP_CDN_ISOLATE", "rtw_function": "cdnprovider",
             "status": "COMPLETED_EMPTY", "duration_secs": 0.1,
             "net_new_count": 0, "reason": "function completed, no net-new output lines"},
            {"capability_id": "CAP_ASN_ENUM", "rtw_function": "sub_asn",
             "status": "SKIPPED_SILENT", "duration_secs": 0.1,
             "net_new_count": 0, "reason": "skip marker 'skip' in reconftw output"},
            {"capability_id": "CAP_ASN_ENUM", "rtw_function": "sub_asn",
             "status": "COMPLETED_WITH_FINDINGS", "duration_secs": 42.0,
             "net_new_count": 7, "reason": "7 net-new finding line(s) collected"},
        ]}
        table = adp.format_health_table(manifest)
        header = table.splitlines()[0]
        for col in ("Capability", "Function", "Status", "Duration",
                    "Net-New", "Reason"):
            assert col in header
        assert "CAP_ASN_ENUM" in table and "CAP_CDN_ISOLATE" in table
        # Latest entry per capability wins.
        assert "COMPLETED_WITH_FINDINGS" in table
        assert "SKIPPED_SILENT" not in table
        assert "42.0" in table


# ── rtw_adapter: acceptance criteria ──────────────────────────────────────────

class TestAdapterAcceptance:
    def test_fail_closed_without_scope(self, full_state, rtw_repo):
        """Fix 2: no scope patterns → fail closed. No reconFTW subprocess, the
        block is audited, and the caller can continue."""
        guard = NoSubprocess()
        original = adp.subprocess.run
        adp.subprocess.run = guard.run
        try:
            result = adp.run_capability("CAP_ASN_ENUM", TARGET)
        finally:
            adp.subprocess.run = original
        assert result["status"] == "SKIPPED"
        assert result["blocked"] is True
        assert "fail-closed" in result["reason"]
        assert guard.calls == 0
        audit_file = Path(os.environ["RHODAWK_HOME"]) / "hunt-memory" / "audit.jsonl"
        assert audit_file.is_file(), "fail-closed block not audited"
        entry = json.loads(audit_file.read_text().splitlines()[-1])
        assert entry["scope_check"] == "fail"

    def test_allow_unscoped_opt_out_runs(self, full_state, rtw_repo):
        """--no-scope-check (allow_unscoped) is the explicit demo opt-out: it
        runs without any scope configuration."""
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, allow_unscoped=True)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"

    def test_rtw_home_unset_with_scope_skips_cleanly(self, full_state):
        """Acceptance: RTW_HOME unset → SKIPPED with a clean reason, no crash,
        nothing blocks the pipeline (with scope configured so the gate passes)."""
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert result["status"] == "SKIPPED"
        assert "reconftw.sh" in result["reason"]

    def test_missing_deps_skips_without_blocking(self, full_state):
        """Acceptance §4: RTW_MISSING_DEPS → SKIPPED(reason) and continue
        (availability is checked before the scope gate)."""
        state = {cap: "RTW_MISSING_DEPS" for cap in reg.CAPABILITIES}
        Path(os.environ["RHODAWK_CAPABILITIES_FILE"]).write_text(json.dumps(state))
        result = adp.run_capability("CAP_CDN_ISOLATE", TARGET)
        assert result["status"] == "SKIPPED"
        assert "RTW_MISSING_DEPS" in result["reason"]

    def test_scope_violation_zero_subprocess_and_audited(self, full_state, rtw_repo):
        """Acceptance: out-of-scope target → zero reconFTW subprocess spawned
        and the block logged to audit.jsonl."""
        guard = NoSubprocess()
        original = adp.subprocess.run
        adp.subprocess.run = guard.run
        try:
            checker = ScopeChecker(SCOPE)
            result = adp.run_capability("CAP_ASN_ENUM", "evil.example", checker=checker)
        finally:
            adp.subprocess.run = original
        assert result["status"] == "SKIPPED"
        assert result["blocked"] is True
        assert guard.calls == 0
        audit_file = Path(os.environ["RHODAWK_HOME"]) / "hunt-memory" / "audit.jsonl"
        assert audit_file.is_file(), "scope block not audited"
        entry = json.loads(audit_file.read_text().splitlines()[-1])
        assert entry["scope_check"] == "fail"
        assert "evil.example" in entry["url"]
        assert "rtw_adapter" in entry["error"]

    def test_scope_fail_closed_on_ambiguous_target(self, full_state, rtw_repo):
        """With scope configured via CLI args, a target not matching the
        allowlist fails closed."""
        result = adp.run_capability("CAP_ASN_ENUM", "not-on-allowlist.example",
                                    scope_domains=SCOPE)
        assert result["status"] == "SKIPPED"
        assert result["blocked"] is True

    def test_dedup_second_call_zero_subprocess(self, full_state, rtw_repo, monkeypatch):
        """Acceptance: same capability twice inside the 7-day TTL → the second
        call short-circuits to cache with zero subprocess spawn."""
        real_run = adp.subprocess.run
        calls = []

        def counting_run(argv, **kwargs):
            calls.append(argv)
            return real_run(argv, **kwargs)

        monkeypatch.setattr(adp.subprocess, "run", counting_run)
        first = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert first["status"] == "COMPLETED_WITH_FINDINGS"
        assert first["cached"] is False
        assert len(calls) == 1
        second = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert second["status"] == "COMPLETED_WITH_FINDINGS"
        assert second["cached"] is True
        assert len(calls) == 1, "dedup must spawn zero subprocesses"

    def test_stale_cache_reruns(self, full_state, rtw_repo):
        """Older than the 7-day TTL → not fresh."""
        manifest = adp.load_manifest(TARGET)
        manifest["entries"].append({
            "capability_id": "CAP_ASN_ENUM", "rtw_function": "sub_asn",
            "target": adp.host_key(TARGET), "input_hash": "stale",
            "status": "COMPLETED_EMPTY",
            "started": "2026-01-01T00:00:00Z", "finished": "2026-01-01T00:00:00Z",
        })
        assert adp.fresh_entry(manifest, "CAP_ASN_ENUM", TARGET, "stale") is None

    def test_native_capability_never_delegates(self):
        state = {"CAP_ASN_ENUM": "NATIVE"}
        Path(os.environ["RHODAWK_CAPABILITIES_FILE"]).write_text(json.dumps(state))
        result = adp.run_capability("CAP_ASN_ENUM", TARGET)
        assert result["status"] == "SKIPPED"
        assert "NATIVE" in result["reason"]

    def test_unknown_capability_rejected(self):
        result = adp.run_capability("CAP_MAKE_COFFEE", TARGET)
        assert result["status"] == "SKIPPED"
        assert "unknown capability_id" in result["reason"]


# ── rtw_adapter: manifest + command construction + split phases ───────────────

class TestManifestShape:
    REQUIRED_KEYS = {"capability_id", "rtw_function", "target", "input_hash",
                     "status", "started", "finished"}

    def test_manifest_entry_shape_and_json_safe(self, full_state, rtw_repo):
        """All 4 runtimes funnel through run_capability → identical shape, and
        the manifest must be JSON-serializable without default=str."""
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        entry = result["entry"]
        assert self.REQUIRED_KEYS <= set(entry)
        manifest = adp.load_manifest(TARGET)
        assert manifest["version"] == 1
        assert manifest["ttl_days"] == 7
        assert manifest["entries"] and manifest["entries"][-1] == entry
        # Re-serialize strictly (no default=str) — catches Path leakage.
        round_trip = json.loads(json.dumps(manifest))
        assert round_trip["entries"][0]["workdir"] == entry["workdir"]
        path = adp.manifest_path(TARGET)
        assert path == (Path(os.environ["RHODAWK_HOME"]) / "recon"
                        / "target.goodscope.example" / "rtw_manifest.json")

    def test_output_published_and_scope_filtered(self, full_state, rtw_repo, tmp_path):
        recon_dir = tmp_path / "recon-out" / "t.goodscope.example"
        recon_dir.mkdir(parents=True)
        checker = ScopeChecker(SCOPE)
        # Stub emits an in-scope host → published + filtered file count >= 1.
        result = adp.run_capability("CAP_ASN_ENUM", TARGET,
                                    recon_dir=recon_dir, checker=checker)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        assert result["entry"]["filter"]["files_filtered"] >= 1
        # A file whose contents are entirely out-of-scope → emptied.
        workdir = recon_dir / "rtw" / ".work" / "oos"
        workdir.mkdir(parents=True)
        (workdir / "hits.txt").write_text("https://evil.example/x\n")
        stats = adp.filter_outputs_to_scope(workdir, checker, TARGET)
        assert stats["lines_kept"] == 0
        assert (workdir / "hits.txt").read_text().strip() == ""

    def test_standardized_outputs_written(self, full_state, rtw_repo, tmp_path):
        """Fix 1b: the bash-merge buckets land at
        <recon_dir>/rtw/<function>/rtw_subdomains.txt and rtw_urls.txt."""
        recon_dir = tmp_path / "recon-std" / "t.goodscope.example"
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        out_dir = recon_dir / "rtw" / "sub_asn"
        subs = (out_dir / "rtw_subdomains.txt").read_text().splitlines()
        assert subs == ["found.goodscope.example"]
        assert result["entry"]["standard_outputs"]["subdomains"] == 1

    def test_classify_lines_buckets(self, tmp_path):
        workdir = tmp_path / "wd"
        workdir.mkdir()
        (workdir / "mixed.txt").write_text(
            "https://app.goodscope.example/login\n"
            "sub.goodscope.example\n"
            "not-a-host\n"
            "https://cdn.goodscope.example/app.js [200]\n"
            "https://x.goodscope.example/sitemap.xml\n"
        )
        buckets = adp.classify_lines(workdir, ["mixed.txt"])
        assert buckets["subdomains"] == ["sub.goodscope.example"]
        # httpx-style suffix lines: first token is the bare URL.
        assert buckets["urls"] == ["https://app.goodscope.example/login",
                                   "https://cdn.goodscope.example/app.js",
                                   "https://x.goodscope.example/sitemap.xml"]

    def test_seed_prepopulation(self, full_state, tmp_path):
        recon_dir = tmp_path / "recon-seed" / "t.goodscope.example"
        (recon_dir / "subdomains").mkdir(parents=True)
        (recon_dir / "live").mkdir()
        (recon_dir / "subdomains" / "all.txt").write_text("a.t.example\nb.t.example\n")
        (recon_dir / "live" / "urls.txt").write_text("https://a.t.example\n")
        spec = reg.CAPABILITIES["CAP_DNS_PERMUT"]
        workdir = tmp_path / "wd"
        workdir.mkdir()
        seeded = adp.seed_files(spec, recon_dir, workdir)
        assert "subdomains/subdomains.txt" in seeded
        assert (workdir / "subdomains" / "subdomains.txt").read_text() == \
            "a.t.example\nb.t.example\n"
        assert adp.seed_files(reg.CAPABILITIES["CAP_ASN_ENUM"],
                              recon_dir, workdir) == []

    def test_override_cfg_always_safe(self, tmp_path):
        cfg = adp.write_override_cfg(tmp_path)
        text = cfg.read_text()
        assert "VULNS_GENERAL=false" in text
        assert "CDN_BYPASS=false" in text
        assert "NOTIFICATION=false" in text
        assert "TLSX_THREADS=25" in text  # reconFTW default is 1000 — capped
        assert "ASN_ENUM=true" in text and "VIRTUALHOSTS=true" in text

    def test_cli_command_shape(self, tmp_path):
        spec = reg.CAPABILITIES["CAP_ASN_ENUM"]
        workdir = tmp_path / "wd"
        cfg = adp.write_override_cfg(workdir)
        argv = adp.build_cli_command(spec, TARGET, workdir, cfg)
        assert argv[:2] == ["bash", str(adp.rtw_script())]
        for flag, val in (("-d", TARGET), ("-c", "sub_asn"),
                          ("-f", str(cfg)), ("-o", str(workdir))):
            i = argv.index(flag)
            assert argv[i + 1] == val
        # Never sourced into our process — always a subprocess of bash.
        assert "source" not in " ".join(argv)

    def test_cli_command_shape_jsmaps(self, tmp_path):
        """Step 1B: CAP_JS_SOURCEMAPS (previously source-only) delegates
        through the same CLI single-function interface."""
        spec = reg.CAPABILITIES["CAP_JS_SOURCEMAPS"]
        workdir = tmp_path / "wd"
        cfg = adp.write_override_cfg(workdir, spec)
        argv = adp.build_cli_command(spec, TARGET, workdir, cfg)
        i = argv.index("-c")
        assert argv[i + 1] == "jschecks"
        assert argv[-1] == "--no-banner"
        assert "source" not in " ".join(argv)

    def test_input_hash_changes_with_seeds(self, full_state, tmp_path):
        recon_dir = tmp_path / "recon-hash" / "t.goodscope.example"
        (recon_dir / "subdomains").mkdir(parents=True)
        spec = reg.CAPABILITIES["CAP_DNS_PERMUT"]
        h1 = adp.input_hash(spec, TARGET, recon_dir)
        (recon_dir / "subdomains" / "all.txt").write_text("new.t.example\n")
        h2 = adp.input_hash(spec, TARGET, recon_dir)
        assert h1 != h2

    def test_phase_split(self, rtw_repo, full_state, monkeypatch):
        """Fix 1: run_phase('1.5') touches only the 3 infra capabilities,
        run_phase('5.5') only the 4 web/JS/TLS ones."""
        calls = []

        def fake_run_cap(cap_id, target, **kwargs):
            calls.append(cap_id)
            return adp._result(adp.RESULT_COMPLETED_EMPTY, cap_id, target)

        monkeypatch.setattr(adp, "run_capability", fake_run_cap)
        p15 = adp.run_phase("1.5", TARGET)
        assert calls == ["CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE"]
        assert len(p15) == 3
        calls.clear()
        p55 = adp.run_phase("5.5", TARGET)
        assert calls == ["CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                         "CAP_FAVICON"]
        assert len(p55) == 4
        with pytest.raises(ValueError):
            adp.run_phase("10.5", TARGET)

    def test_run_all_only_touches_available(self, rtw_repo, full_state, monkeypatch):
        calls = []

        def fake_run_cap(cap_id, target, **kwargs):
            calls.append(cap_id)
            return adp._result(adp.RESULT_COMPLETED_EMPTY, cap_id, target)

        monkeypatch.setattr(adp, "run_capability", fake_run_cap)
        state = {cap: "RTW_MISSING_DEPS" for cap in reg.CAPABILITIES}
        state["CAP_ASN_ENUM"] = "RTW_AVAILABLE"
        Path(os.environ["RHODAWK_CAPABILITIES_FILE"]).write_text(json.dumps(state))
        results = adp.run_all(TARGET)
        assert calls == ["CAP_ASN_ENUM"]
        assert len(results) == 7
        for r in results:
            if r["capability_id"] != "CAP_ASN_ENUM":
                assert r["status"] == "SKIPPED"

    def test_host_key_normalization(self):
        assert adp.host_key("https://Sub.Example.com:8443/path?q=1") == "sub.example.com"
        assert adp.host_key("10.0.0.5") == "10.0.0.5"
        assert adp.host_key("EXAMPLE.com.") == "example.com"


class TestRuntimePinVerification:
    """The adapter must re-verify the reconFTW commit at RUN TIME — the
    registry and doctor only check the pin at install/doctor time. On a
    HEAD != pin mismatch the delegation returns SKIPPED ('pin mismatch')
    and the manifest records it so tool_health surfaces the refusal."""

    def _init_rtw_git_repo(self, repo) -> str:
        import subprocess as sp
        sp.run(["git", "init", "-q", str(repo)], check=True)
        sp.run(["git", "-C", str(repo), "-c", "user.email=t@example.test",
                "-c", "user.name=t", "add", "-A"], check=True)
        sp.run(["git", "-C", str(repo), "-c", "user.email=t@example.test",
                "-c", "user.name=t", "commit", "-q", "-m", "stub rtw"],
               check=True)
        head = sp.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                      capture_output=True, text=True, check=True).stdout.strip()
        return head

    def test_pin_mismatch_skips_without_subprocess(self, rtw_repo,
                                                   full_state,
                                                   tmp_path):
        head = self._init_rtw_git_repo(rtw_repo)
        recon_dir = tmp_path / "recon-out"
        recon_dir.mkdir()
        marker = tmp_path / "stub_marker"
        monkey_ran = False
        saved = adp.RTW_COMMIT_PIN
        try:
            adp.RTW_COMMIT_PIN = "0" * 40  # != actual HEAD
            result = adp.run_capability(
                "CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
                allow_unscoped=True)
            monkey_ran = True
        finally:
            adp.RTW_COMMIT_PIN = saved
        assert monkey_ran
        assert result["status"] == "SKIPPED"
        assert "pin mismatch" in result["reason"]
        assert head in result["reason"]
        # no reconftw subprocess ran (no finding published)
        assert not (recon_dir / "rtw" / "sub_permut").exists() or not any(
            (recon_dir / "rtw" / "sub_permut").iterdir())
        # the refusal is recorded on the manifest for tool_health
        manifest = json.loads((tmp_path / "rhodawk-home" / "recon" /
                               "target.goodscope.example" /
                               "rtw_manifest.json").read_text())
        entries = [e for e in manifest["entries"]
                   if e["capability_id"] == "CAP_DNS_PERMUT"]
        assert entries and entries[-1]["status"] == "SKIPPED"
        assert "pin mismatch" in entries[-1]["reason"]

    def test_matching_pin_runs(self, rtw_repo, full_state,
                               tmp_path, monkeypatch):
        head = self._init_rtw_git_repo(rtw_repo)
        monkeypatch.setattr(adp, "RTW_COMMIT_PIN", head)
        recon_dir = tmp_path / "recon-out"
        recon_dir.mkdir()
        result = adp.run_capability(
            "CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
            allow_unscoped=True)
        assert result["status"] in ("COMPLETED_WITH_FINDINGS",
                                    "COMPLETED_EMPTY"), result["reason"]

    def test_non_git_checkout_is_not_a_mismatch(self, rtw_repo,
                                                full_state,
                                                tmp_path):
        # the DD lab stub checkout has no .git — unknown commit must NOT
        # block the delegation (only a real mismatch does)
        recon_dir = tmp_path / "recon-out"
        recon_dir.mkdir()
        result = adp.run_capability(
            "CAP_DNS_PERMUT", TARGET, recon_dir=recon_dir,
            allow_unscoped=True)
        assert result["status"] in ("COMPLETED_WITH_FINDINGS",
                                    "COMPLETED_EMPTY"), result["reason"]
