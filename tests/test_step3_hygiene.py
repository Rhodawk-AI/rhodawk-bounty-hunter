"""Step 3 — Recon/<target> bridge, multi-hop httpx parsing, tool_health
reason propagation, rtw_home config fallback, and `rhodawk doctor`.

Live-run context: reconftw.sh -c (upstream commit 3925211, line 858)
hardcodes dir="${SCRIPTPATH}/Recon/$domain" and IGNORES -o <workdir>, so
every delegated capability ran inside an empty directory and never saw the
seeded inputs. The adapter now bridges <RTW_HOME>/Recon/<domain> -> <workdir>
for the subprocess call and restores <RTW_HOME>/Recon/ afterwards.
"""

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
PKG_ROOT = os.path.join(ROOT, "rhodawk")
for p in (PKG_ROOT, os.path.join(PKG_ROOT, "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import tools.rtw_adapter as adp  # noqa: E402
import tools.recon_fusion as rf  # noqa: E402
import tools.capability_registry as reg  # noqa: E402

TARGET = "t.goodscope.example"
SCOPE = ["*.goodscope.example"]

STUB_RECONFTW = """#!/bin/bash
# stub: single-function mode. Proves the Recon/<domain> bridge is visible:
# reconftw.sh -c reads ${SCRIPTPATH}/Recon/$domain (hardcoded upstream) and
# appends into $dir/.log/_.txt + $dir/.called_fn/.status_<fn> — BOTH are
# directories upstream; a file at either path failed the live run with
# `Not a directory`.
rtw_dom="$2"
out=""
while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done
mkdir -p "$out/subdomains"
if [[ -d "$out/.log" && -d "$out/.called_fn" ]]; then
    echo "https://dirsok.goodscope.example/precheck" >> "$out/subdomains/rtw_precheck.txt"
fi
sed 's/^/seen-/' "${SCRIPTPATH}/Recon/${rtw_dom}/subdomains/subdomains.txt" \\
    > "$out/subdomains/rtw_out.txt" 2>/dev/null || true
echo "https://status.goodscope.example/CAP_DNS_PERMUT" \\
    >> "$out/.called_fn/.status_CAP_DNS_PERMUT" 2>/dev/null || true
echo "https://log.goodscope.example/stub-ran" >> "$out/.log/_.txt" 2>/dev/null || true
exit 0
"""


@pytest.fixture
def step3_env(tmp_path, monkeypatch):
    """Isolated RTW_HOME (stub reconftw.sh) + isolated homes + capability
    available, mirroring the full_state fixture pattern of
    test_rtw_capability.py."""
    repo = tmp_path / "rtw"
    repo.mkdir()
    script = repo / "reconftw.sh"
    script.write_text(STUB_RECONFTW)
    script.chmod(0o755)

    home = tmp_path / "rhodawk-home"
    home.mkdir()

    monkeypatch.setenv("RTW_HOME", str(repo))
    monkeypatch.setenv("RHODAWK_HOME", str(home))
    monkeypatch.delenv("RHODAWK_CAPABILITIES_FILE", raising=False)
    monkeypatch.setattr(adp, "load_state",
                        lambda: {adp.STATE_RTW_AVAILABLE: "RTW_AVAILABLE",
                                 "CAP_DNS_PERMUT": "RTW_AVAILABLE"})

    recon_dir = tmp_path / "recon" / TARGET
    (recon_dir / "subdomains").mkdir(parents=True)
    (recon_dir / "subdomains" / "all.txt").write_text("seed.goodscope.example\n")
    return {"tmp": tmp_path, "rtw_home": repo, "home": home,
            "recon_dir": recon_dir}


def _run_cap(env, **kw):
    return adp.run_capability("CAP_DNS_PERMUT", TARGET, recon_dir=env["recon_dir"],
                              scope_domains=SCOPE, force=True, **kw)


class TestReconDirBridge:
    def test_seeds_visible_via_bridge_and_cleaned_after(self, step3_env):
        """reconftw.sh -c reads ${SCRIPTPATH}/Recon/<domain>: the bridge makes
        the seeded workdir visible there, .log/.called_fn are pre-created, and
        <RTW_HOME>/Recon/ is clean again once the subprocess returns."""
        result = _run_cap(step3_env)
        assert result["status"] == "COMPLETED_WITH_FINDINGS", result
        workdir = Path(result["entry"]["workdir"])
        # The stub transformed the seeded file THROUGH the bridge symlink.
        seen = (workdir / "subdomains" / "rtw_out.txt").read_text()
        assert "seen-seed.goodscope.example" in seen
        # Regression (live rhodawkai.com run): .log/.called_fn must be
        # DIRECTORIES before reconftw.sh runs — upstream appends
        # .called_fn/.status_<fn> and .log/_.txt into them; a file at either
        # path failed with `Not a directory`.
        assert (workdir / ".log").is_dir()
        assert (workdir / ".called_fn").is_dir()
        status_file = workdir / ".called_fn" / ".status_CAP_DNS_PERMUT"
        # In-scope marker lines survive the post-call scope filter; the
        # file PATHS under .called_fn/.log prove the writes went into
        # directories, not files.
        assert "CAP_DNS_PERMUT" in status_file.read_text()
        assert "stub-ran" in (workdir / ".log" / "_.txt").read_text()
        # Recon/ is clean again — no leftover bridge symlink.
        link = step3_env["rtw_home"] / "Recon" / TARGET
        assert not link.exists() and not link.is_symlink()

    def test_bookkeeping_dirs_exist_before_reconftw_runs(self, step3_env):
        """The stub's `dirs-ok` precheck proves <workdir>/.log and
        <workdir>/.called_fn are already directories BEFORE reconftw.sh
        executes — the exact live failure seen on rhodawkai.com
        (`Recon/<domain>/.log/_.txt: Not a directory`)."""
        result = _run_cap(step3_env)
        assert result["status"] == "COMPLETED_WITH_FINDINGS", result
        workdir = Path(result["entry"]["workdir"])
        precheck = workdir / "subdomains" / "rtw_precheck.txt"
        assert precheck.is_file(), \
            ".log/.called_fn were not directories before reconftw.sh ran"
        assert "dirsok.goodscope.example/precheck" in precheck.read_text()
        assert (workdir / ".log").is_dir()
        assert (workdir / ".called_fn").is_dir()

    def test_stale_file_at_bookkeeping_path_becomes_dir(
            self, tmp_path, monkeypatch):
        """Older releases created .log/.called_fn as FILES; the helper must
        replace any stale file or symlink with a real directory."""
        monkeypatch.setenv("RTW_HOME", str(tmp_path / "rtw"))
        (tmp_path / "rtw").mkdir()
        stale = tmp_path / "wd" / ".log"
        stale.parent.mkdir(parents=True)
        stale.write_text("old file junk\n")
        adp._ensure_rtw_bookkeeping_dir(stale)
        assert stale.is_dir() and not stale.is_file()
        dangling = tmp_path / "wd2" / ".called_fn"
        dangling.parent.mkdir(parents=True)
        dangling.symlink_to(tmp_path / "nowhere")
        adp._ensure_rtw_bookkeeping_dir(dangling)
        assert dangling.is_dir() and not dangling.is_symlink()

    def test_preexisting_symlink_restored(self, step3_env):
        link = step3_env["rtw_home"] / "Recon" / TARGET
        link.parent.mkdir(parents=True, exist_ok=True)
        other = step3_env["tmp"] / "other-recon"
        other.mkdir()
        (other / "keepme.txt").write_text("original\n")
        os.symlink(other, link)
        result = _run_cap(step3_env)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        assert link.is_symlink() and link.resolve() == other.resolve()
        assert (other / "keepme.txt").read_text() == "original\n"

    def test_preexisting_real_dir_restored(self, step3_env):
        link = step3_env["rtw_home"] / "Recon" / TARGET
        link.mkdir(parents=True)
        (link / "old-run.txt").write_text("prior run\n")
        result = _run_cap(step3_env)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        assert link.is_dir() and not link.is_symlink()
        assert (link / "old-run.txt").read_text() == "prior run\n"

    def test_bridge_skipped_for_unsafe_domain(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RTW_HOME", str(tmp_path / "rtw"))
        (tmp_path / "rtw").mkdir()
        assert adp._bridge_recon_dir("../evil", tmp_path) == (None, None)
        assert adp._bridge_recon_dir("", tmp_path) == (None, None)
        assert not (tmp_path / "rtw" / "Recon").exists()


class TestMultiHopStatusAndReason:
    def test_parse_httpx_line_multi_hop_final_hop_wins(self):
        rec = rf.parse_httpx_line(
            "https://h.example [308,200] [Welcome] [nginx] [2048]")
        assert rec["status_code"] == 200          # final hop, as int
        assert rec["title"] == "Welcome"
        assert rec["content_length"] == 2048
        rec2 = rf.parse_httpx_line("https://h.example [301,302,200]")
        assert rec2["status_code"] == 200
        assert rf.parse_httpx_line("https://h.example [30x]") is None

    def test_multi_hop_status_flows_into_truth_hosts(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "bh"))
        rd = tmp_path / "recon" / "h.example"
        (rd / "live").mkdir(parents=True)
        (rd / "live" / "httpx_full.txt").write_text(
            "https://h.example [308,200] [Welcome] [nginx] [2048]\n")
        truth, _ = rf.fuse(rd, "h.example")
        assert truth["hosts"][0]["status_code"] == 200

    def test_tool_health_reason_falls_back_to_stderr_tail(
            self, tmp_path, monkeypatch):
        """FAILED / SKIPPED_SILENT entries without an explicit reason surface
        the last non-empty stderr line instead of an empty string."""
        monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "bh"))
        rd = tmp_path / "recon" / "m.example"
        rd.mkdir(parents=True)
        manifest_dir = tmp_path / "bh" / "recon" / "m.example"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "rtw_manifest.json").write_text(json.dumps({
            "version": 1, "entries": [
                {"capability_id": "CAP_SUB_PERMUT", "rtw_function": "sub_permut",
                 "status": "FAILED", "net_new_count": 0,
                 "stderr_tail": "warn: x\nERROR: modules/utils.sh not found\n"},
                {"capability_id": "CAP_TLS_PIVOTS", "rtw_function": "tls_ip_pivots",
                 "status": "SKIPPED_SILENT", "net_new_count": 0,
                 "reason": "explicit skip reason", "stderr_tail": "noise\n"},
            ]}))
        truth, _ = rf.fuse(rd, "m.example")
        health = {h["capability_id"]: h for h in truth["tool_health"]}
        assert health["CAP_SUB_PERMUT"]["reason"] == \
            "ERROR: modules/utils.sh not found"
        assert health["CAP_TLS_PIVOTS"]["reason"] == "explicit skip reason"


class TestRtwHomeFallback:
    def test_env_wins_over_config(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"rtw_home": str(tmp_path / "from-config")}))
        monkeypatch.setenv("RTW_HOME", str(tmp_path / "from-env"))
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", str(cfg))
        assert reg.rtw_home() == tmp_path / "from-env"

    def test_config_rtw_home_used_when_env_unset(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"rtw_home": str(tmp_path / "from-config")}))
        monkeypatch.delenv("RTW_HOME", raising=False)
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", str(cfg))
        assert reg.rtw_home() == tmp_path / "from-config"

    def test_default_tools_reconftw_when_nothing_set(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RTW_HOME", raising=False)
        # conftest pins RHODAWK_CONFIG_FILE to a nonexistent path already;
        # assert the documented fallback regardless of HOME.
        assert reg.rtw_home() == Path.home() / "Tools" / "reconftw"

    def test_install_sh_persists_rtw_home(self, tmp_path, monkeypatch):
        """install.sh's persist step writes rtw_home into config.json —
        simulated by running the same python block the installer uses."""
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", str(tmp_path / "config.json"))
        monkeypatch.setenv("RTW_HOME_PERSIST", str(tmp_path / "Tools" / "reconftw"))
        code = (
            "import json, os\n"
            "from pathlib import Path\n"
            "cfg_path = Path(os.environ['RHODAWK_CONFIG_FILE'])\n"
            "cfg = {}\n"
            "try:\n"
            "    cfg = json.loads(cfg_path.read_text())\n"
            "    if not isinstance(cfg, dict): cfg = {}\n"
            "except (OSError, ValueError): cfg = {}\n"
            "cfg['rtw_home'] = os.environ['RTW_HOME_PERSIST']\n"
            "cfg_path.parent.mkdir(parents=True, exist_ok=True)\n"
            "fd = os.open(str(cfg_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)\n"
            "with os.fdopen(fd, 'w') as f: f.write(json.dumps(cfg, indent=2))\n"
            "os.chmod(str(cfg_path), 0o600)\n"
        )
        subprocess.run([sys.executable, "-c", code], check=True)
        saved = json.loads((tmp_path / "config.json").read_text())
        assert saved["rtw_home"] == str(tmp_path / "Tools" / "reconftw")


class TestDoctor:
    def _env(self, tmp_path, monkeypatch, rtw_home, caps=None):
        repo = tmp_path / "rtw-doctor"
        if rtw_home is not None:
            repo.mkdir(exist_ok=True)
            script = repo / "reconftw.sh"
            script.write_text("#!/bin/bash\nexit 0\n")
            script.chmod(0o755)
        cfg = tmp_path / "config.json"
        cfg.write_text("{}")
        caps_file = tmp_path / "capabilities.json"
        caps_file.write_text(json.dumps(caps or {}))
        monkeypatch.setenv("RTW_HOME", str(rtw_home) if rtw_home else "")
        monkeypatch.setenv("RHODAWK_HOME", str(tmp_path / "bh"))
        monkeypatch.setenv("RHODAWK_CONFIG_FILE", str(cfg))
        monkeypatch.setenv("RHODAWK_CAPABILITIES_FILE", str(caps_file))
        for var in ("PDCP_API_KEY", "CHAOS_API_KEY", "H1_API_TOKEN",
                    "BRAIN_PROVIDER"):
            monkeypatch.delenv(var, raising=False)

    def _run(self, tmp_path):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "rhodawk", "engine.py"),
             "doctor"],
            capture_output=True, text=True, timeout=60, cwd=ROOT,
            env={**os.environ},
        )

    def test_doctor_pass_output_and_exit_code(self, tmp_path, monkeypatch):
        self._env(tmp_path, monkeypatch, rtw_home=tmp_path / "rtw-doctor",
                  caps={"chromium_path": sys.executable})
        proc = self._run(tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "[PASS]" in proc.stdout and "[WARN]" in proc.stdout
        assert "fix:" in proc.stdout
        assert "0 FAIL" in proc.stdout
        assert "Environment doctor" in proc.stdout

    def test_doctor_fail_on_missing_rtw(self, tmp_path, monkeypatch):
        self._env(tmp_path, monkeypatch,
                  rtw_home=tmp_path / "nonexistent-rtw")
        proc = self._run(tmp_path)
        assert proc.returncode == 1
        assert "[FAIL]" in proc.stdout
        assert "install.sh" in proc.stdout

    def test_doctor_warns_on_missing_chromium_and_keys(self, tmp_path,
                                                       monkeypatch):
        self._env(tmp_path, monkeypatch, rtw_home=tmp_path / "rtw-doctor",
                  caps={})
        proc = self._run(tmp_path)
        assert proc.returncode == 0
        assert "install_tools.sh --browser" in proc.stdout
        assert "export PDCP_API_KEY=" in proc.stdout

    def test_ci_workflow_template_and_gitignore_hygiene(self):
        """The CI workflow lives directly at .github/workflows/ci.yml — the
        duplicate docs/ template was retired in the v2.0.0 standalone
        release. Keep the workflow content and .gitignore hygiene in
        lockstep."""
        assert not (Path(ROOT) / "docs" / "workflow-ci.yml").exists()
        ci_path = Path(ROOT) / ".github" / "workflows" / "ci.yml"
        if ci_path.is_file():
            ci = ci_path.read_text()
            assert "bash -n rhodawk/tools/recon_engine.sh install.sh install_tools.sh" in ci
            assert "pytest -q" in ci
        # else: the workflow ships separately — creating it on GitHub needs a
        # credential with the `workflow` scope (Contents R&W is not enough).
        gi = (Path(ROOT) / ".gitignore").read_text()
        for entry in ("rhodawk/recon/", ".work/", "*.prev.json",
                      ".pytest_cache/"):
            assert entry in gi
