"""Unit tests for rhodawk/tools/recon_fusion.py (Step 2B/2C).

Covers the four acceptance areas from the build brief:
  - recon_truth.json provenance merging (hosts/urls/js/ports with
    discovered_by[]) + tool_health ingestion from rtw_manifest.json
  - URL canonicalization (utm_* stripped, identical parameter-key
    signatures collapsed)
  - pure-Python 64-bit SimHash host clustering (Hamming <= 3, one
    is_cluster_rep per cluster)
  - CDN_EDGE / THIRD_PARTY_SAAS / FIRST_PARTY_ORIGIN classification
  - delta.json run-to-run diffing (+ prev-truth archive + mirror copy)
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

from tools import recon_fusion as rf  # noqa: E402


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "bh-home"
    monkeypatch.setenv("RHODAWK_HOME", str(home))
    return home


def write(recon_dir: Path, rel: str, text: str) -> Path:
    path = recon_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.fixture
def recon_dir(tmp_path):
    rd = tmp_path / "recon" / "t.example.com"
    for sub in ("subdomains", "live", "ports", "urls", "js", "hosts"):
        (rd / sub).mkdir(parents=True)
    write(rd, "subdomains/subfinder.txt", "api.t.example.com\n")
    write(rd, "subdomains/crtsh.txt",
          "api.t.example.com\nwww.t.example.com\n")
    write(rd, "subdomains/all.txt",
          "api.t.example.com\nwww.t.example.com\nt.example.com\n")
    write(rd, "live/httpx_full.txt",
          "https://t.example.com [200] [Example Home] [nginx] [2048]\n"
          "https://api.t.example.com [200] [Example Home] [nginx] [2050]\n"
          "https://cdn.t.example.com [200] [Example CDN] [cloudflare] [99]\n")
    write(rd, "live/urls.txt",
          "https://t.example.com\nhttps://api.t.example.com\n"
          "https://cdn.t.example.com\n")
    write(rd, "ports/nmap_greppable.txt",
          "Host: 93.184.216.34 () Ports: 80/open/tcp//http///, "
          "443/open/tcp//https///\n")
    write(rd, "hosts/resolution.txt",
          "t.example.com\t93.184.216.34\t\n")
    write(rd, "urls/gau.txt",
          "https://t.example.com/blog?page=2&utm_source=feed\n")
    write(rd, "urls/katana.txt",
          "https://t.example.com/blog?page=3&utm_source=feed\n"
          "https://t.example.com/api/v1/users\n")
    write(rd, "urls/all.txt",
          "https://t.example.com/blog?page=2&utm_source=feed\n"
          "https://t.example.com/api/v1/users\n")
    write(rd, "js/endpoints.txt", "/api/v1/users\n/static/app.js\n")
    return rd


class TestCanonicalUrl:
    def test_utm_and_click_ids_stripped(self):
        canon = rf.canonical_url(
            "https://App.Example.com/a?utm_source=x&utm_campaign=y"
            "&id=7&fbclid=z")
        assert canon == "https://app.example.com/a?id=7"
        assert "utm_" not in canon and "fbclid" not in canon

    def test_other_params_kept_and_sorted(self):
        assert rf.canonical_url("https://h.example/p?b=2&a=1") == \
            "https://h.example/p?a=1&b=2"

    def test_param_signature_collapses_same_keys(self):
        assert rf.param_signature("https://h.example/s?user=alice") == \
            rf.param_signature("https://h.example/s?user=bob")
        assert rf.param_signature("https://h.example/s?page=2") != \
            rf.param_signature("https://h.example/s?user=alice")

    def test_garbage_passthrough(self):
        assert rf.canonical_url("not-a-url") == "not-a-url"


class TestClassifyHost:
    def test_cdn_via_cname_suffix(self):
        cls, provider = rf.classify_host(
            "app.example.com", cname="example.cloudflare.net.")
        assert (cls, provider) == (rf.CLASS_CDN_EDGE, "Cloudflare")

    def test_cdn_via_tech_token(self):
        cls, provider = rf.classify_host("app.example.com", tech="cloudflare")
        assert cls == rf.CLASS_CDN_EDGE and provider.lower() == "cloudflare"

    def test_major_cdn_providers(self):
        for cname, provider in (("x.vercel-dns.com", "Vercel"),
                                ("y.akamaiedge.net", "Akamai"),
                                ("z.fastly.net", "Fastly"),
                                ("d.cloudfront.net", "CloudFront")):
            cls, got = rf.classify_host("h.example", cname=cname)
            assert cls == rf.CLASS_CDN_EDGE and got == provider

    def test_saas_beats_cdn_and_plain_is_origin(self):
        # SaaS suffix wins regardless of CDN tech evidence.
        cls, provider = rf.classify_host("widgets.myshopify.com",
                                         tech="cloudflare")
        assert (cls, provider) == (rf.CLASS_SAAS, "Shopify")
        # A plain host behind Cloudflare tech is still a CDN edge, not origin.
        cls2, provider2 = rf.classify_host("shop.example.com", tech="cloudflare")
        assert (cls2, provider2) == (rf.CLASS_CDN_EDGE, "Cloudflare")
        # No evidence at all → first-party origin.
        assert rf.classify_host("origin.example.com") == (rf.CLASS_ORIGIN, "")

    def test_third_party_saas_suffixes(self):
        for host, provider in (("brand.zendesk.com", "Zendesk"),
                               ("pages.github.io", "GitHub Pages"),
                               ("site.hubspot.net", "HubSpot")):
            cls, got = rf.classify_host(host)
            assert cls == rf.CLASS_SAAS and got == provider

    def test_cdn_via_raw_httpx_line_tech_anywhere(self):
        """Live-run fix 2: rhodawkai.com sits on Vercel's apex A-record (no
        CNAME), with the tech tag buried in the httpx line. The evidence is
        the RAW line, so the tag is found wherever the column order puts it —
        and the user's exact provider list all classify as CDN_EDGE."""
        raw = "https://rhodawkai.com [200] [5180] [RhodawkAI] [HSTS,Vercel]"
        assert rf.classify_host("rhodawkai.com", tech=raw) == \
            (rf.CLASS_CDN_EDGE, "Vercel")
        for token, provider in (("cloudflare", "Cloudflare"),
                                ("fastly", "Fastly"),
                                ("akamai", "Akamai"),
                                ("cloudfront", "CloudFront"),
                                ("netlify", "Netlify"),
                                ("imperva", "Imperva")):
            cls, got = rf.classify_host("h.example", tech=f"[HSTS,{provider}]")
            assert cls == rf.CLASS_CDN_EDGE and got == provider, token


def _write_recon_skeleton(tmp_path, name):
    rd = tmp_path / "recon" / name
    for sub in ("subdomains", "live", "ports", "urls", "js", "hosts"):
        (rd / sub).mkdir(parents=True)
    return rd


class TestLiveHostIngest:
    def test_bare_urls_live_hosts_and_classes_populate_hosts(
            self, tmp_path, isolated_home):
        """Live-run fix 3 (hosts=0): a real httpx may emit the
        [status][length][title][tech] column order the old positional regex
        mis-parsed, or bare URLs when -tech-detect is unsupported — and some
        runs only write live/live_hosts.txt + hosts/host_classes.txt. Every
        shape must yield host rows with counts populated."""
        rd = _write_recon_skeleton(tmp_path, "bare.example.com")
        write(rd, "live/httpx_full.txt",
              "https://bare.example.com [200] [5180] [Bare] [HSTS,Vercel]\n"
              "https://plain.example.com\n")
        write(rd, "live/live_hosts.txt", "extra.example.com\n")
        write(rd, "live/urls.txt",
              "https://bare.example.com\nhttps://plain.example.com\n")
        write(rd, "hosts/host_classes.txt",
              "bare.example.com\t76.76.21.21\tCDN_EDGE\tVercel\n"
              "plain.example.com\t\tFIRST_PARTY_ORIGIN\t\n"
              "extra.example.com\t\tFIRST_PARTY_ORIGIN\t\n")
        truth, _ = rf.fuse(rd, "bare.example.com")
        hosts = {h["host"]: h for h in truth["hosts"]}
        assert len(hosts) == 3
        c = truth["counts"]
        assert c["live_hosts"] == 3
        assert c["cdn_edges"] == 1
        assert c["unique_host_clusters"] >= 1
        # Real httpx column order parses cleanly now.
        bare = hosts["bare.example.com"]
        assert bare["status_code"] == 200
        assert bare["content_length"] == 5180
        assert bare["title"] == "Bare"
        assert "Vercel" in bare["tech"] or "HSTS" in bare["tech"]
        # host_classes.txt wins for the asset class; class file hosts are
        # ingested even without any httpx metadata.
        assert bare["asset_class"] == rf.CLASS_CDN_EDGE
        assert hosts["extra.example.com"]["asset_class"] == rf.CLASS_ORIGIN
        assert "live/live_hosts.txt" in hosts["extra.example.com"]["discovered_by"]
        # The only resolved IP (76.76.21.21) belongs to the CDN edge; the
        # first-party rows here carry no resolved A records.
        assert truth["counts"]["origin_ips"] == 0

    def test_parse_httpx_line_both_column_orders(self):
        a = rf.parse_httpx_line(
            "https://h.example [200] [Welcome] [nginx] [2048]")
        b = rf.parse_httpx_line(
            "https://h.example [200] [2048] [Welcome] [HSTS,Vercel]")
        for rec in (a, b):
            assert rec["status_code"] == 200
            assert rec["title"] == "Welcome"
            assert rec["content_length"] == 2048
        assert a["tech"] == ["nginx"]
        assert b["tech"] == ["HSTS", "Vercel"]
        assert rf.parse_httpx_line("https://h.example") is None

    def test_classify_uses_raw_line_evidence_without_classes_file(
            self, tmp_path, isolated_home):
        """No host_classes.txt yet (fresh Phase 2.5): the raw httpx line's
        Vercel tag alone must classify the apex host as CDN_EDGE."""
        rd = _write_recon_skeleton(tmp_path, "rhodawkai.example")
        write(rd, "live/httpx_full.txt",
              "https://rhodawkai.example [200] [5180] [RhodawkAI] [HSTS,Vercel]\n")
        write(rd, "live/urls.txt", "https://rhodawkai.example\n")
        counts = rf.classify_recon_dir(rd)
        assert counts[rf.CLASS_CDN_EDGE] == 1
        assert counts[rf.CLASS_ORIGIN] == 0
        assert (rd / "hosts" / "origin_targets.txt").read_text() == ""


class TestSimHashClustering:
    @staticmethod
    def _hash(rec):
        return rf.simhash64(rf.host_features(rec["status_code"], rec["title"],
                                             rec["tech"], rec["content_length"]))

    def test_identical_pages_cluster_with_one_rep(self):
        recs = [{"host": name, "status_code": 200, "title": "Welcome to Example",
                 "tech": ["nginx"], "content_length": 2048}
                for name in ("a.example.com", "b.example.com", "c.example.com")]
        for rec in recs:
            rec["simhash"] = self._hash(rec)
        rf.cluster_hosts(recs)
        assert len({h["cluster_id"] for h in recs}) == 1
        assert sum(1 for h in recs if h["is_cluster_rep"]) == 1
        assert recs[0]["is_cluster_rep"] is True
        assert recs[1]["is_cluster_rep"] is False

    def test_near_identical_page_clusters_via_content_bucket(self):
        """2048 vs 2050 bytes land in the same content-length bucket → the
        near-duplicate mirrors of one app cluster together (Hamming 0)."""
        recs = [{"host": "www.example.com", "status_code": 200,
                 "title": "Example Home", "tech": ["nginx"],
                 "content_length": 2048},
                {"host": "app.example.com", "status_code": 200,
                 "title": "Example Home", "tech": ["nginx"],
                 "content_length": 2050}]
        for rec in recs:
            rec["simhash"] = self._hash(rec)
        rf.cluster_hosts(recs)
        assert recs[0]["cluster_id"] == recs[1]["cluster_id"]

    def test_different_pages_separate_clusters(self):
        recs = [{"host": "app.example.com", "status_code": 200,
                 "title": "Dashboard", "tech": ["react"],
                 "content_length": 5000},
                {"host": "mail.example.com", "status_code": 401,
                 "title": "Sign in to webmail", "tech": ["express"],
                 "content_length": 120}]
        for rec in recs:
            rec["simhash"] = self._hash(rec)
        rf.cluster_hosts(recs)
        assert recs[0]["cluster_id"] != recs[1]["cluster_id"]
        assert all(h["is_cluster_rep"] for h in recs)

    def test_deterministic_64bit_and_hamming(self):
        a = rf.simhash64(["status=200", "title=hello", "clbucket=2"])
        b = rf.simhash64(["status=200", "title=hello", "clbucket=2"])
        c = rf.simhash64(["status=404", "title=completely different content",
                          "clbucket=5", "tech=iis"])
        assert 0 <= a < 2 ** 64
        assert a == b and rf.hamming_distance(a, b) == 0
        assert rf.hamming_distance(a, c) > 3

    def test_content_length_bucket_boundaries(self):
        assert rf.content_length_bucket(None) == 0
        assert rf.content_length_bucket(0) == 0
        assert rf.content_length_bucket(999) == 1
        assert rf.content_length_bucket(1000) == 2
        assert rf.content_length_bucket(999_999) == 4
        assert rf.content_length_bucket(2_000_000) == 5


class TestFuse:
    def test_truth_schema_counts_provenance(self, recon_dir, isolated_home):
        truth, delta = rf.fuse(recon_dir, "t.example.com",
                               scope_domains=["*.t.example.com"])
        assert truth["schema_version"] == "1.0"
        assert truth["target"] == "t.example.com"
        assert truth["scope_patterns"]["domains"] == ["*.t.example.com"]
        c = truth["counts"]
        assert c["subdomains"] == 3
        assert c["live_hosts"] == 3
        # t + api share features (same title/status/tech, same CL bucket) →
        # one cluster; cdn differs → second cluster.
        assert c["unique_host_clusters"] == 2
        assert c["cdn_edges"] == 1
        assert c["origin_ips"] == 1          # t.example.com -> 93.184.216.34
        assert c["open_ports"] == 2
        assert c["js_endpoints"] == 2
        # URL canonicalization: utm stripped; page=2 vs page=3 collapse on the
        # same parameter-key signature; the API URL stays distinct.
        assert c["unique_urls"] == 2
        urls = {u["url"]: u for u in truth["urls"]}
        assert "https://t.example.com/blog?page=2" in urls
        assert all("utm_source" not in u for u in urls)
        blog = urls["https://t.example.com/blog?page=2"]
        assert set(blog["discovered_by"]) == {"urls/gau.txt", "urls/katana.txt",
                                              "urls/all.txt"}
        # Host provenance merging.
        hosts = {h["host"]: h for h in truth["hosts"]}
        api = hosts["api.t.example.com"]
        assert "subdomains/subfinder.txt" in api["discovered_by"]
        assert "subdomains/crtsh.txt" in api["discovered_by"]
        assert "live/httpx_full.txt" in api["discovered_by"]
        # Clustering + reps (sorted order: api < cdn < t).
        assert hosts["api.t.example.com"]["cluster_id"] == \
            hosts["t.example.com"]["cluster_id"]
        assert hosts["cdn.t.example.com"]["cluster_id"] != \
            hosts["t.example.com"]["cluster_id"]
        assert hosts["api.t.example.com"]["is_cluster_rep"] is True
        assert hosts["t.example.com"]["is_cluster_rep"] is False
        assert hosts["cdn.t.example.com"]["is_cluster_rep"] is True
        # Asset classes: cdn host via tech token; plain hosts origin.
        assert hosts["cdn.t.example.com"]["asset_class"] == rf.CLASS_CDN_EDGE
        assert hosts["t.example.com"]["asset_class"] == rf.CLASS_ORIGIN
        # JS endpoints + ports carry provenance.
        assert {e["endpoint"] for e in truth["js_endpoints"]} == \
            {"/api/v1/users", "/static/app.js"}
        assert truth["ports"][0]["host"] == "t.example.com"
        assert truth["ports"][0]["port"] == 80
        assert truth["ports"][0]["nmap_host"] == "93.184.216.34"
        assert truth["ports"][0]["discovered_by"] == ["ports/nmap_greppable.txt"]
        assert truth["unattributed_ports"] == []
        assert delta["has_previous_run"] is False

    def test_tool_health_from_manifest(self, recon_dir, isolated_home):
        manifest_dir = isolated_home / "recon" / "t.example.com"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "rtw_manifest.json").write_text(json.dumps({
            "version": 1, "ttl_days": 7, "entries": [
                {"capability_id": "CAP_CDN_ISOLATE",
                 "rtw_function": "cdnprovider",
                 "status": "COMPLETED_EMPTY", "duration_secs": 0.1,
                 "net_new_count": 0,
                 "reason": "function completed, no net-new output lines"},
            ]}))
        truth, _ = rf.fuse(recon_dir, "t.example.com")
        assert truth["tool_health"] == [{
            "capability_id": "CAP_CDN_ISOLATE", "rtw_function": "cdnprovider",
            "status": "COMPLETED_EMPTY", "duration_secs": 0.1,
            "net_new_count": 0,
            "reason": "function completed, no net-new output lines"}]

    def test_delta_second_run_prev_archive_and_mirror(self, recon_dir,
                                                      isolated_home):
        rf.fuse(recon_dir, "t.example.com")
        mirror = isolated_home / "recon" / "t.example.com" / "recon_truth.json"
        assert mirror.is_file(), "truth must be mirrored under RHODAWK_HOME"
        assert (recon_dir / "recon_truth.prev.json").exists() is False

        # Next run: one new subdomain, one status flip, one new open port.
        write(recon_dir, "subdomains/all.txt",
              "api.t.example.com\nwww.t.example.com\nt.example.com\n"
              "fresh.t.example.com\n")
        httpx = (recon_dir / "live" / "httpx_full.txt").read_text().replace(
            "[200] [Example Home]", "[403] [Example Home]")
        write(recon_dir, "live/httpx_full.txt", httpx)
        nmap = (recon_dir / "ports" / "nmap_greppable.txt").read_text().replace(
            "443/open", "8443/open")
        write(recon_dir, "ports/nmap_greppable.txt", nmap)

        truth2, delta = rf.fuse(recon_dir, "t.example.com")
        assert (recon_dir / "recon_truth.prev.json").is_file()
        assert delta["has_previous_run"] is True
        assert delta["new_subdomains"] == ["fresh.t.example.com"]
        assert delta["removed_subdomains"] == []
        assert {"host": "t.example.com", "from": 200, "to": 403} in \
            delta["status_code_flips"]
        assert delta["new_open_ports"] == [{"host": "t.example.com",
                                            "port": 8443}]
        prev = json.loads((recon_dir / "recon_truth.prev.json").read_text())
        assert prev["counts"]["open_ports"] == 2
        assert truth2["counts"]["subdomains"] == 4
        line = rf.format_delta_line(delta)
        assert "Delta vs previous run" in line and "+1 subdomains" in line


class TestClassifyCommand:
    def test_classify_recon_dir_writes_files(self, recon_dir, isolated_home):
        write(recon_dir, "hosts/resolution.txt",
              "cdn.t.example.com\t104.21.5.10\tcdn.example.cloudflare.net\n"
              "t.example.com\t93.184.216.34\t\n")
        counts = rf.classify_recon_dir(recon_dir, limit=50)
        assert counts == {rf.CLASS_CDN_EDGE: 1, rf.CLASS_SAAS: 0,
                          rf.CLASS_ORIGIN: 2}
        classes = (recon_dir / "hosts" / "host_classes.txt").read_text()
        assert "CDN_EDGE" in classes and "Cloudflare" in classes
        origins = (recon_dir / "hosts" / "origin_targets.txt").read_text().split()
        # Resolved origin IP wins over the bare host; unresolved origin hosts
        # fall back to the hostname.
        assert origins == ["93.184.216.34", "api.t.example.com"]

    def test_cli_classify_and_delta_line(self, recon_dir, isolated_home):
        rc = rf.main(["classify", "--recon-dir", str(recon_dir)])
        assert rc == 0
        assert (recon_dir / "hosts" / "host_classes.txt").is_file()
        assert rf.main(["delta-line", "--recon-dir", str(recon_dir)]) == 0


class TestFusionScopeOptOutAndHealth:
    """B1 regression: `--no-scope-check` must not kill canonical fusion, the
    truth must record scope_enforced, and fuse failures must never be
    swallowed silently (tool_health FUSION=FAILED)."""

    def test_fuse_cli_accepts_no_scope_check_and_records_false(
            self, recon_dir, isolated_home):
        rc = rf.main(["fuse", "--recon-dir", str(recon_dir),
                      "--target", "t.example.com", "--no-scope-check"])
        assert rc == 0
        truth = json.loads((recon_dir / "recon_truth.json").read_text())
        assert truth["scope_enforced"] is False
        assert (recon_dir / "delta.json").is_file()

    def test_fuse_records_scope_enforced_true_by_default(
            self, recon_dir, isolated_home):
        assert rf.main(["fuse", "--recon-dir", str(recon_dir),
                        "--target", "t.example.com"]) == 0
        truth = json.loads((recon_dir / "recon_truth.json").read_text())
        assert truth["scope_enforced"] is True

    def test_mark_failed_records_fusion_failed_in_tool_health(
            self, recon_dir, isolated_home):
        rc = rf.main(["mark-failed", "--target", "t.example.com",
                      "--reason", "fuse exploded"])
        assert rc == 0
        truth = rf.build_truth(recon_dir, "t.example.com")
        fusion = [h for h in truth["tool_health"]
                  if h["capability_id"] == "FUSION"]
        assert fusion and fusion[0]["status"] == "FAILED"
        assert "fuse exploded" in fusion[0]["reason"]

    def test_successful_fuse_clears_stale_fusion_failed_entry(
            self, recon_dir, isolated_home):
        rf.main(["mark-failed", "--target", "t.example.com", "--reason", "x"])
        rf.main(["fuse", "--recon-dir", str(recon_dir),
                 "--target", "t.example.com"])
        manifest = json.loads(
            (isolated_home / "recon" / "t.example.com" / "rtw_manifest.json")
            .read_text())
        assert all(e.get("capability_id") != "FUSION"
                   for e in manifest.get("entries", []))


class TestPortAttribution:
    """B4 regression: open ports are attributed ONLY to hosts they can be
    joined to — the nmap target hostname itself, or an IP that exactly ONE
    host resolves to (hosts/resolution.txt). Anything unjoinable (hostless
    open_ports.txt fallback rows, shared/ambiguous IPs like the E9 loopback)
    goes to truth['unattributed_ports'] and must never surface as a port on
    oos.example.test."""

    @staticmethod
    def _dir(tmp_path, greppable, resolution="", open_ports=""):
        rd = tmp_path / "recon" / "t.example.com"
        for sub in ("subdomains", "live", "ports", "urls", "js", "hosts"):
            (rd / sub).mkdir(parents=True, exist_ok=True)
        (rd / "subdomains" / "all.txt").write_text("t.example.com\n")
        (rd / "live" / "httpx_full.txt").write_text(
            "https://t.example.com [200] [Example Home] [nginx] [2048]\n")
        if greppable:
            (rd / "ports" / "nmap_greppable.txt").write_text(greppable)
        if resolution:
            (rd / "hosts" / "resolution.txt").write_text(resolution)
        if open_ports:
            (rd / "ports" / "open_ports.txt").write_text(open_ports)
        return rd

    def test_ip_with_single_resolving_host_is_attributed(self, tmp_path):
        rd = self._dir(tmp_path,
                       "Host: 10.0.0.15 () Ports: 80/open/tcp//http//stub-tech/\n",
                       resolution="app2.t.example.com\t10.0.0.15\t\n")
        truth, _ = rf.fuse(rd, "t.example.com")
        assert truth["ports"] == [{
            "host": "app2.t.example.com", "port": 80, "protocol": "tcp",
            "service": "http", "nmap_host": "10.0.0.15",
            "discovered_by": ["ports/nmap_greppable.txt"]}]
        assert truth["unattributed_ports"] == []
        assert truth["counts"]["open_ports"] == 1

    def test_e9_shared_ip_never_borrows_ports(self, tmp_path):
        """The E9 defect: 127.0.0.1 hosts several lab names (one of them
        oos.example.test). Port 80 discovered on the shared loopback IP must
        land in unattributed_ports — NOT on oos.example.test."""
        rd = self._dir(tmp_path,
                       "Host: 127.0.0.1 () Ports: 80/open/tcp//http//stub-tech/\n",
                       resolution="app.t.example.com\t127.0.0.1\t\n"
                                  "oos.example.test\t127.0.0.1\t\n"
                                  "localhost\t127.0.0.1\t\n")
        truth, _ = rf.fuse(rd, "t.example.com")
        assert all(p["host"] != "oos.example.test" for p in truth["ports"])
        assert all(p.get("host") != "oos.example.test"
                   for p in truth["unattributed_ports"])
        assert truth["ports"] == []
        assert len(truth["unattributed_ports"]) == 1
        row = truth["unattributed_ports"][0]
        assert row["port"] == 80 and row["source_host"] == "127.0.0.1"
        assert truth["counts"]["open_ports"] == 0

    def test_hostless_open_ports_fallback_is_unattributed(self, tmp_path):
        rd = self._dir(tmp_path, greppable="", open_ports="80/open\n")
        truth, _ = rf.fuse(rd, "t.example.com")
        assert truth["ports"] == []
        assert truth["unattributed_ports"] == [{
            "port": 80, "protocol": "tcp", "service": "",
            "source_host": "", "discovered_by": ["ports/open_ports.txt"]}]

    def test_unmapped_ip_is_unattributed(self, tmp_path):
        rd = self._dir(tmp_path,
                       "Host: 203.0.113.9 () Ports: 8080/open/tcp//http//proxy/\n")
        truth, _ = rf.fuse(rd, "t.example.com")
        assert truth["ports"] == []
        assert truth["unattributed_ports"][0]["port"] == 8080

    def test_delta_never_reports_oos_host_ports(self, tmp_path):
        """Across two runs, delta.json new_open_ports can never gain a row on
        an ambiguous shared IP's host (the E9 delta leak)."""
        rd = self._dir(tmp_path,
                       "Host: 127.0.0.1 () Ports: 80/open/tcp//http//stub-tech/\n",
                       resolution="oos.example.test\t127.0.0.1\t\n"
                                  "app.t.example.com\t127.0.0.1\t\n")
        truth1, delta1 = rf.fuse(rd, "t.example.com")
        assert delta1["new_open_ports"] == []
        (rd / "ports" / "nmap_greppable.txt").write_text(
            "Host: 127.0.0.1 () Ports: 80/open/tcp//http//stub-tech/, "
            "8443/open/tcp//https//\n")
        _, delta2 = rf.fuse(rd, "t.example.com")
        assert all(p["host"] != "oos.example.test"
                   for p in delta2["new_open_ports"])
        assert delta2["new_open_ports"] == []


class TestInputIntegrity:
    """B7 regression: recon_truth.json carries an input_integrity block (per
    input file: ok / empty / missing / unparseable); any unparseable REQUIRED
    input sets truth status DEGRADED with a visible warning; the exit code is
    unchanged."""

    def test_binary_garbage_degrades_status(self, recon_dir, isolated_home,
                                            capsys):
        (recon_dir / "live" / "httpx_full.txt").write_bytes(
            b"\x00\x01\xff\xfe binary garbage \x00")
        rc = rf.main(["fuse", "--recon-dir", str(recon_dir),
                      "--target", "t.example.com"])
        assert rc == 0  # exit code unchanged
        truth = json.loads((recon_dir / "recon_truth.json").read_text())
        assert truth["input_integrity"]["live/httpx_full.txt"] == "unparseable"
        assert truth["status"] == rf.STATUS_DEGRADED
        assert "DEGRADED" in capsys.readouterr().err

    def test_nul_bytes_in_subdomain_list_unparseable(self, recon_dir,
                                                     isolated_home):
        (recon_dir / "subdomains" / "all.txt").write_bytes(
            b"app\x00.lab.test\ngarbage line no tld\n")
        rf.main(["fuse", "--recon-dir", str(recon_dir),
                 "--target", "t.example.com"])
        truth = json.loads((recon_dir / "recon_truth.json").read_text())
        assert truth["input_integrity"]["subdomains/all.txt"] == "unparseable"
        assert truth["status"] == rf.STATUS_DEGRADED

    def test_empty_and_missing_inputs_are_not_degraded(self, recon_dir,
                                                       isolated_home):
        (recon_dir / "urls" / "all.txt").write_text("")
        (recon_dir / "ports" / "nmap_greppable.txt").unlink()
        rf.main(["fuse", "--recon-dir", str(recon_dir),
                 "--target", "t.example.com"])
        truth = json.loads((recon_dir / "recon_truth.json").read_text())
        assert truth["input_integrity"]["urls/all.txt"] == "empty"
        assert truth["input_integrity"]["ports/nmap_greppable.txt"] == "missing"
        assert truth["status"] == rf.STATUS_OK

    def test_clean_inputs_report_ok(self, recon_dir, isolated_home):
        rf.main(["fuse", "--recon-dir", str(recon_dir),
                 "--target", "t.example.com"])
        truth = json.loads((recon_dir / "recon_truth.json").read_text())
        assert truth["status"] == rf.STATUS_OK
        assert set(truth["input_integrity"].values()) <= {
            "ok", "empty", "missing"}
        assert all(v != "unparseable"
                   for v in truth["input_integrity"].values())
