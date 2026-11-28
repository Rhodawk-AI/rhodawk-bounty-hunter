"""Tests for rhodawk/contracts/scope.py + rhodawk/tools/scope_compiler.py — Commit 2.

Covers the Commit-2 acceptance list (all network calls mocked):
- CompiledScopeManifest SHA-256 integrity verification and tamper detection
  (ValueError on a modified file), native `*.` wildcard preservation, and
  denylist-wins precedence,
- multi-page authenticated HackerOne REST pagination (84 items across 2 pages:
  51 allow / 33 exclude including 172.65.0.0/16 and support.cloudflare.com),
- cursor-paginated public GraphQL fallback,
- keyless bounty-targets-data fallback using EXACT case-insensitive handle
  equality (`shop` does NOT match `shopify`),
- asymmetric safety merge (allowlist intersection + denylist union) with
  h1scope CSV, HuntDeck SQLite (read-only URI) and bbscope `-o tu` caches,
- deterministic Markdown policy extraction (X-Bug-Bounty headers, RPS
  ceiling, excluded vulnerability classes),
- `rhodawk scope-compile` CLI wiring (subcommand + `sc` alias),
- zero secret leakage: the H1 token never appears in manifests, summaries,
  drift notes, or stdout.
"""

from __future__ import annotations

import base64
import csv
import json
import os
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from contracts.scope import CompiledScopeManifest, ScopeAssetMeta
from tools import scope_compiler

REPO = Path(__file__).resolve().parents[1]

SECRET_TOKEN = "h1-api-token-DO-NOT-PRINT-42"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Isolated HOME (vault + manifest mirror) + clean H1 env vars."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in ("H1_USERNAME", "H1_API_TOKEN", "H1_TOKEN",
                "RHODAWK_CREDENTIALS_FILE", "RECON_OUT_DIR"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def _attrs(identifier, submission=True, bounty=None, kind="URL",
           instruction="", max_severity=""):
    return {"asset_identifier": identifier, "asset_type": kind,
            "eligible_for_submission": submission,
            "eligible_for_bounty": (submission if bounty is None else bounty),
            "instruction": instruction, "max_severity": max_severity}


def _fake_rest_84(calls: list):
    """Two-page fake REST API: 51 allow / 33 exclude = 84 scope items."""
    page1 = ([{"attributes": _attrs("*.cloudflare.com")},
              {"attributes": _attrs("cloudflare.com")}]
             + [{"attributes": _attrs(f"host{i}.cloudflare.com")}
                for i in range(1, 50)])
    page2 = ([{"attributes": _attrs("172.65.0.0/16", submission=False,
                                    kind="IPV4_CIDR")},
              {"attributes": _attrs("support.cloudflare.com", submission=False,
                                    instruction="support portal is out of scope")}]
             + [{"attributes": _attrs(f"edge{i}.cloudflare.com",
                                     submission=False)}
                for i in range(1, 32)])
    assert len(page1) == 51 and len(page2) == 33

    def fake(url, auth=None):
        calls.append({"url": url, "auth": auth})
        if "structured_scopes" not in url:
            return {"data": {"attributes": {
                "handle": "cloudflare", "name": "Cloudflare",
                "policy": "You must send the `X-Bug-Bounty: cf-researcher` "
                          "header.\nDo not exceed 5 requests per second.\n"
                          "Out of scope: DDoS, physical testing."}}}
        if url.endswith("page%5Bsize%5D=100"):
            return {"data": page1, "links": {
                "next": "https://api.hackerone.com/v1/hackers/programs/"
                        "cloudflare/structured_scopes?page%5Bsize%5D=100"
                        "&page%5Bnumber%5D=2"}}
        return {"data": page2, "links": {"next": None}}

    return fake


# ── CompiledScopeManifest: invariants + integrity ─────────────────────────────

class TestCompiledScopeManifest:
    def test_post_init_preserves_wildcards_and_sorts_dedupes(self):
        m = CompiledScopeManifest(
            program_handle="TestProg",
            allow_patterns=["b.x.com", "*.cloudflare.com", "b.x.com", "a.com"],
            exclude_patterns=["172.65.0.0/16", "b.x.com"],
            excluded_classes=["dos", "ddos", "dos"],
        )
        # native `*.` wildcard preserved verbatim, dedup + sort applied
        assert m.allow_patterns == ["*.cloudflare.com", "a.com"]
        assert m.exclude_patterns == ["172.65.0.0/16", "b.x.com"]
        assert m.excluded_classes == ["ddos", "dos"]
        assert m.program_handle == "testprog"

    def test_denylist_wins_over_allowlist(self):
        m = CompiledScopeManifest(
            program_handle="p",
            allow_patterns=["keep.com", "drop.com"],
            exclude_patterns=["drop.com"],
        )
        assert m.allow_patterns == ["keep.com"]
        assert m.exclude_patterns == ["drop.com"]

    def test_sha256_deterministic_over_canonical_json(self):
        a = CompiledScopeManifest(program_handle="p", allow_patterns=["a.com"],
                                  exclude_patterns=["x.com"])
        b = CompiledScopeManifest(program_handle="p", allow_patterns=["a.com"],
                                  exclude_patterns=["x.com"])
        assert a.manifest_sha256 == b.manifest_sha256
        assert len(a.manifest_sha256) == 64
        # hash excludes the hash field itself and is order-insensitive
        c = CompiledScopeManifest(program_handle="p",
                                  allow_patterns=["a.com", "b.com"])
        d = CompiledScopeManifest(program_handle="p",
                                  allow_patterns=["b.com", "a.com"])
        assert c.manifest_sha256 == d.manifest_sha256

    def test_verify_integrity_detects_mutation(self):
        m = CompiledScopeManifest(program_handle="p", allow_patterns=["a.com"])
        assert m.verify_integrity() is True
        m.allow_patterns.append("evil.com")  # in-memory tamper
        assert m.verify_integrity() is False

    def test_save_load_roundtrip(self, tmp_path):
        m = CompiledScopeManifest(
            program_handle="cloudflare",
            program_name="Cloudflare",
            auth_mode="authenticated_rest",
            allow_patterns=["*.cloudflare.com", "a.com"],
            exclude_patterns=["x.com"],
            mandatory_headers={"X-Bug-Bounty": "cf-researcher"},
            max_rps=12.0,
            assets_metadata=[{"asset_identifier": "a.com", "asset_type": "URL"}],
            drift_audit=[{"kind": "source_note", "detail": "n"}],
        )
        path = tmp_path / "nested" / "compiled_scope.json"
        saved = m.save(path)
        assert saved == path and path.exists()
        loaded = CompiledScopeManifest.load(path)
        assert loaded.manifest_sha256 == m.manifest_sha256
        assert loaded.program_name == "Cloudflare"
        assert loaded.mandatory_headers == {"X-Bug-Bounty": "cf-researcher"}
        assert loaded.max_rps == 12.0
        assert loaded.assets_metadata[0].asset_identifier == "a.com"
        assert isinstance(loaded.assets_metadata[0], ScopeAssetMeta)
        assert loaded.verify_integrity() is True

    def test_load_tampered_file_raises_valueerror(self, tmp_path):
        m = CompiledScopeManifest(program_handle="p",
                                  allow_patterns=["a.com", "b.com"])
        path = tmp_path / "m.json"
        m.save(path)
        data = json.loads(path.read_text())
        data["allow_patterns"].append("attacker.com")  # in-place tamper
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="manifest_sha256 mismatch"):
            CompiledScopeManifest.load(path)
        # explicit opt-out still loads (audit/recovery path)
        loose = CompiledScopeManifest.load(path, require_valid_hash=False)
        assert "attacker.com" in loose.allow_patterns

    def test_load_hash_covers_exclude_and_metadata(self, tmp_path):
        m = CompiledScopeManifest(program_handle="p",
                                  allow_patterns=["a.com"],
                                  exclude_patterns=["e.com"],
                                  assets_metadata=[{"asset_identifier": "e.com",
                                                    "eligible_for_submission": False}])
        path = tmp_path / "m.json"
        m.save(path)
        data = json.loads(path.read_text())
        data["exclude_patterns"].remove("e.com")  # drop the deny entry
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError):
            CompiledScopeManifest.load(path)


# ── Handle normalization ───────────────────────────────────────────────────────

class TestHandleNormalization:
    @pytest.mark.parametrize("raw,expected", [
        ("cloudflare", "cloudflare"),
        ("CloudFlare", "cloudflare"),
        ("  shop  ", "shop"),
        ("https://hackerone.com/cloudflare?type=team", "cloudflare"),
        ("https://hackerone.com/ibb-rectify/", "ibb-rectify"),
        ("http://www.hackerone.com/shopify", "shopify"),
    ])
    def test_valid(self, raw, expected):
        assert scope_compiler.normalize_handle(raw) == expected

    @pytest.mark.parametrize("bad", [
        "", "   ", "https://google.com/x", "a b", "../etc/passwd",
        "handle;rm", "H1!", "cloudflare/recon",
    ])
    def test_invalid(self, bad):
        with pytest.raises(ValueError):
            scope_compiler.normalize_handle(bad)


# ── Authenticated REST pagination ─────────────────────────────────────────────

class TestAuthenticatedRestPagination:
    def test_84_items_across_two_pages_no_truncation(self, isolated_home, monkeypatch):
        monkeypatch.setenv("H1_USERNAME", "researcher")
        monkeypatch.setenv("H1_API_TOKEN", SECRET_TOKEN)
        calls: list = []
        fetched = scope_compiler.fetch_program_scope(
            "cloudflare", creds={"auth_mode": "authenticated_rest"},
            rest_fn=_fake_rest_84(calls))
        assert fetched["auth_mode"] == "authenticated_rest"
        assert len(fetched["assets"]) == 84  # > 50 — the old truncation bug
        allow = [a.asset_identifier for a in fetched["assets"]
                 if a.eligible_for_submission]
        exclude = [a.asset_identifier for a in fetched["assets"]
                   if not a.eligible_for_submission]
        assert len(allow) == 51 and len(exclude) == 33
        assert "172.65.0.0/16" in exclude
        assert "support.cloudflare.com" in exclude
        assert "*.cloudflare.com" in allow  # native wildcard preserved
        # program metadata came from the REST attributes
        assert fetched["program_name"] == "Cloudflare"
        assert "X-Bug-Bounty" in fetched["policy_md"]
        # exactly 3 HTTP calls: program + scope page 1 + scope page 2
        assert len(calls) == 3
        assert calls[0]["url"].endswith("/hackers/programs/cloudflare")
        assert calls[1]["url"].endswith(
            "/hackers/programs/cloudflare/structured_scopes?page%5Bsize%5D=100")
        assert calls[2]["url"].endswith("page%5Bnumber%5D=2")

    def test_basic_auth_header_and_zero_leakage(self, isolated_home, monkeypatch):
        monkeypatch.setenv("H1_USERNAME", "researcher")
        monkeypatch.setenv("H1_API_TOKEN", SECRET_TOKEN)
        calls: list = []
        scope_compiler.fetch_program_scope(
            "cloudflare", creds={"auth_mode": "authenticated_rest"},
            rest_fn=_fake_rest_84(calls))
        expected = "Basic " + base64.b64encode(
            f"researcher:{SECRET_TOKEN}".encode()).decode()
        assert all(c["auth"] == expected for c in calls if c["auth"])
        # the raw token never leaks into sources/notes (manifest fields)
        assert SECRET_TOKEN not in json.dumps(fetched_json_safe(
            scope_compiler.fetch_program_scope(
                "cloudflare", creds={"auth_mode": "authenticated_rest"},
                rest_fn=_fake_rest_84([]))))

    def test_rest_auth_failure_falls_back_to_public(self, isolated_home):
        def denied(url, auth=None):
            if "structured_scopes" in url:
                raise scope_compiler.RestAuthError(
                    "H1 REST API rejected credentials (HTTP 401)")
            return {"data": {"attributes": {"handle": "x", "name": "X",
                                            "policy": ""}}}

        fetched = scope_compiler.fetch_program_scope(
            "x", creds={"auth_mode": "authenticated_rest"},
            rest_fn=denied,
            graphql_fn=lambda q, v: {"data": {"team": {
                "name": "X", "handle": "x", "policy": "p",
                "structured_scopes": {"nodes": [
                    {"asset_identifier": "x.com", "eligible_for_submission": True}]}}}},
        )
        assert fetched["auth_mode"] == "keyless_public"
        assert fetched["assets"][0].asset_identifier == "x.com"
        assert any("falling back" in n for n in fetched["notes"])
        # the redacted note must not carry the exception internals verbatim
        assert all("Authorization" not in n for n in fetched["notes"])

    def test_auth_rest_without_env_vars_falls_back(self, isolated_home):
        fetched = scope_compiler.fetch_program_scope(
            "x", creds={"auth_mode": "authenticated_rest"},
            rest_fn=lambda url, auth=None: (_ for _ in ()).throw(
                AssertionError("REST must not be called without credentials")),
            graphql_fn=lambda q, v: {"data": {"team": {
                "name": "X", "handle": "x", "policy": "",
                "structured_scopes": {"nodes": [
                    {"asset_identifier": "x.com",
                     "eligible_for_submission": True}]}}}},
        )
        assert fetched["auth_mode"] == "keyless_public"
        assert fetched["assets"][0].asset_identifier == "x.com"


def fetched_json_safe(fetched: dict) -> dict:
    return {k: ([a.to_dict() for a in v] if k == "assets" else v)
            for k, v in fetched.items()}


# ── Keyless public fallback ────────────────────────────────────────────────────

class TestKeylessPublicFallback:
    def test_graphql_cursor_pagination(self):
        pages = [
            {"data": {"team": {"name": "Shop", "handle": "shop",
                               "offers_bounties": True, "policy": "p1",
                               "structured_scopes": {
                                   "pageInfo": {"hasNextPage": True,
                                                "endCursor": "cursor-1"},
                                   "nodes": [_attrs("*.shop.com",
                                                    kind="WILDCARD")]}}}},
            {"data": {"team": {"name": "Shop", "handle": "shop",
                               "structured_scopes": {
                                   "pageInfo": {"hasNextPage": False},
                                   "nodes": [_attrs("172.65.0.0/16",
                                                    submission=False,
                                                    kind="IPV4_CIDR")]}}}},
        ]
        queries: list = []

        def fake_gql(query, variables=None):
            queries.append(variables)
            return pages[0 if variables.get("cursor") is None else 1]

        fetched = scope_compiler.fetch_program_scope(
            "shop", creds={"auth_mode": "keyless_public"},
            graphql_fn=fake_gql)
        assert [v["cursor"] for v in queries] == [None, "cursor-1"]
        assert len(fetched["assets"]) == 2
        assert fetched["program_name"] == "Shop"
        assert fetched["offers_bounties"] is True
        assert "archived: false" in scope_compiler.GRAPHQL_PROGRAM_SCOPE_QUERY

    def test_bounty_targets_exact_handle_equality(self):
        dump = [
            {"handle": "shopify", "name": "Shopify", "targets": {
                "in_scope": [{"asset_identifier": "*.shopify.com"}],
                "out_of_scope": [{"asset_identifier": "internal.shopify.com"}]}},
            {"handle": "shop", "name": "Shop", "targets": {
                "in_scope": [{"asset_identifier": "shop.com",
                              "eligible_for_bounty": True}],
                "out_of_scope": []}},
            {"handle": "Shop2", "name": "Shop Two", "targets": {
                "in_scope": [{"asset_identifier": "shop2.com"}],
                "out_of_scope": []}},
        ]

        def gql_down(query, variables=None):
            raise scope_compiler.ScopeCompilerError("GraphQL unavailable")

        fetched = scope_compiler.fetch_program_scope(
            "shop", creds={"auth_mode": "keyless_public"},
            graphql_fn=gql_down,
            bounty_targets_fn=lambda h: scope_compiler.fetch_bounty_targets_program(
                h, fetch_fn=lambda url: dump))
        # EXACT equality: only handle "shop" — never "shopify" / "Shop2"
        ids = [a.asset_identifier for a in fetched["assets"]]
        assert ids == ["shop.com"]
        assert fetched["assets"][0].eligible_for_bounty is True

    def test_substring_handle_never_matches(self):
        dump = [{"handle": "shopify", "name": "Shopify", "targets": {
            "in_scope": [{"asset_identifier": "*.shopify.com"}],
            "out_of_scope": []}}]

        def gql_down(query, variables=None):
            raise scope_compiler.ScopeCompilerError("GraphQL unavailable")

        with pytest.raises(scope_compiler.ProgramNotFoundError):
            scope_compiler.fetch_program_scope(
                "shop", creds={"auth_mode": "keyless_public"},
                graphql_fn=gql_down,
                bounty_targets_fn=lambda h:
                    scope_compiler.fetch_bounty_targets_program(
                        h, fetch_fn=lambda url: dump))

    def test_graphql_team_none_is_authoritative_not_found(self):
        with pytest.raises(scope_compiler.ProgramNotFoundError):
            scope_compiler.fetch_program_scope(
                "ghost", creds={"auth_mode": "keyless_public"},
                graphql_fn=lambda q, v: {"data": {"team": None}},
                bounty_targets_fn=lambda h: (_ for _ in ()).throw(
                    AssertionError("must not consult the dump after team=None")))


# ── Markdown policy compiler ──────────────────────────────────────────────────

class TestPolicyMarkdown:
    def test_headers_rps_and_classes(self):
        md = """# Bug bounty policy
You must send the `X-Bug-Bounty: h1-researcher` header with every request.
Also set `X-Researcher-ID` when proxying through our infrastructure.
Header: X-Custom-Token: tok-123

## Rate limiting
Do not exceed 5 requests per second.

## Excluded from the program
The following are out of scope:
- DDoS and denial of service
- social engineering
- physical testing
- clickjacking
- SPF/DMARC misconfigurations
- rate-limiting complaints
"""
        policy = scope_compiler.parse_policy_markdown(md)
        assert policy["mandatory_headers"] == {
            "X-Bug-Bounty": "h1-researcher",
            "X-Researcher-ID": "",
            "X-Custom-Token": "tok-123",
        }
        assert policy["max_rps"] == 5.0
        assert policy["excluded_classes"] == [
            "clickjacking", "ddos", "dos", "physical_security",
            "rate_limiting", "social_engineering", "spf_dmarc"]

    def test_default_rps_when_absent(self):
        policy = scope_compiler.parse_policy_markdown("No rate rules here.")
        assert policy["max_rps"] == scope_compiler.DEFAULT_MAX_RPS == 5.0
        assert policy["mandatory_headers"] == {}
        assert policy["excluded_classes"] == []

    def test_rps_variants(self):
        assert scope_compiler.parse_policy_markdown(
            "Rate limit: 10 rps.")["max_rps"] == 10.0
        assert scope_compiler.parse_policy_markdown(
            "max_rps = 2.5")["max_rps"] == 2.5
        assert scope_compiler.parse_policy_markdown(
            "Limit yourself to 3 requests per second.")["max_rps"] == 3.0

    def test_rps_line_is_not_an_excluded_class(self):
        # A rate ceiling alone must NOT flag rate_limiting as excluded class.
        policy = scope_compiler.parse_policy_markdown(
            "Maximum 5 requests per second allowed.")
        assert "rate_limiting" not in policy["excluded_classes"]

    def test_url_span_is_not_a_header(self):
        policy = scope_compiler.parse_policy_markdown(
            "Visit `https://example.com:8080/path` for docs.")
        assert policy["mandatory_headers"] == {}


# ── Optional reconciliation sources ────────────────────────────────────────────

class TestSourceParsers:
    def test_parse_h1scope_csv(self, tmp_path):
        path = tmp_path / "h1scope.csv"
        with open(path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["asset_identifier", "asset_type",
                             "eligible_for_bounty", "eligible_for_submission",
                             "instruction"])
            writer.writerow(["a.com", "URL", "true", "true", ""])
            writer.writerow(["b.com", "URL", "true", "true", ""])
            writer.writerow(["x.com", "URL", "false", "false", "oos"])
        parsed = scope_compiler.parse_h1scope_csv(path)
        assert parsed["allow"] == ["a.com", "b.com"]
        assert parsed["exclude"] == ["x.com"]

    def test_parse_huntdeck_db_read_only(self, tmp_path):
        db = tmp_path / "huntdeck.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE assets (asset_identifier TEXT, "
                     "asset_type TEXT, in_scope INTEGER)")
        conn.executemany("INSERT INTO assets VALUES (?,?,?)",
                         [("a.com", "URL", 1), ("b.com", "URL", 1),
                          ("d.com", "URL", 1), ("y.com", "URL", 0)])
        conn.commit()
        conn.close()
        parsed = scope_compiler.parse_huntdeck_db(db)
        assert sorted(parsed["allow"]) == ["a.com", "b.com", "d.com"]
        assert parsed["exclude"] == ["y.com"]

    def test_parse_bbscope_cache_tu(self, tmp_path):
        cache = tmp_path / "bbscope.tu"
        cache.write_text(
            "Identifier            Type       Bounty  Submission\n"
            "--------------------- ---------- ------- -----------\n"
            "*.cloudflare.com      WILDCARD   Yes     Yes\n"
            "a.com                 URL        Yes     Yes\n"
            "c.com                 URL        No      Yes\n"
            "+---------------------+----------+-------+-----------+\n")
        parsed = scope_compiler.parse_bbscope_cache(cache)
        assert parsed["allow"] == ["*.cloudflare.com", "a.com", "c.com"]
        assert parsed["exclude"] == []


# ── Asymmetric safety merge ────────────────────────────────────────────────────

class TestAsymmetricSafetyMerge:
    def test_intersection_and_denylist_union(self):
        merged_allow, merged_exclude, drift = scope_compiler._asymmetric_merge(
            primary_allow=["a.com", "b.com", "c.com"],
            primary_exclude=["x.com"],
            extra_sources=[
                {"name": "h1scope", "allow": ["a.com", "b.com"],
                 "exclude": ["x.com"]},
                {"name": "huntdeck", "allow": ["a.com", "b.com", "d.com"],
                 "exclude": ["y.com"]},
            ])
        # intersection of primary + both optional allowlists
        assert sorted(merged_allow) == ["a.com", "b.com"]
        # union of every denylist
        assert sorted(merged_exclude) == ["x.com", "y.com"]
        kinds = [d["kind"] for d in drift]
        assert "allow_intersection_drop" in kinds   # c.com missing downstream
        assert "allow_extra_in_source" in kinds     # d.com extra upstream

    def test_single_source_keeps_primary_allow(self):
        merged_allow, merged_exclude, drift = scope_compiler._asymmetric_merge(
            primary_allow=["a.com", "b.com"], primary_exclude=["x.com"],
            extra_sources=[])
        assert sorted(merged_allow) == ["a.com", "b.com"]
        assert merged_exclude == ["x.com"]
        assert drift == []

    def test_cross_source_conflict_deny_wins_in_manifest(self, tmp_path,
                                                         isolated_home,
                                                         monkeypatch):
        monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "recon"))
        summary = scope_compiler.compile_and_save(
            "conflictprog",
            creds={"auth_mode": "keyless_public"},
            rest_fn=lambda url, auth=None: (_ for _ in ()).throw(
                AssertionError("keyless mode must not call REST")),
            graphql_fn=lambda q, v: {"data": {"team": {
                "name": "Conflict", "handle": "conflictprog", "policy": "",
                "structured_scopes": {"nodes": [
                    _attrs("contested.com"),
                    _attrs("safe.com")]}}}},
            huntdeck_db=_huntdeck_db(tmp_path, [("contested.com", 0),
                                                ("contested.com", 1)]))
        manifest = CompiledScopeManifest.load(summary["manifest"])
        # the optional source excludes what primary allows — denylist wins
        assert "contested.com" not in manifest.allow_patterns
        assert "contested.com" in manifest.exclude_patterns
        assert any(d["kind"] == "cross_source_conflict"
                   for d in manifest.drift_audit)

    def test_compile_and_save_full_merge(self, tmp_path, isolated_home,
                                         monkeypatch):
        monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "recon"))

        csv_path = tmp_path / "h1scope.csv"
        with open(csv_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["asset_identifier", "eligible_for_submission"])
            writer.writerow(["a.com", "true"])
            writer.writerow(["b.com", "true"])
            writer.writerow(["x.com", "false"])

        db_path = _huntdeck_db(tmp_path, [("a.com", 1), ("b.com", 1),
                                          ("d.com", 1), ("y.com", 0)])

        bbscope_file = tmp_path / "bbscope.tu"
        bbscope_file.write_text("Identifier   Type\n"
                           "-----------  ----\n"
                           "a.com       URL\n"
                           "*.extra.com URL\n")

        def gql(query, variables=None):
            return {"data": {"team": {"name": "Merged Program",
                                      "handle": "mergeprog", "policy": "",
                                      "structured_scopes": {"nodes": [
                                          _attrs("a.com"),
                                          _attrs("b.com"),
                                          _attrs("c.com"),
                                          _attrs("x.com", submission=False)]}}}}

        summary = scope_compiler.compile_and_save(
            "mergeprog", creds={"auth_mode": "keyless_public"},
            graphql_fn=gql, h1scope_csv=str(csv_path),
            huntdeck_db=str(db_path), bbscope_cache=str(bbscope_file))
        manifest = CompiledScopeManifest.load(summary["manifest"])
        # intersection primary ∩ h1scope ∩ huntdeck ∩ bbscope = {a.com}
        assert manifest.allow_patterns == ["a.com"]
        # denylist union = {x.com (primary), y.com (huntdeck)}
        assert sorted(manifest.exclude_patterns) == ["x.com", "y.com"]
        kinds = [d["kind"] for d in manifest.drift_audit]
        assert "allow_intersection_drop" in kinds
        assert "allow_extra_in_source" in kinds
        assert summary["drift_count"] == len(manifest.drift_audit)
        assert any("h1scope-csv" in s for s in manifest.sources)
        assert any("huntdeck-db" in s for s in manifest.sources)
        assert any("bbscope-cache" in s for s in manifest.sources)


def _huntdeck_db(tmp_path, rows) -> Path:
    db = tmp_path / f"hd_{abs(hash(tuple(rows)))}.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE assets (asset_identifier TEXT, in_scope INTEGER)")
    conn.executemany("INSERT INTO assets VALUES (?,?)", rows)
    conn.commit()
    conn.close()
    return db


# ── compile_and_save: output paths, mirroring, redaction ──────────────────────

class TestCompileAndSave:
    def test_rest_mode_saves_primary_and_mirror(self, tmp_path, isolated_home,
                                                monkeypatch):
        monkeypatch.setenv("H1_USERNAME", "researcher")
        monkeypatch.setenv("H1_API_TOKEN", SECRET_TOKEN)
        monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "recon"))
        calls: list = []
        summary = scope_compiler.compile_and_save(
            "https://hackerone.com/cloudflare?type=team",
            creds={"auth_mode": "authenticated_rest"},
            rest_fn=_fake_rest_84(calls))
        assert summary["program_handle"] == "cloudflare"
        assert summary["allow_patterns"] == 51
        assert summary["exclude_patterns"] == 33
        assert summary["mandatory_headers"] == {"X-Bug-Bounty": "cf-researcher"}
        assert summary["max_rps"] == 5.0
        primary = Path(summary["manifest"])
        mirror = Path(summary["mirror"])
        assert primary == tmp_path / "recon" / "scope" / "compiled_scope.json"
        # Layer 2 hardening: the mirror honors $RHODAWK_HOME (conftest pins it
        # to tmp_path/rhodawk-home) instead of the old hardcoded ~/.rhodawk.
        assert mirror == Path(os.environ["RHODAWK_HOME"]) / "scope" / \
            "cloudflare_compiled_scope.json"
        assert primary.exists() and mirror.exists()
        assert summary["manifest_sha256"] == \
            CompiledScopeManifest.load(primary).manifest_sha256[:16]
        # zero secret leakage in both files + the summary
        for blob in (primary.read_text(), mirror.read_text(),
                     json.dumps(summary)):
            assert SECRET_TOKEN not in blob

    def test_explicit_output_path_respected(self, tmp_path, isolated_home,
                                            monkeypatch):
        out = tmp_path / "custom" / "manifest.json"
        summary = scope_compiler.compile_and_save(
            "progx", creds={"auth_mode": "keyless_public"},
            graphql_fn=lambda q, v: {"data": {"team": {
                "name": "X", "handle": "progx", "policy": "",
                "structured_scopes": {"nodes": [_attrs("x.com")]}}}},
            output=str(out))
        assert Path(summary["manifest"]) == out
        assert out.exists()
        assert Path(summary["mirror"]).exists()

    def test_cli_main_prints_redacted_summary(self, tmp_path, isolated_home,
                                              monkeypatch, capsys):
        monkeypatch.setenv("RECON_OUT_DIR", str(tmp_path / "recon"))
        with patch("tools.scope_compiler._graphql_request", side_effect=lambda q, v=None:
                {"data": {"team": {"name": "Y", "handle": "progy",
                                   "policy": "",
                                   "structured_scopes": {"nodes": [
                                       _attrs("y.com")]}}}}):
            rc = scope_compiler.main(
                ["progy", "--output", str(tmp_path / "m.json")])
        assert rc == 0
        out = capsys.readouterr().out
        summary = json.loads(out)
        assert summary["program_handle"] == "progy"
        assert summary["manifest_sha256"]
        assert len(summary["manifest_sha256"]) == 16

    def test_cli_main_error_is_redacted_json(self, capsys):
        rc = scope_compiler.main(["this handle has spaces"])
        assert rc == 1
        payload = json.loads(capsys.readouterr().out)
        assert "error" in payload


# ── engine wiring: `rhodawk scope-compile` + `sc` alias ─────────────────────

class TestEngineScopeCompileWiring:
    @pytest.fixture
    def engine_module(self):
        if str(REPO / "rhodawk") not in sys.path:
            sys.path.insert(0, str(REPO / "rhodawk"))
        import engine
        return engine

    def _run(self, engine_module, monkeypatch, capsys, argv, tmp_path):
        monkeypatch.setenv("H1_USERNAME", "researcher")
        monkeypatch.setenv("H1_API_TOKEN", SECRET_TOKEN)
        monkeypatch.setattr(sys, "argv", argv)
        calls: list = []
        with patch("tools.scope_compiler._rest_request",
                   side_effect=_fake_rest_84(calls)):
            engine_module.main()
        return capsys.readouterr().out

    def test_scope_compile_subcommand(self, engine_module, isolated_home,
                                      monkeypatch, capsys, tmp_path):
        out = self._run(
            engine_module, monkeypatch, capsys,
            ["engine.py", "scope-compile", "cloudflare",
             "--output", str(tmp_path / "out" / "compiled_scope.json")],
            tmp_path)
        assert "allow patterns: 51" in out
        assert "exclude patterns: 33" in out
        assert "X-Bug-Bounty" in out
        assert "max RPS: 5.0" in out
        assert str(tmp_path / "out" / "compiled_scope.json") in out
        manifest = CompiledScopeManifest.load(
            tmp_path / "out" / "compiled_scope.json")
        assert manifest.program_handle == "cloudflare"
        assert len(manifest.allow_patterns) == 51
        # zero secret leakage through the whole CLI output
        assert SECRET_TOKEN not in out
        assert SECRET_TOKEN not in (tmp_path / "out" /
                                    "compiled_scope.json").read_text()

    def test_sc_alias(self, engine_module, isolated_home, monkeypatch,
                      capsys, tmp_path):
        out = self._run(
            engine_module, monkeypatch, capsys,
            ["engine.py", "sc", "cloudflare",
             "--output", str(tmp_path / "out2" / "compiled_scope.json")],
            tmp_path)
        assert "allow patterns: 51" in out
        assert (tmp_path / "out2" / "compiled_scope.json").exists()

    def test_invalid_handle_exits_cleanly(self, engine_module, isolated_home,
                                          monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv",
                            ["engine.py", "scope-compile", "not a handle!"])
        with pytest.raises(SystemExit) as exc:
            engine_module.main()
        assert exc.value.code == 2
        assert "invalid program handle" in capsys.readouterr().out


# ── MCP server get_program_policy upgrade ─────────────────────────────────────

class TestServerGetProgramPolicyUpgrade:
    @pytest.fixture
    def server_module(self):
        mcp_dir = REPO / "rhodawk" / "mcp" / "hackerone-mcp"
        if str(mcp_dir) not in sys.path:
            sys.path.insert(0, str(mcp_dir))
        import server
        return server

    def _paginated_gql(self, pages, queries):
        def fake(query, variables=None):
            queries.append(variables)
            cursor = (variables or {}).get("cursor")
            return pages[0] if cursor is None else pages[1]
        return fake

    def test_policy_over_50_items_via_pagination(self, server_module,
                                                 isolated_home):
        page1 = {"data": {"team": {
            "name": "Acme", "handle": "acme", "policy": "be nice",
            "offers_bounties": True,
            "structured_scopes": {
                "pageInfo": {"hasNextPage": True, "endCursor": "c2"},
                "nodes": [_attrs(f"a{i}.acme.com") for i in range(60)]}}}}
        page2 = {"data": {"team": {
            "name": "Acme", "handle": "acme",
            "structured_scopes": {
                "pageInfo": {"hasNextPage": False},
                "nodes": [_attrs(f"b{i}.acme.com") for i in range(25)]}}}}
        queries: list = []
        with patch.object(server_module, "_graphql_request",
                          side_effect=self._paginated_gql([page1, page2],
                                                          queries)):
            policy = server_module.get_program_policy("acme")
        assert [v["cursor"] for v in queries] == [None, "c2"]
        assert len(policy["scopes"]) == 85  # 60 + 25 — NOT truncated at 50
        assert policy["program"] == "acme"
        assert policy["offers_bounties"] is True
        assert policy["scopes"][0]["identifier"] == "a0.acme.com"

    def test_policy_not_found_error_dict(self, server_module, isolated_home):
        with patch.object(server_module, "_graphql_request",
                          return_value={"data": {"team": None}}):
            policy = server_module.get_program_policy("ghost")
        assert "error" in policy and policy["program"] == "ghost"

    def test_policy_legacy_shape_preserved(self, server_module, isolated_home):
        team = {"name": "Acme", "handle": "acme", "policy": "p",
                "offers_bounties": False,
                "structured_scopes": {"nodes": [
                    {"asset_type": "URL", "asset_identifier": "*.acme.com",
                     "eligible_for_bounty": True,
                     "eligible_for_submission": True,
                     "instruction": "main"}]}}
        with patch.object(server_module, "_graphql_request",
                          return_value={"data": {"team": team}}):
            policy = server_module.get_program_policy("acme")
        assert policy["scopes"][0] == {
            "type": "URL", "identifier": "*.acme.com",
            "bounty_eligible": True, "submission_eligible": True,
            "instruction": "main"}
        assert policy["policy_text"] == "p"
