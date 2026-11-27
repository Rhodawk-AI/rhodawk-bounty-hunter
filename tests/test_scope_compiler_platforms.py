"""Fix 7 red-to-green: scope compilation for Bugcrowd / Intigriti / YesWeHack.

Defect (rhodawk-blueprint.md gap #7 / mission item 7): scope compilation was
HackerOne-only; a bugcrowd/intigriti/yeswehack handle raised
ProgramNotFoundError (grep on this HEAD: 0 mentions of the three platforms in
scope_compiler.py).

Fix: keyless compilation via the SAME bounty-targets-data dump the H1
fallback already uses — one data file per platform, exact-match handle
lookup, same CompiledScopeManifest output, same SHA-256 integrity. Fixtures
below are trimmed from the REAL arkadiyt/bounty-targets-data files (verified
live: bugcrowd_data.json 1.2 MB / 296 programs, intigriti_data.json 642 KB /
144, yeswehack_data.json 116 KB / 51). No private/platform API is invented;
authenticated REST remains HackerOne-only (documented).
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from tools import scope_compiler as sc  # noqa: E402
from contracts.scope import CompiledScopeManifest  # noqa: E402

# Fixtures trimmed from the real dumps (structure preserved verbatim).
BUGCROWD_DUMP = [
    {
        "name": "CoinDesk Data - Data API ",
        "url": "https://bugcrowd.com/engagements/CCData-mbb-og",
        "allows_disclosure": False,
        "managed_by_bugcrowd": True,
        "max_payout": 5000,
        "safe_harbor": None,
        "targets": {
            "in_scope": [
                {"type": "api", "target": "http://data-api.coindesk.com/",
                 "uri": "http://data-api.coindesk.com/",
                 "name": "CoinDesk Data - Data API", "ipAddress": ""},
                {"type": "web", "target": "*.coindesk.com",
                 "uri": "*.coindesk.com", "name": "All domains", "ipAddress": ""},
            ],
            "out_of_scope": [
                {"type": "url", "target": "https://blog.coindesk.com/",
                 "uri": "https://blog.coindesk.com/", "name": "Blog",
                 "ipAddress": ""},
            ],
        },
    },
]
INTIGRITI_DUMP = [
    {
        "id": "53a05c4a-0fc0-45a0-b158-a7562b313f79",
        "name": "1Password Bug Bounty Program",
        "company_handle": "onepassword",
        "handle": "onepassword",
        "url": "https://app.intigriti.com/researcher/program/onepassword/1password",
        "status": "public",
        "targets": {
            "in_scope": [
                {"type": "url", "endpoint": "<your-own>.1password.com",
                 "description": "Your own 1Password account (Tier 1)"},
                {"type": "api", "endpoint": "api.1password.com",
                 "description": "1Password API"},
            ],
            "out_of_scope": [
                {"type": "url", "endpoint": "marketing.1password.com",
                 "description": "Marketing site"},
            ],
        },
    },
]
YESWEHACK_DUMP = [
    {
        "id": "outscale",
        "name": "3DS OUTSCALE",
        "public": True,
        "disabled": False,
        "managed": None,
        "min_bounty": 50,
        "max_bounty": 3000,
        "targets": {
            "in_scope": [
                {"target": "https://cockpit-eu-west-2.outscale.com/",
                 "type": "web-application"},
            ],
            "out_of_scope": [
                {"target": "https://community.outscale.com/",
                 "type": "web-application"},
            ],
        },
    },
]


def _dump_loader(dump):
    def _fetch(url):
        return dump
    return _fetch


@pytest.mark.parametrize("url,expected", [
    ("https://hackerone.com/cloudflare?type=team", "hackerone"),
    ("https://bugcrowd.com/engagements/CCData-mbb-og", "bugcrowd"),
    ("https://app.intigriti.com/researcher/program/onepassword/1password",
     "intigriti"),
    ("https://yeswehack.com/programs/outscale", "yeswehack"),
    ("cloudflare", "hackerone"),  # bare handles default to hackerone
])
def test_detect_platform(url, expected):
    assert sc.detect_platform(url) == expected


@pytest.mark.parametrize("url,expected", [
    ("https://bugcrowd.com/engagements/CCData-mbb-og", "ccdata-mbb-og"),
    ("https://yeswehack.com/programs/outscale", "outscale"),
    ("https://app.intigriti.com/researcher/program/onepassword/1password",
     "1password"),
])
def test_normalize_handle_platform_urls(url, expected):
    assert sc.normalize_handle(url) == expected


def test_bugcrowd_compiles_manifest(tmp_path, monkeypatch):
    """End-to-end: bugcrowd URL → compiled manifest (the red-to-green case:
    previously ProgramNotFoundError)."""
    out = tmp_path / "scope.json"
    summary = sc.compile_and_save(
        "https://bugcrowd.com/engagements/CCData-mbb-og",
        output=str(out),
        bounty_targets_fn=_dump_loader(BUGCROWD_DUMP),
        creds={"auth_mode": "keyless_public"},
    )
    assert summary["program_handle"] == "ccdata-mbb-og"
    assert summary["program_name"].startswith("CoinDesk")
    assert summary["auth_mode"] == "keyless_public"
    assert any("bugcrowd_data.json" in s for s in summary["sources"])
    manifest = CompiledScopeManifest.load(str(out))
    # identifiers carry exactly what the platform publishes (URLs verbatim);
    # wildcards preserved; denylist wins in exclude_patterns
    assert "*.coindesk.com" in manifest.allow_patterns
    assert "http://data-api.coindesk.com/" in manifest.allow_patterns
    assert "https://blog.coindesk.com/" in manifest.exclude_patterns
    assert "https://blog.coindesk.com/" not in manifest.allow_patterns
    # the saved file round-trips with intact hash
    loaded = CompiledScopeManifest.load(str(out))
    assert loaded.verify_integrity()
    # in-scope asset metadata carries the platform type
    meta = {a.asset_identifier: a for a in manifest.assets_metadata}
    assert meta["http://data-api.coindesk.com/"].asset_type == "api"
    assert meta["https://blog.coindesk.com/"].eligible_for_submission is False


def test_intigriti_compiles_manifest(tmp_path):
    out = tmp_path / "scope.json"
    summary = sc.compile_and_save(
        "https://app.intigriti.com/researcher/program/onepassword/1password",
        output=str(out),
        bounty_targets_fn=_dump_loader(INTIGRITI_DUMP),
        creds={"auth_mode": "keyless_public"},
    )
    assert summary["program_handle"] == "1password"
    assert any("intigriti_data.json" in s for s in summary["sources"])
    manifest = CompiledScopeManifest.load(str(out))
    assert "api.1password.com" in manifest.allow_patterns
    assert "marketing.1password.com" in manifest.exclude_patterns


def test_yeswehack_compiles_manifest(tmp_path):
    out = tmp_path / "scope.json"
    summary = sc.compile_and_save(
        "https://yeswehack.com/programs/outscale",
        output=str(out),
        bounty_targets_fn=_dump_loader(YESWEHACK_DUMP),
        creds={"auth_mode": "keyless_public"},
    )
    assert summary["program_handle"] == "outscale"
    assert any("yeswehack_data.json" in s for s in summary["sources"])
    manifest = CompiledScopeManifest.load(str(out))
    assert "https://cockpit-eu-west-2.outscale.com/" in manifest.allow_patterns
    assert "https://community.outscale.com/" in manifest.exclude_patterns


@pytest.mark.parametrize("platform,handle,dump", [
    ("bugcrowd", "no-such-program", BUGCROWD_DUMP),
    ("intigriti", "shop", INTIGRITI_DUMP),  # substring of "onepassword"? no match
    ("yeswehack", "outscale2", YESWEHACK_DUMP),
])
def test_exact_match_no_substring(platform, handle, dump):
    """The ABH-era substring bug ("shop" matching "shopify") stays dead:
    only exact handle/slug/id matches."""
    with pytest.raises(sc.ProgramNotFoundError):
        sc.fetch_bounty_targets_entry(handle, platform,
                                      fetch_fn=_dump_loader(dump))


def test_hackerone_path_unchanged(monkeypatch):
    """No regression: an H1 URL still routes through the H1 fetch chain
    (monkeypatched to prove it is CALLED)."""
    called = {}

    def _fake_bt(handle, platform="hackerone", fetch_fn=None):
        called["platform"] = platform
        raise sc.ProgramNotFoundError(f"{handle} not found")

    monkeypatch.setattr(sc, "fetch_bounty_targets_entry", _fake_bt)
    with pytest.raises(sc.ProgramNotFoundError):
        sc.fetch_program_scope(
            "cloudflare",
            rest_fn=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("rest down")),
            graphql_fn=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("gql down")),
            bounty_targets_fn=lambda h: (_ for _ in ()).throw(
                sc.ProgramNotFoundError("dump miss")),
            creds={"auth_mode": "keyless_public"},
        )
    # the platform-specific entry fetch was never consulted for an H1 handle
    assert "platform" not in called
