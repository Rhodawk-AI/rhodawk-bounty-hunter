#!/usr/bin/env python3
"""scope_compiler.py — unified, lossless scope compiler (Commit 2).

Replaces `scope_aggregator.sh`'s lossy intake (substring handle matching,
stripped `*.` wildcards, first-50 truncation) with a typed, hashed
`CompiledScopeManifest`:

  Authenticated mode (`auth_mode == "authenticated_rest"`):
    GET  https://api.hackerone.com/v1/hackers/programs/{handle}
         -> program metadata + top-level `.attributes.policy` Markdown
    GET  https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes?page[size]=100
         -> follows `links.next` until null (no first:50 truncation)
    HTTP Basic auth; credentials always come from
    `rhodawk/tools/credentials.py` (never logged, never embedded).

  Keyless public fallback (`auth_mode == "keyless_public"`):
    Public https://hackerone.com/graphql with cursor pagination
    (structured_scopes(first: 100, after: $cursor, archived: false)),
    then the arkadiyt/bounty-targets-data JSON dump using EXACT
    case-insensitive handle equality (`p["handle"].lower() == handle`) —
    fixing the `shop` matches `shopify` substring collision.

  Optional multi-source reconciliation (asymmetric safety merge):
    --h1scope-csv <path>    h1scope CSV export
    --huntdeck-db <path>    HuntDeck SQLite (opened read-only, URI
                            `file:<path>?mode=ro`)
    --bbscope-cache <path>  bbscope `-o tu` table cache
    allow_patterns = intersection across primary + every supplied allowlist
                     (primary alone when no optional source is given);
    exclude_patterns = union of every out-of-scope entry;
    every cross-source discrepancy lands in `drift_audit`.

  Deterministic Markdown policy compiler (`parse_policy_markdown`):
    mandatory_headers, max_rps (default 5.0), excluded_classes.

Output:
  <primary>  : --output, or $RECON_OUT_DIR/scope/compiled_scope.json,
               or recon/<handle>/scope/compiled_scope.json
  mirror     : ~/.rhodawk/scope/<handle>_compiled_scope.json

CLI:
  python3 -m rhodawk.tools.scope_compiler acme
  python3 -m rhodawk.tools.scope_compiler https://hackerone.com/acme?type=team \
      [--output <path>] [--h1scope-csv <path>] [--huntdeck-db <path>] \
      [--bbscope-cache <path>]

Zero secret leakage: tokens are read via the credential vault and used only
inside Authorization headers; manifests, summaries and error notes carry
counts, codes and paths only.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import sqlite3
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:  # package import (pythonpath=rhodawk, or engine-style sys.path setup)
    from tools import credentials as _credentials
except ImportError:  # standalone execution from rhodawk/tools/
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        from tools import credentials as _credentials
    except ImportError:
        import credentials as _credentials  # type: ignore

try:
    from contracts.scope import CompiledScopeManifest, ScopeAssetMeta
except ImportError:
    _TOOLS_DIR = Path(__file__).resolve().parent
    sys.path.insert(0, str(_TOOLS_DIR.parent))
    from contracts.scope import CompiledScopeManifest, ScopeAssetMeta

__all__ = [
    "ScopeCompilerError",
    "ProgramNotFoundError",
    "RestAuthError",
    "normalize_handle",
    "detect_platform",
    "parse_policy_markdown",
    "fetch_program_scope",
    "fetch_bounty_targets_program",
    "fetch_bounty_targets_entry",
    "parse_h1scope_csv",
    "parse_huntdeck_db",
    "parse_bbscope_cache",
    "compile_and_save",
    "resolve_output_paths",
    "main",
]

# ── Constants ─────────────────────────────────────────────────────────────────

H1_API_BASE = "https://api.hackerone.com/v1"
H1_GRAPHQL_URL = "https://hackerone.com/graphql"
BOUNTY_TARGETS_URL = ("https://raw.githubusercontent.com/arkadiyt/"
                      "bounty-targets-data/main/data/hackerone_data.json")
# Mission fix 7: Bugcrowd / Intigriti / YesWeHack scope compilation via the
# SAME keyless bounty-targets-data dump (one file per platform). This closes
# the "HackerOne-only scope compilation" limitation flagged in the README —
# keyless, no private-API guessing, same CompiledScopeManifest output.
BOUNTY_TARGETS_BASE = ("https://raw.githubusercontent.com/arkadiyt/"
                       "bounty-targets-data/main/data")
PLATFORM_DATA_FILES = {
    "hackerone": "hackerone_data.json",
    "bugcrowd": "bugcrowd_data.json",
    "intigriti": "intigriti_data.json",
    "yeswehack": "yeswehack_data.json",
}
# URL hosts that imply a platform (used by detect_platform).
_PLATFORM_URL_HOSTS = {
    "bugcrowd.com": "bugcrowd",
    "www.bugcrowd.com": "bugcrowd",
    "app.intigriti.com": "intigriti",
    "intigriti.com": "intigriti",
    "yeswehack.com": "yeswehack",
    "app.yeswehack.com": "yeswehack",
}
SCOPE_PAGE_SIZE = 100
MAX_PAGES = 100
DEFAULT_TIMEOUT = 20
DEFAULT_MAX_RPS = 5.0
USER_AGENT = "rhodawk-bounty-hunter/2.2 scope-compiler"

_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    pass  # system CA store via ssl.create_default_context() — never disable


class ScopeCompilerError(Exception):
    """Scope compilation failed (network, platform, or data)."""


class ProgramNotFoundError(ScopeCompilerError):
    """The handle does not exist on the queried platform/source."""


class RestAuthError(ScopeCompilerError):
    """H1 REST API rejected the credentials (HTTP 401/403)."""


# ── Handle normalization ──────────────────────────────────────────────────────

_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def detect_platform(handle_or_url: str) -> str:
    """Infer the bug-bounty platform from a handle or program URL.

    "https://hackerone.com/x" → hackerone (the historical default);
    "https://bugcrowd.com/engagements/slug" → bugcrowd;
    "https://app.intigriti.com/researcher/program/c/p" → intigriti;
    "https://yeswehack.com/programs/id" → yeswehack;
    bare handles → hackerone (unchanged default; bare handles are compiled
    against the platform the caller means — pass a URL to disambiguate).
    """
    raw = str(handle_or_url or "").strip()
    if "://" in raw:
        host = (urllib.parse.urlsplit(raw).netloc or "").lower()
        return _PLATFORM_URL_HOSTS.get(host, "hackerone")
    return "hackerone"


def normalize_handle(handle_or_url: str) -> str:
    """Extract the exact lowercase program handle from a handle or URL.

    "Acme", "acme", and
    "https://hackerone.com/acme?type=team" all yield "acme".
    Platform URLs are supported too:
      https://bugcrowd.com/engagements/<slug>              → <slug>
      https://app.intigriti.com/researcher/program/c/p/... → last segment
      https://yeswehack.com/programs/<id>                  → <id>
    (For Intigriti the dump's `handle` field is the reliable key — a URL slug
    may differ; pass the bare handle when in doubt.) Raises ValueError on
    anything that is not a safe single path component.
    """
    raw = str(handle_or_url or "").strip()
    if not raw:
        raise ValueError("empty program handle")
    candidate = raw
    if "://" in candidate:
        parsed = urllib.parse.urlsplit(candidate)
        candidate = parsed.netloc.lower()
        # hackerone.com/<handle>[?...] — take the first path segment instead
        # of the host when the host is the HackerOne site itself.
        if candidate in ("hackerone.com", "www.hackerone.com"):
            path = (parsed.path or "").strip("/")
            candidate = path.split("/", 1)[0] if path else ""
        elif candidate in _PLATFORM_URL_HOSTS:
            # bugcrowd /<slug>, intigriti /researcher/program/<c>/<p>,
            # yeswehack /programs/<id> — the LAST path segment is the
            # program-identifying slug on all three platforms.
            path = (parsed.path or "").strip("/")
            candidate = path.rsplit("/", 1)[-1] if path else ""
        if not candidate:
            raise ValueError(f"cannot extract a program handle from {raw!r}")
    else:
        # Bare handle form: must be exactly one safe token — no paths, no
        # query strings (fail closed rather than guess a prefix).
        if "/" in candidate or "?" in candidate or "#" in candidate:
            raise ValueError(
                f"invalid program handle {raw!r}: pass a bare handle or a "
                f"full https://hackerone.com/<handle> URL")
        candidate = candidate.strip()
    handle = candidate.strip().lower()
    if not _HANDLE_RE.match(handle):
        raise ValueError(
            f"invalid program handle {raw!r}: expected lowercase "
            "[a-z0-9_-] (e.g. acme)")
    return handle


# ── Markdown policy compiler ──────────────────────────────────────────────────

# Canonical excluded-class slugs and the policy phrases that map to them.
_EXCLUDED_CLASS_PATTERNS: list[tuple[str, list[str]]] = [
    ("dos", [r"\bdos\b", r"denial[\s-]*of[\s-]*service"]),
    ("ddos", [r"\bddos\b", r"distributed[\s-]*denial[\s-]*of[\s-]*service"]),
    ("social_engineering", [r"social[\s-]*engineering"]),
    ("physical_security", [r"physical[\s-]*(?:security|testing|attack|test)"]),
    ("clickjacking", [r"clickjacking", r"ui[\s-]*redress"]),
    ("spf_dmarc", [r"\bspf\b", r"\bdmarc\b", r"sender[\s-]*policy"]),
    ("rate_limiting", [r"rate[\s-]*limit", r"\brps\b"]),
    ("brute_force", [r"brute[\s-]*force"]),
    ("spam", [r"\bspam(?:ming)?\b"]),
]
_CLASS_COMPILED = [(slug, [re.compile(p, re.IGNORECASE) for p in pats])
                   for slug, pats in _EXCLUDED_CLASS_PATTERNS]

# Lines that put vulnerability-class mentions into "exclusion context".
_EXCLUSION_CONTEXT_RE = re.compile(
    r"(?i)(exclud|out[\s-]of[\s-]scope|do(?:es)?\s+not\s+qualify|"
    r"not\s+eligible|ineligible|no\s+(?:bounty|award)|"
    r"won'?t\s+(?:be\s+)?(?:award|accepted?|considered?)|"
    r"do(?:\s+not|\s*n'?t)\s+(?:report|test|submit|award))")
_BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")

_MAX_RPS_PATTERNS = [
    re.compile(r"(?i)max(?:imum)?[_\s-]*rps\D{0,10}(\d+(?:\.\d+)?)"),
    re.compile(r"(?i)(\d+(?:\.\d+)?)\s*(?:rps|req/s|requests?\s*/\s*s)\b"),
    re.compile(r"(?i)(\d+(?:\.\d+)?)\s*(?:requests?\s+)?per\s+second"),
    re.compile(r"(?i)rate\s+limit(?:ed|ing)?\s*(?:to|of|:)?\s*"
               r"(\d+(?:\.\d+)?)\s*(?:rps|req/s|requests?\s*per\s*second)"),
]

# `Header: value` code spans — the header name must look like one: an X-*
# prefix, or the span sits on a line that talks about headers.
_HEADER_SPAN_RE = re.compile(r"`([A-Za-z][A-Za-z0-9_-]{1,62}):\s*([^`]+)`")
_BARE_X_HEADER_RE = re.compile(r"`(X-[A-Za-z0-9-]{1,62})`")
_PLAIN_HEADER_RE = re.compile(
    r"(?im)^[\s>*_#-]*headers?\b[^:\n]{0,24}[:：]\s*`?"
    r"([A-Za-z][A-Za-z0-9-]{1,62})`?\s*[:=：]\s*(.+?)\s*$")


def parse_policy_markdown(policy_md: str) -> dict:
    """Deterministically extract rate/policy rules from program-policy text.

    Returns {"mandatory_headers": {name: value}, "max_rps": float,
    "excluded_classes": [slug, ...] (sorted)}. Missing rate limits default
    to DEFAULT_MAX_RPS (5.0). Heuristics are anchored to explicit context
    ("header", "excluded", rps units) to avoid false positives.
    """
    md = str(policy_md or "")
    lines = md.splitlines()

    mandatory_headers: dict[str, str] = {}
    for line in lines:
        line_has_header_ctx = "header" in line.lower()
        for m in _HEADER_SPAN_RE.finditer(line):
            name = m.group(1).strip()
            if name.upper().startswith("X-") or line_has_header_ctx:
                mandatory_headers[name] = m.group(2).strip().strip("`")
        for m in _BARE_X_HEADER_RE.finditer(line):
            mandatory_headers.setdefault(m.group(1), "")
        for m in _PLAIN_HEADER_RE.finditer(line):
            mandatory_headers.setdefault(m.group(1), m.group(2).strip().strip("`"))

    max_rps = None
    for pattern in _MAX_RPS_PATTERNS:
        m = pattern.search(md)
        if m:
            try:
                max_rps = float(m.group(1))
                break
            except ValueError:
                continue

    # Collect exclusion-context segments (the matching line + its immediate
    # bullet children) so "rate limit: 5 rps" never becomes an excluded class.
    segments: list[str] = []
    for i, line in enumerate(lines):
        if _EXCLUSION_CONTEXT_RE.search(line):
            segments.append(line)
            j = i + 1
            while j < len(lines) and _BULLET_RE.match(lines[j]):
                segments.append(lines[j])
                j += 1

    excluded: set[str] = set()
    for segment in segments:
        for slug, patterns in _CLASS_COMPILED:
            if any(p.search(segment) for p in patterns):
                excluded.add(slug)
    # Backticked canonical slugs anywhere in the policy are explicit enough.
    for m in re.finditer(r"`([a-z][a-z_]{2,40})`", md):
        slug = m.group(1)
        if slug in {s for s, _ in _EXCLUDED_CLASS_PATTERNS}:
            excluded.add(slug)

    return {
        "mandatory_headers": mandatory_headers,
        "max_rps": max_rps if max_rps is not None else DEFAULT_MAX_RPS,
        "excluded_classes": sorted(excluded),
    }


# ── HTTP plumbing (stdlib only, verifying TLS context) ────────────────────────

def _basic_auth(username: str, token: str) -> str:
    raw = f"{username}:{token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _rest_request(url: str, auth_header: str | None = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """GET a JSON endpoint (H1 REST API / raw dumps) with optional Basic auth."""
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if auth_header:
        headers["Authorization"] = auth_header
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise RestAuthError(f"H1 REST API rejected credentials "
                                f"(HTTP {e.code})") from None
        raise ScopeCompilerError(f"HTTP {e.code}: {e.reason} for {url}") from None
    except urllib.error.URLError as e:
        raise ScopeCompilerError(f"network error: {e.reason}") from None
    except json.JSONDecodeError as e:
        raise ScopeCompilerError(f"invalid JSON from {url}: {e}") from None


def _graphql_request(query: str, variables: dict | None = None,
                     timeout: int = DEFAULT_TIMEOUT) -> dict:
    """POST a GraphQL query (with variables) to HackerOne's public endpoint."""
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(
        H1_GRAPHQL_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        raise ScopeCompilerError(f"HTTP {e.code}: {e.reason}") from None
    except urllib.error.URLError as e:
        raise ScopeCompilerError(f"network error: {e.reason}") from None
    except json.JSONDecodeError as e:
        raise ScopeCompilerError(f"invalid JSON response: {e}") from None
    if "errors" in data:
        raise ScopeCompilerError(f"GraphQL errors: {data['errors']}")
    return data


GRAPHQL_PROGRAM_SCOPE_QUERY = """
query ProgramScope($handle: String!, $cursor: String) {
  team(handle: $handle) {
    name
    handle
    offers_bounties
    policy
    structured_scopes(first: 100, after: $cursor, archived: false) {
      pageInfo { hasNextPage endCursor }
      nodes {
        asset_identifier
        asset_type
        eligible_for_submission
        eligible_for_bounty
        max_severity
        instruction
      }
    }
  }
}
"""


# ── Asset shaping ─────────────────────────────────────────────────────────────

def _asset_from_attrs(attrs: dict) -> ScopeAssetMeta | None:
    identifier = str(attrs.get("asset_identifier") or "").strip()
    if not identifier:
        return None
    return ScopeAssetMeta(
        asset_identifier=identifier,
        asset_type=str(attrs.get("asset_type") or "").strip(),
        eligible_for_submission=bool(attrs.get("eligible_for_submission", True)),
        eligible_for_bounty=bool(attrs.get("eligible_for_bounty", False)),
        max_severity=str(attrs.get("max_severity") or "").strip(),
        instruction=str(attrs.get("instruction") or "").strip(),
    )


# ── Authenticated REST mode ───────────────────────────────────────────────────

def _fetch_rest_program(handle: str, rest_fn, auth_header: str) -> dict:
    data = rest_fn(f"{H1_API_BASE}/hackers/programs/{handle}", auth_header)
    attrs = ((data.get("data") or {}).get("attributes")) or {}
    if not attrs:
        raise ProgramNotFoundError(
            f"program '{handle}' not found (or invisible to these credentials)")
    return attrs


def _fetch_rest_scopes(handle: str, rest_fn, auth_header: str
                       ) -> tuple[list[ScopeAssetMeta], int]:
    """Paginate structured_scopes via links.next — no first:50 truncation."""
    assets: list[ScopeAssetMeta] = []
    url = (f"{H1_API_BASE}/hackers/programs/{handle}/structured_scopes"
           f"?page%5Bsize%5D={SCOPE_PAGE_SIZE}")
    pages = 0
    while url and pages < MAX_PAGES:
        data = rest_fn(url, auth_header)
        for item in data.get("data") or []:
            asset = _asset_from_attrs(item.get("attributes") or {})
            if asset:
                assets.append(asset)
        url = (data.get("links") or {}).get("next") or None
        pages += 1
    if pages >= MAX_PAGES and url:
        raise ScopeCompilerError(
            f"structured_scopes pagination exceeded {MAX_PAGES} pages — aborting")
    return assets, pages


# ── Keyless public mode ───────────────────────────────────────────────────────

def _fetch_graphql_scope(handle: str, graphql_fn) -> dict:
    """Cursor-paginated public GraphQL scope pull (archived: false).

    Program metadata (name / policy / offers_bounties) is captured from the
    first page; later pages only contribute additional scope nodes.
    """
    data = graphql_fn(GRAPHQL_PROGRAM_SCOPE_QUERY,
                      {"handle": handle, "cursor": None})
    team = ((data.get("data") or {}).get("team")) or None
    if team is None:
        raise ProgramNotFoundError(f"program '{handle}' not found on HackerOne")

    meta = {
        "program_name": str(team.get("name") or ""),
        "offers_bounties": bool(team.get("offers_bounties", False)),
        "policy_md": str(team.get("policy") or ""),
    }
    assets: list[ScopeAssetMeta] = []
    cursor = None
    pages = 0
    while True:
        scopes = team.get("structured_scopes") or {}
        for node in scopes.get("nodes") or []:
            asset = _asset_from_attrs(node)
            if asset:
                assets.append(asset)
        pages += 1
        page_info = scopes.get("pageInfo") or {}
        if not page_info.get("hasNextPage") or pages >= MAX_PAGES:
            break
        cursor = page_info.get("endCursor")
        if not cursor:
            break
        team = ((graphql_fn(GRAPHQL_PROGRAM_SCOPE_QUERY,
                            {"handle": handle, "cursor": cursor})
                 .get("data") or {}).get("team")) or {}
        if not team:
            break

    return {**meta, "assets": assets, "pages": pages}


def fetch_bounty_targets_program(handle: str,
                                 fetch_fn=None) -> dict:
    """Exact case-insensitive handle lookup in the bounty-targets-data dump.

    `p["handle"].lower() == handle` — substring matches ("shop" vs "shopify")
    are the bug this replaces, never a feature.
    """
    if fetch_fn is None:
        fetch_fn = _rest_request
    data = fetch_fn(BOUNTY_TARGETS_URL)
    programs = data if isinstance(data, list) else (data.get("programs") or [])
    for entry in programs:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("handle") or "").strip().lower() == handle:
            return entry
    raise ProgramNotFoundError(
        f"program '{handle}' not found in bounty-targets-data "
        f"(exact handle match)")


def fetch_bounty_targets_entry(handle: str, platform: str = "hackerone",
                               fetch_fn=None) -> dict:
    """Exact case-insensitive per-platform lookup in the bounty-targets-data
    dump (mission fix 7). Handle keys per platform:
      hackerone → entry["handle"]; bugcrowd → url slug or exact name;
      intigriti → entry["handle"] or entry["id"]; yeswehack → entry["id"].
    Substring matches ("shop" vs "shopify") are the bug this replaces, never
    a feature.
    """
    if fetch_fn is None:
        fetch_fn = _rest_request
    filename = PLATFORM_DATA_FILES.get(platform)
    if not filename:
        raise ValueError(f"unsupported platform {platform!r}")
    data = fetch_fn(f"{BOUNTY_TARGETS_BASE}/{filename}")
    programs = data if isinstance(data, list) else (data.get("programs") or [])
    for entry in programs:
        if not isinstance(entry, dict):
            continue
        if _platform_handle_match(entry, platform, handle):
            return entry
    raise ProgramNotFoundError(
        f"program '{handle}' not found in bounty-targets-data "
        f"({platform}_data.json, exact match)")


def _platform_handle_match(entry: dict, platform: str, handle: str) -> bool:
    h = handle.strip().lower()

    def _url_slug(entry, key="url") -> str:
        return str(entry.get(key) or "").rstrip("/").rsplit("/", 1)[-1].lower()

    if platform == "hackerone":
        return str(entry.get("handle") or "").strip().lower() == h
    if platform == "bugcrowd":
        return (_url_slug(entry) == h
                or str(entry.get("name") or "").strip().lower() == h)
    if platform == "intigriti":
        return (str(entry.get("handle") or "").strip().lower() == h
                or str(entry.get("id") or "").strip().lower() == h
                or _url_slug(entry) == h)
    if platform == "yeswehack":
        return (str(entry.get("id") or "").strip().lower() == h
                or _url_slug(entry) == h)
    return False


def _platform_asset_identifier(raw: dict, platform: str) -> str:
    if platform == "bugcrowd":
        return str(raw.get("target") or raw.get("uri")
                   or raw.get("ipAddress") or "").strip()
    if platform == "intigriti":
        return str(raw.get("endpoint") or "").strip()
    return str(raw.get("target") or "").strip()  # yeswehack


def _scope_from_platform_entry(entry: dict, platform: str) -> dict:
    """Map a platform dump entry to the SAME result dict the H1 paths return:
    {"program_name", "offers_bounties", "policy_md", "assets", "pages"}."""
    targets = entry.get("targets") or {}
    in_scope = targets.get("in_scope") if isinstance(targets, dict) else targets
    out_scope = targets.get("out_of_scope") if isinstance(targets, dict) else []
    assets: list[ScopeAssetMeta] = []
    for raw in in_scope or []:
        attrs = raw if isinstance(raw, dict) else {"asset_identifier": str(raw)}
        identifier = _platform_asset_identifier(attrs, platform)
        if not identifier:
            continue
        instruction = str(attrs.get("name") or attrs.get("description") or "")
        assets.append(ScopeAssetMeta(
            asset_identifier=identifier,
            asset_type=str(attrs.get("type") or "").strip(),
            eligible_for_submission=True,
            instruction=instruction[:500],
        ))
    for raw in out_scope or []:
        attrs = raw if isinstance(raw, dict) else {"asset_identifier": str(raw)}
        identifier = _platform_asset_identifier(attrs, platform)
        if not identifier:
            continue
        instruction = str(attrs.get("name") or attrs.get("description") or "")
        assets.append(ScopeAssetMeta(
            asset_identifier=identifier,
            asset_type=str(attrs.get("type") or "").strip(),
            eligible_for_submission=False,
            instruction=instruction[:500],
        ))
    return {
        "program_name": str(entry.get("name") or ""),
        "offers_bounties": False,
        "policy_md": "",
        "assets": assets,
        "pages": 1,
    }


def _fetch_bounty_targets_scope(handle: str, bounty_targets_fn) -> dict:
    entry = bounty_targets_fn(handle)
    targets = entry.get("targets") or {}
    in_scope = targets.get("in_scope") if isinstance(targets, dict) else targets
    out_scope = targets.get("out_of_scope") if isinstance(targets, dict) else []
    assets: list[ScopeAssetMeta] = []
    for raw in in_scope or []:
        asset = _asset_from_attrs(raw if isinstance(raw, dict)
                                  else {"asset_identifier": raw})
        if asset:
            assets.append(asset)
    for raw in out_scope or []:
        attrs = raw if isinstance(raw, dict) else {"asset_identifier": raw}
        attrs.setdefault("eligible_for_submission", False)
        asset = _asset_from_attrs(attrs)
        if asset:
            assets.append(asset)
    return {
        "program_name": str(entry.get("name") or ""),
        "offers_bounties": False,
        "policy_md": "",
        "assets": assets,
        "pages": 1,
    }


# ── Optional reconciliation-source parsers ────────────────────────────────────

_ID_COL_CANDIDATES = ["asset_identifier", "identifier", "asset", "target",
                      "domain", "host", "url", "endpoint", "fqdn"]
_SCOPE_COL_CANDIDATES = ["eligible_for_submission", "in_scope", "is_in_scope",
                         "eligible", "submission"]
_TRUE_TOKENS = {"true", "1", "yes", "y"}
_BBSCOPE_HEADER_WORDS = {"identifier", "type", "asset", "target", "domain",
                         "host", "url", "eligible", "bounty", "submission",
                         "in_scope", "program", "handle", "scope", "max",
                         "severity", "instruction"}


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in _TRUE_TOKENS


def _pick_column(columns: list[str], candidates: list[str]) -> str | None:
    lowered = {c.strip().lower(): c for c in columns}
    for cand in candidates:
        if cand in lowered:
            return lowered[cand]
    for cand in candidates:  # fuzzy second pass (e.g. "asset_identifier_2")
        for low, orig in lowered.items():
            if cand in low:
                return orig
    return None


def parse_h1scope_csv(path) -> dict:
    """h1scope CSV export -> {"allow": [..], "exclude": [..]}."""
    allow: list[str] = []
    exclude: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        columns = reader.fieldnames or []
        id_col = _pick_column(columns, _ID_COL_CANDIDATES)
        scope_col = _pick_column(columns, _SCOPE_COL_CANDIDATES)
        if id_col is None and columns:
            id_col = columns[0]
        for row in reader:
            identifier = str((row.get(id_col) if id_col else "") or "").strip()
            if not identifier:
                continue
            if scope_col is not None and not _truthy(row.get(scope_col)):
                exclude.append(identifier)
            else:
                allow.append(identifier)
    return {"allow": allow, "exclude": exclude}


def parse_huntdeck_db(path) -> dict:
    """HuntDeck SQLite via a read-only URI (file:<path>?mode=ro)."""
    uri = f"file:{Path(path).resolve()}?mode=ro"
    allow: list[str] = []
    exclude: list[str] = []
    try:
        conn = sqlite3.connect(uri, uri=True)
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            target_table = None
            for table in tables:
                if re.search(r"asset|scope|target", table, re.IGNORECASE):
                    target_table = table
                    break
            if target_table is None and tables:
                target_table = tables[0]
            if target_table is None:
                return {"allow": [], "exclude": []}
            columns = [r[1] for r in conn.execute(
                f'PRAGMA table_info("{target_table}")')]
            id_col = _pick_column(columns, _ID_COL_CANDIDATES)
            scope_col = _pick_column(columns, _SCOPE_COL_CANDIDATES)
            for row in conn.execute(f'SELECT * FROM "{target_table}"'):
                record = dict(zip(columns, row))
                identifier = str((record.get(id_col) if id_col else "") or "").strip()
                if not identifier:
                    continue
                if scope_col is not None and not _truthy(record.get(scope_col)):
                    exclude.append(identifier)
                else:
                    allow.append(identifier)
        finally:
            conn.close()
    except sqlite3.Error as e:
        raise ScopeCompilerError(f"HuntDeck DB unreadable: {e}") from None
    return {"allow": allow, "exclude": exclude}


def parse_bbscope_cache(path) -> dict:
    """bbscope `-o tu` table cache -> allow list (bbscope prints in-scope only).

    Tolerant of box-drawing separators and header rows; the first
    non-separator, non-header token on each line is the asset identifier.
    """
    allow: list[str] = []
    for raw_line in Path(path).read_text(encoding="utf-8",
                                         errors="replace").splitlines():
        line = raw_line.strip().strip("|").strip()
        if not line:
            continue
        if set(line) <= set("+-=| \t_"):
            continue
        tokens = line.split()
        if not tokens:
            continue
        first = tokens[0].strip().strip(",;").lower()
        if not first or first in _BBSCOPE_HEADER_WORDS:
            continue
        allow.append(tokens[0].strip().strip(",;"))
    return {"allow": allow, "exclude": []}


# ── Asymmetric safety merge ───────────────────────────────────────────────────

def _norm_cmp(pattern: str) -> str:
    """Comparison form: lowercase, scheme- and trailing-dot-free.

    Display forms are preserved verbatim in the manifest; this normalization
    exists only to compare identifiers across sources."""
    p = str(pattern).strip().lower()
    p = re.sub(r"^https?://", "", p)
    return p.rstrip(".")


def _asymmetric_merge(primary_allow: list[str], primary_exclude: list[str],
                      extra_sources: list[dict]) -> tuple[list[str], list[str], list[dict]]:
    """Allowlist intersection + denylist union, with drift recorded.

    primary: the H1-sourced allow/exclude pools (authoritative representation).
    extra_sources: [{"name": str, "allow": [..], "exclude": [..]}, ...]
    """
    drift: list[dict] = []
    primary_allow_norm = {_norm_cmp(p): p for p in primary_allow}
    primary_exclude_norm = {_norm_cmp(p): p for p in primary_exclude}

    if extra_sources:
        source_norms = []
        for src in extra_sources:
            allow_norms = {_norm_cmp(a): a for a in src["allow"]}
            exclude_norms = {_norm_cmp(x): x for x in src["exclude"]}
            source_norms.append((allow_norms, exclude_norms, src["name"]))
        merged_allow = []
        for norm, display in primary_allow_norm.items():
            missing_in = [name for norms, _, name in source_norms if norm not in norms]
            if missing_in:
                drift.append({
                    "kind": "allow_intersection_drop",
                    "pattern": display,
                    "detail": f"missing from {', '.join(missing_in)} — "
                              f"dropped by allowlist intersection",
                })
            else:
                merged_allow.append(display)
    else:
        merged_allow = list(primary_allow)

    merged_exclude: dict[str, str] = dict(primary_exclude_norm)
    for src in extra_sources:
        src_allow_norm = {_norm_cmp(a) for a in src["allow"]}
        for raw in src["exclude"]:
            norm = _norm_cmp(raw)
            if norm and norm not in merged_exclude:
                merged_exclude[norm] = str(raw).strip()
        # allow-side extras: present in the source but absent from primary
        for raw in src["allow"]:
            norm = _norm_cmp(raw)
            if norm and norm not in primary_allow_norm:
                drift.append({
                    "kind": "allow_extra_in_source",
                    "pattern": str(raw).strip(),
                    "source": src["name"],
                    "detail": "allowlisted by the optional source but not by "
                              "the primary H1 scope",
                })
        # cross-source conflicts: source excludes something primary allows
        for raw in src["exclude"]:
            norm = _norm_cmp(raw)
            if norm in primary_allow_norm and norm not in primary_exclude_norm:
                drift.append({
                    "kind": "cross_source_conflict",
                    "pattern": primary_allow_norm[norm],
                    "source": src["name"],
                    "detail": "primary allowlists this asset but an optional "
                              "source excludes it — denylist wins",
                })

    return merged_allow, list(merged_exclude.values()), drift


# ── Credential-aware fetch orchestration ──────────────────────────────────

def _redact_exception(exc: Exception) -> str:
    """One-line, token-free reason for drift notes (status codes only)."""
    text = f"{type(exc).__name__}: {exc}".replace("\n", " ")
    # Defense in depth: Authorization headers / tokens must never reach notes.
    text = re.sub(r"(?i)(authorization\s*[:=]\s*)\S+", r"\1<redacted>", text)
    text = re.sub(r"(?i)(basic\s+)[A-Za-z0-9+/=]{8,}", r"\1<redacted>", text)
    return text[:200]


def _h1_env_pair() -> tuple[str, str]:
    """H1 Basic-auth pair from the environment: H1_USERNAME + H1_API_TOKEN,
    or the combined H1_TOKEN=user:token form. A bare H1_TOKEN without a
    colon counts as the API token alone (mirrors credentials._derive_h1_pair)."""
    username = os.environ.get("H1_USERNAME", "")
    token = os.environ.get("H1_API_TOKEN", "")
    if not (username and token):
        combined = os.environ.get("H1_TOKEN", "")
        if combined:
            user, sep, tok = combined.partition(":")
            if sep:
                username = username or user
                token = token or tok
            else:
                token = token or combined
    return username, token


def _load_data_home_env() -> None:
    """Second-chance credential load for relocated data homes (v2.0.1).

    credentials.load_credentials() reads the standard vault
    (~/.rhodawk/.env, $RHODAWK_CREDENTIALS_FILE, /root/.secrets/h1_api).
    When $RHODAWK_HOME points somewhere else, scope-compile must still find
    the HackerOne credentials BEFORE falling back to keyless mode — export
    H1_USERNAME / H1_API_TOKEN / H1_TOKEN from $RHODAWK_HOME/.env into the
    process environment. Values are only exported, never printed or logged.
    """
    base = os.environ.get("RHODAWK_HOME", "").strip()
    if not base:
        return
    env_file = Path(base).expanduser() / ".env"
    try:
        text = env_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for key, value in _credentials.parse_env_text(text).items():
        if key in ("H1_USERNAME", "H1_API_TOKEN", "H1_TOKEN") and value \
                and not os.environ.get(key):
            os.environ[key] = value


def fetch_program_scope(handle_or_url: str, *, creds: dict | None = None,
                        rest_fn=None, graphql_fn=None,
                        bounty_targets_fn=None) -> dict:
    """Fetch program metadata + the FULL structured scope (lossless).

    Authenticated REST pagination when the credential vault reports
    `authenticated_rest`, cursor-paginated public GraphQL (then
    bounty-targets-data) otherwise. Any authenticated-REST failure falls back
    to public sources with a redacted note. Returns:
      {"handle", "program_name", "offers_bounties", "policy_md", "assets",
       "auth_mode", "sources", "notes"}

    When an authenticated-REST run fell back to keyless_public, the result
    also carries "auth_fallback_reason": a one-line, token-free reason
    (HTTP status codes / paths only) surfaced by the CLI as a warning.
    """
    handle = normalize_handle(handle_or_url)
    rest_fn = rest_fn or _rest_request
    graphql_fn = graphql_fn or _graphql_request
    bounty_targets_fn = bounty_targets_fn or fetch_bounty_targets_program

    # Mission fix 7: non-HackerOne platforms compile from their OWN
    # bounty-targets-data dump — never from H1's (a bugcrowd handle has no
    # business being looked up in hackerone_data.json, and the old flow
    # simply raised ProgramNotFoundError for them).
    platform = detect_platform(handle_or_url)
    if platform != "hackerone":
        result = _scope_from_platform_entry(
            fetch_bounty_targets_entry(handle, platform, bounty_targets_fn),
            platform)
        result.update({
            "handle": handle,
            "auth_mode": "keyless_public",
            "sources": [f"bounty-targets-data:{platform}_data.json "
                        f"(exact match)"],
            "notes": [],
        })
        return result

    notes: list[str] = []
    auth_fallback_reason: str | None = None
    if creds is None:
        # Load the credential vault (~/.rhodawk/.env and friends) into the
        # environment BEFORE any H1_USERNAME / H1_API_TOKEN / H1_TOKEN check.
        creds = _credentials.load_credentials(interactive=False)
    auth_mode = creds.get("auth_mode", "keyless_public")
    if auth_mode != "authenticated_rest":
        # Relocated data home ($RHODAWK_HOME/.env): second chance before
        # declaring the run keyless (v2.0.1 — a READY vault must never
        # silently drop scope-compile down to the public GraphQL path).
        _load_data_home_env()
        env_user, env_token = _h1_env_pair()
        if env_user and env_token:
            creds = {**creds, "auth_mode": "authenticated_rest"}
            auth_mode = "authenticated_rest"

    if auth_mode == "authenticated_rest":
        username, token = _h1_env_pair()
        if username and token:
            auth_header = _basic_auth(username, token)
            try:
                attrs = _fetch_rest_program(handle, rest_fn, auth_header)
                assets, pages = _fetch_rest_scopes(handle, rest_fn, auth_header)
                return {
                    "handle": handle,
                    "program_name": str(attrs.get("name") or handle),
                    "offers_bounties": bool(attrs.get("offers_bounties", False)),
                    "policy_md": str(attrs.get("policy") or ""),
                    "assets": assets,
                    "auth_mode": "authenticated_rest",
                    "sources": [
                        f"hackerone:rest:programs/{handle}",
                        f"hackerone:rest:structured_scopes?page[size]={SCOPE_PAGE_SIZE}"
                        f" ({pages} page{'s' if pages != 1 else ''})",
                    ],
                    "notes": notes,
                }
            except Exception as exc:  # noqa: BLE001 — any REST failure falls
                # back to public sources; notes carry redacted status text only.
                auth_fallback_reason = _redact_exception(exc)
                notes.append(
                    f"authenticated REST failed ({auth_fallback_reason}) — "
                    f"falling back to public sources")
        else:
            auth_fallback_reason = ("H1 credentials absent from the "
                                    "environment after vault load")
            notes.append("auth mode authenticated_rest but H1_USERNAME/"
                         "H1_API_TOKEN not set — falling back to public sources")

    # Keyless public path: cursor-paginated GraphQL, then the dump.
    try:
        result = _fetch_graphql_scope(handle, graphql_fn)
        result.update({
            "handle": handle,
            "auth_mode": "keyless_public",
            "sources": [f"hackerone:graphql:structured_scopes(first: {SCOPE_PAGE_SIZE}, "
                        f"archived: false) ({result['pages']} pages)"],
            "notes": notes,
        })
        if auth_fallback_reason:
            result["auth_fallback_reason"] = auth_fallback_reason
        return result
    except ProgramNotFoundError:
        # Authoritative "no such program" — do not second-guess with mirrors.
        raise
    except Exception as exc:  # noqa: BLE001 — GraphQL failure -> dump fallback
        notes.append(f"public GraphQL failed ({_redact_exception(exc)}) — "
                     f"falling back to bounty-targets-data")

    result = _fetch_bounty_targets_scope(handle, bounty_targets_fn)
    result.update({
        "handle": handle,
        "auth_mode": "keyless_public",
        "sources": ["bounty-targets-data:hackerone_data.json (exact handle match)"],
        "notes": notes,
    })
    if auth_fallback_reason:
        result["auth_fallback_reason"] = auth_fallback_reason
    return result


# ── Compilation + output ──────────────────────────────────────────────────────

def resolve_output_paths(handle: str, output=None) -> dict:
    """Primary manifest path (--output / RECON_OUT_DIR / <data home>/recon/<handle>) + mirror."""
    # Layer 2 + B-7: every runtime write anchors to $RHODAWK_HOME (the
    # engine._data_home / hunt._bh_home contract) — the mirror lives under
    # <home>/scope and the standalone primary default under
    # <home>/recon/<handle>. The old CWD-relative `Path("recon") / handle`
    # wrote a recon tree into whatever directory the operator (or a model)
    # happened to stand in — including the package source tree.
    home_env = os.environ.get("RHODAWK_HOME", "").strip()
    data_home = Path(home_env).expanduser() if home_env else Path.home() / ".rhodawk"
    if output:
        primary = Path(output).expanduser()
    else:
        env = os.environ.get("RECON_OUT_DIR", "").strip()
        base = Path(env).expanduser() if env else data_home / "recon" / handle
        primary = base / "scope" / "compiled_scope.json"
    mirror_dir = data_home / "scope"
    return {
        "primary": primary,
        "mirror": mirror_dir / f"{handle}_compiled_scope.json",
    }


def compile_and_save(handle_or_url: str, *, output=None,
                     h1scope_csv=None, huntdeck_db=None, bbscope_cache=None,
                     creds: dict | None = None, rest_fn=None,
                     graphql_fn=None, bounty_targets_fn=None) -> dict:
    """Compile the manifest, apply the asymmetric merge, save + mirror.

    Returns a redacted summary dict (counts, paths, short hash — no secrets).
    """
    fetched = fetch_program_scope(
        handle_or_url, creds=creds, rest_fn=rest_fn,
        graphql_fn=graphql_fn, bounty_targets_fn=bounty_targets_fn)
    handle = fetched["handle"]

    allow = [a.asset_identifier for a in fetched["assets"]
             if a.eligible_for_submission]
    exclude = [a.asset_identifier for a in fetched["assets"]
               if not a.eligible_for_submission]
    policy = parse_policy_markdown(fetched["policy_md"])

    sources = list(fetched["sources"])
    extra_sources: list[dict] = []
    if h1scope_csv:
        parsed = parse_h1scope_csv(h1scope_csv)
        extra_sources.append({"name": f"h1scope-csv:{h1scope_csv}",
                              **parsed})
        sources.append(f"h1scope-csv:{h1scope_csv}")
    if huntdeck_db:
        parsed = parse_huntdeck_db(huntdeck_db)
        extra_sources.append({"name": f"huntdeck-db:{huntdeck_db}",
                              **parsed})
        sources.append(f"huntdeck-db:{huntdeck_db} (sqlite read-only)")
    if bbscope_cache:
        parsed = parse_bbscope_cache(bbscope_cache)
        extra_sources.append({"name": f"bbscope-cache:{bbscope_cache}",
                              **parsed})
        sources.append(f"bbscope-cache:{bbscope_cache} (-o tu)")

    merged_allow, merged_exclude, drift = _asymmetric_merge(
        allow, exclude, extra_sources)
    for note in fetched["notes"]:
        drift.insert(0, {"kind": "source_note", "detail": note})

    manifest = CompiledScopeManifest(
        program_handle=handle,
        program_name=fetched["program_name"],
        auth_mode=fetched["auth_mode"],
        sources=sources,
        allow_patterns=merged_allow,
        exclude_patterns=merged_exclude,
        excluded_classes=policy["excluded_classes"],
        mandatory_headers=policy["mandatory_headers"],
        max_rps=policy["max_rps"],
        assets_metadata=fetched["assets"],
        drift_audit=drift,
    )

    paths = resolve_output_paths(handle, output)
    manifest.save(paths["primary"])
    mirror_dir = Path(paths["mirror"]).parent
    try:
        mirror_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(mirror_dir, 0o700)
    except OSError:
        pass
    if Path(paths["mirror"]).resolve() != Path(paths["primary"]).resolve():
        manifest.save(paths["mirror"])

    summary = {
        "program_handle": handle,
        "program_name": manifest.program_name,
        "auth_mode": manifest.auth_mode,
        "sources": manifest.sources,
        "allow_patterns": len(manifest.allow_patterns),
        "exclude_patterns": len(manifest.exclude_patterns),
        "excluded_classes": list(manifest.excluded_classes),
        "mandatory_headers": dict(manifest.mandatory_headers),
        "max_rps": manifest.max_rps,
        "manifest": str(paths["primary"]),
        "mirror": str(paths["mirror"]),
        "manifest_sha256": manifest.manifest_sha256[:16],
        "drift_count": len(manifest.drift_audit),
    }
    # v2.0.1: surface WHY an authenticated run fell back to keyless mode
    # (pre-redacted — HTTP status codes only, never the token itself).
    if fetched.get("auth_fallback_reason"):
        summary["auth_fallback_reason"] = fetched["auth_fallback_reason"]
    return summary


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scope_compiler.py",
        description="Compile a bug-bounty program scope into a typed, hashed "
                    "CompiledScopeManifest (lossless, drift-audited). "
                    "Platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack "
                    "(full program URL auto-detection; authenticated REST "
                    "remains HackerOne-only).",
    )
    parser.add_argument("handle",
                        help="program handle or full program URL — the "
                             "platform is auto-detected from the URL for "
                             "HackerOne, Bugcrowd, Intigriti and YesWeHack "
                             "(a bare handle compiles as HackerOne)")
    parser.add_argument("--output", default=None,
                        help="primary manifest path "
                             "(default: $RECON_OUT_DIR/scope/compiled_scope.json "
                             "or recon/<handle>/scope/compiled_scope.json)")
    parser.add_argument("--h1scope-csv", default=None, dest="h1scope_csv",
                        help="h1scope CSV export for allowlist intersection")
    parser.add_argument("--huntdeck-db", default=None, dest="huntdeck_db",
                        help="HuntDeck SQLite DB (opened read-only)")
    parser.add_argument("--bbscope-cache", default=None, dest="bbscope_cache",
                        help="bbscope '-o tu' cache for reconciliation")
    args = parser.parse_args(argv)

    try:
        summary = compile_and_save(
            args.handle, output=args.output,
            h1scope_csv=args.h1scope_csv, huntdeck_db=args.huntdeck_db,
            bbscope_cache=args.bbscope_cache)
    except (ScopeCompilerError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
