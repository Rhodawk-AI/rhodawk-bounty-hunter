#!/usr/bin/env python3
"""recon_fusion.py — canonical single-source-of-truth fusion for the
RhodawkAI Edition recon pipeline (Step 2B/2C of the honest-recon rebuild).

Everything downstream (LLM analysis, human review, run-over-run diffing)
reads ONE artifact — <recon_dir>/recon_truth.json — instead of 20 loose
files. Pure Python, stdlib only, no network at fuse time: it ingests what
recon_engine.sh and the reconFTW gap-fill adapter already wrote on disk.

What it produces:
  <recon_dir>/recon_truth.json
      schema_version "1.0", target, generated_at, scope_patterns
      counts    — subdomains, live_hosts, unique_host_clusters, origin_ips,
                  cdn_edges, open_ports, unique_urls, js_endpoints
      tool_health — per-capability status/duration/net_new_count/reason from
                  rtw_manifest.json (the honest accounting from Step 1B)
      hosts[]   — {host, ips, asset_class, cdn_provider, status_code, title,
                  content_length, tech, simhash, cluster_id, is_cluster_rep,
                  discovered_by[]}
      urls[]    — canonicalized + deduplicated (utm_* stripped, identical
                  parameter-key signatures collapsed), with discovered_by[]
      js_endpoints[] / ports[] — with discovered_by[] provenance
      subdomains[] — the probe list (also the delta baseline)
  <recon_dir>/delta.json — run-to-run diff against the previous truth
      (has_previous_run, new_subdomains, removed_subdomains,
       status_code_flips, new_js_endpoints, new_open_ports); the previous
       truth is archived to recon_truth.prev.json before overwrite.
  mirror copy at ~/.rhodawk/recon/<target>/recon_truth.json (RHODAWK_HOME
  aware) so harness/agent runtimes find the same truth.

Asset classification (shared with recon_engine.sh Phase 2.5/Phase 3 via the
`classify` subcommand): CDN_EDGE (Cloudflare/Vercel/Akamai/Fastly/CloudFront
— via CNAME suffix, cdncheck-style tech column, or httpx headers) vs
THIRD_PARTY_SAAS (Shopify, HubSpot, Zendesk, GitHub Pages, ...) vs
FIRST_PARTY_ORIGIN (everything else). Phase 3 nmaps FIRST_PARTY_ORIGIN only.

Host clustering: deterministic 64-bit SimHash over each live host's
(status_code, normalized title + title tokens, tech stack, content-length
bucket); hosts within Hamming distance <= 3 share a cluster_id and exactly
one host per cluster is is_cluster_rep — the LLM prompt gets reps only
(token-smart).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SCHEMA_VERSION = "1.0"

CLASS_CDN_EDGE = "CDN_EDGE"
CLASS_SAAS = "THIRD_PARTY_SAAS"
CLASS_ORIGIN = "FIRST_PARTY_ORIGIN"

# Phase 5.75 headless JS crawl: which captured paths surface in
# js_endpoints[] (API-shaped paths only — static assets stay in urls[]).
_API_PATH_RE = re.compile(r"^/(api(/|$)|v[0-9]+/|rest/|graphql)")

# tool_health pseudo-capability recording the canonical-fusion step itself.
# A failed fuse used to be swallowed as a single non-fatal log line; it is now
# persisted as a FAILED row in rtw_manifest.json so recon_truth.json's
# tool_health (and the adapter health-table) surface it until fusion heals.
FUSION_CAPABILITY_ID = "FUSION"

# Truth-level status (B7): "OK" or "DEGRADED" when a required input is
# unparseable. See input_integrity().
STATUS_OK = "OK"
STATUS_DEGRADED = "DEGRADED"

# Recon-dir inputs tracked by the integrity block (B7). A REQUIRED input that
# is present but unparseable (binary garbage / NUL bytes / undecodable)
# degrades the whole truth document — downstream consumers must not treat the
# fused counts as reliable.
_INTEGRITY_INPUTS = (
    "subdomains/all.txt", "live/httpx_full.txt", "live/urls.txt",
    "urls/all.txt", "ports/nmap_greppable.txt", "js/endpoints.txt",
)
_REQUIRED_INPUTS = (
    "subdomains/all.txt", "live/httpx_full.txt", "urls/all.txt",
    "ports/nmap_greppable.txt",
)

# Same status vocabulary as rtw_adapter.py's manifest entries (fusion is
# stdlib-only and must not import the adapter).
RESULT_FAILED = "FAILED"
RESULT_SKIPPED_SILENT = "SKIPPED_SILENT"

# (suffix, provider) — CNAME/apex suffix match (trailing dot stripped first).
_CDN_SUFFIXES: Tuple[Tuple[str, str], ...] = (
    (".cloudflare.net", "Cloudflare"), (".cloudflare.com", "Cloudflare"),
    (".vercel.app", "Vercel"), (".vercel-dns.com", "Vercel"),
    (".akamaiedge.net", "Akamai"), (".akamai.net", "Akamai"),
    (".edgekey.net", "Akamai"), (".edgesuite.net", "Akamai"),
    (".fastly.net", "Fastly"), (".fastlylb.net", "Fastly"),
    (".cloudfront.net", "CloudFront"),
    (".azureedge.net", "Azure CDN"), (".cdn77.org", "CDN77"),
    (".cdn77.net", "CDN77"),
)
_CDN_TECH_TOKENS: Tuple[str, ...] = (
    "cloudflare", "vercel", "akamai", "fastly", "cloudfront", "cdn77",
    "netlify", "imperva", "incapsula",
)
# Proper vendor casing for tech-token matches (token.title() would yield
# "Cloudfront"/"Cdn77").
_CDN_TECH_PROVIDER: Dict[str, str] = {
    "cloudflare": "Cloudflare", "vercel": "Vercel", "akamai": "Akamai",
    "fastly": "Fastly", "cloudfront": "CloudFront", "cdn77": "CDN77",
    "netlify": "Netlify", "imperva": "Imperva", "incapsula": "Imperva",
}
# Third-party SaaS endpoints: probing them tests the vendor, not the program.
_SAAS_SUFFIXES: Tuple[Tuple[str, str], ...] = (
    (".myshopify.com", "Shopify"), (".shopify.com", "Shopify"),
    (".hubspot.net", "HubSpot"), (".hs-sites.com", "HubSpot"),
    (".zendesk.com", "Zendesk"),
    (".github.io", "GitHub Pages"),
    (".netlify.app", "Netlify"), (".netlify-global.com", "Netlify"),
    (".herokuapp.com", "Heroku"), (".herokussl.com", "Heroku"),
    (".wordpress.com", "WordPress.com"),
    (".statuspage.io", "Statuspage"), (".intercom.help", "Intercom"),
    (".helpscout.net", "HelpScout"), (".helpjuice.com", "HelpJuice"),
    (".readme.io", "Readme"), (".webflow.io", "Webflow"),
    (".ghost.io", "Ghost"), (".surge.sh", "Surge"),
    (".pantheonsite.io", "Pantheon"), (".azurewebsites.net", "Azure Web Apps"),
    (".cloudapp.net", "Azure"), (".trafficmanager.net", "Azure"),
    (".tumblr.com", "Tumblr"),
)
_SAAS_TECH_TOKENS: Tuple[str, ...] = (
    "shopify", "hubspot", "zendesk", "github pages", "wix", "squarespace",
)

# Tracking params stripped during URL canonicalization (Step 2B: strip
# utm_* + the common click-id beacons).
_TRACKING_KEY_EXACT = {
    "fbclid", "gclid", "dclid", "msclkid", "yclid", "mc_cid", "mc_eid",
    "_ga", "igshid", "vero_id", "wickedid",
}

_HTTPX_LINE_RE = re.compile(r"^(\S+)\s+((?:\[[^\]]*\]\s*)+)$")
_NMAP_GREP_RE = re.compile(r"Host:\s+(?P<host>\S+)\s+\(\)\s+Ports:\s+(?P<ports>.*)")
_PORT_FIELD_RE = re.compile(r"^(?P<port>\d+)/open/(?P<proto>\w+)//(?P<svc>[^/]*)")


# ── Small pure helpers ────────────────────────────────────────────────────────

def _strip_host(value: str) -> str:
    """URL/host:port -> bare host (lowercased), mirroring rtw_adapter.host_key
    (kept local so this module stays import-standalone)."""
    s = (value or "").strip()
    s = s.split("://", 1)[1] if "://" in s else s
    s = s.rsplit("@", 1)[-1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    elif s.count(":") == 1 and s.rsplit(":", 1)[1].isdigit():
        s = s.rsplit(":", 1)[0]
    return s.rstrip(".").lower()


def canonical_url(url: str) -> str:
    """Canonical form: lowercase scheme/host, '/' path, utm_* + click-id
    tracking params stripped, remaining params sorted, fragment dropped."""
    raw = (url or "").strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if not parts.scheme or not parts.netloc:
        return raw
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if not (k.lower().startswith("utm_") or k.lower() in _TRACKING_KEY_EXACT)]
    query.sort(key=lambda kv: kv[0])
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                       parts.path or "/", urlencode(query), ""))


def param_signature(url: str) -> Tuple[str, str, str, Tuple[str, ...]]:
    """Dedup signature: (scheme, host, path, sorted param KEYS). Two URLs with
    the same signature collapse to one representative."""
    canon = canonical_url(url)
    parts = urlsplit(canon)
    keys = tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True)))
    return (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", keys)


def classify_host(host: str, cname: str = "", tech: str = "") -> Tuple[str, str]:
    """Asset classification (Step 2A). Returns (asset_class, cdn_provider).
    cname is a CNAME target; tech is the httpx tech-detect column (any text).
    THIRD_PARTY_SAAS wins over CDN_EDGE (a *.myshopify.com behind Cloudflare
    is still the vendor's SaaS endpoint, not the program's origin)."""
    def _norm(text: str) -> str:
        return (text or "").strip().rstrip(".").lower()

    host_n, cname_n, tech_n = _norm(host), _norm(cname), _norm(tech)
    for suffix, provider in _SAAS_SUFFIXES:
        if host_n.endswith(suffix) or (cname_n and cname_n.endswith(suffix)):
            return CLASS_SAAS, provider
    for token in _SAAS_TECH_TOKENS:
        if token in tech_n:
            return CLASS_SAAS, token.title()
    for suffix, provider in _CDN_SUFFIXES:
        if host_n.endswith(suffix) or (cname_n and cname_n.endswith(suffix)):
            return CLASS_CDN_EDGE, provider
    for token in _CDN_TECH_TOKENS:
        if token in tech_n:
            return CLASS_CDN_EDGE, _CDN_TECH_PROVIDER.get(token, token.title())
    return CLASS_ORIGIN, ""


def content_length_bucket(content_length: Optional[int]) -> int:
    """Coarse size bucket so near-identical pages cluster despite ±1 byte."""
    if not content_length or content_length <= 0:
        return 0
    for i, cap in enumerate((1_000, 10_000, 100_000, 1_000_000), start=1):
        if content_length < cap:
            return i
    return 5


def simhash64(features: Iterable[str]) -> int:
    """Deterministic 64-bit SimHash over a feature string iterable (md5-derived)."""
    weights = [0] * 64
    for feature in features:
        digest = hashlib.md5(feature.encode("utf-8", "replace")).digest()
        value = int.from_bytes(digest[:8], "big")
        for bit in range(64):
            weights[bit] += 1 if (value >> bit) & 1 else -1
    return sum(1 << bit for bit in range(64) if weights[bit] > 0)


def hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def host_features(status_code: Optional[int], title: str,
                  tech: Sequence[str], content_length: Optional[int]) -> List[str]:
    """SimHash feature vector per the Step 2B spec: status_code, normalized
    title (+ tokens), tech stack, content-length bucket. The hostname itself
    is deliberately excluded — near-identical apps on different hosts cluster."""
    norm_title = re.sub(r"\s+", " ", (title or "")).strip().lower()
    feats = [f"status={status_code if status_code is not None else 'none'}",
             f"title={norm_title}"]
    feats += [f"title_tok={t}" for t in re.findall(r"[a-z0-9]+", norm_title)]
    feats += [f"tech={t.strip().lower()}" for t in tech if t.strip()]
    feats.append(f"clbucket={content_length_bucket(content_length)}")
    return feats


def cluster_hosts(hosts: List[dict], threshold: int = 3) -> None:
    """Greedy clustering in place (deterministic: input order sorted upstream).
    Hamming distance <= threshold joins a cluster; the first member of a
    cluster is its representative (is_cluster_rep=True)."""
    clusters: List[dict] = []  # {"cluster_id": str, "simhash": int}
    for rec in hosts:
        h = rec.get("simhash")
        if h is None:
            rec["cluster_id"] = ""
            rec["is_cluster_rep"] = False
            continue
        joined = None
        for cl in clusters:
            if hamming_distance(cl["simhash"], h) <= threshold:
                joined = cl
                break
        if joined is None:
            joined = {"cluster_id": f"c{len(clusters) + 1}",
                      "simhash": h, "members": 0}
            clusters.append(joined)
        joined["members"] += 1
        rec["cluster_id"] = joined["cluster_id"]
        rec["is_cluster_rep"] = joined["members"] == 1


# ── Ingest (best-effort, never raises) ────────────────────────────────────────

def _read_lines(path: Path) -> List[str]:
    try:
        return [line.strip() for line in
                path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip()]
    except OSError:
        return []


def _glob_one(recon_dir: Path, pattern: str) -> List[Path]:
    try:
        return sorted(recon_dir.glob(pattern))
    except OSError:
        return []


def parse_httpx_line(line: str) -> Optional[dict]:
    """Parse a PD httpx output line into a record (None for bare lines).

    Live-run fix: the bracket column order varies by httpx version —
    `https://h [200] [Title] [Tech] [5180]` and
    `https://h [200] [5180] [Title] [HSTS,Vercel]` are both seen in the wild.
    The old positional [title][tech][cl] assumption mis-parsed the second
    order (and hosts=0 followed). This parser is order-agnostic: the first
    bracket group must be the 3-digit status; a trailing pure-digit group is
    the content length; a LEADING pure-digit group after status is the
    content length too; the first remaining text group is the title and the
    rest are tech tags."""
    match = _HTTPX_LINE_RE.match(line.strip())
    if not match:
        return None
    url = match.group(1)
    groups = re.findall(r"\[([^\]]*)\]", match.group(2))
    if not groups or len(groups[0]) != 3 and not re.search(r"\d{3}", groups[0]):
        return None
    # Multi-hop status: httpx reports redirect chains in one bracket, e.g.
    # `[308,200]` — the FINAL hop is the live status. The old
    # `int(groups[0])` mis-parsed it, so such hosts degraded to bare rows
    # with status None and delta.json recorded status flips "from": null.
    hops = re.findall(r"\d{3}", groups[0])
    if not hops:
        return None
    status_code = int(hops[-1])
    rest = groups[1:]
    content_length = None
    if rest and rest[-1].isdigit():
        content_length = int(rest[-1])
        rest = rest[:-1]
    while rest and rest[0].isdigit() and content_length is None:
        content_length = int(rest[0])
        rest = rest[1:]
    title = rest[0].strip() if rest else ""
    tech = [t.strip() for t in ",".join(rest[1:]).split(",") if t.strip()] \
        if len(rest) > 1 else []
    return {
        "url": url,
        "status_code": status_code,
        "title": title,
        "tech": tech,
        "content_length": content_length,
    }


def parse_nmap_greppable(lines: List[str]) -> List[dict]:
    """`Host: 1.2.3.4 () Ports: 80/open/tcp//http///, ...` -> port records."""
    out: List[dict] = []
    for line in lines:
        match = _NMAP_GREP_RE.search(line)
        if not match:
            continue
        host = match.group("host")
        for field in match.group("ports").split(","):
            pm = _PORT_FIELD_RE.match(field.strip())
            if pm:
                out.append({"host": host, "port": int(pm.group("port")),
                            "protocol": pm.group("proto"), "service": pm.group("svc")})
    return out


def data_home() -> Path:
    env = os.environ.get("RHODAWK_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".rhodawk"


def input_integrity(recon_dir: Path) -> Dict[str, str]:
    """Per-input-file integrity for the fusion pass (B7): "ok" / "empty" /
    "missing" / "unparseable". Unparseable = present with content that is not
    valid UTF-8 text or contains NUL bytes (binary garbage, truncation,
    encoding tricks). Never raises."""
    out: Dict[str, str] = {}
    for rel in _INTEGRITY_INPUTS:
        try:
            raw = (recon_dir / rel).read_bytes()
        except OSError:
            out[rel] = "missing"
            continue
        if not raw.strip():
            out[rel] = "empty"
            continue
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            out[rel] = "unparseable"
            continue
        if b"\x00" in raw:
            out[rel] = "unparseable"
            continue
        out[rel] = "ok"
    return out


def _host_key(target: str) -> str:
    s = _strip_host(target)
    return s or "unknown"


def record_fusion_status(target: str, status: str, reason: str = "") -> None:
    """Write (or clear) the FUSION row of rtw_manifest.json — the same manifest
    the rtw_adapter uses, so tool_health in recon_truth.json and the
    health-table both show the canonical-fusion outcome. status FAILED upserts
    the row; any other status clears it (a successful fuse must not leave a
    stale FAILED row behind). Never raises."""
    manifest_path = data_home() / "recon" / _host_key(target) / "rtw_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            manifest = {}
    except (OSError, ValueError):
        manifest = {}
    entries = manifest.setdefault("entries", [])
    if status == RESULT_FAILED:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entries[:] = [e for e in entries
                      if e.get("capability_id") != FUSION_CAPABILITY_ID]
        entries.append({
            "capability_id": FUSION_CAPABILITY_ID,
            "rtw_function": "recon_fusion.fuse",
            "target": _host_key(target),
            "input_hash": "",
            "status": RESULT_FAILED,
            "started": now, "finished": now,
            "reason": reason,
        })
    else:
        kept = [e for e in entries
                if e.get("capability_id") != FUSION_CAPABILITY_ID]
        if len(kept) == len(entries):
            return
        manifest["entries"] = kept
    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    except OSError:
        pass


# ── Fusion ────────────────────────────────────────────────────────────────────

def _live_host_records(recon_dir: Path) -> List[dict]:
    """Collect live-host evidence from live/httpx_full.txt, live/live_hosts.txt
    and live/urls.txt into one record per host.

    Live-run fix (hosts=0): recon_engine.sh writes live/ evidence under the
    filenames above, and a real httpx run may emit lines the rich parser
    rejects (bare URLs when -tech-detect is unsupported, or a bracket order
    the old positional regex mis-read). Every line now yields a host record —
    rich metadata when parseable, bare host otherwise — and the RAW line is
    kept as classification evidence so a tech tag anywhere in it
    ([HSTS,Vercel] on an apex A-record with no CNAME) drives CDN_EDGE."""
    records: Dict[str, dict] = {}

    def _row(host: str) -> dict:
        return records.setdefault(host, {
            "host": host, "status_code": None, "title": "", "tech": [],
            "content_length": None, "sources": set(), "raw": [],
        })

    for rel in ("live/httpx_full.txt", "live/live_hosts.txt", "live/urls.txt"):
        for raw in _read_lines(recon_dir / rel):
            rec = parse_httpx_line(raw)
            bare = raw.split()[0] if raw.split() else ""
            host = _strip_host(rec["url"] if rec else bare)
            if not host:
                continue
            row = _row(host)
            row["sources"].add(rel)   # full artifact path, e.g. live/httpx_full.txt
            row["raw"].append(raw)
            if rec and row["status_code"] is None:
                row.update(status_code=rec["status_code"], title=rec["title"],
                           tech=rec["tech"],
                           content_length=rec["content_length"])
    return [records[host] for host in sorted(records)]


def load_resolution(recon_dir: Path) -> Dict[str, dict]:
    """hosts/resolution.txt written by recon_engine.sh Phase 2.5:
    `host<TAB>ip<TAB>cname`."""
    out: Dict[str, dict] = {}
    for line in _read_lines(recon_dir / "hosts" / "resolution.txt"):
        parts = line.split("\t")
        if not parts or not parts[0].strip():
            continue
        host = _strip_host(parts[0])
        ip = parts[1].strip() if len(parts) > 1 else ""
        cname = parts[2].strip() if len(parts) > 2 else ""
        out[host] = {"ip": ip, "cname": cname}
    return out


def load_host_classes(recon_dir: Path) -> Dict[str, dict]:
    """hosts/host_classes.txt written by the `classify` subcommand:
    `host<TAB>ip<TAB>class<TAB>provider`."""
    out: Dict[str, dict] = {}
    for line in _read_lines(recon_dir / "hosts" / "host_classes.txt"):
        parts = line.split("\t")
        if len(parts) < 3 or not parts[0].strip():
            continue
        out[_strip_host(parts[0])] = {
            "ip": parts[1].strip(), "asset_class": parts[2].strip(),
            "cdn_provider": parts[3].strip() if len(parts) > 3 else "",
        }
    return out


def classify_recon_dir(recon_dir: Path, limit: int = 100) -> Dict[str, int]:
    """Phase 2.5 helper: resolve + classify live hosts and write
    hosts/host_classes.txt + hosts/origin_targets.txt. Resolution evidence
    comes from hosts/resolution.txt (dig output captured by bash — this
    module never touches the network). Classification evidence is the RAW
    httpx line, so a tech tag anywhere in it (Vercel apex A-record with no
    CNAME) classifies the host as CDN_EDGE (live-run fix 2)."""
    records = _live_host_records(recon_dir)
    resolution = load_resolution(recon_dir)

    rows: List[str] = []
    origin_targets: Set[str] = set()
    counts = {CLASS_CDN_EDGE: 0, CLASS_SAAS: 0, CLASS_ORIGIN: 0}
    for rec in records[:limit]:
        host = rec["host"]
        res = resolution.get(host, {})
        evidence = " ".join(rec["raw"])
        asset_class, provider = classify_host(host, res.get("cname", ""), evidence)
        ip = res.get("ip", "")
        rows.append(f"{host}\t{ip}\t{asset_class}\t{provider}")
        counts[asset_class] += 1
        if asset_class == CLASS_ORIGIN:
            origin_targets.add(ip or host)

    hosts_dir = recon_dir / "hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    (hosts_dir / "host_classes.txt").write_text("\n".join(rows) + ("\n" if rows else ""),
                                                encoding="utf-8")
    (hosts_dir / "origin_targets.txt").write_text(
        "\n".join(sorted(origin_targets)) + ("\n" if origin_targets else ""),
        encoding="utf-8")
    return counts


def build_truth(recon_dir: Path, target: str,
                scope_domains: Optional[List[str]] = None,
                scope_excluded: Optional[List[str]] = None) -> dict:
    """Ingest every recon artifact + published rtw outputs -> truth dict."""
    recon_dir = Path(recon_dir)
    resolution = load_resolution(recon_dir)
    classes = load_host_classes(recon_dir)

    # Subdomains + provenance (subdomains/all.txt is the merged probe list).
    sub_sources = [("subdomains/all.txt", recon_dir / "subdomains" / "all.txt")]
    for name in ("subfinder.txt", "amass.txt", "crtsh.txt", "wayback_subs.txt"):
        sub_sources.append((f"subdomains/{name}", recon_dir / "subdomains" / name))
    for path in _glob_one(recon_dir, "rtw/*/rtw_subdomains.txt"):
        sub_sources.append((f"rtw/{path.parent.name}/rtw_subdomains.txt", path))
    sub_provenance: Dict[str, Set[str]] = {}
    for label, path in sub_sources:
        for line in _read_lines(path):
            host = _strip_host(line.split()[0] if line.split() else "")
            if host:
                sub_provenance.setdefault(host, set()).add(label)
    subdomains = sorted(sub_provenance)

    # Live hosts (Phase 2 httpx + live/ evidence) — the hosts[] rows. The RAW
    # httpx line is the classification evidence so tech tags drive CDN_EDGE
    # regardless of the httpx output column order (live-run fixes 2+3).
    hosts: List[dict] = []
    for rec in _live_host_records(recon_dir):
        host = rec["host"]
        res = resolution.get(host, {})
        cls = classes.get(host)
        if cls and cls.get("asset_class"):
            asset_class, provider = cls["asset_class"], cls.get("cdn_provider", "")
        else:
            asset_class, provider = classify_host(host, res.get("cname", ""),
                                                  " ".join(rec["raw"]))
        discovered = set(rec["sources"]) | sub_provenance.get(host, set())
        hosts.append({
            "host": host,
            "ips": [res["ip"]] if res.get("ip") else [],
            "asset_class": asset_class,
            "cdn_provider": provider,
            "status_code": rec["status_code"],
            "title": rec["title"],
            "content_length": rec["content_length"],
            "tech": rec["tech"],
            "simhash": None,
            "cluster_id": "",
            "is_cluster_rep": False,
            "discovered_by": sorted(discovered),
        })
    hosts.sort(key=lambda h: h["host"])
    # SimHash is an int while clustering; serialized as a 16-hex-digit string.
    for rec in hosts:
        rec["simhash"] = simhash64(host_features(rec["status_code"], rec["title"],
                                                 rec["tech"], rec["content_length"]))
    cluster_hosts(hosts)
    for rec in hosts:
        rec["simhash"] = f"{rec['simhash']:016x}"

    # URLs — canonicalized, tracking-stripped, param-signature deduped.
    url_sources = [("urls/gau.txt", recon_dir / "urls" / "gau.txt"),
                   ("urls/wayback.txt", recon_dir / "urls" / "wayback.txt"),
                   ("urls/katana.txt", recon_dir / "urls" / "katana.txt")]
    for path in _glob_one(recon_dir, "rtw/*/rtw_urls.txt"):
        url_sources.append((f"rtw/{path.parent.name}/rtw_urls.txt", path))
    # Phase 5.75 headless JS crawl (opt-in; see CRAWLER-REDESIGN.md). Emitted
    # BEFORE urls/all.txt so a crawled URL that also appears in the merged
    # corpus keeps its real provenance alongside the aggregate label.
    url_sources.append(("js_crawl/endpoints.txt", recon_dir / "js_crawl" / "endpoints.txt"))
    url_sources.append(("urls/all.txt", recon_dir / "urls" / "all.txt"))
    urls: Dict[Tuple, dict] = {}
    for label, path in url_sources:
        for line in _read_lines(path):
            canon = canonical_url(line.split()[0] if line.split() else "")
            if "://" not in canon:
                continue
            sig = param_signature(canon)
            row = urls.setdefault(sig, {"url": canon, "discovered_by": set()})
            row["discovered_by"].add(label)
    url_rows = [{"url": row["url"], "discovered_by": sorted(row["discovered_by"])}
                for row in urls.values()]
    url_rows.sort(key=lambda r: r["url"])

    # JS endpoints + ports. Phase 5 static extraction feeds js/endpoints.txt;
    # the Phase 5.75 headless crawl additionally contributes the PATH form of
    # every API-looking runtime endpoint it captured (same schema, provenance
    # "js_crawl/endpoints.txt" — downstream hunt/validate/report need no
    # changes; see CRAWLER-REDESIGN.md §5).
    js_rows = [{"endpoint": ep, "discovered_by": ["js/endpoints.txt"]}
               for ep in sorted(set(_read_lines(recon_dir / "js" / "endpoints.txt")))]
    _js_seen = {r["endpoint"] for r in js_rows}
    for canon in sorted(set(_read_lines(recon_dir / "js_crawl" / "endpoints.txt"))):
        if "://" not in canon:
            continue
        path_form = urlsplit(canon).path or "/"
        if not _API_PATH_RE.match(path_form) or path_form in _js_seen:
            continue
        _js_seen.add(path_form)
        js_rows.append({"endpoint": path_form,
                        "discovered_by": ["js_crawl/endpoints.txt"]})
    js_rows.sort(key=lambda r: r["endpoint"])
    ports = parse_nmap_greppable(
        _read_lines(recon_dir / "ports" / "nmap_greppable.txt"))
    if not ports:
        # Fallback: open_ports.txt (`80/open` lines) has no host column —
        # inherently unjoinable, so these rows can only ever be unattributed.
        ports = [{"host": "", "port": int(p.split("/")[0]), "protocol": "tcp",
                  "service": ""}
                 for p in sorted(set(_read_lines(recon_dir / "ports" / "open_ports.txt")))
                 if p.split("/")[0].isdigit()]

    # B4: attribute open ports ONLY to hosts they can be joined to. The nmap
    # row's own hostname is kept; an IP is joined through hosts/resolution.txt
    # ONLY when exactly ONE host resolves to it — a shared IP (loopback, NAT,
    # CDN edge) is ambiguous and must never silently borrow port rows (the E9
    # defect put port 80 on oos.example.test via the shared lab loopback).
    # Everything unjoinable is reported under truth['unattributed_ports'].
    ip_to_hosts: Dict[str, Set[str]] = {}
    for _h, _res in resolution.items():
        _ip = (_res or {}).get("ip", "")
        if _ip:
            ip_to_hosts.setdefault(_ip, set()).add(_h)

    def _is_ip_literal(text: str) -> bool:
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    seen_ports: Set[Tuple] = set()
    port_rows: List[dict] = []
    unattributed_rows: List[dict] = []
    for p in ports:
        key = (p.get("host") or "", p["port"])
        if key in seen_ports:
            continue
        seen_ports.add(key)
        nmap_host = p.get("host") or ""
        host_label = ""
        if nmap_host and not _is_ip_literal(nmap_host):
            host_label = nmap_host
        elif nmap_host:
            joinable = sorted(ip_to_hosts.get(nmap_host, set()))
            if len(joinable) == 1:
                host_label = joinable[0]
        if host_label:
            port_rows.append({"host": host_label, "port": p["port"],
                              "protocol": p.get("protocol", "tcp"),
                              "service": p.get("service", ""),
                              "nmap_host": nmap_host,
                              "discovered_by": ["ports/nmap_greppable.txt"]})
        else:
            unattributed_rows.append({
                "port": p["port"],
                "protocol": p.get("protocol", "tcp"),
                "service": p.get("service", ""),
                "source_host": nmap_host,
                "discovered_by": ["ports/open_ports.txt"] if not nmap_host
                                 else ["ports/nmap_greppable.txt"],
            })
    port_rows.sort(key=lambda r: (r["host"], r["port"]))
    unattributed_rows.sort(key=lambda r: (r["source_host"], r["port"]))

    # Tool health — the honest per-capability accounting from rtw_manifest.json.
    tool_health: List[dict] = []
    manifest_path = data_home() / "recon" / _host_key(target) / "rtw_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    latest: Dict[str, dict] = {}
    for entry in manifest.get("entries", []):
        cid = entry.get("capability_id")
        if cid:
            latest[cid] = entry
    for cid in sorted(latest):
        e = latest[cid]
        status = e.get("status", "")
        reason = e.get("reason", "")
        if not reason and status in (RESULT_FAILED, RESULT_SKIPPED_SILENT):
            # Live-run fix: the truth doc must keep the failure reason
            # visible — fall back to the last non-empty stderr line the
            # manifest entry stored.
            tail = [ln.strip() for ln in str(e.get("stderr_tail", "")).splitlines()
                    if ln.strip()]
            reason = tail[-1] if tail else ""
        tool_health.append({
            "capability_id": cid,
            "rtw_function": e.get("rtw_function", ""),
            "status": status,
            "duration_secs": e.get("duration_secs"),
            "net_new_count": e.get("net_new_count"),
            "reason": reason,
        })

    origin_ips = {ip for h in hosts if h["asset_class"] == CLASS_ORIGIN
                  for ip in h["ips"] if ip}
    # B3: every line the post-enumeration scope filter dropped is quarantined
    # in scope/dropped_oos.txt ("<relpath>\t<line>"); surface the count.
    scope_dropped = len(_read_lines(recon_dir / "scope" / "dropped_oos.txt"))
    # B7: per-input integrity; an unparseable REQUIRED input degrades the truth.
    integrity = input_integrity(recon_dir)
    status = STATUS_DEGRADED if any(integrity.get(rel) == "unparseable"
                                    for rel in _REQUIRED_INPUTS) else STATUS_OK
    counts = {
        "subdomains": len(subdomains),
        "live_hosts": len(hosts),
        "unique_host_clusters": len({h["cluster_id"] for h in hosts
                                     if h["cluster_id"]}),
        "origin_ips": len(origin_ips),
        "cdn_edges": sum(1 for h in hosts if h["asset_class"] == CLASS_CDN_EDGE),
        "open_ports": len(port_rows),
        "unique_urls": len(url_rows),
        "js_endpoints": len(js_rows),
        "scope_dropped": scope_dropped,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "target": _host_key(target),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope_patterns": {"domains": list(scope_domains or []),
                           "excluded": list(scope_excluded or [])},
        "status": status,
        "input_integrity": integrity,
        "counts": counts,
        "tool_health": tool_health,
        "subdomains": subdomains,
        "hosts": hosts,
        "urls": url_rows,
        "js_endpoints": js_rows,
        "ports": port_rows,
        "unattributed_ports": unattributed_rows,
    }


def compute_delta(previous: dict, current: dict) -> dict:
    """Run-to-run diff (Step 2C) between two truth documents."""
    prev_subs = set(previous.get("subdomains", []))
    cur_subs = set(current.get("subdomains", []))
    prev_status = {h.get("host"): h.get("status_code")
                   for h in previous.get("hosts", []) if h.get("host")}
    flips = [{"host": h["host"], "from": prev_status[h["host"]],
              "to": h.get("status_code")}
             for h in current.get("hosts", [])
             if h.get("host") in prev_status
             and prev_status[h["host"]] != h.get("status_code")]

    def _endpoint_set(doc: dict) -> Set[str]:
        out = set()
        for e in doc.get("js_endpoints", []):
            out.add(e.get("endpoint") if isinstance(e, dict) else str(e))
        return out

    def _port_set(doc: dict) -> Set[Tuple]:
        out = set()
        for p in doc.get("ports", []):
            if isinstance(p, dict):
                out.add((p.get("host", ""), p.get("port")))
            else:
                out.add(("", p))
        return out

    cur_js, prev_js = _endpoint_set(current), _endpoint_set(previous)
    cur_ports, prev_ports = _port_set(current), _port_set(previous)
    return {
        "has_previous_run": True,
        "new_subdomains": sorted(cur_subs - prev_subs),
        "removed_subdomains": sorted(prev_subs - cur_subs),
        "status_code_flips": flips,
        "new_js_endpoints": sorted(cur_js - prev_js),
        "new_open_ports": [{"host": h, "port": p} for (h, p) in cur_ports - prev_ports],
    }


def fuse(recon_dir: Path, target: str,
         scope_domains: Optional[List[str]] = None,
         scope_excluded: Optional[List[str]] = None,
         scope_enforced: bool = True) -> Tuple[dict, Optional[dict]]:
    """Build the new truth, diff against the previous run, archive the old
    truth, write recon_truth.json + delta.json + the mirror copy.

    scope_enforced=False records an explicit --no-scope-check run so the
    truth document states its own enforcement status (B1)."""
    recon_dir = Path(recon_dir)
    truth_path = recon_dir / "recon_truth.json"
    delta_path = recon_dir / "delta.json"

    # A successful fuse clears any stale FUSION=FAILED row BEFORE the truth is
    # built, so recon_truth.json reflects this (healthy) fusion outcome.
    record_fusion_status(target, "COMPLETED")

    previous: Optional[dict] = None
    try:
        previous = json.loads(truth_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = None
    if previous is None:
        # B5: recon_engine.sh archives the previous run's truth under
        # .prev_run/ and clears the recon dir before each run — the delta
        # baseline lives there now.
        try:
            previous = json.loads(
                (recon_dir / ".prev_run" / "recon_truth.json").read_text(
                    encoding="utf-8"))
        except (OSError, ValueError):
            previous = None
    if isinstance(previous, dict) and previous.get("schema_version"):
        try:
            (recon_dir / "recon_truth.prev.json").write_text(
                json.dumps(previous, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
        except OSError:
            pass
    else:
        previous = None

    # B6: recon_engine.sh archives a leftover .run_incomplete marker to
    # .prev_run/ at startup — its presence means the PREVIOUS run never
    # reached a clean exit. Record it in this run's truth and warn.
    previous_run_incomplete = (recon_dir / ".prev_run" / "run_incomplete").is_file()
    if previous_run_incomplete:
        print("[!] previous recon run did not complete cleanly — "
              "previous_run_incomplete=true recorded in recon_truth.json",
              file=sys.stderr)
        # consume-once: the flag describes exactly the run before this one
        try:
            (recon_dir / ".prev_run" / "run_incomplete").unlink()
        except OSError:
            pass

    truth = build_truth(recon_dir, target, scope_domains, scope_excluded)
    truth["scope_enforced"] = bool(scope_enforced)
    truth["previous_run_incomplete"] = bool(previous_run_incomplete)
    if truth.get("status") == STATUS_DEGRADED:
        bad = [rel for rel, state in truth["input_integrity"].items()
               if state == "unparseable"]
        print(f"[!] recon_truth.json status DEGRADED — unparseable required "
              f"input(s): {', '.join(bad)} (see input_integrity)",
              file=sys.stderr)
    truth_path.write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")

    if previous is not None:
        delta = compute_delta(previous, truth)
    else:
        delta = {"has_previous_run": False, "new_subdomains": [],
                 "removed_subdomains": [], "status_code_flips": [],
                 "new_js_endpoints": [], "new_open_ports": []}
    delta_path.write_text(json.dumps(delta, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")

    # Mirror for harness/agent runtimes (RHODAWK_HOME aware).
    try:
        mirror_dir = data_home() / "recon" / truth["target"]
        mirror_dir.mkdir(parents=True, exist_ok=True)
        (mirror_dir / "recon_truth.json").write_text(
            json.dumps(truth, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass
    return truth, delta


def format_delta_line(delta: dict) -> str:
    return (f"Delta vs previous run: +{len(delta.get('new_subdomains', []))} subdomains, "
            f"-{len(delta.get('removed_subdomains', []))} subdomains, "
            f"{len(delta.get('status_code_flips', []))} status flips, "
            f"+{len(delta.get('new_js_endpoints', []))} js endpoints, "
            f"+{len(delta.get('new_open_ports', []))} open ports")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="recon_fusion.py",
        description="Canonical recon fusion (recon_truth.json + delta.json) — RhodawkAI Edition.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fuse = sub.add_parser("fuse", help="build recon_truth.json + delta.json")
    p_fuse.add_argument("--recon-dir", required=True)
    p_fuse.add_argument("--target", required=True)
    p_fuse.add_argument("--scope-domain", action="append", default=[])
    p_fuse.add_argument("--scope-exclude", action="append", default=[])
    p_fuse.add_argument("--no-scope-check", action="store_true",
                        help="record scope_enforced=false (recon_engine.sh forwards "
                             "this when the run used the demo opt-out; fusion still runs)")
    p_fuse.add_argument("--quiet", action="store_true")

    p_mark = sub.add_parser(
        "mark-failed",
        help="record a FAILED FUSION row in rtw_manifest.json (surfaces in "
             "tool_health + health-table); used by recon_engine.sh when fuse fails")
    p_mark.add_argument("--target", required=True)
    p_mark.add_argument("--reason", required=True)

    p_classify = sub.add_parser("classify",
                                help="write hosts/host_classes.txt + origin_targets.txt "
                                     "(CDN_EDGE / THIRD_PARTY_SAAS / FIRST_PARTY_ORIGIN)")
    p_classify.add_argument("--recon-dir", required=True)
    p_classify.add_argument("--limit", type=int, default=100)

    p_delta = sub.add_parser("delta-line",
                             help="print the 1-line delta summary from delta.json "
                                  "(used by the recon_engine.sh Recon Summary)")
    p_delta.add_argument("--recon-dir", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "classify":
        counts = classify_recon_dir(Path(args.recon_dir), limit=args.limit)
        print(f"[+] Classified: {counts['FIRST_PARTY_ORIGIN']} first-party origin(s), "
              f"{counts['CDN_EDGE']} CDN edge(s), {counts['THIRD_PARTY_SAAS']} third-party SaaS")
        return 0

    if args.cmd == "mark-failed":
        record_fusion_status(args.target, RESULT_FAILED, args.reason)
        print(f"[!] FUSION marked FAILED in rtw_manifest.json: {args.reason}",
              file=sys.stderr)
        return 0

    if args.cmd == "delta-line":
        try:
            delta = json.loads(
                (Path(args.recon_dir) / "delta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return 0
        if delta.get("has_previous_run"):
            print(format_delta_line(delta))
        return 0

    truth, delta = fuse(Path(args.recon_dir), args.target,
                        scope_domains=args.scope_domain,
                        scope_excluded=args.scope_exclude,
                        scope_enforced=not args.no_scope_check)
    if not args.quiet:
        c = truth["counts"]
        print(f"[+] recon_truth.json: {Path(args.recon_dir) / 'recon_truth.json'} "
              f"(hosts={c['live_hosts']}, clusters={c['unique_host_clusters']}, "
              f"origins={c['origin_ips']}, cdn_edges={c['cdn_edges']}, "
              f"urls={c['unique_urls']}, js={c['js_endpoints']}, ports={c['open_ports']})")
        if delta.get("has_previous_run"):
            print(f"[i] {format_delta_line(delta)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
