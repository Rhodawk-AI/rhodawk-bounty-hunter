#!/usr/bin/env python3
"""Shared primitives for the deterministic verifier library.

The verifier library is the false-positive killer: a candidate finding is only
a *lead* until an independent, **non-AI** verifier reproduces it against the
live target and a deterministic oracle fires. Verifiers never emit a confidence
score — they return a boolean plus a reproducible request/response trace.

This mirrors XBOW's discovery/validation split: the agent that surfaces a bug is
never the system that confirms it. Everything here is pure plumbing + an
SSRF-safe single-hop fetch; the per-class oracles live in the sibling modules.
"""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Prefer certifi's CA bundle when available; never disable verification.
_SSL_CTX = ssl.create_default_context()
try:  # pragma: no cover - depends on local install
    import certifi

    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX = ssl.create_default_context()

try:  # package import (pythonpath=rhodawk)
    from tools.safe_http import initial_host_blocked  # noqa: E402
except ImportError:  # standalone execution: python3 tools/verifiers/base.py
    import os as _os, sys as _sys

    _TOOLS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    if _TOOLS not in _sys.path:
        _sys.path.insert(0, _TOOLS)
    from safe_http import initial_host_blocked  # noqa: E402

USER_AGENT = "rhodawk-bounty-hunter/verifier"

# Hosts treated as loopback for the explicit test seam. Anything else on the
# SSRF blocklist (RFC1918, link-local, cloud metadata, ULA) is NEVER allowed
# through the seam — only a real loopback server running on the operator's own
# machine may use it.
_LOOPBACK_HOST_SUFFIX = ".localhost"
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _is_loopback_host(hostname: str) -> bool:
    host = (hostname or "").strip().lower()
    if not host:
        return False
    if host in _LOOPBACK_HOSTS or host.endswith(_LOOPBACK_HOST_SUFFIX):
        return True
    import ipaddress

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def preflight_blocked(
    url: str,
    scope_checker=None,
    allow_localhost_testing: bool = False,
) -> str | None:
    """The single hop-0 gate for every verifier network action.

    Returns None when the fetch may proceed, or a human-readable block reason.
    Applied BEFORE any socket is opened (and before a headless browser is
    launched), so a blocked URL costs 0 packets:

      1. SSRF blocklist — loopback / RFC1918 / link-local / cloud metadata /
         reserved / multicast hosts are refused outright (169.254.169.254,
         127.0.0.1, fd00::/8, ...). No seam bypasses this except the explicit
         loopback test allowance below.
      2. Scope gate — a valid scope_checker is REQUIRED (fail closed). The only
         exception is ``allow_localhost_testing=True`` + a loopback target,
         which exists so unit tests can exercise fetch()/capture() against a
         local http.server without a compiled manifest. The seam never applies
         to a public host: a missing scope checker still blocks those.
      3. Manifest scope — when a checker is present, the URL must be in scope.
    """
    host = ""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        host = ""

    if allow_localhost_testing and _is_loopback_host(host):
        return None  # explicit unit-test seam: loopback targets only

    if initial_host_blocked(url):
        return (
            f"blocked: initial host is loopback/private/metadata "
            f"({host or 'unparseable URL'}) — SSRF guard (hop 0)"
        )
    if scope_checker is None:
        return (
            "blocked: no scope_checker provided — the verifier spine fails "
            "closed (build one via ScopeChecker/ScopeChecker.from_manifest)"
        )
    if not scope_checker.is_in_scope(url):
        return f"blocked: {url} is out of scope"
    return None


@dataclass
class HttpExchange:
    """One request/response pair in a verifier's reproducible trace."""

    method: str
    url: str
    status: int | None
    request_headers: dict
    response_headers: dict
    response_snippet: str
    elapsed_ms: float
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VerifyResult:
    """The verdict of a verifier run.

    confirmed=True means a deterministic oracle fired — the bug is real and
    reproducible via `trace`. skipped=True means the verifier could not run
    (missing dependency, missing creds, no OOB callback); it is NOT a pass and
    NOT a fail — the finding stays an unverified lead.
    """

    confirmed: bool
    vuln_class: str
    oracle: str
    trace: list[HttpExchange] = field(default_factory=list)
    evidence: str = ""
    error: str | None = None
    skipped: bool = False

    def to_dict(self) -> dict:
        return {
            "confirmed": self.confirmed,
            "vuln_class": self.vuln_class,
            "oracle": self.oracle,
            "evidence": self.evidence,
            "error": self.error,
            "skipped": self.skipped,
            "trace": [x.to_dict() for x in self.trace],
        }


def confirmed(vuln_class: str, oracle: str, trace: list[HttpExchange], evidence: str) -> VerifyResult:
    return VerifyResult(True, vuln_class, oracle, trace, evidence)


def rejected(vuln_class: str, oracle: str, trace: list[HttpExchange], evidence: str = "") -> VerifyResult:
    return VerifyResult(False, vuln_class, oracle, trace, evidence or "oracle did not fire")


def skipped(vuln_class: str, reason: str) -> VerifyResult:
    return VerifyResult(False, vuln_class, reason, [], "", error=reason, skipped=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow; verifiers inspect raw 3xx + Location themselves."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def _opener(context: ssl.SSLContext | None):
    handlers: list = [_NoRedirect]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def fetch(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    data: bytes | None = None,
    timeout: float = 15.0,
    scope_checker=None,
    note: str = "",
    max_body: int = 65536,
    allow_localhost_testing: bool = False,
) -> tuple[HttpExchange, bytes]:
    """Single-hop fetch (no redirect following) returning a trace entry + body.

    Hop 0 is gated by ``preflight_blocked`` BEFORE any socket is opened: the
    SSRF blocklist (loopback / RFC1918 / link-local / cloud metadata) applies
    unconditionally, and a valid ``scope_checker`` is REQUIRED — with none
    supplied every URL is refused (fail closed). A blocked fetch never opens a
    socket; it returns an exchange whose note carries the block reason and an
    empty body, so callers keep their normal trace handling.

    The only seam is ``allow_localhost_testing=True`` together with a loopback
    target — for unit tests against a local http.server. It never permits a
    public host without a scope checker.

    Redirects are never followed, so a target cannot 302 us into cloud
    metadata or an RFC1918 host either (the SSRF seam `safe_http` guards).
    """
    headers = dict(headers or {})
    headers.setdefault("User-Agent", USER_AGENT)

    block = preflight_blocked(url, scope_checker, allow_localhost_testing)
    if block:
        # The block reason is the signal here — the caller's note, if any, is
        # kept as a prefix but never REPLACES the reason in the trace.
        block_note = f"{note} [{block}]" if note else block
        ex = HttpExchange(method, url, None, headers, {}, "", 0.0, block_note)
        return ex, b""

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = _opener(_SSL_CTX)
    start = time.perf_counter()
    status: int | None
    resp_headers: dict = {}
    body = b""
    try:
        resp = opener.open(req, timeout=timeout)
        status = getattr(resp, "status", None) or resp.getcode()
        resp_headers = dict(resp.headers.items())
        body = resp.read(max_body)
    except urllib.error.HTTPError as exc:
        # HTTPError doubles as a response object (incl. 3xx when not followed).
        status = exc.code
        try:
            resp_headers = dict(exc.headers.items())
        except Exception:  # noqa: BLE001
            resp_headers = {}
        try:
            body = exc.read(max_body)
        except Exception:  # noqa: BLE001
            body = b""
    except Exception as exc:  # noqa: BLE001 - a dead host shouldn't crash the sweep
        elapsed = (time.perf_counter() - start) * 1000
        ex = HttpExchange(method, url, None, headers, {}, "", elapsed,
                          note or f"{type(exc).__name__}: {exc}")
        return ex, b""

    elapsed = (time.perf_counter() - start) * 1000
    snippet = body[:2048].decode("utf-8", "replace")
    ex = HttpExchange(method, url, status, headers, resp_headers, snippet, elapsed, note)
    return ex, body


def set_param(url: str, param: str, value: str) -> str:
    """Return `url` with query `param` set to `value` (preserving the rest)."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def finding_url(finding: dict) -> str:
    """Pull the testable URL out of a finding dict (url or endpoint)."""
    return str(finding.get("url") or finding.get("endpoint") or "").strip()
