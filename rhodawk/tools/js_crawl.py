#!/usr/bin/env python3
"""js_crawl.py — headless JS crawl phase (Phase 5.75, opt-in via --js-crawl).

Loads in-scope pages in a real headless Chromium (Playwright), captures every
XHR/fetch/document request the running application issues, performs a bounded
interaction pass (click visible buttons, fill visible text inputs with an
inert placeholder — never password fields, never forms containing password
fields), and writes the discovered endpoints into the SAME artifacts the rest
of the pipeline already reads:

  <recon-dir>/js_crawl/endpoints.txt   absolute request URLs, deduped + sorted
  <recon-dir>/js_crawl/summary.json    {status, pages_visited, requests_captured,
                                        endpoints_found, duration_secs, reason?}
  <recon-dir>/js_crawl/dropped_oos.txt out-of-scope captures (never written to
                                        endpoints.txt)

Scope contract (identical to every other phase — see CRAWLER-REDESIGN.md):
  - exactly one scope authority is required: --manifest <compiled_scope.json>
    (SHA-256 verified via ScopeChecker.from_manifest) or --domain patterns;
    refusing to run scope-less is fail-closed by design;
  - seeds AND captured URLs are checked against that authority; out-of-scope
    URLs are dropped and quarantined, never visited or exported;
  - TLS verification is never disabled (no --ignore-https-errors).

Degradation is graceful by contract: a missing Playwright package or Chromium
build writes summary.json with status "skipped" (and a reason) and exits 0 —
the engine logs a WARN and continues; doctor is unaffected.

Usage (usually invoked by recon_engine.sh Phase 5.75):
  python3 tools/js_crawl.py --url https://host/ --recon-dir recon/<host> \
      [--manifest PATH | --domain PATTERN ...] [--max-pages 10] \
      [--timeout 120] [--header 'Name: value' ...] [--chromium PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

try:  # package import (pythonpath=rhodawk, pytest, engine wiring)
    from tools.scope_checker import ScopeChecker
except ImportError:  # standalone execution from rhodawk/tools/
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        from tools.scope_checker import ScopeChecker
    except ImportError:
        from scope_checker import ScopeChecker  # type: ignore

PLACEHOLDER_TEXT = "rhodawk-recon-crawl@example.invalid"
MAX_CLICKS_PER_PAGE = 10
PER_PAGE_TIMEOUT_CAP = 20  # seconds


class ScopeRefusal(Exception):
    """Raised when the phase is invoked without a resolvable scope authority."""


# ---------------------------------------------------------------------------
# Scope resolution (pure, unit-testable)
# ---------------------------------------------------------------------------

def resolve_scope(manifest: str | None, domains: list[str],
                  excludes: list[str]) -> ScopeChecker:
    """Build the one scope authority for this run. Refuses scope-less runs."""
    if manifest:
        return ScopeChecker.from_manifest(manifest)  # hash-verified, fail-closed
    if domains:
        patterns: list[str] = []
        for d in domains:
            patterns.extend(p.strip() for p in d.split(",") if p.strip())
        excludes_pats: list[str] = []
        for e in excludes or []:
            excludes_pats.extend(p.strip() for p in e.split(",") if p.strip())
        return ScopeChecker(domains=patterns, excluded_domains=excludes_pats)
    raise ScopeRefusal(
        "js-crawl requires a scope authority: pass --manifest <compiled_scope.json> "
        "or --domain PATTERN (repeatable). The engine forwards its resolved scope "
        "automatically; refusing to browse scope-less is fail-closed by design."
    )


def filter_in_scope(urls: list[str], checker: ScopeChecker | None
                    ) -> tuple[list[str], list[str]]:
    """Split captured URLs into (in_scope, dropped). Checker failure = drop
    (fail-closed): an unverifiable URL is never exported."""
    kept: list[str] = []
    dropped: list[str] = []
    for u in urls:
        try:
            if checker is not None and checker.is_in_scope(u):
                kept.append(u)
            else:
                dropped.append(u)
        except Exception:
            dropped.append(u)
    return kept, dropped


# ---------------------------------------------------------------------------
# Output writing (pure, unit-testable)
# ---------------------------------------------------------------------------

def write_outputs(recon_dir: Path, endpoints: list[str], dropped: list[str],
                  summary: dict) -> None:
    out_dir = recon_dir / "js_crawl"
    out_dir.mkdir(parents=True, exist_ok=True)
    if endpoints:
        (out_dir / "endpoints.txt").write_text(
            "\n".join(sorted(set(endpoints))) + "\n", encoding="utf-8")
    if dropped:
        (out_dir / "dropped_oos.txt").write_text(
            "\n".join(sorted(set(dropped))) + "\n", encoding="utf-8")
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def skipped_summary(reason: str, duration: float = 0.0) -> dict:
    return {
        "status": "skipped",
        "pages_visited": 0,
        "requests_captured": 0,
        "endpoints_found": 0,
        "duration_secs": round(duration, 2),
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# The browser crawl (Playwright; degrades gracefully)
# ---------------------------------------------------------------------------

def _resolve_chromium_path(explicit: str | None) -> str | None:
    """capabilities.json chromium_path wins; else Playwright's bundled build."""
    if explicit:
        return explicit
    try:
        try:
            from _compat import get_env  # type: ignore
        except ImportError:
            from rhodawk._compat import get_env  # type: ignore
        home = Path(get_env("RHODAWK_HOME", str(Path.home() / ".rhodawk"))).expanduser()
        caps = home / "capabilities.json"
        if caps.is_file():
            import json as _json
            p = _json.loads(caps.read_text(encoding="utf-8")).get("chromium_path", "")
            if p and Path(p).is_file():
                return p
    except Exception:
        pass
    return None


def _safe_to_submit(button) -> bool:
    """True when the button's enclosing form has NO password field (we never
    submit credentials, even placeholders)."""
    try:
        return not button.evaluate(
            "el => { const f = el.closest('form');"
            " return !!(f && f.querySelector('input[type=password]')); }")
    except Exception:
        return False


def crawl(seeds: list[str], checker: ScopeChecker, *,
          max_pages: int = 10, timeout_secs: float = 120.0,
          headers: list[str] | None = None, chromium_path: str | None = None
          ) -> tuple[list[str], list[str], dict]:
    """Run the browser crawl. Returns (endpoints, dropped_oos, summary).

    Import/launch failures raise PlaywrightUnavailable — the caller converts
    that into a skipped summary (graceful degradation)."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError as exc:
        raise PlaywrightUnavailable(f"playwright not installed: {exc}") from exc

    captured: set[str] = set()
    visited = 0
    started = time.time()
    extra_headers = {}
    for h in headers or []:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    def _remaining() -> float:
        return max(0.0, timeout_secs - (time.time() - started))

    with sync_playwright() as p:
        try:
            launch_kwargs: dict = {"headless": True, "args": ["--no-sandbox"]}
            exe = _resolve_chromium_path(chromium_path)
            if exe:
                launch_kwargs["executable_path"] = exe
            browser = p.chromium.launch(**launch_kwargs)
        except Exception as exc:
            raise PlaywrightUnavailable(f"chromium unavailable: {exc}") from exc
        try:
            context = browser.new_context(
                user_agent="rhodawk-js-crawl/1.0 (+authorized recon; scope-gated)",
                extra_http_headers=extra_headers or None,
            )
            queue: list[str] = []
            for s in seeds:
                if len(queue) >= max_pages:
                    break
                if checker.is_in_scope(s):
                    queue.append(s)
                # out-of-scope seeds: silently not queued (engine pre-checks
                # and audits them; the summary reports what was skipped)

            while queue and visited < max_pages and _remaining() > 1.0:
                url = queue.pop(0)
                if not checker.is_in_scope(url):
                    continue
                page = context.new_page()
                page.on("request", lambda req: captured.add(req.url))
                per_page = min(PER_PAGE_TIMEOUT_CAP, max(1.0, _remaining()))
                try:
                    page.goto(url, wait_until="domcontentloaded",
                              timeout=int(per_page * 1000))
                    try:
                        page.wait_for_load_state("networkidle",
                                                 timeout=int(min(6, per_page) * 1000))
                    except Exception:
                        pass  # networkidle is best-effort on chatty apps
                    visited += 1

                    # Interaction pass: fill visible text inputs with the
                    # inert placeholder (never password fields).
                    try:
                        for box in page.query_selector_all(
                                "input[type=text], input[type=email], "
                                "input[type=search], textarea")[:10]:
                            if box.is_visible():
                                try:
                                    box.fill(PLACEHOLDER_TEXT, timeout=1000)
                                except Exception:
                                    pass
                    except Exception:
                        pass

                    # Click visible buttons/submit controls whose form has no
                    # password field, waiting briefly for the network after each.
                    clicks = 0
                    try:
                        for btn in page.query_selector_all(
                                "button, [role=button], input[type=submit]"):
                            if clicks >= MAX_CLICKS_PER_PAGE:
                                break
                            if btn.is_visible() and _safe_to_submit(btn):
                                try:
                                    btn.click(timeout=1000)
                                    clicks += 1
                                    try:
                                        page.wait_for_load_state(
                                            "networkidle", timeout=2000)
                                    except Exception:
                                        pass
                                except Exception:
                                    pass
                    except Exception:
                        pass

                    # Queue same-origin links within the page budget.
                    try:
                        hrefs = page.eval_on_selector_all(
                            "a[href]",
                            "els => els.map(e => e.href)")
                        origin = urlsplit(url).netloc
                        for h in hrefs or []:
                            if len(queue) >= max_pages:
                                break
                            if h and h.startswith("http") and \
                                    urlsplit(h).netloc == origin and \
                                    h not in queue:
                                queue.append(h)
                    except Exception:
                        pass
                except Exception:
                    pass  # navigation failure on one seed: try the next
                finally:
                    try:
                        page.close()
                    except Exception:
                        pass
        finally:
            browser.close()

    duration = time.time() - started
    endpoints, dropped = filter_in_scope(sorted(captured), checker)
    summary = {
        "status": "ok",
        "pages_visited": visited,
        "requests_captured": len(captured),
        "endpoints_found": len(endpoints),
        "duration_secs": round(duration, 2),
    }
    return endpoints, dropped, summary


class PlaywrightUnavailable(Exception):
    """Playwright package or Chromium build missing — graceful-skip condition."""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _env_auth_headers() -> list[str]:
    """RHODAWK_AUTH_HEADERS env (newline-separated 'Name: value') → header list.
    Same filtering contract as tools/_auth_helper.sh: skip empty/commented
    entries and anything containing CR."""
    raw = os.environ.get("RHODAWK_AUTH_HEADERS", "")
    out: list[str] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "\r" in line:
            continue
        if ":" in line:
            out.append(line)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="js_crawl.py",
        description="Headless JS crawl phase (opt-in; scope-gated, fail-closed)")
    ap.add_argument("--url", action="append", default=[],
                    help="seed URL to load (repeatable)")
    ap.add_argument("--recon-dir", required=True,
                    help="recon output dir for this target")
    ap.add_argument("--manifest", default=None,
                    help="compiled_scope.json (SHA-256 verified) — the scope authority")
    ap.add_argument("--domain", action="append", default=[],
                    help="in-scope pattern (repeatable or comma-separated)")
    ap.add_argument("--scope-exclude", action="append", default=[],
                    help="out-of-scope pattern (repeatable or comma-separated)")
    ap.add_argument("--max-pages", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="total crawl budget in seconds")
    ap.add_argument("--header", action="append", default=[],
                    help="extra HTTP header 'Name: value' (repeatable)")
    ap.add_argument("--chromium", default=None,
                    help="explicit Chromium executable path (else capabilities.json / bundled)")
    args = ap.parse_args(argv)

    recon_dir = Path(args.recon_dir)
    t0 = time.time()

    # 1. Scope authority — refuse scope-less (fail-closed).
    try:
        checker = resolve_scope(args.manifest, args.domain, args.scope_exclude)
    except ScopeRefusal as exc:
        write_outputs(recon_dir, [], [], skipped_summary(str(exc), time.time() - t0))
        print(f"[!] js-crawl refused: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:  # tampered manifest
        write_outputs(recon_dir, [], [],
                      {"status": "failed", "pages_visited": 0,
                       "requests_captured": 0, "endpoints_found": 0,
                       "duration_secs": round(time.time() - t0, 2),
                       "reason": f"manifest integrity: {exc}"})
        print(f"[!] js-crawl blocked: {exc}", file=sys.stderr)
        return 3

    if not args.url:
        write_outputs(recon_dir, [], [], skipped_summary(
            "no seed URLs (no live hosts?)", time.time() - t0))
        return 0

    # 2. Crawl (graceful degradation on missing playwright/chromium).
    headers = _env_auth_headers() + list(args.header)
    try:
        endpoints, dropped, summary = crawl(
            args.url, checker, max_pages=args.max_pages,
            timeout_secs=args.timeout, headers=headers,
            chromium_path=args.chromium)
    except PlaywrightUnavailable as exc:
        summary = skipped_summary(str(exc), time.time() - t0)
        endpoints, dropped = [], []
        print(f"[!] Headless JS crawl skipped: {summary['reason']}", file=sys.stderr)

    write_outputs(recon_dir, endpoints, dropped, summary)
    print(f"[js-crawl] status={summary['status']} "
          f"pages={summary['pages_visited']} "
          f"endpoints={summary.get('endpoints_found', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
