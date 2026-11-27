# CRAWLER-REDESIGN.md — Headless JS Crawl Phase (opt-in)

**Status:** Implemented in this branch (Phase 5.75, `--js-crawl`, opt-in).
**Author:** fix/verified-defects-and-headless-crawl branch.
**Related defects:** "Static crawler returns 0 API endpoints against a JS-rendered
SPA" — verified against a local SPA fixture on this HEAD: `recon_truth.json`
reported `unique_urls: 0, js_endpoints: 0` while the app served three live
runtime API routes (`/api/v2/session`, `/api/v2/user/4242`,
`/api/internal/admin/ping`) that exist nowhere in the HTML source and are only
constructed at runtime by JavaScript. Static fetch/regex (Phase 5) and static
crawlers (katana in existing installs) cannot see endpoints that only exist
once a browser executes the app's JS.

## 1. Problem

Every existing URL-collection path in the pipeline (Phase 4 katana/gau/wayback,
Phase 5 regex-over-JS, Phase 5.5 reconFTW gap-fill, Phase 6 ffuf) operates on
**static** text. Modern SPAs build their API surface at runtime: routes are
concatenated from config objects, fetched via `fetch()`/XHR after hydration,
and gated behind client-side routing. Result: the most interesting endpoints of
an SPA target are invisible to `recon_truth.json`, and every downstream stage
(prioritized surface, hypothesis hunt, validate, report) inherits the blind
spot.

## 2. Design goals

1. **Real browser, real network truth.** Load the target in headless Chromium
   via **Playwright** (preferred over Puppeteer: better network-interception
   API — `page.on("request")` gives every XHR/fetch with resource type, method
   and URL without CDP plumbing).
2. **Same schema, zero downstream changes.** Output lands in the artifacts
   `recon_fusion.py` already ingests, so `recon_truth.json`, `delta.json`,
   `rhodawk_prioritized_surface`, hunt, validate and report need **no changes**.
3. **Same fail-closed scope contract.** The phase is *not* exempt from the
   scope-manifest gate: seeds are pre-checked by the engine before any browser
   launch, captured URLs are dropped through the same B3 scope filter as every
   other source, and blocks are audited exactly like the rest of the pipeline.
4. **Opt-in first.** `--js-crawl` flag on `rhodawk recon` / `rhodawk hunt` and
   the engine script. Off by default until proven not to regress recon
   speed/reliability on non-SPA targets (adds no packets when off).
5. **Graceful degradation.** Missing Playwright or Chromium is a **WARN + skip
   with an artifact trail** — never a hard failure, never a doctor FAIL.

## 3. Phase slot and pipeline position

**Phase 5.75 — Headless JS Crawl (opt-in).**

```
Phase 5   JS static analysis (js/endpoints.txt, js/potential_secrets.txt)
Phase 5.5 reconFTW web/JS/TLS gap-fill (merge into urls/all.txt)
Phase 5.75  ← THIS PHASE (headless crawl; new urls merged before B3)
B3 filter point 4/4 (scope-filter of the merged URL corpus — unchanged)
Phase 6   Directory fuzzing (ffuf) — now sees crawled API paths too
```

Placing it **after 5.5 and before the B3 filter point 4/4** means:
- crawled URLs are scope-filtered by the *same* `_rhodawk_scope_filter` call
  that already guards the merged corpus (no second filter implementation);
- Phase 6 fuzzing and the candidate classifiers see the crawled endpoints;
- non-SPA targets are unaffected when the flag is off (the phase block is
  entirely behind `JS_CRAWL=1`).

## 4. What it reads

| Input | Source | Purpose |
|---|---|---|
| Seed URLs | `recon/<host>/live/urls.txt` (top N, default 10, http/https only) | pages to load in the browser |
| Extra seeds | `recon/<host>/urls/all.txt` same-origin entries (up to `--max-pages` total) | deeper pages when live probing found few hosts |
| Scope authority | `--manifest <compiled_scope.json>` **or** `--domain <pattern>` (repeatable), forwarded from the engine's resolved scope | pre-launch check + capture-time filtering |
| Auth headers | `RHODAWK_AUTH_ARGS` (via env → `--header`, repeatable) | replay the operator's authenticated session |
| Chromium path | `~/.rhodawk/capabilities.json` `chromium_path` → else Playwright-bundled Chromium | browser executable resolution |

## 5. What it writes

| Artifact | Contents | Consumer |
|---|---|---|
| `recon/<host>/js_crawl/endpoints.txt` | every XHR/fetch/document request URL observed during load + interaction (absolute, deduped, sorted) | `recon_fusion.py` (new source, provenance `js_crawl/endpoints.txt`) → `urls[]` and `js_endpoints[]` of `recon_truth.json` |
| `recon/<host>/js_crawl/summary.json` | `{status: ok|skipped|failed, pages_visited, requests_captured, endpoints_found, duration_secs, reason?}` | humans + tests; `skipped` records the degradation reason |
| `recon/<host>/js_crawl/dropped_oos.txt` | out-of-scope URLs dropped at capture time (defense in depth) | audit trail |

`recon_fusion.py` change (additive, schema-preserving):
`js_crawl/endpoints.txt` joins `url_sources` with
`discovered_by: ["js_crawl/endpoints.txt"]`; API-looking paths (`/api/…`,
`/v1/…`, `/v2/…`, `/rest/…`, `/graphql`) additionally surface in
`js_endpoints[]` with the same provenance. `counts.unique_urls` /
`counts.js_endpoints` update automatically; **no schema fields are added or
removed** and no downstream code changes.

## 6. Crawler behavior (`rhodawk/tools/js_crawl.py`)

1. Resolve scope: manifest (hash-verified) or explicit patterns. Without
   either, refuse with a clear error — the engine passes its resolved scope,
   and `--no-scope-check` on the engine side skips the phase entirely (crawl
   opt-in without scope = opt-out, consistent with the engine's contract).
2. Launch Chromium headless (`--no-sandbox` for containers), one context,
   `ignore_https_errors=False` (Rhodawk never disables TLS verification).
3. For each seed (≤ `--max-pages`, default 10, ≤ `--timeout` total budget,
   default 120 s):
   - pre-check the URL against the resolved scope (`ScopeChecker.is_in_scope`);
     out-of-scope seeds are dropped and audited, never loaded;
   - `page.goto(url, wait_until="networkidle")` with a per-page cap;
   - record every request via `page.on("request")` (all methods);
   - scripted interaction pass: click visible `<button>`/`role=button`
     elements and text inputs' submit buttons (≤ 10 per page), fill visible
     text/email/search inputs with the inert placeholder
     `rhodawk-recon-crawl@example.invalid` (never password fields — no
     credential submission, never `type=submit` inside a form containing a
     password field), then wait briefly for the network to settle;
   - same-origin links discovered are queued for visiting (breadth ≤ max-pages).
4. Dedupe + sort captured URLs; drop any that fail the scope check at capture
   time (quarantined to `dropped_oos.txt`); write `endpoints.txt` +
   `summary.json`.

## 7. Degradation matrix

| Condition | Behavior |
|---|---|
| `playwright` package not importable | `summary.json {status:"skipped", reason:"playwright not installed"}`; engine logs `[!] Headless JS crawl skipped: playwright not installed (pip install playwright)`; exit 0; **no doctor change** |
| Chromium not launchable (no bundled build, no `chromium_path`) | same as above with `reason:"chromium unavailable"` |
| Page timeout / navigation error | record, continue with remaining seeds |
| Playwright raises mid-run | partial endpoints already captured are still written; status `failed` with the error string; engine continues |
| `--js-crawl` not passed | phase block never runs — zero packets, zero behavior change |

`doctor` already treats managed Chromium as an optional WARN; it stays that
way. No new doctor check is added.

## 8. Security posture

- The phase inherits the engine's pre-flight gate (a tampered/missing manifest
  still exits 3 before any probe, including this one).
- Seeds and captured URLs are checked against the *same* verified manifest —
  a response body cannot widen scope (kernel.md §2 applies to captured data).
- TLS verification is never disabled in the browser context.
- No credential submission (password fields are never filled; forms containing
  password fields are never submitted).
- All outbound browser traffic targets in-scope origins only (out-of-scope
  navigation targets are not followed; iframes/redirects to out-of-scope
  origins are recorded in `dropped_oos.txt`, not visited).

## 9. Tests (red-to-green)

- `tests/test_js_crawl.py::test_scope_refusal_without_scope` — no manifest/patterns ⇒ refusal (fail-closed).
- `tests/test_js_crawl.py::test_out_of_scope_seed_never_loaded` — with patterns, an OOS seed is dropped, never visited (verified via summary counters, no network).
- `tests/test_js_crawl.py::test_degradation_skips_cleanly` — monkeypatched import failure ⇒ `status:"skipped"`, exit 0, endpoints file absent.
- `tests/test_js_crawl.py::test_capture_and_output` — pure helpers: captured URL list → dedup/sort/drop-oos → files (deterministic, no browser).
- `tests/test_js_crawl.py::test_spa_endpoints_discovered_end_to_end` — **real browser** against a local SPA fixture (`http.server` page whose JS fetches 3 runtime API routes); skipped when Playwright/Chromium is unavailable (CI-safe). Asserts the 3 routes appear in `endpoints.txt`.
- `tests/test_recon_fusion.py` additions — `js_crawl/endpoints.txt` fixture flows into `recon_truth.json` (`urls[]` + `js_endpoints[]`, provenance preserved, counts updated).
- `tests/test_recon_engine_js_crawl.py` — engine wiring: `--js-crawl` reaches `recon_engine.sh` (`JS_CRAWL=1`), Phase 5.75 block runs `js_crawl.py` with the resolved scope and passes its output through `_rhodawk_scope_filter`; absent flag ⇒ block inert (grep-level shell contract tests, matching the repo's existing shell-test style).
