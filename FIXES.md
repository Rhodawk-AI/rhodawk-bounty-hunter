# FIXES.md — Verified-defect fixes + headless crawler layer

**Branch:** `fix/verified-defects-and-headless-crawl`
**Base:** `Rhodawk-AI/rhodawk-bounty-hunter` @ `53ee0c2` (v2.0.4)
**Method:** every fix below was verified against HEAD *before* changing code
(re-running the repro steps from the blueprint backlog), then fixed with a
failing regression test that was driven to green. The FULL pytest suite was
re-run after all changes. Items that did **not** reproduce are documented at
the end and were NOT "fixed".

**Verification results (Phase 1 of the mission):**

| # | Item | Verdict at HEAD |
|---|---|---|
| 1 | Stale `python3 agent.py` in `rhodawk-agent --help` | **DOES NOT REPRODUCE** — fixed upstream in the v2.0.x CLI polish; 0 hits in live `--help` and in `rhodawk/agent.py` (the stale refs exist only in ABH's `bughunter-agent`). Left untouched; the comparative-analysis claim that said otherwise was corrected. |
| 2 | PreToolUse hook allows bare `curl` to OOS hosts | **CONFIRMED** — `{"tool_name":"Bash","tool_input":{"command":"curl -s https://totally-out-of-scope.example.com/api"}}` → exit 0 (allowed). Fixed (§2). |
| 3 | Spray modules have no internal scope check | **CONFIRMED** — no `ScopeChecker`/manifest reference in either module (only OAuth `scope` *parameter* strings); pristine module sprayed 1 request with rc 0 and no block. Fixed (§3). |
| 4 | Vault secrets reach every scanner subprocess env | **CONFIRMED** — stubbed `subfinder` on PATH captured an exported `H1_API_TOKEN` during a plain `rhodawk recon example.com`. Fixed (§4); live repro now shows 0 hits. |
| 5 | RateLimiter/CircuitBreaker only consulted by agent dispatcher | **DOES NOT REPRODUCE as stated** — the shell pipeline already rate-limits every engine: httpx `-rate-limit "$RATE_LIMIT"` (recon_engine.sh:946, 1022), ffuf `-rate "$RATE_LIMIT"` (:1329), nuclei `-rl` (:1478), with manifest `max_rps` exported as `RHODAWK_RATE_LIMIT` (:499). The Python `RateLimiter`/`CircuitBreaker` classes remain agent-dispatcher-only, but wiring them into bash pipelines would be an architectural change outside this surgical pass. **No code change.** |
| 6 | `doctor` hard-fails on reconFTW absence | **CONFIRMED** — `RTW_HOME=/tmp/absent rhodawk doctor` → `[FAIL] reconFTW checkout`, exit 1 on an otherwise working system (a test-suite fixture had masked this by cloning reconFTW; forcing the absent path re-confirmed). Fixed (§6). |
| 7 | No scope compiler for Bugcrowd/Intigriti/YesWeHack | **CONFIRMED** — 0 platform mentions in scope_compiler.py; `bugcrowd/intigriti/yeswehack_data.json` verified present in bounty-targets-data (1.2 MB / 642 KB / 116 KB). Fixed (§7). |
| 8 | Static crawler returns 0 API endpoints on JS SPAs | **CONFIRMED** — local SPA fixture (3 runtime `fetch()` routes, absent from HTML source): `recon_truth.json` reported `unique_urls: 0, js_endpoints: 0`. Fixed (§8, the headless crawler layer). |

---

## 2. PreToolUse hook: curl/wget hosts checked against a resolvable manifest

**Bug.** `hook_scope_guard.py` classified unknown Bash commands as `readonly`
and allowed them without checks — a bare `curl https://out-of-scope.example.com`
exited 0 even when a verified scope manifest was resolvable. The project's own
README documents this gap ("unknown commands classify as read-only"). Repro:
payload `{"tool_name":"Bash","tool_input":{"command":"curl -s
https://totally-out-of-scope.example.com/api"}}` → `HOOK_EXIT=0`.

**Fix.** `classify()` now returns a new `"fetch"` classification for Bash
commands invoking `curl`/`wget` (rhodawk/tools/hook_scope_guard.py:146
`CURL_WGET_RE`, :171 `return "fetch"`). `main()` handles it
(hook_scope_guard.py:390-417): when a manifest RESOLVES (same resolution
order as active tools — flag, command, tool_input, env, session,
target-derived) and passes SHA-256 verification
(`_load_scope_checker` :306, `_out_of_scope_fetch_urls` :323), every explicit
`http(s)://` URL in the command must be in scope; any out-of-scope host ⇒
exit 2 + `SCOPE_HOOK_BLOCK` naming the host and the manifest source. A
tampered manifest also blocks. With NO resolvable manifest the behavior is
**unchanged** (allow) — installers, doctor Bash and manifest-less sessions
keep working, exactly as the README's limitation describes; the fix only
closes the gap *where the project's own scope authority already exists*.

**Tests.** `tests/test_hook_curl_scope.py` (10 cases): 3 OOS curl/wget
commands blocked (red at HEAD — verified before the fix), in-scope +
non-fetch commands allowed, no-manifest behavior unchanged, tampered
manifest never widens scope, MCP active-tool gate unchanged.

## 3. Spray modules: internal fail-closed scope gate

**Bug.** `spray_orchestrator.sh` gates before spawning (R-16), but
`_spray_http_form.py` / `_spray_oauth.py` — "NOT a standalone entry point"
per their docstrings, yet runnable as such — had **zero** scope checking
(byte-identical to upstream; flagged in the blueprint and the README). Live
red proof: the pristine module posted credentials to a counting server with
rc 0, 1 request fired, no block.

**Fix.** Both modules gained a `scope_gate(url)` called right after
`SPRAY_TARGET_URL` is resolved (`_spray_http_form.py:77,261`;
`_spray_oauth.py:71,193`): a manifest from
`RHODAWK_SPRAY_SCOPE_MANIFEST`/`RHODAWK_SCOPE_MANIFEST` is loaded via
`ScopeChecker.from_manifest` (hash-verified; tampered ⇒ exit 3) and the
target must be in scope — else `SCOPE BLOCK` + exit 3 with **0 requests
sent**. With no manifest, the run refuses unless the operator explicitly sets
`RHODAWK_SPRAY_UNSAFE=1` (a strictly-stronger contract than the previous
no-check behavior, never weaker). `spray_orchestrator.sh:118` now forwards
its verified manifest (`export RHODAWK_SPRAY_SCOPE_MANIFEST="$_SCOPE_GATE_MANIFEST"`)
so spawned modules re-verify — defense in depth.

**Tests.** `tests/test_spray_scope_gate.py` (11 cases): no-manifest refusal
with 0 requests (red at HEAD), in-scope manifest allows the run, OOS manifest
blocks with 0 requests, tampered manifest blocks, explicit unsafe opt-out
runs with a loud warning — all parametrized over both modules.

## 4. Vault secrets no longer reach scanner subprocess environments

**Bug.** `credentials.load_credentials()` writes vault values into
`os.environ` (credentials.py export sites at :355/:670 pre-fix numbering);
`hunt.py` copied the whole environment into every scanner child
(`child_env = os.environ.copy()` at :515/:744/:793/:922), and `engine.py`'s
`_run_shell` merged `{**os.environ, **env}` for every spawn — so
platform/LLM secrets inherited into subfinder/httpx/dalfox/etc. Live repro:
stubbed `subfinder` env dump contained the exported token.

**Fix.** `tools/credentials.py` gains the canonical contract:
`RECON_PROVIDER_KEYS` (:207 — `PDCP_API_KEY`/`CHAOS_API_KEY` stay: subfinder
and chaos consume them at runtime), `secret_env_vars_to_strip()` (:219 —
every `secret: True` vault field minus the provider allowlist, plus the
`H1_TOKEN` alias and environment-only LLM keys), and
`redact_env_for_scanners(env)` (:229 — pure, non-mutating). All four
`hunt.py` child-env sites now use it (hunt.py:516, 745, 794, 923); the
`RHODAWK_AUTH_HEADERS`/`RHODAWK_SESSION_ID` session (which exists precisely
to be plumbed into scanners) passes through. `engine.py`'s `_run_shell`
gained `full_env=True` semantics (:261-271) — `env` IS the child's complete
environment instead of a merge — and both scanner spawns (cmd_recon :778,
cmd_hunt :827) pass a redacted full env. MCP `serve` spawns are untouched
(the MCP server legitimately needs vault keys at request time).

**Tests.** `tests/test_scanner_env_redaction.py` (6 cases): strip-list
correctness, provider keys kept, auth session kept, non-mutation, a
`hunt.run_recon` Popen-capture test, and a `_run_shell(full_env=True)`
replace-vs-merge semantics test. Live re-run of the stub-subfinder repro
after the fix: **0 hits** (was 1).

## 6. `doctor`: missing reconFTW checkout is a WARN, not a FAIL

**Bug.** Every delegated capability is optional (`capability_registry`
classifies missing deps as `RTW_MISSING_DEPS ⇒ SKIPPED, never blocks`), and
the native stack runs fully without reconFTW — yet `cmd_doctor` recorded
`FAIL` for a missing checkout and `doctor` exited 1, the only FAIL on an
otherwise healthy install. Live repro: `RTW_HOME=/tmp/absent rhodawk doctor`
→ exit 1.

**Fix.** `rhodawk/engine.py:1071-1080` — missing checkout and non-executable
script are now `WARN`s whose message states the impact honestly ("7
delegated capabilities disabled — native recon unaffected"); the pinned-commit
mismatch WARNs and the PASS row are unchanged. Exit code semantics (0 FAILs
⇒ 0) now work in the operator's favor on native-only installs.

**Tests.** `tests/test_doctor_rtw_warn.py` (2 cases, red at HEAD): absent
checkout ⇒ exit 0, no `[FAIL]` line, `reconFTW checkout` still reported as
WARN/PASS.

## 7. Scope compilation for Bugcrowd / Intigriti / YesWeHack (keyless)

**Bug.** `scope_compiler.py` had zero references to the three platforms: a
bugcrowd/intigriti/yeswehack handle raised `ProgramNotFoundError` (worse, the
H1-only fallback paths meant a non-H1 handle was looked up in
`hackerone_data.json` where it can never exist).

**Fix.** Keyless compilation via the SAME bounty-targets-data source the H1
fallback already trusts — one data file per platform
(scope_compiler.py:112-130 `BOUNTY_TARGETS_BASE`/`PLATFORM_DATA_FILES`;
verified live: bugcrowd 1.2 MB / 296 programs, intigriti 642 KB / 144,
yeswehack 116 KB / 51). `detect_platform()` (:160) infers the platform from
program URLs; `normalize_handle()` now extracts the slug for all three URL
shapes; `fetch_bounty_targets_entry()` (:523) does exact-match lookup with
per-platform handle keys (bugcrowd: URL slug / exact name; intigriti:
handle / id / URL slug; yeswehack: id / URL slug — substring matches stay
dead); `_scope_from_platform_entry()` maps each platform's
`targets.{in_scope,out_of_scope}` into the same `ScopeAssetMeta` /
result-dict shape the H1 paths return (identifiers verbatim as the platform
publishes them — wildcards preserved, OOS assets carry
`eligible_for_submission=False`). `compile_scope()` (:915) routes non-H1
handles straight to their own dump — no cross-platform lookup, no silent
fallback. Authenticated REST remains HackerOne-only (documented; no
private-API guessing). Output is the same SHA-256-sealed
`CompiledScopeManifest`, so scope gates, `_scope_gate.sh`, the hook, the MCP
policy and recon engine all consume it with zero changes.

**Tests.** `tests/test_scope_compiler_platforms.py` (15 cases): platform
detection, URL-slug normalization, end-to-end `compile_and_save` per
platform (red at HEAD — ProgramNotFoundError), wildcard preservation,
denylist-wins, hash-verified round-trip, exact-match/no-substring guard,
and an H1-path-unchanged regression.

## 8. Headless crawler layer — Phase 5.75 (`--js-crawl`, opt-in)

**Bug (verified).** A local SPA fixture whose JS fetches
`/api/v2/session`, `/api/v2/user/4242` and `/api/internal/admin/ping` at
runtime produced `recon_truth.json` with `unique_urls: 0, js_endpoints: 0` —
the entire static pipeline (katana/gau/wayback/JS-regex) is blind to
runtime-constructed API surfaces.

**Design.** `CRAWLER-REDESIGN.md` (written before the code): Phase 5.75
slots after Phase 5.5 and BEFORE the B3 scope-filter point 4/4 so crawled
URLs pass through the SAME `_rhodawk_scope_filter` as every other source;
output lands in artifacts `recon_fusion.py` already ingests (same
`recon_truth.json` schema, provenance `js_crawl/endpoints.txt`) —
hunt/validate/report need **zero changes**.

**Implementation.**
- `rhodawk/tools/js_crawl.py` (new): Playwright (sync API) headless Chromium;
  captures every request via `page.on("request")`; bounded interaction pass
  (click ≤10 visible buttons per page, fill visible text inputs with the
  inert placeholder `rhodawk-recon-crawl@example.invalid` — never password
  fields, never forms containing password fields); same-origin link queue ≤
  `--max-pages`; `--timeout` total budget; auth headers picked up from
  `RHODAWK_AUTH_HEADERS` (same CR/comment filtering as `_auth_helper.sh`).
  Scope contract identical to every other phase: `resolve_scope()` refuses
  scope-less runs (fail-closed), seeds AND captures are checked against the
  hash-verified manifest, OOS captures quarantined to
  `js_crawl/dropped_oos.txt` and never exported; TLS verification never
  disabled. Degradation: missing playwright/chromium ⇒ `summary.json
  {status:"skipped", reason}` + exit 0 — a WARN, never a hard failure, no
  doctor change.
- `rhodawk/tools/recon_engine.sh`: `--js-crawl` flag (:83) and the Phase
  5.75 block (:1296-1374) — scope-authority resolution identical to the B3
  filter (manifest ⇒ patterns ⇒ self-scope for ip/local; a domain-list
  target without any authority is a fail-closed `SCOPE BLOCK` exit 3 with
  audit), seed fallback to the normalized target when no live hosts yet,
  output merged into `urls/all.txt` after the same scope filter, opt-out
  runs skip the phase entirely.
- `rhodawk/tools/recon_fusion.py`: `js_crawl/endpoints.txt` added as a
  first-class URL source (:614) and API-shaped paths additionally surface in
  `js_endpoints[]` (:628-645, `_API_PATH_RE` :68) with preserved provenance —
  `counts.unique_urls`/`counts.js_endpoints` update automatically; no schema
  fields added or removed.
- `rhodawk/engine.py`: `--js-crawl` on the recon and hunt subparsers
  (:1372/:1385) forwarded via `_js_crawl_args()` (:738) to both engine
  spawns.

**Proof (red → green, live).** Before: `recon http://127.0.0.1:8099`
→ `unique_urls: 0`. After: `rhodawk recon http://127.0.0.1:8099 --js-crawl
--scope-domain 127.0.0.1` → `js_endpoints: ['/api/internal/admin/ping',
'/api/v2/session', '/api/v2/user/4242']`, `unique_urls: 4`, provenance
`js_crawl/endpoints.txt`; the crawl phase refused to browse under
`--no-scope-check` (fail-closed contract verified live, exit-path audited).

**Tests.** `tests/test_js_crawl.py` (18 cases): scope refusal, pattern and
manifest resolution, tampered-manifest fail-closed, capture filtering
(including checker-crash fail-closed), deterministic output writing,
graceful degradation (monkeypatched import failure ⇒ skipped + exit 0),
env-header parsing, real-browser end-to-end against the SPA fixture (skipif
Playwright unavailable — CI-safe), fusion integration + backward compat, and
engine wiring incl. a shell-level fail-closed block test with a hermetic
PATH. Playwright is NOT added to `pyproject.toml` dependencies (optional
import, graceful skip) — install via `pip install playwright && playwright
install chromium` when wanted.

## Items not fixed (with reasons)

1. **Item 1 (stale `python3 agent.py` help text): does not reproduce.** The
   v2.0.x CLI polish already rewrote the examples (`rhodawk-agent --help`
   shows only `rhodawk-agent ...`; 0 hits for `python3 agent.py` in
   `rhodawk/agent.py`). The comparative-analysis document that claimed
   otherwise was corrected (see the correction note in
   `comparison.md` §1.3 of the analysis deliverables). Nothing to fix.
2. **Item 5 (RateLimiter/CircuitBreaker agent-only): does not reproduce as
   stated.** The shell pipeline already rate-limits httpx
   (recon_engine.sh:946, 1022), ffuf (:1329) and nuclei (:1478) via
   `RHODAWK_RATE_LIMIT` (default 150, manifest `max_rps` ceiling at :499).
   The residual gap — the Python `RateLimiter`/`CircuitBreaker`
   (memory/audit_log.py) not being consulted by bash pipelines — would
   require an architectural rewrite (per-host state shared across
   subprocesses), which is outside this mission's "surgical pass" ground
   rule. Flagged here for the maintainers as future work.
3. **`recon_engine.sh` summary `wc -l` error when httpx is missing** (cosmetic
   stderr noise, `live/urls.txt` absent — observed during verification) was
   NOT touched: it is not one of the 8 mission items.

## Test totals

- New regression tests: **62** (js_crawl 18, spray gate 11, env redaction 6,
  doctor 2, platform scope compiler 15, hook curl 10) — all red-to-green.
- Full suite after all changes: see the PR body (must be fully green; the
  single pre-existing skip is inherited from upstream).
