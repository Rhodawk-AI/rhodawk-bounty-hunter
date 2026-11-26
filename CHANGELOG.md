# Changelog

All notable changes to RhodawkAI Bounty Hunter are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: SemVer.

## [2.0.4] — 2026-11-26

Live-sandbox fixes: three bugs observed running v2.0.3 in a fresh sandbox.

### Fixed

- **recon: `.run_incomplete` directory race.** The B6 marker
  (`touch "$RECON_DIR/.run_incomplete"`) ran before the recon directory
  existed on a brand-new target — live failure: `touch: cannot touch
  '/sandbox/home/.rhodawk/recon/target.local/.run_incomplete': No such file
  or directory`. `recon_engine.sh` now runs `mkdir -p "$RECON_DIR"`
  immediately before the touch; the `.prev_run` rotation of a leftover
  incomplete run is unchanged.
- **recon: ffuf soft-200 false-positive flood.** SPA targets (Angular, OWASP
  Juice Shop) answer every nonexistent route with HTTP 200 and a constant
  body (e.g. Size: 9831 / Words: 468 / Lines: 34), flooding ffuf with 100%
  false positives until timeout. The Phase 6 ffuf invocation now passes
  `-ac` (auto-calibration) so catch-all responses are filtered; scope,
  rate-limit, header and output flags are unchanged.
- **mcp: `rhodawk mcp doctor` stale CWD-relative memory path.** Doctor still
  reported `RHODAWK_MEMORY_DIR=hunt-memory exists=False` after v2.0.3
  unified adapters onto the data home. It now resolves through
  `adapters._memory_root()` (explicit `RHODAWK_MEMORY_DIR` wins, else
  `$RHODAWK_HOME`/`~/.rhodawk` + `hunt-memory`), reporting the exact path
  the runtime reads and writes.

## [2.0.3] — 2026-11-26

Pre-launch audit fixes: one state root for every runtime, data-home auto
validation, OAuth compat, and honest launch documentation.

### Fixed — one state root (pre-launch audit G1)

- `mcp/rhodawk-mcp/adapters.py` rooted all runtime reads/writes at the package
  install tree (`REPO/recon`, `REPO/findings`, `REPO/reports`) while the CLI,
  agent and shell runtimes write under `$RHODAWK_HOME`. MCP tools now resolve
  `recon/`, `findings/`, `reports/`, `recon_truth.json` and `RECON_OUT_DIR`
  through `_data_home()` (mirrors `engine._data_home()`), so CLI-generated
  artifacts are visible to `rhodawk_attack_surface`, `rhodawk_subdomains`,
  `rhodawk_list_findings`, `rhodawk_get_report` and
  `rhodawk_prioritized_surface`, and MCP-run reconFTW results land where
  `recon_fusion.py` and `brain.py` read them. `REPO` remains the CODE root
  (scripts, tools, mcp servers).
- `rhodawk_get_finding` in `mcp/rhodawk-mcp/server.py` resolved artifact paths
  against the install tree too; it now resolves under the data home (with the
  same containment guarantee, via a parents-based check instead of a string
  prefix).

### Fixed — MCP memory reads (G2)

- `memory_patterns` / `memory_search` defaulted to a CWD-relative
  `"hunt-memory"` directory the writers never populate. They now resolve
  through `_memory_root()`: explicit `$RHODAWK_MEMORY_DIR` wins, else
  `$RHODAWK_HOME/hunt-memory` — matching `memory/hunt_journal.py
  ::default_memory_root()`.

### Fixed — `validate --auto` output path (G3)

- The `--auto` default output dir was package-relative
  (`<site-packages>/rhodawk/findings/auto-<ts>`), so a global pipx install
  wrote runtime findings into site-packages. It now defaults to
  `<RHODAWK_HOME>/findings/auto-<ts>` via `_default_auto_out_dir()`.

### Fixed — legacy OAuth env compat (G18)

- `RHODAWK_GOOGLE_CLIENT_ID` / `RHODAWK_GOOGLE_CLIENT_SECRET` were read with
  plain `os.environ.get`, silently dropping the pre-2.0
  `BUGHUNTER_GOOGLE_CLIENT_ID` / `_SECRET` overrides. They now resolve through
  `_compat.get_env` like every other `RHODAWK_*` variable.

### Changed — docs (G16 + launch blueprint)

- `BENCHMARKS.md`: edition labels reconciled to the release line
  (`v6.1.1`/`v2.0.0` → `v2.0.3`) and "Original Rhodawk" renamed to "Upstream
  Agentic-Bug-Hunter" so fork reviewers are not confused.
- `README.md`: honest platform coverage (scope compilation is HackerOne-only;
  Bugcrowd/Intigriti/YesWeHack are vault rows; any scope pinnable via
  `--scope-domain`), a "What Changed from Upstream" comparison table, the
  Security Architecture split into code-enforced vs LLM-assisted boundaries,
  npm-wrapper/toolchain/no-Docker install reality, and a new Honest
  Limitations & Responsible Use section.

## [Unreleased]

Release-audit Sprint 1 — P0 hardening (security review of the v2.0.0
standalone tree). All findings carry their audit IDs.

### Fixed — runtime artifacts and wheel pollution (R-01)

- Output-home resolution no longer falls back to the install directory:
  `engine._data_home()`, `hunt._bh_home()`, `rtw_adapter._default_recon_dir()`
  and the memory modules resolve `$RHODAWK_HOME` → `~/.rhodawk` and never the
  package directory. A plain `pytest` run (or a hunt from a git clone) used to
  write `recon/`, `findings/`, `hunt-memory/` INTO the source tree.
- `tests/conftest.py` pins `RHODAWK_HOME`, `RECON_OUT_DIR` and `XDG_DATA_HOME`
  into `tmp_path` for every test (autouse).
- Packaging: `MANIFEST.in` prunes runtime directories; the `**/*` package-data
  wildcard is replaced by explicit data subtrees; new
  `tests/test_wheel_cleanliness.py` + `tests/check_wheel_clean.py` gate (also
  a CI step) asserts a built wheel contains zero runtime artifacts.

### Fixed — dependencies (R-03)

- `requirements.txt` is runtime-only; `pytest` moved to the new
  `requirements-dev.txt` (with `build`), and CI installs the dev set.

### Fixed — release identity (R-02, R-10, R-24)

- Console entry points (`rhodawk`, `rhodawk-agent`) are regression-tested to
  exist and resolve.
- Version parity test across pyproject / `__init__.py` / `plugin.json` /
  npm `package.json` (all 2.0.0); SECURITY.md supported-versions table now
  tracks 2.x.
- Issue templates no longer declare an organization login as assignee.

### Fixed — TLS (R-04)

- `_spray_http_form.py` mirrors `_spray_oauth.py`: on missing certifi it
  falls back to the verifying system-CA context instead of disabling
  verification; it joins the TLS regression scan list.

### Fixed — secret handling (R-08, R-09, R-14, L-10)

- `h1_run.sh`: `set -euo pipefail`; tokens come from `RHODAWK_H1_TOKEN_A/B`
  env vars or a 0600 token file; curl auth headers go through 0600 temp files
  (no token on argv); scanners read tokens from the environment; no token
  material (not even prefixes) reaches stdout or the scan log; findings land
  in the data home.
- `graphql_audit.sh` banner prints `cookie set` / `header set` / `(none)`
  instead of the raw credential values.
- `credentials.write_env_file` and `google_oauth._save_json_secure` write
  atomically via a 0600 temp file + `os.replace` — pre-existing loose files
  can no longer hold fresh secrets, and the swallowed chmod failure is gone.
- Credential values containing CR/LF are rejected (newline could inject an
  extra `KEY=` line into the .env vault).

### Fixed — shell/python injection (R-15)

- All seven `python3 -c` call sites that interpolated shell variables into
  the Python source (secrets_hunter, takeover_scanner, cve_scan,
  param_discovery, osint_employees, full_hunt ×2, vuln_scanner) now pass
  values as `sys.argv` arguments; a regression gate bans the pattern.

### Fixed — paths and wiring (R-12, R-13)

- `.claude/settings.json` Stop hook and every doc/docstring referencing
  `python3 -m tools.…` now use `python3 -m rhodawk.tools.…` (the old module
  path stopped resolving after the package rename).
- `install_tools.sh --with-cicd-scanner` and `tests/test_cicd_scanner.sh`
  point at `rhodawk/tools/cicd_scanner.sh` (the path they referenced never
  existed in this repo); the shell suite is wired into pytest via
  `tests/test_shell_test_suites.py` so it runs in CI.

## [2.0.1] — 2026-11-26

Polish pass for global (pipx / npm / npx) installs: the CLI must never speak
in repo-checkout terms, doctor fixes must work from any directory, and the
release gate must cover sdists.

### Fixed — CLI help identity (prog names + examples)

- `rhodawk --help` now prints `usage: rhodawk ...` (top-level parser
  `prog="rhodawk"`) and every epilog example uses `rhodawk setup` /
  `rhodawk recon target.com` instead of `./engine.py ...` — pipx and npx
  users have no `engine.py` file to run.
- `rhodawk-agent --help` now prints `usage: rhodawk-agent ...` and its
  examples read `rhodawk-agent --target ...` instead of
  `python3 agent.py --target ...`.
- Runtime error hints in `engine.py` ("Run: ./engine.py setup",
  "./engine.py providers", ...) use the installed `rhodawk` command.

### Fixed — doctor fix hints are location-independent

- All `fix:` lines emitted by `rhodawk doctor` that pointed at repo-relative
  paths now work from any working directory:
  `python3 rhodawk/tools/credentials.py --setup|--verify` became
  `python3 -m rhodawk.tools.credentials --setup|--verify`,
  `python3 rhodawk/engine.py setup` became `rhodawk setup`, and the MCP hint
  became `rhodawk mcp doctor`.
- Repo-only scripts (`install.sh`, `install_tools.sh`) are now explicitly
  labeled `# repo checkout` so users on pipx/npm installs are not sent
  hunting for files they do not have.
- The credential vault header and module docstring advertise the
  module-invocable form too.

### Fixed — scope-compile H1 credential auto-load + silent-fallback warning

- `rhodawk scope-compile` loads the credential vault
  (`credentials.load_credentials()`: `$RHODAWK_CREDENTIALS_FILE` ->
  `~/.rhodawk/.env` -> `/root/.secrets/h1_api`) BEFORE checking
  `H1_USERNAME` / `H1_API_TOKEN`, and gains a second-chance loader for
  relocated data homes: `$RHODAWK_HOME/.env`.
- The authenticated-REST path now accepts the combined `H1_TOKEN=user:token`
  form directly (plus the bare-token form), so a vault that only recorded
  `H1_TOKEN` still drives authenticated mode instead of dropping to
  `keyless_public` (GraphQL).
- When authenticated REST fails (HTTP 401/403/404/...) and the compiler
  falls back to public sources, the CLI prints a one-line warning carrying
  the redacted reason (HTTP status code, never the token); the manifest
  summary records it as `auth_fallback_reason` too.

### Fixed — sdist coverage in the wheel-cleanliness gate

- `tests/check_wheel_clean.py` inspects `.tar.gz` / `.tgz` sdists via
  `tarfile.open(..., "r:gz")` alongside `.whl` / `.zip` via
  `zipfile.ZipFile`, so `python3 tests/check_wheel_clean.py dist/*` checks
  wheel AND sdist in one pass instead of crashing with
  `zipfile.BadZipFile` on the sdist (its usage line already advertised
  `<wheel-or-sdist>`).
- The memory-stray detector now handles the versioned top-level directory of
  an sdist (`rhodawk-2.0.1/rhodawk/memory/...`), and unreadable archives are
  reported as `ERROR:` lines instead of tracebacks.

### Changed — version

- 2.0.0 -> 2.0.1 across `pyproject.toml`, `rhodawk/__init__.py`,
  `.claude-plugin/plugin.json` and `npm/package.json`
  (`@rhodawkai/bounty-hunter` stays aligned with `npm/README.md`).

## [2.0.0] — 2026-11-25

Initial **standalone** release of **RhodawkAI Bounty Hunter** — the first
version published as its own product (`rhodawk-bounty-hunter`), with its own
package identities, its own data home, and zero upstream sponsor wiring.

### Added

- **MIT attribution layer** — root and `npm/` `NOTICE` files crediting the
  upstream framework; LICENSE carries both copyright lines.
- **Environment compat shim** — `rhodawk/_compat.py` with `get_env()`:
  `RHODAWK_*` variables are read first, pre-2.0 spellings are honored with a
  one-line stderr deprecation notice; `ensure_home_migrated()` performs the
  one-time migration of the pre-2.0 data home to `~/.rhodawk` (chmod
  `0700`/`0600` re-enforced after the move). `install.sh` performs the same
  migration in shell form.
- **Go module identity** — `go.mod` pins
  `github.com/Rhodawk-AI/rhodawk-bounty-hunter` for GitHub's dependency graph.

### Changed

- **Package identities** — PyPI `rhodawk-bounty-hunter` v2.0.0
  (console scripts `rhodawk` / `rhodawk-agent`), npm `@rhodawk-ai/bounty-hunter`
  v2.0.0 (single `rhodawk` bin), Claude plugin `rhodawk-bounty-hunter` v2.0.0.
- **Python package layout** — the legacy package directory moved to `rhodawk/`;
  the MCP server directory and its config key moved to the rhodawk namespace;
  all 29 MCP tool functions and the policy allowlist keys now carry the
  `rhodawk_*` prefix; PreToolUse matchers and the hook command path were
  updated atomically with the server key (`rhodawk`).
- **Environment variable families collapsed** — every pre-2.0 variable family
  (the long package-prefix family and the short BB-derived families) unified
  into `RHODAWK_*` across Python and Bash; shell helper prefixes moved to the
  `_rhodawk_*` form; the demo-lab quiet flag renamed to `DEMO_LAB_QUIET`.
- **Data home** — the pre-2.0 data home moved to `~/.rhodawk/` everywhere
  (vault, config, capabilities, OAuth, audit, workspace), with automatic
  one-time migration.
- **Demo lab rebrand** — the local vulnerable demo target is now
  `demo-lab.rhodawkai.test` (was a personal-domain lookalike) across
  `demo/`, `rhodawk/serve.py`, docs, benchmarks, and issue templates.
- **Visual identity** — block-letter banners regenerated with the rhodawk
  wordmark (`rhodawk/tools/banner.py`, `banner.sh`, engine startup banner);
  tag line set to `rhodawkai.com · github.com/Rhodawk-AI/rhodawk-bounty-hunter`.
- **Project site** — upstream Product Hunt widget and `.fun` domain removed;
  clone/install commands and footer updated to the new repository.
- **CI** — `.github/workflows/ci.yml` cleaned: script paths fixed and stale
  comments referencing the retired `docs/` workflow template removed;
  `docs/workflow-ci.yml` deleted (single source of truth in `.github/`).

### Removed

- **Sponsor-gateway LLM provider** — the third-party multi-model gateway that
  shipped in pre-2.0 releases was removed end to end: provider branch, env
  mapping, setup-menu entry, model catalog, config example entry, and its
  tests. The supported provider set is unchanged otherwise.
- **Dead weight** — `BUILD-MANIFEST.txt`, the eight upstream phase-validation
  dev diaries (`docs/phase1-…` – `docs/phase10-…`), the duplicate docs
  workflow template, and upstream sponsor/funding artwork references.

### Security

- No change to the core guarantees: `chmod 600 ~/.rhodawk/.env` credential
  vault, paginated SHA-256-verified `CompiledScopeManifest`, pre-probe dnsx
  3rd-party SaaS CNAME quarantine, fail-closed `ScopeChecker`, deterministic
  `PreToolUse` scope hooks, and `<untrusted_target_data>` isolation all remain
  in force and are covered by the test suite (1,482 tests green at release).
