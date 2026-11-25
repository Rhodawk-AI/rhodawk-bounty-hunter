# Changelog

All notable changes to RhodawkAI Bounty Hunter are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: SemVer.

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
