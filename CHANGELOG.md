# Changelog

All notable changes to RhodawkAI Bounty Hunter are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: SemVer.

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
