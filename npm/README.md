<div align="center">

# @rhodawkai/bounty-hunter

**npm CLI wrapper for [RhodawkAI Bounty Hunter](https://github.com/Rhodawk-AI/rhodawk-bounty-hunter) —
AI-powered bug bounty hunting, recon to report, in your terminal.**

[![npm](https://img.shields.io/npm/v/@rhodawkai/bounty-hunter?style=for-the-badge&logo=npm&logoColor=white&color=CB3837)](https://www.npmjs.com/package/@rhodawkai/bounty-hunter)
[![PyPI](https://img.shields.io/pypi/v/rhodawk-bounty-hunter?style=for-the-badge&logo=pypi&logoColor=white&color=3775A9)](https://pypi.org/project/rhodawk-bounty-hunter/)
[![CI](https://github.com/Rhodawk-AI/rhodawk-bounty-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/Rhodawk-AI/rhodawk-bounty-hunter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](https://github.com/Rhodawk-AI/rhodawk-bounty-hunter/blob/main/LICENSE)

</div>

---

## What is this package?

`@rhodawkai/bounty-hunter` is a thin, dependency-free Node.js launcher for the
Python package [`rhodawk-bounty-hunter`](https://pypi.org/project/rhodawk-bounty-hunter/).
It resolves and runs the `rhodawk` engine — fail-closed, CDN-aware autonomous
bug bounty reconnaissance and attack-surface prioritization — and falls back to
`uvx` / `pipx run` when the Python package is not installed yet.

## Install

```bash
# global install (recommended)
npm install -g @rhodawkai/bounty-hunter

# or run without installing
npx @rhodawkai/bounty-hunter doctor
```

The wrapper exposes a single binary: `rhodawk`.

1. If a real `rhodawk` is already on `PATH` (pipx / uv tool / source install),
   it is executed directly.
2. Otherwise the wrapper delegates to
   `uvx --from rhodawk-bounty-hunter rhodawk` when `uvx` is available, else to
   `pipx run --spec rhodawk-bounty-hunter rhodawk`. The wrapper's own install
   directory (e.g. npx's temporary `node_modules/.bin`) is stripped from the
   child `PATH`, so neither runner mistakes the wrapper itself for an
   installed `rhodawk` and no "already on your PATH" warning is printed.
3. If neither is possible, it prints install instructions for
   [uv](https://docs.astral.sh/uv/) / [pipx](https://pipx.pypa.io/) and the
   [PyPI package](https://pypi.org/project/rhodawk-bounty-hunter/).

## First run

```bash
rhodawk doctor          # fast environment diagnostic (PASS/WARN/FAIL)
rhodawk setup           # configure provider/model
rhodawk scope-compile <program-handle>   # compile the SHA-256 scope manifest
rhodawk recon <target>  # scoped, CDN-aware recon
```

The full CLI workflow, the agent slash commands, the MCP server, and the
security architecture (0600 `~/.rhodawk/.env` credential vault, SHA-256-verified
compiled scope manifests, pre-probe dnsx CNAME quarantine, fail-closed
`ScopeChecker`, deterministic `PreToolUse` scope hooks, and
`<untrusted_target_data>` isolation) are documented in the
[main repository README](https://github.com/Rhodawk-AI/rhodawk-bounty-hunter#readme).

## License & attribution

MIT — see [LICENSE](./LICENSE). Upstream attribution is preserved in
[NOTICE](./NOTICE); please keep it intact in redistributions.

**Hunt only what you are authorized to hunt.**
