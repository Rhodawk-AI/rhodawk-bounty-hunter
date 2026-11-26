# Hooks

Claude Code hook configuration for the bug bounty toolkit.

| File | Purpose |
|:---|:---|
| `hooks.json` | Hook definitions — runs safety checks before tool calls, enforces scope validation |

Hooks are loaded automatically by Claude Code from `~/.claude/hooks/` after `install.sh`.

## PreToolUse scope guard (`rhodawk/tools/hook_scope_guard.py`)

`hooks.json` wires the deterministic scope guard as a `PreToolUse` hook:

```
"command": "python3 \"${CLAUDE_PLUGIN_ROOT}/rhodawk/tools/hook_scope_guard.py\""
```

- `${CLAUDE_PLUGIN_ROOT}` is quoted, so a plugin path containing spaces cannot
  word-split; it is kept as a required variable (no `:-` fallback) so Claude
  Code's own missing-plugin-root protection stays in effect.
- Active network tools (Bash commands running `recon_engine.sh` /
  `full_hunt.sh` / `rtw_adapter.py` / `scope_aggregator.sh` / `hunt.py`, and
  the `rhodawk_recon` / `rhodawk_hunt` / `rhodawk_hunt_class` /
  `rhodawk_research` / `rhodawk_run_rtw_capability` MCP tools) are blocked
  with exit 2 unless a SHA-256-verified `compiled_scope.json` resolves.
- An unparseable or non-object stdin payload is ALSO exit 2 (fail closed): an
  unverifiable call is treated as potentially active, never as read-only.

### Self-hash integrity trust model

The manifest's `manifest_sha256` is a SHA-256 over its own canonical JSON
content (hash field excluded). `CompiledScopeManifest.load(...,
require_valid_hash=True)` re-hashes the file and refuses a mismatch. What this
model does and does not guarantee:

- **Detects:** accidental drift, truncation, hand-edits, or corruption of a
  manifest after compilation — any content change invalidates the self-hash,
  and the guard blocks with `SCOPE_HOOK_BLOCK`.
- **Does NOT detect:** an attacker who rewrites the manifest AND recomputes the
  self-hash in the same file. The trust anchor is therefore the local
  filesystem's write permissions: whoever can write
  `recon/<target>/scope/compiled_scope.json` can authorize any scope. Protect
  the data home (`~/.rhodawk`) accordingly (the installer already tightens it
  to 0700/0600), and treat a manifest you did not compile yourself as
  untrusted until re-verified against the program policy.

In short: the self-hash is a tamper-EVIDENT seal for drift and accidents; it is
not a cryptographic signature against a local attacker with write access.
