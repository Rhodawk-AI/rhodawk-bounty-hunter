---
description: Compile every in-scope asset for a bug bounty program into a verified scope manifest. Authoritative path: rhodawk scope-compile <handle> -> recon/<handle>/scope/compiled_scope.json (typed, SHA-256 self-verifying). Legacy fallback: scope_aggregator.sh (bbscope / bounty-targets-data). Usage: /scope-aggregate <program-handle> [--platform h1|bc|it|ywh|imf|all]
---

# /scope-aggregate

Aggregate the full in-scope asset list for a public program without copy-pasting
from the program page.

## Authoritative path (preferred): `rhodawk scope-compile`

```bash
rhodawk scope-compile <handle>
# -> recon/<handle>/scope/compiled_scope.json   (typed CompiledScopeManifest, SHA-256 self-verifying)

rhodawk_compile_scope(program_handle="<handle>")   # MCP equivalent
```

The compiled manifest — allow/exclude patterns, excluded classes, mandatory
headers, max RPS — is the single scope authority for `/scope`, `/recon`,
`/hunt` and both MCP servers (see `rhodawk/prompts/kernel.md`). Everything
downstream verifies its hash fail-closed:

```bash
python3 rhodawk/tools/scope_checker.py <asset> \
  --manifest recon/<handle>/scope/compiled_scope.json
bash rhodawk/tools/recon_engine.sh <target> \
  --scope-manifest recon/<handle>/scope/compiled_scope.json
```

## Legacy fallback (`scope_aggregator.sh`) — raw seed only

Only when `scope-compile` cannot authenticate (private program, no platform
creds) fall back to the old aggregator. `rhodawk/tools/scope_aggregator.sh`
runs in two strategies:

1. **bbscope** (`sw33tLie/bbscope`) — authenticated multi-platform pull. Best
   freshness, but needs platform tokens in env (`H1_USERNAME`, `H1_API_KEY`,
   `BUGCROWD_EMAIL`, etc.). Tries it first when installed.
2. **bounty-targets-data dump** (`arkadiyt/bounty-targets-data`) — hourly
   public dump of every public program. No auth needed; fallback if bbscope
   returns nothing.

Output: `~/.cache/bbhunt/scope/<program>.scope.txt` (one host per line, with
wildcards stripped to bare domains). This raw list is **not** integrity-verified —
treat it as a seed for `/scope` review and list-mode recon only. If you have a
genuine bbscope `-o tu` table cache (not this text dump), reconcile it into a
real manifest with `rhodawk scope-compile <handle> --bbscope-cache <path>`.

## Next steps

```
/scope <asset>                                   # verify individual assets against the manifest
/recon <target>                                  # engine auto-detects recon/<handle>/scope/compiled_scope.json
```

`recon_engine.sh` accepts `--scope-manifest <path>` explicitly and also
auto-detects `recon/<target>/scope/compiled_scope.json`; it fail-closes with
exit 3 when no valid manifest (or explicit scope patterns) exists.

## When NOT to use

- Programs with `*.target.com`-style wildcards: `scope-compile` preserves the
  wildcards natively (`CompiledScopeManifest` never strips them); still run
  `/recon target.com` to brute the wildcard.
- Private programs you cannot install bbscope creds for: bounty-targets-data
  only covers public scope, so private invites won't appear.
