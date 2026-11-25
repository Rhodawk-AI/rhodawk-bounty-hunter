---
description: Check if a target asset is in scope for the program before hunting or submitting. Authoritative source is the SHA-256-verified compiled scope manifest (rhodawk scope-compile <handle> -> recon/<handle>/scope/compiled_scope.json), checked via scope_checker.py --manifest. Usage: /scope <asset>
---

# /scope

Verify an asset is in scope before hunting or submitting a finding.

## Why This Matters

Out-of-scope reports are immediately closed. Testing out-of-scope assets can get you banned.
Always check scope BEFORE the first request.

**Real example:** City of Vienna explicitly excludes `/advuew/*`. Submitting XSS on that path = instant close.

## Usage

```
/scope api.target.com
/scope https://target.com/api/v2/users
/scope target-staging.company.com
/scope *.company.com
```

## Authoritative Pre-Recon Workflow

The single source of truth for program scope is the compiled, SHA-256-verified manifest — not a pasted scope list, not a scraped program page:

```bash
rhodawk scope-compile <handle>
# -> recon/<handle>/scope/compiled_scope.json   (typed CompiledScopeManifest)

rhodawk_compile_scope(program_handle="<handle>")   # MCP equivalent
```

Every scope check, recon run, hunt and MCP call verifies that manifest's hash fail-closed. The manifest wins over any prose in this file — see `rhodawk/prompts/kernel.md` (root authority).

## Deterministic Local Check

Use the local scope checker against the verified manifest before sending traffic:

```bash
python3 rhodawk/tools/scope_checker.py https://api.target.com/v2/users \
  --manifest recon/<handle>/scope/compiled_scope.json
```

Filter a discovered URL list:

```bash
python3 rhodawk/tools/scope_checker.py \
  --manifest recon/<handle>/scope/compiled_scope.json \
  --input-file recon/target.com/urls/all.txt \
  --output recon/target.com/urls/in_scope.txt
```

If no manifest exists yet, compile one first with `rhodawk scope-compile <handle>`. The legacy `--domain '*.target.com'` pattern flags still work for quick sanity checks, but hand-typed patterns are not integrity-verified — prefer the manifest for anything that will drive traffic.

## Scope Check Process

### Step 1: Read In-Scope List

Go to the program page and extract:
```
In-scope:
- *.target.com
- target.com
- api.target.com
- mobile.target.com (iOS + Android apps)

Out-of-scope:
- staging.target.com (explicitly excluded)
- target.com/help/* (documentation only)
- partners.target.com (third-party managed)
```

### Step 2: Asset Ownership & Third-Party Check (manifest-driven)

Ownership and third-party isolation are compiled into the verified manifest — do not re-derive them with raw `whois`/`dig` shell one-liners:

```bash
python3 rhodawk/tools/scope_checker.py api.target.com \
  --manifest recon/<handle>/scope/compiled_scope.json --explain
```

- `excluded_classes` in the manifest carries the program's own exclusions; the checker reports which rule matched.
- Third-party SaaS CNAME aliases (zendesk, statuspage, freshdesk, workday, greenhouse, lever, salesforce, shopify, github.io, marketo) are detected and isolated automatically by `recon_engine.sh`'s pre-probe CNAME gate before any HTTP traffic — a `*.target.com` wildcard that CNAMEs to Zendesk lands in `scope/dropped_oos.txt`, not in the probe set.
- If ownership is genuinely ambiguous, compile the owning program (`rhodawk scope-compile <handle>`) and compare manifests — the verified manifest is the authority, not ad-hoc WHOIS output.

### Step 3: Wildcard Interpretation

| Scope Pattern | Covers | Does NOT Cover |
|---|---|---|
| `*.target.com` | `api.target.com`, `app.target.com` | `target.com` itself |
| `target.com` | `target.com` only | `api.target.com` |
| `*.target.com` + `target.com` | Both | Sub-subdomains like `a.api.target.com` (depends on program) |

### Step 4: Path Exclusions

Some programs exclude specific paths on in-scope domains:
```
Domain: target.com (in scope)
But: target.com/terms, target.com/privacy, target.com/help/* = usually excluded

Check for:
- Wildcard exclusions: /admin/* excluded
- Path-specific exclusions: /api/v1/* excluded (use v2 only)
- Feature exclusions: "Do not test file upload feature"
```

### Step 5: Staging / Dev Check

Unless the program explicitly includes staging:
```
staging.target.com     → NOT in scope (usually)
dev.target.com         → NOT in scope (usually)
qa.target.com          → NOT in scope (usually)
test.target.com        → NOT in scope (usually)

Always confirm: does scope say "*.target.com" or only list production domains?
```

## Output

**IN SCOPE:** "asset.target.com is covered by the *.target.com wildcard. Owned by TargetCorp (WHOIS confirms). No path exclusions apply. Clear to test."

**OUT OF SCOPE:** "target.com/admin/* is explicitly excluded in the program rules under 'Out of Scope: Internal admin panel.' Do not test. Move to a different endpoint."

**UNCLEAR:** "third-party.target.com appears to be a CNAME to Zendesk. This is a third-party service not owned by TargetCorp. Most programs exclude third-party services even if they're in the scope wildcard. Do not test without explicit confirmation."

## Safe Harbor Check

Before testing, confirm the program has a safe harbor clause:
```
Look for: "We will not pursue legal action against security researchers who..."
If no safe harbor → be more careful → stick strictly to documented scope
```
