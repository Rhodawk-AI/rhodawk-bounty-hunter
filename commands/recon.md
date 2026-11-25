---
description: Run the full recon pipeline by invoking rhodawk/tools/recon_engine.sh — subdomain enum (subfinder + amass + crt.sh + wayback), httpx live host probing with tech detection, nmap port scan, gau URL collection, JS analysis, ffuf directory fuzzing, parameter discovery, config exposure check, CI/CD workflow scan. Outputs to recon/<target>/. Handles FQDN, IP, CIDR, and file-of-hosts targets automatically. Usage: /recon target.com
---

# /recon

Run the full recon pipeline on a target. **Always invoke the production script directly** — do not re-implement the steps inline. The methodology below is reference material; the script is the entry point.

## Pre-Recon: Compile Scope First (authoritative)

Recon is fail-closed. Compile the verified manifest before running the engine — `recon/<handle>/scope/compiled_scope.json` is the single scope authority for the whole pipeline (see `rhodawk/prompts/kernel.md`):

```bash
rhodawk scope-compile <handle>
# -> recon/<handle>/scope/compiled_scope.json   (typed CompiledScopeManifest, SHA-256 self-verifying)

rhodawk_compile_scope(program_handle="<handle>")   # MCP equivalent
```

Without a valid manifest (or explicit scope patterns) the engine exits 3 **before any probe** — that is the design, not a malfunction. Recompile scope; never retry with the gate stripped off.

## Run This (the only required step)

```bash
# Domain (full subdomain enum + crawl + fuzz), scoped by the verified manifest:
bash rhodawk/tools/recon_engine.sh target.com --scope-manifest recon/<handle>/scope/compiled_scope.json

# Auto-detect — the engine picks up recon/<target>/scope/compiled_scope.json when present:
bash rhodawk/tools/recon_engine.sh target.com

# CIDR — skips subdomain enum, runs nmap host sweep:
bash rhodawk/tools/recon_engine.sh 10.0.0.0/24 --scope-manifest recon/<handle>/scope/compiled_scope.json

# Single IP — scope-locked, no subdomain enum:
bash rhodawk/tools/recon_engine.sh 192.0.2.10 --scope-manifest recon/<handle>/scope/compiled_scope.json

# Domain list (programs without wildcard scope) — pre-resolved hosts in a file:
# (list mode is still manifest-filtered — the list is never trusted as scope)
bash rhodawk/tools/recon_engine.sh path/to/scope.txt --scope-manifest recon/<handle>/scope/compiled_scope.json

# Quick mode (skip amass + reduce ffuf coverage):
bash rhodawk/tools/recon_engine.sh target.com --quick
```

The script auto-detects target type:
- Path to a readable file → loads it as a host list (one per line, `#` comments OK) and **skips subdomain enumeration entirely**.
- `x.x.x.x/y` → CIDR sweep (max /24, scope-locked).
- `x.x.x.x` → single IP, scope-locked.
- Anything else → treated as a domain; full enum runs.

Output lands in `recon/<target>/` (or `recon/<file-basename>/` for list mode):

```
recon/<target>/
├── scope/compiled_scope.json   (verified manifest, if scope-compile ran for this program)
├── scope/dropped_oos.txt       (out-of-scope + third-party SaaS CNAMEs, isolated pre-probe)
├── subdomains/all.txt
├── rtw/<function>/          (reconFTW gap-fill output, Phases 1.5 + 5.5)
├── live/urls.txt
├── urls/all.txt
├── candidates/{xss,ssrf,idor,sqli,redirect,lfi}.txt
├── api-endpoints.txt
├── nuclei/findings.txt
└── cicd/summary.txt        (if CI/CD workflows detected)
```

## reconFTW Gap-Fill (RhodawkAI Edition, Phases 1.5 + 5.5)

If `RTW_HOME` is set (reconFTW cloned and `capabilities.json` built), the engine
runs two extra phases automatically and deterministically — never a model
judgment call:

- **Phase 1.5** (before httpx probing): `CAP_ASN_ENUM` (sub_asn), `CAP_DNS_PERMUT`
  (sub_permut), `CAP_CDN_ISOLATE` (cdnprovider). Discovered subdomains are
  scope-filtered and merged into `subdomains/all.txt`, so Phase 2 probes them
  in the same run.
- **Phase 5.5** (before directory fuzzing): `CAP_JS_SOURCEMAPS` (jschecks),
  `CAP_VHOSTS` (virtualhosts), `CAP_TLS_PIVOTS` (tls_ip_pivots), `CAP_FAVICON`
  (favirecon_tech). New JS endpoints/routes are merged into `urls/all.txt`.

Rule (worded identically across every prompt layer): **If recon_summary flags a capability gap and capabilities.json marks it RTW_AVAILABLE, call run_rtw_capability before proceeding.**

Scope is fail-closed: reconFTW delegation runs only when scope patterns are
provided (`--scope-domain PATTERN`, repeatable, forwarded by `rhodawk recon` /
`rhodawk hunt` / the ReAct agent automatically) or when `--no-scope-check` is
passed explicitly (local demo testing only). Without either, the adapter blocks
the delegation, logs the block to `hunt-memory/audit.jsonl`, and the native
pipeline continues.

To run a phase's group by hand:

```bash
python3 rhodawk/tools/rtw_adapter.py phase 1.5 --target target.com \
    --recon-dir recon/target.com --scope-domain "*.target.com"
python3 rhodawk/tools/rtw_adapter.py phase 5.5 --target target.com \
    --recon-dir recon/target.com --scope-domain "*.target.com"
```

## Troubleshooting

### "/recon path/to/file.txt still runs subdomain enumeration"

You're on an older revision of this command file where the model re-implemented the pipeline inline and never invoked the production script. Pull latest, or run the script directly:

```bash
bash rhodawk/tools/recon_engine.sh path/to/file.txt
```

You should see `[*] Domain-list target — loading <file> (skipping subdomain enum)` near the start.

### "/recon loops / doesn't actually run anything"

Same root cause as the hunt-loop bug. Run the bash directly:

```bash
bash rhodawk/tools/recon_engine.sh target.com
```

Or in your prompt: "Run `bash rhodawk/tools/recon_engine.sh target.com` and report the output. Do not re-implement the steps."

### "Missing tools"

```bash
bash install_tools.sh
```

Recon needs: `subfinder`, `httpx` (ProjectDiscovery — not the Python CLI), `katana`, `gau`, `nuclei`, `ffuf`, `nmap`, `anew`. (`dnsx` and `gf` are optional conveniences the current engine does not invoke.) The installer handles all of them.

## After Recon

1. Review `recon/<target>/live/urls.txt` — open interesting ones in a browser.
2. Check `recon/<target>/nuclei/findings.txt` — any high/critical?
3. Review `recon/<target>/api-endpoints.txt` — start IDOR testing.
4. `grep -E "admin|jenkins|grafana|gitlab" recon/<target>/live/urls.txt` — admin panels.
5. Run `/hunt target.com` to start active vulnerability testing on the recon output.

## 5-Minute Kill Signal

If after running this pipeline you see:
- All hosts return 403 even after `rhodawk/tools/bypass_403.sh` + wafw00f bypass, or return only static marketing pages
- No API endpoints visible
- No interesting parameters in URLs
- nuclei returns 0 medium/high findings

**→ Move on to a different target.** Don't sink hours into a dead surface.

---

# Reference: What the script does (informational)

The pipeline in `rhodawk/tools/recon_engine.sh` runs these phases (numbers may shift; check the script source):

The engine actually implements: subfinder (+ amass + crt.sh + wayback — no Chaos API call exists in the engine), httpx probing with status/title/tech-detect (no dnsx resolve step), origin-only nmap port scan (CDN/SaaS hosts are skipped), katana + gau/wayback URL collection, JS endpoint extraction via curl+sed (LinkFinder/SecretFinder are NOT wired in), ffuf directory fuzzing, parameter extraction from collected URLs (no Arjun/x8 active probing), config-file exposure checks, sisakulint CI/CD scan, and the reconFTW gap-fill phases 1.5/5.5. The following steps are commonly assumed but NOT implemented in `recon_engine.sh` — do not promise them in operator prompts:

- ~~Chaos API subdomain enumeration~~ — not implemented (no `$CHAOS_API_KEY` code path).
- ~~dnsx resolve before httpx~~ — not implemented (httpx does its own resolution).
- ~~gf classification (xss/ssrf/idor/sqli/redirect/lfi candidate files)~~ — not implemented.
- ~~LinkFinder / SecretFinder JS analysis~~ — not implemented (curl+sed extraction only).
- ~~Arjun / x8 parameter discovery~~ — not implemented (parameter names are extracted from collected URLs only).

For the IDOR / SSRF / GraphQL / SSTI / etc. active-testing playbooks, see `/hunt` and its methodology section.
