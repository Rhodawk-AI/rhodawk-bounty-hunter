# RhodawkAI Bounty Hunter — Operator Playbook

> **5-Minute Zero-Friction Guide:** Go from a fresh machine to a verified, fail-closed reconnaissance run with canonical JSON truth (`recon_truth.json`), run-to-run diffs (`delta.json`), and an AI-prioritized attack brief (`recon_brief.md`).

---

## 1. Mental Model: How the System Works

Most testers get tripped up by assuming this is either a pure Python script or an unguarded LLM wrapper. It is neither:

1. **Deterministic Recon Core (Hardened):** Every scan runs through a fail-closed scope gate *before* sending a single packet, classifies live hosts into `CDN_EDGE` vs. `FIRST_PARTY_ORIGIN` (so `nmap` skips Cloudflare/Vercel edges), delegates specialized gap-fill checks to a pinned `reconFTW` checkout (`3925211`), and fuses everything into structured artifacts.
2. **AI Reasoning Layer (Model-Agnostic):** Your configured LLM never decides scope or raw tool flags. It consumes the redacted, deduplicated `recon_truth.json` to produce an actionable `recon_brief.md` (and powers downstream `hunt`, `validate`, and `report` workflows).
3. **Two-Part Installation:**
   - **Part A (CLI Package):** `pipx` or `npm` installs the `rhodawk` / `rhodawk` command.
   - **Part B (Security Toolchain + Managed Chromium):** `./install.sh` and `install_tools.sh` install the backing Go/system binaries, pin `reconFTW`, and provision a dedicated Chromium binary for headless SPA crawling.

---

## 2. Fresh Machine Setup (Copy-Paste)

### Step 1: Clone & Install the CLI + External Toolchain

```bash
# 1. Clone the repository (required for toolchain & reconFTW installers)
git clone https://github.com/Rhodawk-AI/rhodawk-bounty-hunter.git
cd rhodawk-bounty-hunter

# 2. Install the CLI globally (PEP 668 safe on Ubuntu 24.04 / Debian 12 / Kali)
pipx install rhodawk-bounty-hunter
# Alternative Node.js CLI wrapper:
# npm install -g rhodawk-bounty-hunter

# 3. Wire the standalone engine, persist RTW_HOME, and pin reconFTW (3925211)
chmod +x install.sh install_tools.sh
./install.sh --agent standalone

# 4. Install backing recon & reconFTW gap-fill Go binaries
bash install_tools.sh --rtw-deps
```

### Step 2: Install Managed Chromium (Headless SPA & JS Crawling)

Instead of relying on fragile system Chrome installs, RhodawkAI Edition provisions a single pinned Chromium binary via Playwright and registers it in `~/.rhodawk/capabilities.json` (`~/.rhodawk/browser/chromium`) for `katana -headless`:

```bash
bash install_tools.sh --browser
```

**Expected output:**
`[+] Managed Chromium ready: ~/.rhodawk/browser/chromium`

### Step 3: Configure Your LLM Provider

Pick **one** provider below.

> **VPS Tip:** If you are running on a CPU-only VPS, use a cloud provider like **NVIDIA NIM** or **Groq**. Local Ollama on CPU will bottleneck the AI brief stage.

#### Option A — NVIDIA NIM (Recommended for VPS / Hosted Inference)
```bash
export NVIDIA_API_KEY="nvapi-YOUR_KEY_HERE"
echo 'export NVIDIA_API_KEY="nvapi-YOUR_KEY_HERE"' >> ~/.bashrc

# Press Enter when prompted for NVIDIA_NIM_BASE_URL to keep https://integrate.api.nvidia.com/v1
rhodawk setup --provider nvidia --model nvidia/nemotron-3-ultra-550b-a55b
```

#### Option B — Local Ollama (100% Local — Requires GPU or Apple Silicon)
```bash
ollama pull qwen2.5:14b
rhodawk setup --provider ollama --model qwen2.5:14b
```

#### Option C — Groq / DeepSeek / Anthropic / OpenAI
```bash
export GROQ_API_KEY="gsk_YOUR_KEY_HERE"   # or DEEPSEEK_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY
rhodawk setup --provider groq
```

### Step 4: Verify Everything With `rhodawk doctor`

Always run `rhodawk doctor` before scanning a target:

```bash
rhodawk doctor
```

**Healthy Output:**
```text
════════════════════════════════════════════════════════════
  Environment doctor (rhodawk doctor)
════════════════════════════════════════════════════════════
  [PASS] Core binaries        8/8 on PATH
  [PASS] reconFTW checkout    39252113a matches pin, +x ok
  [PASS] Managed Chromium     ~/.rhodawk/browser/chromium
  [WARN] PDCP_API_KEY         unset — ProjectDiscovery API disabled (optional)
  [WARN] CHAOS_API_KEY        unset — Chaos public recon dataset disabled (optional)
  [WARN] H1_API_TOKEN         unset — HackerOne scope sync disabled (optional)
  [PASS] LLM provider nvidia  responded READY
  [PASS] MCP module           cli.py imports cleanly
  0 FAIL, 3 WARN — environment ready
```

> **Note:** The 3 `[WARN]` lines are optional API keys. **`0 FAIL, 3 WARN` means your environment is 100% ready.**

---

## 3. Test the System in 3 Steps

### Test 1: Verify the Fail-Closed Scope Gate (5 Seconds)

Confirm that out-of-scope targets are aborted before any tool runs or any packet leaves your machine:

```bash
rhodawk evil.example -recon --scope-domain "*.goodscope.example"
```

**Expected result:** Immediate scope block — `0` packets sent **to the blocked target** and `0` tools spawned. (Discovered hosts are filtered before probing too; `--no-scope-check` disables scoping entirely.)

### Test 2: Run Live Scoped Recon on an Authorized Public Target

Run against an authorized testing domain (`rest.vulnweb.com` or `scanme.nmap.org`) to see live HTTP probing, first-party origin `nmap`, JS endpoint extraction, `nuclei` hits, and the AI attack brief end-to-end:

```bash
rhodawk rest.vulnweb.com -recon --scope-domain "rest.vulnweb.com"
```

*(For a root domain with subdomains, pass both patterns: `--scope-domain "example.com" --scope-domain "*.example.com"`.)*

### Test 3: Inspect the 3 Structured Artifacts

Outputs are written to the recon dir for the target — `<host>` or `<host>_<port>` when the target carries an explicit port. The location depends on the install layout (verified with real `engine.py recon` runs):

- **Writable git clone** (default): `<clone>/rhodawk/recon/<target>/`
- **pipx / read-only install, or when `RHODAWK_HOME` is set**: `$RHODAWK_HOME/recon/<target>/` (default `~/.rhodawk/recon/<target>/`)

```bash
RECON_DIR=~/rhodawk-bounty-hunter/rhodawk/recon/rest.vulnweb.com

# 1. Canonical JSON truth: counts, CDN/Origin classification, SimHash clusters, honest tool health
jq '{counts, tool_health, hosts: [.hosts[] | {host, asset_class, cdn_provider, cluster_id}]}' \
  "$RECON_DIR/recon_truth.json"

# 2. Run-to-run diff (highlights new hosts, ports, and JS endpoints on Run 2+)
cat "$RECON_DIR/delta.json"

# 3. Prioritized AI attack-surface brief
cat "$RECON_DIR/recon_brief.md"
```

---

## 4. What Happens Under the Hood (Recon Pipeline)

| Phase | Engine / Tools | Guardrail / Output |
| :--- | :--- | :--- |
| **Phase 0** | `scope_checker.py` | **Fail-closed gate:** aborts immediately if `--scope-domain` is missing or mismatched. |
| **Phase 1** | `subfinder`, passive `amass` | Passive subdomain discovery + post-filter against scope. |
| **Phase 1.5** | `rtw_adapter.py` → `reconFTW` (`sub_asn`, `sub_permut`, `cdnprovider`) | Bounded on-demand gap-fill; gracefully skips `sub_asn` if `PDCP_API_KEY` is unset. |
| **Phase 2 & 2.5** | `httpx` + CDN/Origin Classifier | Tags live hosts as `CDN_EDGE`, `THIRD_PARTY_SAAS`, or `FIRST_PARTY_ORIGIN`. |
| **Phase 3** | Origin-only `nmap` | **Skips `CDN_EDGE` hosts** (0 edge packets); port-scans only `FIRST_PARTY_ORIGIN` IPs. |
| **Phase 4–5** | `katana` (Managed Chromium), `gau` / Wayback, JS parser | Extracts URLs, SPA routes, API paths, and JS endpoints. |
| **Phase 5.5** | `rtw_adapter.py` → `reconFTW` (`jschecks`, `virtualhosts`, `tls_ip_pivots`, `favirecon_tech`) | Deep JS sourcemap/secret checks, vhosts, TLS pivots, and favicon fingerprinting. |
| **Phase 6–10** | Parameter discovery, `nuclei`, CNAME takeover check | Runs targeted checks only when live hosts/parameters exist. |
| **Fusion & AI** | `recon_fusion.py` + `brain.py` | 64-bit SimHash host clustering, `recon_truth.json`, `delta.json`, honest `tool_health` table, and `recon_brief.md`. |

---

## 5. Troubleshooting: The 6 Traps That Confuse New Testers

| Symptom | Root Cause | Instant Fix |
| :--- | :--- | :--- |
| **`error: externally-managed-environment` (PEP 668)** | Ran global `pip install` on Ubuntu 24.04 / Debian 12 / Kali. | Use `pipx install rhodawk-bounty-hunter`. |
| **Immediate `SCOPE BLOCK` error** | Fail-closed safety gate working as designed because no scope pattern was supplied. | Pass `--scope-domain "<target>"` (or `--no-scope-check` strictly for local Docker labs). |
| **Two ports on one host** | Fixed in 6.1.1.1: `127.0.0.1:8082` and `127.0.0.1:8083` now key separate recon dirs (`rhodawk/recon/127.0.0.1_8082/` vs `..._8083/`); each run also archives the previous run to `.prev_run/` so stale artifacts never leak into a Summary. | Nothing to do — but only the data-home mirror (`~/.rhodawk/recon/<host>/recon_truth.json`) stays host-keyed by design. |
| **`[WARN]` in `doctor` or `SKIPPED_SILENT` / `COMPLETED_EMPTY` in `tool_health`** | Honest telemetry reporting optional API keys or reconFTW modules that returned zero net-new items. | Ignore unless `[FAIL]` appears in `rhodawk doctor`. Export `PDCP_API_KEY` only if you need ASN enumeration. |
| **AI brief hangs or takes 10+ minutes** | Local Ollama running on a CPU-only VPS. | Switch to cloud inference: `rhodawk setup --provider nvidia` (or `groq`). |
| **`rhodawk` installed, but `doctor` fails on binaries / Chromium** | Installed only the PyPI/npm CLI without running the toolchain scripts. | Run `./install.sh --agent standalone && bash install_tools.sh --rtw-deps && bash install_tools.sh --browser`. |

---

## 6. Command Cheat Sheet

```bash
rhodawk doctor                                         # Verify binaries, reconFTW pin, Chromium & LLM
rhodawk setup --provider nvidia                        # Configure LLM provider
rhodawk <domain> -recon --scope-domain "<domain>"      # Full fail-closed recon + JSON truth + AI brief
rhodawk hunt <domain> --scope-domain "<domain>"        # Autonomous vulnerability hunting (post-recon)
rhodawk validate "<finding>"                           # 7-Question Gate to eliminate weak findings
rhodawk report                                         # Generate HackerOne / Bugcrowd / Intigriti report
rhodawk mcp doctor && rhodawk mcp serve            # Expose tools to Cursor / Claude Code / Codex via MCP
```
