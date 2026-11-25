# Agentic-Bug-Hunter (RhodawkAI Edition) — Live Benchmarks

Reproducible, timed 3-way reconnaissance benchmarks executed on the same Ubuntu VPS against **5 publicly authorized testing domains**, comparing:

1. **Agentic-Bug-Hunter — RhodawkAI Edition (`v6.1.1`)**
2. **Original `awarexone/Agentic-Bug-Hunter` (commit `82f4512`)**
3. **Standalone `six2dez/reconftw` (`-r` mode, commit `3925211`)**

---

## Test Environment

- **Run Window:** `2026-11-23` – `2026-11-24 UTC`
- **Host:** Ubuntu Linux VPS (`8 vCPU` / `32 GB RAM`, `nyc1`)
- **LLM Provider (RhodawkAI Edition):** NVIDIA NIM (`nvidia/nemotron-3-ultra-550b-a55b`)
- **Target Suite:** `testphp.vulnweb.com`, `testhtml5.vulnweb.com`, `testaspnet.vulnweb.com`, `rest.vulnweb.com`, `scanme.nmap.org`
- **Scope Enforcement:** RhodawkAI Edition ran with explicit `--scope-domain <target>`; Original Rhodawk (`recon_engine.sh`) has no native fail-closed scope flag.

---

## 1. Executive Summary (5-Domain Head-to-Head)

| Metric | RhodawkAI Edition (`v6.1.1`) | Original Rhodawk (`82f4512`) | Standalone `reconFTW` (`3925211`) |
| :--- | :--- | :--- | :--- |
| **Targets Completed (out of 5)** | **5 / 5** (`exit=0`) | **5 / 5** (`exit=0`) | **0 / 5** (stalled >30m in `OSINT`) |
| **Total Wall-Clock Time** | **40m 48s** (`2,448s`) | 46m 04s (`2,764s`) | DNF (`>1,800s` on Target 1) |
| **Total URLs Collected** | **16,428** | 13,984 | — |
| **Total Nuclei Hits** | **6** | 5 | — |
| **Fail-Closed Scope Gate** | **Yes** (0 packets on OOS) | No | Exclusion file only (`-x`) |
| **Structured Outputs** | `recon_truth.json`, `delta.json`, `recon_brief.md` | Flat `.txt` files only | Flat files / optional export |
| **Honest Tool Telemetry** | **Yes** (`SKIPPED_SILENT` surfacing) | No | Checkpoint flags only |

---

## 2. Per-Domain Timing & Discovery Comparison

### Wall-Clock Runtime

| Domain | Stack | RhodawkAI (`v6.1.1`) | Original Rhodawk (`82f4512`) | Delta (RhodawkAI vs. Rhodawk) | `reconFTW -r` (`3925211`) |
| :--- | :--- | ---: | ---: | ---: | :--- |
| `testphp.vulnweb.com` | Apache / PHP / MySQL | **367s** (`6m 07s`) | 651s (`10m 51s`) | **-43.6%** (`-284s`) | DNF (`>1,800s` hang in `OSINT`) |
| `testhtml5.vulnweb.com` | Nginx / Python / HTML5 | 369s (`6m 09s`) | **325s** (`5m 25s`) | +13.5% (`+44s`) | Not reached (stalled on #1) |
| `testaspnet.vulnweb.com` | IIS / ASP.NET | **505s** (`8m 25s`) | 657s (`10m 57s`) | **-23.1%** (`-152s`) | Not reached (stalled on #1) |
| `rest.vulnweb.com` | Apache / PHP REST API | 404s (`6m 44s`) | **346s** (`5m 46s`) | +16.8% (`+58s`) | Not reached (stalled on #1) |
| `scanme.nmap.org` | Linux / Nmap Official Target | 803s (`13m 23s`) | **785s** (`13m 05s`) | +2.3% (`+18s`) | Not reached (stalled on #1) |
| **Total (5 Domains)** | — | **2,448s (`40m 48s`)** | **2,764s (`46m 04s`)** | **-11.4% (`-316s`)** | **DNF (Stalled in OSINT)** |

---

### Surface Discovery Breakdown (RhodawkAI Edition vs. Original Rhodawk)

| Domain | Edition | Subdomains | Live Hosts | Open Ports | URLs | Parameterized | API | JS | Nuclei Hits |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `testphp.vulnweb.com` | **RhodawkAI `v6.1.1`** | **1** *(scoped)* | 0 | 0 | 12,861 | 11,776 | 3 | 0 | 0 |
| `testphp.vulnweb.com` | Original Rhodawk `82f4512` | 44 *(unscoped)* | 0 | 0 | 12,861 | 11,776 | 3 | 0 | 0 |
| `testhtml5.vulnweb.com` | **RhodawkAI `v6.1.1`** | 3 | 0 | 0 | 210 | 152 | 0 | 0 | 0 |
| `testhtml5.vulnweb.com` | Original Rhodawk `82f4512` | 3 | 0 | 0 | 210 | 152 | 0 | 0 | 0 |
| `testaspnet.vulnweb.com` | **RhodawkAI `v6.1.1`** | **1** *(scoped)* | 1 | 1 | **68** | 32 | 0 | 0 | 1 |
| `testaspnet.vulnweb.com` | Original Rhodawk `82f4512` | 3 | 1 | 1 | 64 | 32 | 0 | 0 | 1 |
| `rest.vulnweb.com` | **RhodawkAI `v6.1.1`** | 3 | 1 | 1 | 102 | 80 | 0 | 33 | 3 |
| `rest.vulnweb.com` | Original Rhodawk `82f4512` | 3 | 1 | 1 | 102 | 80 | 0 | 33 | 3 |
| `scanme.nmap.org` | **RhodawkAI `v6.1.1`** | **2** *(scoped)* | 1 | 1 | **3,187** | **33** | 0 | 1 | **2** |
| `scanme.nmap.org` | Original Rhodawk `82f4512` | 5 | 1 | 1 | 747 | 17 | 0 | 1 | 1 |

---

## 3. Additional CDN Edge Isolation Proof (`rhodawkai.com`)

On a Vercel-hosted CDN domain (`rhodawkai.com`, verified on the same VPS on `2026-11-22`):

| Tool / Edition | Wall Time | CDN Edge Port-Scan Behavior |
| :--- | ---: | :--- |
| **RhodawkAI Edition (`v6.1.1`)** | **~5m 00s** | Classified Vercel as `CDN_EDGE` in Phase 2.5 and skipped `nmap` (**0 edge packets**, ~104–107s saved) |
| **Original Rhodawk (`82f4512`)** | 6m 45s | Blindly port-scanned CDN edge IP |
| **Standalone `reconFTW -r` (`3925211`)** | >31m (DNF) | Stalled inside `sub_brute` (`puredns`) |

---

## 4. Known Observations & Engineering Notes

- **`Live hosts: 0` on `testphp` & `testhtml5`:** Both RhodawkAI Edition and Original Rhodawk recorded `Live hosts: 0` during HTTP probing on `testphp.vulnweb.com` and `testhtml5.vulnweb.com` while still collecting historical/archived URLs.
- **Transparent Telemetry (`SKIPPED_SILENT`):** RhodawkAI Edition's `tool_health` checker surfaced an upstream `reconFTW` subshell error (`/root/Tools/reconftw/modules/utils.sh: line 1493: _is_behind_nat: command not found`) rather than silently ignoring it—tracked for a clean fix in `v6.1.2`.
