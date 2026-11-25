# Contributing to Agentic-Bug-Hunter — RhodawkAI Edition

Bug hunters and security engineers welcome. Every improvement here makes autonomous, fail-closed reconnaissance and validation more reliable in real engagements[span_1](start_span)[span_1](end_span).

---

## 🎯 What We Most Need

| Contribution | Why It Matters |
| :--- | :--- |
| **Fail-closed scope & CDN/origin isolation improvements** | Keeps active probing strictly on first-party origins (`0` packets on OOS / CDN edges) |
| **Bounded `reconFTW` `-c <fn>` gap-fillers & adapters** | Expands recon depth without monolithic hangs or silent failures |
| **Deterministic PoC validators & false-positive fixes** | Eliminates hallucinated or unverified findings with regression tests[span_2](start_span)[span_2](end_span) |
| **Open-weight AI provider tuning (NVIDIA NIM / Ollama)** | Improves `recon_brief.md` prioritization with zero closed-model lock-in |
| **New scanner modules & payload additions** | Increases real-world vulnerability coverage backed by proven PoCs[span_3](start_span)[span_3](end_span) |
| **Platform & scope-ingestion support (YesWeHack · Synack · Intigriti)** | Wider authorized program coverage[span_4](start_span)[span_4](end_span) |

---

## ✅ Before You Start

1. **Check open issues & discussions** — your idea may already be in progress[span_5](start_span)[span_5](end_span).
2. **One focused change per PR** — keeps review fast and CI clean[span_6](start_span)[span_6](end_span).
3. **Run the full local verification suite** — both `pytest -q` and shell syntax checks (`bash -n`) must pass before opening a PR.
4. **No theoretical bugs or silent failures** — scanner additions must have a real PoC or precedent[span_7](start_span)[span_7](end_span), and every tool wrapper must report honest `tool_health` status.
5. **Respect fail-closed scope** — never bypass `--scope-domain` or delegate `modules/vulns.sh` to `reconFTW`.

---

## 🚀 Workflow

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone [https://github.com/YOUR_USERNAME/rhodawk-bounty-hunter.git](https://github.com/YOUR_USERNAME/rhodawk-bounty-hunter.git)
cd rhodawk-bounty-hunter

# 2. Create a feature or fix branch
git checkout -b feat/your-contribution

# 3. Make your changes, then run the exact CI checks locally
bash -n rhodawk/tools/recon_engine.sh install.sh install_tools.sh
pytest -q

# 4. (Optional) Verify local environment health
rhodawk doctor

# 5. Commit using conventional format
git commit -m "feat: short description of what and why"

# 6. Push and open a Pull Request against Rhodawk-AI/rhodawk-bounty-hunter (main)
git push origin feat/your-contribution
