# MCP Tools

| Tool | Risk | Scope | Approval |
|---|---|---|---|
| `rhodawk_research` | active | yes | yes |
| `rhodawk_scope_check` | read-only | — | — |
| `rhodawk_get_scope` | read-only | — | — |
| `rhodawk_recon` | active | yes | yes |
| `rhodawk_attack_surface` | read-only | — | — |
| `rhodawk_subdomains` | read-only | — | — |
| `rhodawk_endpoints` | read-only | — | — |
| `rhodawk_parameters` | read-only | — | — |
| `rhodawk_hunt` | active | yes | yes |
| `rhodawk_hunt_class` | active | yes | yes |
| `rhodawk_list_findings` | read-only | — | — |
| `rhodawk_get_finding` | read-only | — | — |
| `rhodawk_validate` | gated | yes | yes |
| `rhodawk_get_validation` | read-only | — | — |
| `rhodawk_generate_report` | read-only | — | — |
| `rhodawk_get_report` | read-only | — | — |
| `rhodawk_get_evidence` | read-only | — | — |
| `rhodawk_memory_*` | read-only | target filter | — |
| `rhodawk_leads` / `next` / `update` | local | — | — |
| `rhodawk_program*` | external read | — | — |

List at runtime: `rhodawk mcp tools`.

Backed by existing `rhodawk/tools/recon_engine.sh`, `rhodawk/tools/hunt.py`, `rhodawk/tools/validate.py`, `rhodawk/tools/lead_board.py`, `memory/*`, and `mcp/hackerone-mcp/`.
