# MCP server — scope, authorization, and audit

`rhodawk/mcp/rhodawk-mcp/server.py` exposes the engine's recon capabilities
over stdio MCP. This page documents how **scope** works for the one tool where
the caller can influence it.

## `rhodawk_run_rtw_capability` — caller-supplied scope (self-authorization)

```python
@mcp.tool(...)
def rhodawk_run_rtw_capability(capability_id: str, target: str,
                                 scope_domains: list[str] | None = None,
                                 approve: bool = False) -> dict[str, Any]:
```

**The caller supplies `scope_domains`, and the server trusts that declaration.**
Concretely (`server.py`, `rhodawk_run_rtw_capability`):

1. `POLICY.set_scope(scope_domains or [target])` — the policy engine's allow
   list is REPLACED with whatever the MCP client passed. When the caller omits
   the argument, the target itself is used as the single allow pattern.
2. The delegation then runs through the same fail-closed `rtw_adapter`
   scope gate as every other runtime (no patterns → no subprocess; outputs
   filtered post-call), but it is gated by the caller's declaration, not by a
   server-side program file.

This is deliberate self-authorization: the MCP client (an AI agent or IDE
extension) is treated as the operator of record for scope. It means:

- **A malicious or confused client can widen its own scope** — there is no
  server-side allowlist that overrides the caller. The tool cannot escape the
  scope it declared, but it can *declare* any scope.
- Mitigations that still apply: `_gate()` requires `approve=true` and runs the
  PolicyEngine check; every delegated output file is filtered to the declared
  scope post-call; blocks and refusals are audited.

## Audit trail

Every call to `rhodawk_run_rtw_capability` appends a JSONL entry to the audit
log (`RHODAWK_AUDIT_FILE`, default `<data home>/hunt-memory/audit.jsonl`)
recording the caller-supplied scope:

```json
{"ts": "...", "scope_check": "caller-supplied-scope",
 "caller_scope_domains": ["*.example.test"], "capability_id": "CAP_DNS_PERMUT",
 "error": "rhodawk_run_rtw_capability: caller supplied scope_domains ...",
 ...}
```

Operators running the MCP server for agents they do not fully trust should pin
`RHODAWK_AUDIT_FILE` to a watched location and alert on
`scope_check == "caller-supplied-scope"` entries whose `caller_scope_domains`
do not match the intended program scope.

## Related docs

- [MCP security model](mcp-security.md) — scope, approval, isolation
- [MCP clients](mcp-clients.md) — wiring up Burp / Caido / HackerOne
