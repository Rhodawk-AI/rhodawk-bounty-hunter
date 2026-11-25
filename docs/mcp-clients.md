# MCP Clients

Primary transport: **stdio** (dual-era MCP SDK v2).

| Host | Config |
|---|---|
| Claude Code | Merge `mcp/rhodawk-mcp/claude-config.json` into `mcpServers` |
| OpenCode | Merge `mcp/rhodawk-mcp/opencode-config.json` |
| Cursor | Point `command`/`args` at `python3 mcp/rhodawk-mcp/server.py` |
| Codex | Same stdio command pattern |

Run from the repo root so relative paths resolve.

```bash
rhodawk mcp doctor
```

Do not enable `RHODAWK_MCP_APPROVE=1` in shared configs by default.
