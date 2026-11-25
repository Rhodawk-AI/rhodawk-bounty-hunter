# RhodawkAI Bounty Hunter MCP

Native MCP **server** that exposes the existing RhodawkAI Bounty Hunter research engine to AI agents.

This does **not** replace:

- `burp-mcp-client/`
- `caido-mcp-client/`
- `hackerone-mcp/`

## Install (any MCP client)

```bash
git clone https://github.com/Rhodawk-AI/rhodawk-bounty-hunter.git
cd rhodawk-bounty-hunter
pip install -r requirements.txt && ./install.sh --agent mcp
```

That installs the `rhodawk` command (and the `rhodawk` brand alias). The MCP server
runs as `rhodawk mcp serve`, so the same config works from any directory in any
MCP-compatible agent.

```bash
rhodawk mcp doctor   # verify SDK, tools, and paths
rhodawk mcp tools    # list the exposed tool catalog
```

## Clients

Add this to your client's MCP config (works after the install above):

```json
{
  "mcpServers": {
    "rhodawk": {
      "command": "rhodawk",
      "args": ["mcp", "serve"],
      "env": { "RHODAWK_MCP_APPROVE": "0" }
    }
  }
}
```

- **Claude Desktop / Claude Code**: merge `claude-config.json` into `mcpServers`
- **Cursor / Cline / Windsurf / Zed**: same `command` + `args` in their MCP settings
- **OpenCode**: see `opencode-config.json`

Running without the installer? Use `python3 rhodawk/mcp/rhodawk-mcp/server.py`.

## Safety

- Scope must be set (`scope_domains`) before active tools
- Active tools need `approve=true` or `RHODAWK_MCP_APPROVE=1`
- Discovered hosts are not automatically authorized
- Reports are never auto-submitted
- Target content is untrusted data (not instructions)

## Primary tool

`rhodawk_research` — modes `RECON|HUNT|VALIDATE|REPORT|FULL`

See `docs/mcp.md` and `docs/mcp-research.md`.
