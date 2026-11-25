#!/usr/bin/env python3
"""
HackerOne MCP Server — public endpoints + authenticated scope pull.

Provides three tools:
  - search_disclosed_reports: Search Hacktivity for disclosed reports
  - get_program_stats: Bounty ranges, response times, resolved counts
  - get_program_policy: Safe harbor, response SLA, excluded vuln classes
    (Commit 2: backed by tools/scope_compiler.py — authenticated paginated
    REST when H1 credentials are configured via the credential vault,
    cursor-paginated public GraphQL fallback when keyless — so >50 scope
    items are never truncated)

This is a lightweight wrapper around HackerOne's public GraphQL API plus the
shared scope compiler for program scope/policy reads.
Authenticated endpoints (submit_report, private scope) are deferred.

Usage (standalone test):
    python3 mcp/hackerone-mcp/server.py search "ssrf" --limit 5
    python3 mcp/hackerone-mcp/server.py stats "example-corp"
    python3 mcp/hackerone-mcp/server.py policy "example-corp"

MCP integration:
    Add to .claude/settings.json mcpServers — see config.json.
"""

import json
import ssl
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path


# ─── SSL context ─────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    # certifi isn't installed — fall back to the system CA store via
    # ssl.create_default_context(), which is already a verifying context.
    # Never disable verification: see SECURITY-REVIEW-2026-08-22.md
    # finding #9 — this fallback used to disable verification outright,
    # silently exposing every request to MITM on any stock install, since
    # certifi is not a declared dependency.
    _SSL_CTX = ssl.create_default_context()

H1_GRAPHQL = "https://hackerone.com/graphql"
DEFAULT_TIMEOUT = 15

# ─── Shared scope compiler (Commit 2) ────────────────────────────────────────
# get_program_policy routes through tools/scope_compiler.py for lossless
# scope reads. The compiler is optional: when unavailable (stripped install,
# standalone copy) get_program_policy falls back to the legacy inline
# GraphQL read below, preserving pre-Commit-2 behavior.
_REPO_ROOT = Path(__file__).resolve().parents[3]  # .../rhodawk-bounty-hunter/...
for _p in (str(_REPO_ROOT / "rhodawk"), str(_REPO_ROOT)):
    if _p not in sys.path and Path(_p).is_dir():
        sys.path.insert(0, _p)
try:
    from tools import scope_compiler as _scope_compiler
except ImportError:
    _scope_compiler = None


def _escape_graphql_string(s: str) -> str:
    """Escape a value for safe interpolation inside a GraphQL double-quoted string."""
    return (s
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t"))


class HackerOneAPIError(Exception):
    """Raised on API failures (rate limit, timeout, bad response)."""
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _graphql_request(query: str, variables: dict | None = None,
                     timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute a GraphQL request against HackerOne's public API.

    ``variables`` is optional (Commit 2): the scope compiler passes cursor
    pagination variables through this same verified-SSL path.
    """
    payload = json.dumps({"query": query,
                          "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(
        H1_GRAPHQL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "rhodawk-bounty-hunter/2.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            if "errors" in data:
                raise HackerOneAPIError(
                    f"GraphQL errors: {data['errors']}",
                    status_code=200,
                )
            return data
    except urllib.error.HTTPError as e:
        raise HackerOneAPIError(
            f"HTTP {e.code}: {e.reason}",
            status_code=e.code,
        )
    except urllib.error.URLError as e:
        raise HackerOneAPIError(f"Network error: {e.reason}")
    except json.JSONDecodeError as e:
        raise HackerOneAPIError(f"Invalid JSON response: {e}")


# ─── Tool: search_disclosed_reports ──────────────────────────────────────────

def search_disclosed_reports(
    keyword: str = "",
    program: str = "",
    limit: int = 10,
) -> list[dict]:
    """Search HackerOne Hacktivity for disclosed reports.

    Args:
        keyword: Search term (vuln type, tech, etc.)
        program: HackerOne program handle (e.g. "shopify")
        limit: Max results (1-25)

    Returns:
        List of disclosed report summaries.
    """
    limit = max(1, min(25, limit))

    where_clauses = ['disclosed_at: { _is_null: false }']
    if keyword:
        safe_keyword = _escape_graphql_string(keyword)
        where_clauses.append(
            f'report: {{ title: {{ _icontains: "{safe_keyword}" }} }}'
        )
    if program:
        safe_program = _escape_graphql_string(program)
        where_clauses.append(
            f'team: {{ handle: {{ _eq: "{safe_program}" }} }}'
        )

    where = ", ".join(where_clauses)

    query = f"""{{
      hacktivity_items(
        first: {limit},
        order_by: {{ field: popular, direction: DESC }},
        where: {{ {where} }}
      ) {{
        nodes {{
          ... on HacktivityDocument {{
            report {{
              title
              severity_rating
              disclosed_at
              url
              substate
            }}
            team {{
              handle
              name
            }}
          }}
        }}
      }}
    }}"""

    data = _graphql_request(query)
    nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])

    results = []
    for node in nodes:
        report = node.get("report")
        if not report:
            continue
        team = node.get("team") or {}
        results.append({
            "title": report.get("title", ""),
            "severity": (report.get("severity_rating") or "unknown").upper(),
            "disclosed_at": (report.get("disclosed_at") or "")[:10],
            "url": report.get("url", ""),
            "state": report.get("substate", ""),
            "program": team.get("handle", ""),
            "program_name": team.get("name", ""),
        })

    return results


# ─── Tool: get_program_stats ────────────────────────────────────────────────

def get_program_stats(program: str) -> dict:
    """Get public statistics for a HackerOne program.

    Args:
        program: HackerOne program handle (e.g. "shopify")

    Returns:
        Dict with bounty info, response times, resolved counts.
    """
    safe_program = _escape_graphql_string(program)
    query = f"""{{
      team(handle: "{safe_program}") {{
        name
        handle
        url
        offers_bounties
        currency
        base_bounty
        resolved_report_count
        average_bounty_lower_amount
        average_bounty_upper_amount
        launched_at
        state
      }}
    }}"""

    data = _graphql_request(query)
    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found", "program": program}

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "url": team.get("url", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "currency": (team.get("currency") or "usd").upper(),
        "base_bounty": team.get("base_bounty"),
        "resolved_reports": team.get("resolved_report_count"),
        # H1 dropped the old `average_time_to_bounty_awarded` /
        # `average_time_to_first_program_response` fields. The closest
        # replacement is a dollar range, not a duration in days — so these
        # are bounty amounts, NOT `avg_days_to_bounty`.
        "avg_bounty_lower": team.get("average_bounty_lower_amount"),
        "avg_bounty_upper": team.get("average_bounty_upper_amount"),
        "launched_at": (team.get("launched_at") or "")[:10],
        "state": team.get("state", ""),
    }


# ─── Tool: get_program_policy ────────────────────────────────────────────────

def _get_program_policy_legacy(program: str) -> dict:
    """Pre-Commit-2 inline GraphQL read (kept for stripped installs).

    Truncated at first: 50 scope items — scope_compiler removes that limit;
    this path only survives when tools/scope_compiler.py is unavailable.
    """
    safe_program = _escape_graphql_string(program)
    query = f"""{{
      team(handle: "{safe_program}") {{
        name
        handle
        policy
        offers_bounties
        structured_scopes(first: 50, archived: false) {{
          nodes {{
            asset_type
            asset_identifier
            eligible_for_bounty
            eligible_for_submission
            instruction
          }}
        }}
      }}
    }}"""

    data = _graphql_request(query)
    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found", "program": program}

    scopes = []
    scope_nodes = (team.get("structured_scopes") or {}).get("nodes", [])
    for s in scope_nodes:
        scopes.append({
            "type": s.get("asset_type", ""),
            "identifier": s.get("asset_identifier", ""),
            "bounty_eligible": s.get("eligible_for_bounty", False),
            "submission_eligible": s.get("eligible_for_submission", True),
            "instruction": s.get("instruction", ""),
        })

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "policy_text": team.get("policy", ""),
        "scopes": scopes,
    }


def get_program_policy(program: str) -> dict:
    """Get the public policy for a HackerOne program (lossless scope read).

    Commit 2: routes through tools/scope_compiler.py — authenticated
    paginated REST API when credentials are configured in the vault,
    cursor-paginated public GraphQL fallback when keyless — so programs with
    more than 50 scope items are no longer truncated. Credentials always come
    from the credential vault; tokens never appear in the returned dict.

    Args:
        program: HackerOne program handle (e.g. "shopify")

    Returns:
        Dict with safe harbor status, response SLAs, excluded vuln classes.
    """
    if _scope_compiler is not None:
        try:
            fetched = _scope_compiler.fetch_program_scope(
                program, graphql_fn=_graphql_request)
        except _scope_compiler.ProgramNotFoundError as e:
            return {"error": str(e), "program": program}
        except HackerOneAPIError:
            raise
        except _scope_compiler.ScopeCompilerError as e:
            # Preserve the historical error contract of this tool.
            raise HackerOneAPIError(str(e),
                                    status_code=getattr(e, "status_code", None))
        return {
            "program": fetched["handle"],
            "name": fetched["program_name"],
            "offers_bounties": bool(fetched.get("offers_bounties", False)),
            "policy_text": fetched.get("policy_md", ""),
            "scopes": [{
                "type": a.asset_type,
                "identifier": a.asset_identifier,
                "bounty_eligible": a.eligible_for_bounty,
                "submission_eligible": a.eligible_for_submission,
                "instruction": a.instruction,
            } for a in fetched["assets"]],
        }
    return _get_program_policy_legacy(program)


# ─── CLI interface ───────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 server.py search <keyword> [--program <handle>] [--limit N]")
        print("  python3 server.py stats <program>")
        print("  python3 server.py policy <program>")
        sys.exit(1)

    cmd = sys.argv[1]

    try:
        if cmd == "search":
            keyword = sys.argv[2] if len(sys.argv) > 2 else ""
            program = ""
            limit = 10
            i = 3
            while i < len(sys.argv):
                if sys.argv[i] == "--program" and i + 1 < len(sys.argv):
                    program = sys.argv[i + 1]
                    i += 2
                elif sys.argv[i] == "--limit" and i + 1 < len(sys.argv):
                    limit = int(sys.argv[i + 1])
                    i += 2
                else:
                    i += 1
            results = search_disclosed_reports(keyword=keyword, program=program, limit=limit)
            print(json.dumps(results, indent=2))

        elif cmd == "stats":
            program = sys.argv[2] if len(sys.argv) > 2 else ""
            if not program:
                print("Error: program handle required")
                sys.exit(1)
            result = get_program_stats(program)
            print(json.dumps(result, indent=2))

        elif cmd == "policy":
            program = sys.argv[2] if len(sys.argv) > 2 else ""
            if not program:
                print("Error: program handle required")
                sys.exit(1)
            result = get_program_policy(program)
            print(json.dumps(result, indent=2))

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)

    except HackerOneAPIError as e:
        print(json.dumps({"error": str(e), "status_code": e.status_code}))
        sys.exit(1)


if __name__ == "__main__":
    main()
