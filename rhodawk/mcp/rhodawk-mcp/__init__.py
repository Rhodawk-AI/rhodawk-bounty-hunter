"""RhodawkAI Bounty Hunter native MCP server (adapter over existing engines)."""

# B-2: never hardcode a version here — it drifted to a stale "0.1.0" while the
# package moved to 2.0.x. Resolve the real version from the rhodawk package
# (this directory sits inside the rhodawk package tree, so a plain parent-path
# import resolves it without the package being pip-installed).
try:
    from rhodawk import __version__ as _rhodawk_version
except Exception:  # pragma: no cover - standalone inspection outside the tree
    _rhodawk_version = None

__version__ = _rhodawk_version or "unknown"
