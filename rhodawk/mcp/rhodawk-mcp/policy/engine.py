"""Server-side policy: scope + approval before active MCP tools."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from .decisions import (
    ACTIVE_TEST_APPROVAL_REQUIRED,
    AUTHORIZATION_REQUIRED,
    Decision,
    DecisionKind,
    OUT_OF_SCOPE,
    REPORT_APPROVAL_REQUIRED,
    SCOPE_REQUIRED,
    TARGET_REQUIRED,
    ApprovalLevel,
)
from .tool_meta import get_tool_meta


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _ensure_path() -> None:
    import sys
    root = _repo_root()
    if root not in sys.path:
        sys.path.insert(0, root)


def _host_of(target: str) -> str:
    raw = target if "://" in target else f"https://{target}"
    try:
        return (urlparse(raw).hostname or target).lower()
    except Exception:
        return target.lower()


class PolicyEngine:
    """Wrap existing ScopeChecker; enforce approval for active tools."""

    def __init__(
        self,
        domains: list[str] | None = None,
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
        *,
        auto_approve: bool | None = None,
    ):
        self._domains: list[str] = [d.lower() for d in (domains or [])]
        self._excluded = excluded_domains
        self._excluded_classes = excluded_classes
        self._checker = None
        # Commit 3: session manifest state. A CompiledScopeManifest loaded via
        # load_manifest() (SHA-256 verified) is the third way to authorize a
        # session — next to explicit scope_domains — and removes the old
        # `scope_domains or [target]` self-authorization from the server tools.
        self.manifest = None
        self.manifest_path: str | None = None
        self.mandatory_headers: dict[str, str] = {}
        self.max_rps: float | None = None
        if self._domains:
            self.set_scope(self._domains, excluded_domains)
        if auto_approve is None:
            auto_approve = os.environ.get("RHODAWK_MCP_APPROVE", "").strip().lower() in {
                "1", "true", "yes",
            }
        self.auto_approve = auto_approve
        self.discovered: set[str] = set()
        self.authorized: set[str] = {d.lstrip("*.").lower() for d in self._domains if d}

    def load_manifest(self, manifest_path: str) -> dict[str, Any]:
        """Load a compiled scope manifest as THE session scope (Commit 3).

        Loads the CompiledScopeManifest with SHA-256 verification enforced
        (require_valid_hash=True — a tampered file raises ValueError), builds
        the authoritative ScopeChecker via ScopeChecker.from_manifest(), and
        stores the manifest plus its policy knobs (excluded_classes,
        mandatory_headers, max_rps) for the server tools to surface and
        enforce.

        Raises:
            ValueError: manifest file tampered (hash mismatch) or a dangerous
                pattern inside it (ScopeError subclasses ValueError).
            OSError: manifest file missing/unreadable.

        Returns a redacted summary (counts + short hash — never raw asset
        dumps) for tool responses.
        """
        _ensure_path()
        from contracts.scope import CompiledScopeManifest
        from tools.scope_checker import ScopeChecker

        manifest = CompiledScopeManifest.load(
            str(manifest_path), require_valid_hash=True)
        checker = ScopeChecker.from_manifest(manifest)

        self._checker = checker
        self._domains = [d.lower() for d in manifest.allow_patterns]
        self._excluded_classes = [c.lower() for c in manifest.excluded_classes]
        self.manifest = manifest
        self.manifest_path = str(manifest_path)
        self.mandatory_headers = {str(k): str(v)
                                  for k, v in (manifest.mandatory_headers or {}).items()}
        try:
            self.max_rps = float(manifest.max_rps)
        except (TypeError, ValueError):
            self.max_rps = None
        self.authorized = {d.lstrip("*.").lower() for d in self._domains if d}
        return {
            "program_handle": manifest.program_handle,
            "program_name": manifest.program_name,
            "auth_mode": manifest.auth_mode,
            "manifest_path": self.manifest_path,
            "manifest_sha256": manifest.manifest_sha256[:16],
            "allow_count": len(manifest.allow_patterns),
            "exclude_count": len(manifest.exclude_patterns),
            "excluded_classes": list(manifest.excluded_classes),
            "mandatory_headers": dict(self.mandatory_headers),
            "max_rps": self.max_rps,
        }

    def set_scope(self, domains: list[str], excluded_domains: list[str] | None = None) -> None:
        _ensure_path()
        from tools.scope_checker import ScopeChecker, ScopeError

        self._domains = [d.lower() for d in domains]
        try:
            self._checker = ScopeChecker(
                domains=self._domains,
                excluded_domains=excluded_domains or self._excluded,
                excluded_classes=self._excluded_classes,
            )
        except ScopeError as exc:
            # Dangerous scope config (e.g. a public-suffix wildcard). Leave the
            # checker unset so promote_asset() fails closed (BLOCK) rather than
            # widening scope. Surface the reason on stderr.
            import sys as _sys
            print(f"WARNING: rejected unsafe scope configuration: {exc}", file=_sys.stderr)
            self._checker = None
            self.authorized = set()
            return
        self.authorized = {d.lstrip("*.").lower() for d in self._domains if d}

    def note_discovered(self, host: str) -> None:
        h = host.lower().strip()
        if h and h not in self.authorized:
            self.discovered.add(h)

    def promote_asset(self, host: str) -> Decision:
        h = host.lower().strip()
        if not self._checker:
            return Decision(DecisionKind.BLOCK, "No scope configured", SCOPE_REQUIRED)
        if not self._checker.is_in_scope(h):
            return Decision(DecisionKind.BLOCK, f"{h} is out of scope", OUT_OF_SCOPE)
        self.authorized.add(h)
        self.discovered.discard(h)
        return Decision(DecisionKind.ALLOW, f"{h} authorized")

    def _approval_ok(self, args: dict[str, Any]) -> bool:
        if self.auto_approve:
            return True
        if args.get("approve") is True:
            return True
        token = str(args.get("approval_token") or "").strip()
        expected = os.environ.get("RHODAWK_MCP_APPROVAL_TOKEN", "").strip()
        return bool(expected and token and token == expected)

    def authorize_tool(self, tool: str, args: dict[str, Any]) -> Decision:
        meta = get_tool_meta(tool)
        target = str(args.get("target") or args.get("host") or "").strip()

        scope_domains = args.get("scope_domains") or args.get("domains")
        if scope_domains and isinstance(scope_domains, list) and scope_domains:
            self.set_scope([str(d) for d in scope_domains])
        # NOTE (Commit 3): there is deliberately NO fallback to [target] here.
        # When neither explicit scope_domains nor a previously loaded manifest
        # authorizes the session, requires_scope tools fail closed below with
        # SCOPE_REQUIRED — the server no longer self-authorizes the caller's
        # own target string as a scope pattern.

        if meta.requires_scope:
            if not self._domains or not self._checker:
                return Decision(
                    DecisionKind.BLOCK,
                    "Configure scope domains before active research",
                    SCOPE_REQUIRED,
                )
            if not target:
                return Decision(DecisionKind.BLOCK, "target is required", TARGET_REQUIRED)
            if not self._checker.is_in_scope(target):
                return Decision(DecisionKind.BLOCK, f"Target out of scope: {target}", OUT_OF_SCOPE)
            host = _host_of(target)
            if host in self.discovered and host not in self.authorized:
                if not self._checker.is_in_scope(host):
                    return Decision(
                        DecisionKind.BLOCK,
                        f"Host {host} is discovered but not authorized",
                        AUTHORIZATION_REQUIRED,
                        {"host": host, "state": "discovered"},
                    )
            self.authorized.add(host)

        if meta.external_action or meta.approval_level == ApprovalLevel.HIGH_RISK:
            if not self._approval_ok(args):
                return Decision(
                    DecisionKind.HIGH_RISK,
                    "External action requires explicit approval",
                    REPORT_APPROVAL_REQUIRED,
                )

        if meta.requires_approval or meta.active_testing:
            if not self._approval_ok(args):
                return Decision(
                    DecisionKind.REQUIRE_APPROVAL,
                    "Active testing requires approval "
                    "(pass approve=true or set RHODAWK_MCP_APPROVE=1)",
                    ACTIVE_TEST_APPROVAL_REQUIRED,
                    {"tool": tool, "target": target, "level": meta.approval_level.value},
                )

        return Decision(DecisionKind.ALLOW, "ok")

    def authorize_url(self, method: str, url: str) -> Decision:
        if not self._checker:
            return Decision(DecisionKind.BLOCK, "No scope configured", SCOPE_REQUIRED)
        if not self._checker.is_in_scope(url):
            return Decision(DecisionKind.BLOCK, f"URL out of scope: {url}", OUT_OF_SCOPE)
        try:
            from memory.audit_log import AutopilotGuard

            # scope_checker is a keyword arg (first positional is circuit_threshold);
            # check_request returns a dict whose "decision" key holds the verdict.
            guard = AutopilotGuard(scope_checker=self._checker, fail_closed=True)
            result = guard.check_request(method.upper(), url)
            decision = result.get("decision")
            if decision == "block":
                return Decision(
                    DecisionKind.BLOCK,
                    f"AutopilotGuard blocked request: {result.get('reason', '')}",
                    OUT_OF_SCOPE,
                )
            if decision == "require_approval":
                return Decision(
                    DecisionKind.REQUIRE_APPROVAL,
                    f"Method {method} requires approval",
                    ACTIVE_TEST_APPROVAL_REQUIRED,
                )
        except Exception as exc:  # noqa: BLE001
            return Decision(DecisionKind.BLOCK, f"Guard error: {exc}", AUTHORIZATION_REQUIRED)
        return Decision(DecisionKind.ALLOW, "ok")


def denied_payload(decision: Decision) -> dict[str, Any]:
    return {
        "status": "denied",
        "error": decision.error_code or "AUTHORIZATION_REQUIRED",
        "reason": decision.reason,
        "details": decision.details,
        "next_action": {
            SCOPE_REQUIRED: "Pass scope_domains, call rhodawk_compile_scope, or pass a manifest_path",
            OUT_OF_SCOPE: "Choose an in-scope target",
            TARGET_REQUIRED: "Provide target",
            ACTIVE_TEST_APPROVAL_REQUIRED: "Pass approve=true after researcher confirmation",
            REPORT_APPROVAL_REQUIRED: "Preview then approve submission separately",
            AUTHORIZATION_REQUIRED: "Promote discovered host only if scope allows",
        }.get(decision.error_code or "", "Fix the error and retry"),
    }
