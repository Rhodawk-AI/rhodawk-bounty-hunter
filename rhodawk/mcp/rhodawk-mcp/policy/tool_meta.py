"""Per-tool security metadata (hints + server-side policy inputs)."""

from __future__ import annotations

from dataclasses import dataclass

from .decisions import ApprovalLevel


@dataclass(frozen=True)
class ToolSecurity:
    read_only: bool = False
    active_testing: bool = False
    network_access: bool = False
    external_action: bool = False
    destructive: bool = False
    idempotent: bool = True
    requires_scope: bool = False
    requires_approval: bool = False
    approval_level: ApprovalLevel = ApprovalLevel.AUTO


TOOL_META: dict[str, ToolSecurity] = {
    "rhodawk_research": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "rhodawk_scope_check": ToolSecurity(read_only=True),
    "rhodawk_get_scope": ToolSecurity(read_only=True),
    "rhodawk_recon": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    # reconFTW gap-fill delegation (RhodawkAI Edition): same posture as recon —
    # scope-required (the adapter additionally fail-closes on its own gate),
    # approval required, network-touching, not read-only.
    "rhodawk_run_rtw_capability": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "rhodawk_attack_surface": ToolSecurity(read_only=True),
    "rhodawk_subdomains": ToolSecurity(read_only=True),
    "rhodawk_endpoints": ToolSecurity(read_only=True),
    "rhodawk_parameters": ToolSecurity(read_only=True),
    "rhodawk_hunt": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "rhodawk_hunt_class": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "rhodawk_list_findings": ToolSecurity(read_only=True),
    "rhodawk_get_finding": ToolSecurity(read_only=True),
    "rhodawk_validate": ToolSecurity(
        network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
    ),
    "rhodawk_get_validation": ToolSecurity(read_only=True),
    "rhodawk_generate_report": ToolSecurity(read_only=True),
    "rhodawk_get_report": ToolSecurity(read_only=True),
    "rhodawk_get_evidence": ToolSecurity(read_only=True),
    "rhodawk_memory_search": ToolSecurity(read_only=True),
    "rhodawk_memory_get": ToolSecurity(read_only=True),
    "rhodawk_memory_patterns": ToolSecurity(read_only=True),
    "rhodawk_leads": ToolSecurity(read_only=True),
    "rhodawk_next_lead": ToolSecurity(read_only=True),
    "rhodawk_update_lead": ToolSecurity(idempotent=False),
    "rhodawk_program": ToolSecurity(read_only=True, network_access=True),
    "rhodawk_program_policy": ToolSecurity(read_only=True, network_access=True),
    # Commit 3 additions. rhodawk_compile_scope fetches PUBLIC program data
    # (no target traffic) and writes local manifests — read-only w.r.t. the
    # target, network-touching. The two surface-slicing tools are strictly
    # local recon-artifact readers.
    "rhodawk_compile_scope": ToolSecurity(read_only=True, network_access=True),
    "rhodawk_prioritized_surface": ToolSecurity(read_only=True),
    "rhodawk_inspect_endpoint_slice": ToolSecurity(read_only=True),
}


def get_tool_meta(name: str) -> ToolSecurity:
    return TOOL_META.get(
        name,
        ToolSecurity(
            requires_approval=True,
            approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        ),
    )


def list_tool_catalog() -> list[dict]:
    """Flat catalog for `rhodawk mcp tools`."""
    rows = []
    for name, meta in sorted(TOOL_META.items()):
        rows.append({
            "tool": name,
            "read_only": meta.read_only,
            "active_testing": meta.active_testing,
            "network_access": meta.network_access,
            "external_action": meta.external_action,
            "requires_scope": meta.requires_scope,
            "requires_approval": meta.requires_approval,
            "approval_level": meta.approval_level.value,
        })
    return rows
