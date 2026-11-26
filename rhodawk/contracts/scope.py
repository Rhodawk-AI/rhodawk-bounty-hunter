"""scope.py — typed scope contract for RhodawkAI Bounty Hunter (Commit 2).

`CompiledScopeManifest` is the single canonical representation of a program
scope. Invariants are enforced in ``__post_init__`` so an instance can never
exist in a non-canonical state:

  - native ``*.`` wildcards are preserved verbatim (never stripped) —
    ``*.cloudflare.com`` keeps its apex-excluding semantics;
  - ``allow_patterns``, ``exclude_patterns`` and ``excluded_classes`` are
    deduplicated and sorted (deterministic byte-stable output);
  - the denylist always wins: any pattern present in ``exclude_patterns`` is
    removed from ``allow_patterns``;
  - ``manifest_sha256`` is a deterministic SHA-256 over the canonical JSON
    (``sort_keys=True``, compact separators, the hash field itself excluded).

Integrity:
  - ``verify_integrity()`` re-hashes the current content and compares it with
    the stored hash (catches post-construction mutations);
  - ``CompiledScopeManifest.load(path)`` validates the hash stored in the file
    against the file content and raises ``ValueError`` on mismatch (tamper
    detection), unless ``require_valid_hash=False``.

Trust model (see hooks/README.md for the consumer-facing version): the
self-hash is tamper-EVIDENT — it detects accidental drift, truncation, and
hand-edits — but it is not a signature. A local attacker with write access to
the manifest file can rewrite the content and recompute ``manifest_sha256``.
Trust is anchored in the filesystem: whoever can write the manifest can
authorize that scope, so the data home must be permission-protected (the
installer applies 0700/0600). The hash guarantees "this file is byte-for-byte
what was compiled"; it cannot guarantee "who compiled it was authorized".

Zero secret leakage: this contract carries scope geometry (hosts, wildcards,
CIDRs, paths, policy rules) only — no tokens, no credentials, no auth headers.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["ScopeAssetMeta", "CompiledScopeManifest"]

SCHEMA_VERSION = "1.0"


@dataclass
class ScopeAssetMeta:
    """One structured-scope asset exactly as the platform reported it."""

    asset_identifier: str = ""
    asset_type: str = ""
    eligible_for_submission: bool = True
    eligible_for_bounty: bool = False
    max_severity: str = ""
    instruction: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _canonical_json(payload: dict) -> str:
    """Canonical JSON: sorted keys, compact separators, UTF-8 safe."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _sha256_of_payload(payload: dict) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass
class CompiledScopeManifest:
    """Deterministic, self-verifying program-scope contract (schema 1.0).

    Constructing one normalizes the content and (re)computes
    ``manifest_sha256`` over the canonical form, so two manifests compiled
    from the same inputs hash identically regardless of insertion order.
    """

    program_handle: str = ""
    program_name: str = ""
    auth_mode: str = "keyless_public"
    sources: list = field(default_factory=list)
    allow_patterns: list = field(default_factory=list)
    exclude_patterns: list = field(default_factory=list)
    excluded_classes: list = field(default_factory=list)
    mandatory_headers: dict = field(default_factory=dict)
    max_rps: float = 5.0
    assets_metadata: list = field(default_factory=list)
    drift_audit: list = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""
    manifest_sha256: str = ""

    # ── invariants ────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_patterns(values) -> list[str]:
        """Whitespace-trim, drop empties, dedupe (stable), sort.

        Native ``*.``, CIDR and path forms pass through untouched — this
        contract never strips wildcards or rewrites identifiers.
        """
        seen: dict[str, None] = {}
        for raw in values or []:
            pat = str(raw).strip()
            if pat:
                seen.setdefault(pat, None)
        return sorted(seen)

    def __post_init__(self):
        self.program_handle = str(self.program_handle or "").strip().lower()
        self.program_name = str(self.program_name or "")
        self.auth_mode = str(self.auth_mode or "keyless_public")
        self.sources = [str(s) for s in (self.sources or [])]

        self.allow_patterns = self._normalize_patterns(self.allow_patterns)
        self.exclude_patterns = self._normalize_patterns(self.exclude_patterns)
        self.excluded_classes = sorted({
            str(c).strip().lower()
            for c in (self.excluded_classes or []) if str(c).strip()
        })
        self.mandatory_headers = {str(k): str(v)
                                  for k, v in (self.mandatory_headers or {}).items()}

        # Denylist always wins — never test what the program excluded.
        excluded = set(self.exclude_patterns)
        self.allow_patterns = [p for p in self.allow_patterns if p not in excluded]

        coerced_assets = []
        for asset in (self.assets_metadata or []):
            if isinstance(asset, dict):
                asset = ScopeAssetMeta(
                    asset_identifier=str(asset.get("asset_identifier") or ""),
                    asset_type=str(asset.get("asset_type") or ""),
                    eligible_for_submission=bool(asset.get("eligible_for_submission", True)),
                    eligible_for_bounty=bool(asset.get("eligible_for_bounty", False)),
                    max_severity=str(asset.get("max_severity") or ""),
                    instruction=str(asset.get("instruction") or ""),
                )
            coerced_assets.append(asset)
        self.assets_metadata = coerced_assets

        self.drift_audit = [dict(d) if isinstance(d, dict) else {"detail": str(d)}
                            for d in (self.drift_audit or [])]

        try:
            self.max_rps = float(self.max_rps)
        except (TypeError, ValueError):
            self.max_rps = 5.0

        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        # Canonical hash over the post-invariant content — always consistent
        # with the fields actually stored.
        self.manifest_sha256 = self.compute_sha256()

    # ── integrity ─────────────────────────────────────────────────────────

    def compute_sha256(self) -> str:
        """SHA-256 over canonical JSON of the content, hash field excluded."""
        payload = self.to_dict()
        payload.pop("manifest_sha256", None)
        return _sha256_of_payload(payload)

    def verify_integrity(self) -> bool:
        """True when the stored hash still matches the current content."""
        return self.manifest_sha256 == self.compute_sha256()

    # ── serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data["assets_metadata"] = [a.to_dict() if isinstance(a, ScopeAssetMeta)
                                   else dict(a) for a in self.assets_metadata]
        return data

    def save(self, path) -> Path:
        """Write the manifest as canonical-ish JSON; refresh hash first."""
        self.manifest_sha256 = self.compute_sha256()
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
                     encoding="utf-8")
        return p

    @classmethod
    def load(cls, path, require_valid_hash: bool = True) -> "CompiledScopeManifest":
        """Load a manifest and verify its integrity against the file content.

        Raises ``ValueError`` when the stored ``manifest_sha256`` does not
        match the stored content (tamper detection) and
        ``require_valid_hash=True`` (the default).
        """
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"manifest at {path} is not a JSON object")
        stored = str(raw.pop("manifest_sha256", "") or "")
        known = {f.name for f in dataclasses.fields(cls)}
        fields = {k: v for k, v in raw.items() if k in known}
        # Verify against the content this schema version actually consumes —
        # a stale or hand-edited hash over a modified payload must fail loudly.
        expected = _sha256_of_payload(fields)
        if require_valid_hash and stored != expected:
            raise ValueError(
                f"manifest_sha256 mismatch for {path}: manifest was modified "
                f"after compilation (expected {expected[:16]}..., "
                f"file has {stored[:16]}...)")
        return cls(manifest_sha256=stored, **fields)
