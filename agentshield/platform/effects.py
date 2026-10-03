"""Exact-effect authorization issued by trusted host infrastructure.

The digest binds a canonical tool identity, manifest and complete payload. It is
not a permission token by itself: the host must independently approve the effect
and issue a scope containing it through its server-owned grant authority.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .actions import ActionDescriptor, normalize_capabilities
from .authorization import AuthorizationScope, ScopeStatus
from .integrity import action_digest, payload_digest, tool_manifest_digest
from .tools import ToolManifest

EFFECT_SCHEMA_VERSION = "agentshield-effect-v1"


def effect_digest(
    *, action: ActionDescriptor, payload: Mapping[str, Any] | None, manifest: ToolManifest,
) -> str:
    """Bind the exact host-approved effect before issuing its authorization grant.

    The adapter must resolve resource identity/tenant and destination semantics
    before approval; this generic primitive does not resolve paths, URLs or DNS.
    """
    return effect_digest_from_payload_digest(
        action=action, submitted_payload_digest=payload_digest(payload), manifest=manifest,
    )


def effect_digest_from_payload_digest(
    *, action: ActionDescriptor, submitted_payload_digest: str, manifest: ToolManifest,
) -> str:
    """Runtime helper operating on a digest already captured by the gateway."""
    if (
        action.name != manifest.name
        or normalize_capabilities(action.capabilities) != manifest.capabilities
    ):
        raise ValueError("effect action must exactly match the authoritative tool manifest")
    # All components are fixed-format hashes; the version separates this domain
    # from payload/scope hashes. No raw resource or recipient data is persisted.
    material = "\n".join((
        EFFECT_SCHEMA_VERSION, action_digest(action), submitted_payload_digest,
        tool_manifest_digest(manifest),
    ))
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def check_effect_scope(effect: str | None, scope: AuthorizationScope | None) -> ScopeStatus:
    if scope is None or not scope.allowed_effects or effect is None:
        return ScopeStatus.UNKNOWN
    return ScopeStatus.PERMITTED if effect in scope.allowed_effects else ScopeStatus.DENIED
