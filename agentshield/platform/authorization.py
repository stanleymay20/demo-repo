"""Capability-scoped authorization primitives for AgentShield.

A content detector does not grant authority. Every proposed action must fit inside an
explicit capability grant issued by the surrounding application/user workflow.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from .actions import ActionDescriptor, normalize_capabilities


class ScopeStatus(str, Enum):
    PERMITTED = "permitted"
    DENIED = "denied"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AuthorizationScope:
    """Host-issued identity, capabilities and exact effects for one task/workflow.

    ``issuer`` identifies the authority that minted the grant. ``principal`` identifies
    the end-user or service on whose behalf the agent is acting. ``tenant`` optionally
    identifies the containing organization/account. Principal and tenant are bound into
    the scope digest and must survive delegation unchanged.
    """

    grant_id: str
    allowed_capabilities: tuple[str, ...]
    issuer: str = "user"
    allowed_effects: tuple[str, ...] = ()
    principal: str | None = None
    tenant: str | None = None

    def __post_init__(self) -> None:
        grant_id = self.grant_id.strip()
        issuer = self.issuer.strip()
        if not grant_id:
            raise ValueError("grant_id must be non-empty")
        if not issuer:
            raise ValueError("issuer must be non-empty")
        object.__setattr__(self, "grant_id", grant_id)
        object.__setattr__(self, "issuer", issuer)
        for field in ("principal", "tenant"):
            value = getattr(self, field)
            if value is not None:
                if type(value) is not str or not value.strip():
                    raise ValueError(f"{field} must be a non-empty string when present")
                object.__setattr__(self, field, value.strip())
        object.__setattr__(
            self,
            "allowed_capabilities",
            normalize_capabilities(self.allowed_capabilities),
        )
        effects = tuple(self.allowed_effects)
        if any(
            type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in effects
        ):
            raise ValueError("allowed_effects must contain lowercase SHA-256 digests")
        object.__setattr__(self, "allowed_effects", tuple(sorted(set(effects))))


def check_action_scope(
    action: ActionDescriptor,
    scope: AuthorizationScope | None,
) -> ScopeStatus:
    """Return whether the action's declared capabilities fit the frozen grant."""

    if scope is None:
        return ScopeStatus.UNKNOWN

    requested = normalize_capabilities(action.capabilities)
    if not requested:
        return ScopeStatus.UNKNOWN

    allowed = set(scope.allowed_capabilities)
    return (
        ScopeStatus.PERMITTED
        if set(requested).issubset(allowed)
        else ScopeStatus.DENIED
    )
