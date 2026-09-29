"""Capability-scoped authorization primitives for AgentShield.

A content detector does not grant authority. Every proposed action must fit inside an
explicit capability grant issued by the surrounding application/user workflow.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .actions import ActionDescriptor, normalize_capabilities


class ScopeStatus(str, Enum):
    PERMITTED = "permitted"
    DENIED = "denied"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AuthorizationScope:
    """Least-privilege capability grant attached to one originating task/workflow."""

    grant_id: str
    allowed_capabilities: tuple[str, ...]
    issuer: str = "user"

    def __post_init__(self) -> None:
        grant_id = self.grant_id.strip()
        issuer = self.issuer.strip()
        if not grant_id:
            raise ValueError("grant_id must be non-empty")
        if not issuer:
            raise ValueError("issuer must be non-empty")
        object.__setattr__(self, "grant_id", grant_id)
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(
            self,
            "allowed_capabilities",
            normalize_capabilities(self.allowed_capabilities),
        )


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
