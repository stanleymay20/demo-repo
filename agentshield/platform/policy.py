"""Versioned policy engine for AgentShield.

Detection, provenance, capability scope, authoritative grant lifecycle, authoritative
tool metadata and action consequence are deliberately separate inputs. A detector emits
risk evidence; it never grants authority, and an agent cannot self-declare a weaker
capability set or manufacture a grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .provenance import TrustLevel

POLICY_VERSION = "agentshield-policy-v3"


class ContentRisk(str, Enum):
    LOW = "low"
    HIGH = "high"
    UNKNOWN = "unknown"


class ActionRisk(str, Enum):
    NORMAL = "normal"
    SENSITIVE = "sensitive"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True)
class PolicyInput:
    content_risk: ContentRisk
    action_risk: ActionRisk
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    scope_permitted: bool | None = None
    tool_verified: bool | None = None
    grant_valid: bool | None = None


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    policy_version: str
    reason: str


def decide(value: PolicyInput) -> PolicyDecision:
    """Return the deterministic policy-v3 decision for one request."""

    if value.tool_verified is False:
        return PolicyDecision(
            decision=Decision.BLOCK,
            policy_version=POLICY_VERSION,
            reason="tool capability declaration is unregistered or mismatches the authoritative manifest",
        )

    if value.grant_valid is False:
        return PolicyDecision(
            decision=Decision.BLOCK,
            policy_version=POLICY_VERSION,
            reason="authorization grant is invalid, expired, revoked, consumed, or unknown to the authority",
        )

    if value.scope_permitted is False:
        return PolicyDecision(
            decision=Decision.BLOCK,
            policy_version=POLICY_VERSION,
            reason="requested action capabilities exceed the authorization scope",
        )

    if (
        value.content_risk is ContentRisk.HIGH
        and value.action_risk is ActionRisk.SENSITIVE
    ):
        return PolicyDecision(
            decision=Decision.BLOCK,
            policy_version=POLICY_VERSION,
            reason="high content risk combined with a sensitive action",
        )

    if value.tool_verified is None:
        return PolicyDecision(
            decision=Decision.REVIEW,
            policy_version=POLICY_VERSION,
            reason="authoritative tool verification is missing or indeterminate",
        )

    if value.grant_valid is None:
        return PolicyDecision(
            decision=Decision.REVIEW,
            policy_version=POLICY_VERSION,
            reason="authoritative grant verification is missing or indeterminate",
        )

    if value.scope_permitted is None:
        return PolicyDecision(
            decision=Decision.REVIEW,
            policy_version=POLICY_VERSION,
            reason="authorization scope is missing or indeterminate",
        )

    if value.trust_level is TrustLevel.UNKNOWN:
        return PolicyDecision(
            decision=Decision.REVIEW,
            policy_version=POLICY_VERSION,
            reason="input provenance trust is unknown",
        )

    if (
        value.content_risk is ContentRisk.LOW
        and value.action_risk is ActionRisk.NORMAL
    ):
        return PolicyDecision(
            decision=Decision.ALLOW,
            policy_version=POLICY_VERSION,
            reason="low content risk, verified tool, live grant, known provenance and an in-scope normal action",
        )

    return PolicyDecision(
        decision=Decision.REVIEW,
        policy_version=POLICY_VERSION,
        reason="mixed, elevated, or unknown risk requires review",
    )
