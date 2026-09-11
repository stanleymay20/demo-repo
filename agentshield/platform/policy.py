"""Versioned policy engine for AgentShield.

Detection, provenance, capability scope and action consequence are deliberately separate
inputs. A detector emits risk evidence; it never grants authority.

Policy v2 rules:
- an action outside its explicit capability grant -> BLOCK;
- a missing/indeterminate grant -> REVIEW;
- HIGH content + SENSITIVE action -> BLOCK;
- LOW content + NORMAL action may ALLOW only with known provenance and in-scope authority;
- every other mixed, elevated or UNKNOWN state -> REVIEW.

UNKNOWN never silently degrades to ALLOW.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .provenance import TrustLevel

POLICY_VERSION = "agentshield-policy-v2"


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


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    policy_version: str
    reason: str


def decide(value: PolicyInput) -> PolicyDecision:
    """Return the deterministic policy-v2 decision for one request."""

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
            reason="low content risk, known provenance and an in-scope normal action",
        )

    return PolicyDecision(
        decision=Decision.REVIEW,
        policy_version=POLICY_VERSION,
        reason="mixed, elevated, or unknown risk requires review",
    )
