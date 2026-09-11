"""Versioned policy engine for AgentShield.

This module deliberately separates *detection* from *authorization*. A detector emits
content risk; the application supplies action risk; policy combines the two.

Policy v1 is intentionally small and auditable:
- LOW content + NORMAL action -> ALLOW
- HIGH content + SENSITIVE action -> BLOCK
- every mixed or UNKNOWN state -> REVIEW

UNKNOWN never silently degrades to ALLOW.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

POLICY_VERSION = "agentshield-policy-v1"


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


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    policy_version: str
    reason: str


def decide(value: PolicyInput) -> PolicyDecision:
    """Return the deterministic policy-v1 decision for one request."""

    if (
        value.content_risk is ContentRisk.HIGH
        and value.action_risk is ActionRisk.SENSITIVE
    ):
        return PolicyDecision(
            decision=Decision.BLOCK,
            policy_version=POLICY_VERSION,
            reason="high content risk combined with a sensitive action",
        )

    if (
        value.content_risk is ContentRisk.LOW
        and value.action_risk is ActionRisk.NORMAL
    ):
        return PolicyDecision(
            decision=Decision.ALLOW,
            policy_version=POLICY_VERSION,
            reason="low content risk combined with a normal action",
        )

    return PolicyDecision(
        decision=Decision.REVIEW,
        policy_version=POLICY_VERSION,
        reason="mixed, elevated, or unknown risk requires review",
    )
