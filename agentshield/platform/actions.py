"""Action-risk primitives for AgentShield policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .policy import ActionRisk


SENSITIVE_CAPABILITIES = frozenset(
    {
        "send_message",
        "publish",
        "purchase",
        "transfer_funds",
        "disclose_private_data",
        "delete_data",
        "overwrite_data",
        "execute_code",
        "modify_permissions",
        "deploy",
        "sign",
        "submit_transaction",
    }
)


@dataclass(frozen=True)
class ActionDescriptor:
    name: str
    capabilities: tuple[str, ...] = ()


def classify_action(action: ActionDescriptor) -> ActionRisk:
    """Classify action consequence from declared capabilities.

    Unknown/missing declarations are REVIEW-safe rather than ALLOW-safe.
    """

    if not action.name.strip():
        return ActionRisk.UNKNOWN
    if not action.capabilities:
        return ActionRisk.UNKNOWN

    caps = {c.strip().lower() for c in action.capabilities if c.strip()}
    if not caps:
        return ActionRisk.UNKNOWN
    if caps & SENSITIVE_CAPABILITIES:
        return ActionRisk.SENSITIVE
    return ActionRisk.NORMAL


def normalize_capabilities(values: Iterable[str]) -> tuple[str, ...]:
    """Normalize a tool/action capability declaration deterministically."""

    return tuple(sorted({v.strip().lower() for v in values if v and v.strip()}))
