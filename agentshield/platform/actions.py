"""Action-risk primitives for AgentShield policy evaluation.

Capability labels are an explicit security taxonomy. A new or misspelled capability
must never become automatically executable merely because it is absent from the
sensitive list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .policy import ActionRisk


NORMAL_CAPABILITIES = frozenset(
    {
        "read_data",
        "transform_text",
        "classify_text",
        "summarize",
        "local_compute",
        "list_metadata",
    }
)

SENSITIVE_CAPABILITIES = frozenset(
    {
        "send_message",
        "publish",
        "purchase",
        "transfer_funds",
        "disclose_private_data",
        "read_secrets",
        "delete_data",
        "overwrite_data",
        "write_data",
        "create_external_state",
        "network_access",
        "execute_code",
        "execute_command",
        "start_process",
        "modify_permissions",
        "modify_authentication",
        "deploy",
        "sign",
        "submit_transaction",
        "install_software",
        "control_device",
    }
)


@dataclass(frozen=True)
class ActionDescriptor:
    name: str
    capabilities: tuple[str, ...] = ()


def classify_action(action: ActionDescriptor) -> ActionRisk:
    """Classify consequence from a closed, versioned capability taxonomy.

    Sensitive capabilities dominate. An action is NORMAL only when every declared
    capability is explicitly allow-listed as normal. Any unknown capability is UNKNOWN,
    which policy routes to review rather than automatic execution.
    """

    if not action.name.strip():
        return ActionRisk.UNKNOWN

    caps = set(normalize_capabilities(action.capabilities))
    if not caps:
        return ActionRisk.UNKNOWN
    if caps & SENSITIVE_CAPABILITIES:
        return ActionRisk.SENSITIVE
    if caps.issubset(NORMAL_CAPABILITIES):
        return ActionRisk.NORMAL
    return ActionRisk.UNKNOWN


def normalize_capabilities(values: Iterable[str]) -> tuple[str, ...]:
    """Normalize a tool/action capability declaration deterministically."""

    return tuple(sorted({v.strip().lower() for v in values if v and v.strip()}))
