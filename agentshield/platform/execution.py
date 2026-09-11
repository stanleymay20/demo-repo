"""Fail-closed execution boundary for AgentShield.

The policy decision is not advisory: side effects are dispatched only after an ALLOW
decision whose action, payload, least-privilege grant and authoritative tool manifest
still match evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .actions import ActionDescriptor, classify_action
from .authorization import AuthorizationScope, ScopeStatus, check_action_scope
from .integrity import action_digest, payload_digest, scope_digest, tool_manifest_digest
from .pipeline import PipelineResult
from .policy import Decision
from .tools import ToolRegistry, ToolVerificationStatus, verify_action_descriptor


class ExecutionStatus(str, Enum):
    EXECUTED = "executed"
    HELD_FOR_REVIEW = "held_for_review"
    BLOCKED = "blocked"


class ToolExecutor(Protocol):
    def execute(self, *, action_name: str, payload: Mapping[str, Any]) -> Any: ...


@dataclass(frozen=True)
class ExecutionResult:
    status: ExecutionStatus
    decision: Decision
    reason: str
    output: Any | None = None


def enforce_and_execute(
    *,
    pipeline_result: PipelineResult,
    action: ActionDescriptor,
    payload: Mapping[str, Any],
    executor: ToolExecutor,
    authorization_scope: AuthorizationScope | None = None,
    tool_registry: ToolRegistry | None = None,
) -> ExecutionResult:
    """Dispatch a tool call only when the evaluated request remains ALLOW-safe."""

    decision = pipeline_result.policy.decision
    event = pipeline_result.audit_event
    metadata = event.metadata or {}
    recorded_action = metadata.get("action_name")
    recorded_action_digest = metadata.get("action_digest")
    recorded_payload_digest = metadata.get("payload_digest")
    recorded_grant_id = metadata.get("authorization_grant_id")
    recorded_scope_digest = metadata.get("authorization_scope_digest")
    recorded_tool_manifest_digest = metadata.get("tool_manifest_digest")
    current_action_risk = classify_action(action).value

    if recorded_action != action.name:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action identity changed after policy evaluation",
        )

    if not recorded_action_digest or recorded_action_digest != action_digest(action):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action descriptor changed after policy evaluation",
        )

    if not recorded_payload_digest or recorded_payload_digest != payload_digest(payload):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action payload changed after policy evaluation",
        )

    if tool_registry is None:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="authoritative tool registry missing at execution",
        )

    tool_status, manifest = verify_action_descriptor(action, tool_registry)
    if tool_status is not ToolVerificationStatus.VERIFIED or manifest is None:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="tool is no longer verified by the authoritative registry",
        )

    if (
        not recorded_tool_manifest_digest
        or recorded_tool_manifest_digest != tool_manifest_digest(manifest)
    ):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="authoritative tool manifest changed after policy evaluation",
        )

    if authorization_scope is None:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="authorization scope missing at execution",
        )

    if recorded_grant_id != authorization_scope.grant_id:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="authorization grant changed after policy evaluation",
        )

    if (
        not recorded_scope_digest
        or recorded_scope_digest != scope_digest(authorization_scope)
    ):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="authorization scope changed after policy evaluation",
        )

    if check_action_scope(action, authorization_scope) is not ScopeStatus.PERMITTED:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action is no longer permitted by the authorization scope",
        )

    if event.action_risk != current_action_risk:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action risk changed after policy evaluation",
        )

    if event.decision != decision.value:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="audit decision does not match pipeline decision",
        )

    if decision is Decision.BLOCK:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason=pipeline_result.policy.reason,
        )

    if decision is Decision.REVIEW:
        return ExecutionResult(
            status=ExecutionStatus.HELD_FOR_REVIEW,
            decision=decision,
            reason=pipeline_result.policy.reason,
        )

    if decision is not Decision.ALLOW:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="unknown policy decision failed closed",
        )

    output = executor.execute(action_name=action.name, payload=payload)
    return ExecutionResult(
        status=ExecutionStatus.EXECUTED,
        decision=decision,
        reason="policy allowed action and all execution integrity checks passed",
        output=output,
    )
