"""Fail-closed execution boundary for AgentShield.

The policy decision is not advisory: sensitive side effects are only dispatched after
an ALLOW decision whose action metadata still matches the evaluated request.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .actions import ActionDescriptor, classify_action
from .pipeline import PipelineResult
from .policy import Decision


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
) -> ExecutionResult:
    """Dispatch a tool call only when the evaluated request remains ALLOW-safe.

    Integrity mismatches fail closed. REVIEW and BLOCK never reach the executor.
    Raw untrusted content is not required at this boundary.
    """

    decision = pipeline_result.policy.decision
    event = pipeline_result.audit_event
    metadata = event.metadata or {}
    recorded_action = metadata.get("action_name")
    current_action_risk = classify_action(action).value

    if recorded_action != action.name:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action identity changed after policy evaluation",
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
        reason="policy allowed action and execution integrity checks passed",
        output=output,
    )
