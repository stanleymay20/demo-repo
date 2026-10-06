"""Fail-closed execution boundary for AgentShield.

The policy decision is not advisory: side effects are dispatched only after an ALLOW
decision, or after an exact REVIEW decision receives a valid cryptographically-bound
human approval. Action, payload, grant and tool state are re-verified immediately before
dispatch. Single-use grants are consumed before the side effect.

In-process evaluations carry a process-local integrity seal. Detached evaluations must
carry a valid Ed25519 signature from a configured evaluation service; unsigned detached
ALLOW/REVIEW results fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .actions import ActionDescriptor, classify_action
from .authorization import AuthorizationScope, ScopeStatus, check_action_scope
from .events import evaluation_digest
from .effects import check_effect_scope, effect_digest_from_payload_digest
from .grants import GrantAuthorityProtocol, GrantStatus, grant_record_digest
from .integrity import (
    action_digest, payload_digest, scope_digest, snapshot_payload, tool_manifest_digest,
)
from .pipeline import PipelineResult, verify_in_process_evaluation
from .policy import Decision, POLICY_VERSION
from .review import ReviewApproval, ReviewAuthority, ReviewStatus, review_approval_digest
from .signing import EvaluationSignature, EvaluationSignatureStatus, EvaluationVerifier
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
    review_approval_id: str | None = None
    review_approval_digest: str | None = None


def enforce_and_execute(
    *,
    pipeline_result: PipelineResult,
    action: ActionDescriptor,
    payload: Mapping[str, Any],
    executor: ToolExecutor,
    authorization_scope: AuthorizationScope | None = None,
    tool_registry: ToolRegistry | None = None,
    grant_authority: GrantAuthorityProtocol | None = None,
    review_approval: ReviewApproval | None = None,
    review_authority: ReviewAuthority | None = None,
    evaluation_signature: EvaluationSignature | None = None,
    evaluation_verifier: EvaluationVerifier | None = None,
) -> ExecutionResult:
    """Dispatch only when the evaluated authority still matches and remains valid."""

    decision = pipeline_result.policy.decision
    if (
        pipeline_result.policy.policy_version != POLICY_VERSION
        or pipeline_result.audit_event.policy_version != POLICY_VERSION
    ):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED, decision=decision,
            reason="policy version is stale or inconsistent; reevaluate the request",
        )
    try:
        # A private deep snapshot closes the check/dispatch mutation window.
        # Never pass the original mapping or nested caller-owned values onward.
        execution_payload = snapshot_payload(payload)
        current_payload_digest = payload_digest(execution_payload)
    except ValueError:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action payload is not a valid canonical JSON object",
        )
    event = pipeline_result.audit_event
    metadata = event.metadata or {}
    recorded_action = metadata.get("action_name")
    recorded_action_digest = metadata.get("action_digest")
    recorded_payload_digest = metadata.get("payload_digest")
    recorded_grant_id = metadata.get("authorization_grant_id")
    recorded_scope_digest = metadata.get("authorization_scope_digest")
    recorded_grant_record_digest = metadata.get("grant_record_digest")
    recorded_tool_manifest_digest = metadata.get("tool_manifest_digest")
    current_action_risk = classify_action(action).value

    if recorded_action != action.name:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action identity changed after policy evaluation",
        )

    current_action_digest = action_digest(action)
    if not recorded_action_digest or recorded_action_digest != current_action_digest:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="action descriptor changed after policy evaluation",
        )

    if not recorded_payload_digest or recorded_payload_digest != current_payload_digest:
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

    current_manifest_digest = tool_manifest_digest(manifest)
    if (
        not recorded_tool_manifest_digest
        or recorded_tool_manifest_digest != current_manifest_digest
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

    current_scope_digest = scope_digest(authorization_scope)
    if not recorded_scope_digest or recorded_scope_digest != current_scope_digest:
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

    current_effect_digest = effect_digest_from_payload_digest(
        action=action, submitted_payload_digest=current_payload_digest, manifest=manifest,
    )
    if (
        metadata.get("effect_digest") != current_effect_digest
        or check_effect_scope(current_effect_digest, authorization_scope) is not ScopeStatus.PERMITTED
    ):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED, decision=decision,
            reason="exact effect is not permitted by the authorization scope",
        )

    if grant_authority is None:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="authoritative grant registry missing at execution",
        )

    grant_status, grant_record = grant_authority.verify(authorization_scope)
    if grant_status is not GrantStatus.VALID or grant_record is None:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason=f"authorization grant is not executable: {grant_status.value}",
        )

    if (
        not recorded_grant_record_digest
        or recorded_grant_record_digest != grant_record_digest(grant_record)
    ):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="authoritative grant record changed after policy evaluation",
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
    if event.reason != pipeline_result.policy.reason:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="audit reason does not match pipeline policy",
        )
    if (
        event.content_risk != pipeline_result.detection.content_risk.value
        or event.detector_name != pipeline_result.detection.detector_name
        or event.detector_version != pipeline_result.detection.detector_version
        or event.detector_score != pipeline_result.detection.score
    ):
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="audit detector evidence does not match pipeline detection",
        )

    # BLOCK cannot create a side effect, so it is safe to honor even when it arrived
    # detached. Any decision that could progress toward execution must be authenticated.
    if decision is not Decision.BLOCK and not verify_in_process_evaluation(pipeline_result):
        if evaluation_signature is None or evaluation_verifier is None:
            return ExecutionResult(
                status=ExecutionStatus.BLOCKED,
                decision=decision,
                reason="detached evaluation is unsigned or has no trusted verifier",
            )
        signature_status = evaluation_verifier.verify(pipeline_result, evaluation_signature)
        if signature_status is not EvaluationSignatureStatus.VALID:
            return ExecutionResult(
                status=ExecutionStatus.BLOCKED,
                decision=decision,
                reason=f"detached evaluation authentication failed: {signature_status.value}",
            )

    if decision is Decision.BLOCK:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason=pipeline_result.policy.reason,
        )

    approved_review: ReviewApproval | None = None
    if decision is Decision.REVIEW:
        if not grant_record.single_use:
            return ExecutionResult(
                status=ExecutionStatus.BLOCKED,
                decision=decision,
                reason="human-review execution requires a single-use grant",
            )
        if review_approval is None or review_authority is None:
            return ExecutionResult(
                status=ExecutionStatus.HELD_FOR_REVIEW,
                decision=decision,
                reason=pipeline_result.policy.reason,
            )
        try:
            reviewed_evaluation_digest = evaluation_digest(event)
        except ValueError:
            return ExecutionResult(
                status=ExecutionStatus.BLOCKED, decision=decision,
                reason="evaluation evidence bindings are missing or invalid; reevaluate",
            )
        review_status = review_authority.verify(
            review_approval,
            request_id=event.request_id,
            action_digest=current_action_digest,
            payload_digest=current_payload_digest,
            scope_digest=current_scope_digest,
            tool_manifest_digest=current_manifest_digest,
            policy_version=pipeline_result.policy.policy_version,
            evaluation_digest=reviewed_evaluation_digest,
        )
        if review_status is not ReviewStatus.VALID:
            return ExecutionResult(
                status=ExecutionStatus.BLOCKED,
                decision=decision,
                reason=f"human review approval is not executable: {review_status.value}",
            )
        approved_review = review_approval
    elif decision is not Decision.ALLOW:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason="unknown policy decision failed closed",
        )

    consume_status, _ = grant_authority.consume(authorization_scope)
    if consume_status is not GrantStatus.VALID:
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            decision=decision,
            reason=f"authorization grant could not be consumed: {consume_status.value}",
        )

    output = executor.execute(action_name=action.name, payload=execution_payload)
    if approved_review is None:
        reason = "policy allowed action; grant consumed and all execution integrity checks passed"
        approval_id = None
        approval_digest = None
    else:
        reason = "human review approved the exact held action; grant consumed and all execution integrity checks passed"
        approval_id = approved_review.approval_id
        approval_digest = review_approval_digest(approved_review)

    return ExecutionResult(
        status=ExecutionStatus.EXECUTED,
        decision=decision,
        reason=reason,
        output=output,
        review_approval_id=approval_id,
        review_approval_digest=approval_digest,
    )
