"""Structured, versioned audit events for AgentShield decisions and execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .policy import ActionRisk, ContentRisk, POLICY_VERSION, PolicyDecision

EVENT_SCHEMA_VERSION = "agentshield-audit-event-v1"
EXECUTION_EVENT_SCHEMA_VERSION = "agentshield-execution-audit-event-v2"


@dataclass(frozen=True)
class AuditEvent:
    event_schema_version: str
    timestamp_utc: str
    request_id: str
    source_type: str
    content_risk: str
    action_risk: str
    decision: str
    policy_version: str
    reason: str
    detector_name: str | None = None
    detector_version: str | None = None
    detector_score: float | None = None
    metadata: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExecutionAuditEvent:
    """No-raw-payload evidence for one decision/execution lifecycle transition."""

    event_schema_version: str
    timestamp_utc: str
    request_id: str
    evaluation_digest: str
    action_name: str
    decision: str
    phase: str
    status: str
    grant_id: str
    effect_digest: str
    policy_version: str = POLICY_VERSION
    grant_record_digest: str | None = None
    review_approval_digest: str | None = None
    exception_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_audit_event(
    *,
    request_id: str,
    source_type: str,
    content_risk: ContentRisk,
    action_risk: ActionRisk,
    policy_decision: PolicyDecision,
    detector_name: str | None = None,
    detector_version: str | None = None,
    detector_score: float | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> AuditEvent:
    """Create a UTC audit event without including raw untrusted content."""

    if not request_id.strip():
        raise ValueError("request_id must be non-empty")
    if not source_type.strip():
        raise ValueError("source_type must be non-empty")
    if detector_score is not None and not 0.0 <= detector_score <= 1.0:
        raise ValueError("detector_score must be between 0 and 1")

    return AuditEvent(
        event_schema_version=EVENT_SCHEMA_VERSION,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        request_id=request_id,
        source_type=source_type,
        content_risk=content_risk.value,
        action_risk=action_risk.value,
        decision=policy_decision.decision.value,
        policy_version=policy_decision.policy_version,
        reason=policy_decision.reason,
        detector_name=detector_name,
        detector_version=detector_version,
        detector_score=detector_score,
        metadata=metadata,
    )


def build_execution_audit_event(
    *,
    request_id: str,
    evaluation_digest: str,
    action_name: str,
    decision: str,
    phase: str,
    status: str,
    grant_id: str,
    effect_digest: str,
    policy_version: str = POLICY_VERSION,
    grant_record_digest: str | None = None,
    review_approval_digest: str | None = None,
    exception_class: str | None = None,
) -> ExecutionAuditEvent:
    """Create an evidence event without raw input, payload, output, or exception text."""

    for value, field in (
        (request_id, "request_id"), (evaluation_digest, "evaluation_digest"),
        (action_name, "action_name"), (decision, "decision"), (phase, "phase"),
        (status, "status"), (grant_id, "grant_id"), (effect_digest, "effect_digest"),
        (policy_version, "policy_version"),
    ):
        if type(value) is not str or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")
    for digest, field in (
        (evaluation_digest, "evaluation_digest"),
        (effect_digest, "effect_digest"),
        (grant_record_digest, "grant_record_digest"),
        (review_approval_digest, "review_approval_digest"),
    ):
        if digest is not None and (
            len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError(f"{field} must be a SHA-256 hex digest")
    return ExecutionAuditEvent(
        event_schema_version=EXECUTION_EVENT_SCHEMA_VERSION,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        request_id=request_id,
        evaluation_digest=evaluation_digest,
        action_name=action_name,
        decision=decision,
        phase=phase,
        status=status,
        grant_id=grant_id,
        effect_digest=effect_digest,
        policy_version=policy_version,
        grant_record_digest=grant_record_digest,
        review_approval_digest=review_approval_digest,
        exception_class=exception_class,
    )


def evaluation_digest(event: AuditEvent) -> str:
    """Bind review to one complete evaluation, without retaining raw source content."""
    from .integrity import payload_digest

    material = event.to_dict()
    metadata = material.get("metadata") or {}
    for field in ("evaluation_id", "content_digest", "provenance_digest"):
        value = metadata.get(field)
        if (type(value) is not str or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)):
            raise ValueError("evaluation lacks valid evidence bindings; reevaluate")
    return payload_digest({"review_schema": "agentshield-review-evaluation-v1", "event": material})
