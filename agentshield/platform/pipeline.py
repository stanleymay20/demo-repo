"""Composable AgentShield decision pipeline.

Detector scoring, provenance, capability authorization, authoritative grant lifecycle,
authoritative tool manifests, action classification, policy and audit are separate so
that no model output becomes authorization by accident.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .actions import ActionDescriptor, classify_action
from .authorization import AuthorizationScope, ScopeStatus, check_action_scope
from .detectors import DetectionResult, Detector
from .events import AuditEvent, build_audit_event
from .grants import GrantAuthority, GrantStatus, grant_record_digest
from .integrity import action_digest, payload_digest, scope_digest, tool_manifest_digest
from .policy import PolicyDecision, PolicyInput, decide
from .provenance import InputProvenance, TrustLevel
from .tools import ToolRegistry, ToolVerificationStatus, verify_action_descriptor


@dataclass(frozen=True)
class PipelineResult:
    detection: DetectionResult
    policy: PolicyDecision
    audit_event: AuditEvent


def evaluate_request(
    *,
    request_id: str,
    source_type: str,
    content: str,
    action: ActionDescriptor,
    detector: Detector,
    payload: Mapping[str, Any] | None = None,
    provenance: InputProvenance | None = None,
    authorization_scope: AuthorizationScope | None = None,
    tool_registry: ToolRegistry | None = None,
    grant_authority: GrantAuthority | None = None,
) -> PipelineResult:
    """Evaluate one proposed action against risk, authority, scope and tool metadata."""

    if provenance is None:
        provenance = InputProvenance(
            source_type=source_type,
            trust_level=TrustLevel.UNKNOWN,
        )
    elif provenance.source_type != source_type:
        raise ValueError("source_type must match provenance.source_type")

    tool_status, manifest = verify_action_descriptor(action, tool_registry)
    tool_verified = (
        True
        if tool_status is ToolVerificationStatus.VERIFIED
        else False
        if tool_status
        in {ToolVerificationStatus.MISMATCH, ToolVerificationStatus.UNREGISTERED}
        else None
    )

    detection = detector.detect(content)
    action_risk = classify_action(action)
    scope_status = check_action_scope(action, authorization_scope)
    scope_permitted = (
        True
        if scope_status is ScopeStatus.PERMITTED
        else False
        if scope_status is ScopeStatus.DENIED
        else None
    )

    grant_status = GrantStatus.UNKNOWN
    grant_record = None
    grant_valid: bool | None = None
    if authorization_scope is not None and grant_authority is not None:
        grant_status, grant_record = grant_authority.verify(authorization_scope)
        grant_valid = grant_status is GrantStatus.VALID
    elif authorization_scope is not None and grant_authority is None:
        grant_valid = None

    policy_decision = decide(
        PolicyInput(
            content_risk=detection.content_risk,
            action_risk=action_risk,
            trust_level=provenance.trust_level,
            scope_permitted=scope_permitted,
            tool_verified=tool_verified,
            grant_valid=grant_valid,
        )
    )

    metadata: dict[str, Any] = {
        "action_name": action.name,
        "action_digest": action_digest(action),
        "payload_digest": payload_digest(payload),
        "provenance_trust": provenance.trust_level.value,
        "scope_status": scope_status.value,
        "grant_status": grant_status.value,
        "tool_status": tool_status.value,
    }
    if authorization_scope is not None:
        metadata.update(
            {
                "authorization_grant_id": authorization_scope.grant_id,
                "authorization_scope_digest": scope_digest(authorization_scope),
            }
        )
    if grant_record is not None:
        metadata.update(
            {
                "grant_record_digest": grant_record_digest(grant_record),
                "grant_expires_at_utc": grant_record.expires_at_utc.isoformat(),
                "grant_single_use": grant_record.single_use,
            }
        )
    if manifest is not None:
        metadata.update(
            {
                "tool_manifest_version": manifest.version,
                "tool_manifest_digest": tool_manifest_digest(manifest),
            }
        )

    event = build_audit_event(
        request_id=request_id,
        source_type=source_type,
        content_risk=detection.content_risk,
        action_risk=action_risk,
        policy_decision=policy_decision,
        detector_name=detection.detector_name,
        detector_version=detection.detector_version,
        detector_score=detection.score,
        metadata=metadata,
    )
    return PipelineResult(
        detection=detection,
        policy=policy_decision,
        audit_event=event,
    )
