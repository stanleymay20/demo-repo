"""Composable AgentShield decision pipeline.

Detector scoring, provenance, capability authorization, authoritative grant lifecycle,
authoritative tool manifests, action classification, policy and audit are separate so
that no model output becomes authorization by accident.

Pipeline results produced in-process are sealed with a process-local integrity tag. The
tag is intentionally not a cross-service credential; detached evaluations must use the
optional Ed25519 signing path.

When an ``AuditTrail`` is supplied, every authenticated policy decision (ALLOW, REVIEW or
BLOCK) is appended before the result is returned. A durable sink failure therefore stops
the governed flow before execution can begin.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import hmac
import secrets
from typing import Any, Mapping

from .actions import ActionDescriptor, classify_action
from .audit import AuditTrail
from .authorization import AuthorizationScope, ScopeStatus, check_action_scope
from .detectors import DetectionResult, Detector
from .events import AuditEvent, build_audit_event
from .effects import check_effect_scope, effect_digest_from_payload_digest
from .grants import GrantAuthorityProtocol, GrantStatus, grant_record_digest
from .integrity import (
    action_digest,
    payload_digest,
    scope_digest,
    scope_material,
    tool_manifest_digest,
)
from .policy import PolicyDecision, PolicyInput, decide
from .provenance import InputProvenance, TrustLevel
from .tools import ToolRegistry, ToolVerificationStatus, verify_action_descriptor


_PIPELINE_INTEGRITY_SCHEMA = "agentshield-pipeline-integrity-v1"
_PROCESS_EVALUATION_KEY = secrets.token_bytes(32)


@dataclass(frozen=True)
class PipelineResult:
    detection: DetectionResult
    policy: PolicyDecision
    audit_event: AuditEvent
    _integrity_tag: str = field(default="", repr=False, compare=False)


def pipeline_result_digest(result: PipelineResult) -> str:
    """Return a canonical digest of the complete authority-relevant evaluation.

    The digest deliberately excludes ``_integrity_tag`` itself. It is suitable as the
    message authenticated by the process-local seal and by detached Ed25519 signatures.
    """

    return payload_digest(
        {
            "schema": _PIPELINE_INTEGRITY_SCHEMA,
            "detection": {
                "content_risk": result.detection.content_risk.value,
                "score": result.detection.score,
                "detector_name": result.detection.detector_name,
                "detector_version": result.detection.detector_version,
            },
            "policy": {
                "decision": result.policy.decision.value,
                "policy_version": result.policy.policy_version,
                "reason": result.policy.reason,
            },
            "audit_event": result.audit_event.to_dict(),
        }
    )


def _integrity_tag(result: PipelineResult) -> str:
    return hmac.new(
        _PROCESS_EVALUATION_KEY,
        pipeline_result_digest(result).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def verify_in_process_evaluation(result: PipelineResult) -> bool:
    """Verify that an evaluation is unchanged since this process created it.

    This is a same-process integrity boundary, not a substitute for detached signing.
    Arbitrary code execution inside the trusted host process is outside this mechanism's
    threat model.
    """

    if not result._integrity_tag:
        return False
    return hmac.compare_digest(_integrity_tag(result), result._integrity_tag)


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
    grant_authority: GrantAuthorityProtocol | None = None,
    audit_trail: AuditTrail | None = None,
) -> PipelineResult:
    """Evaluate one proposed action against risk, authority, scope and tool metadata.

    When ``audit_trail`` is provided, the complete policy decision event is synchronously
    chained before this function returns. This is the evidence-mode path used to produce
    verifiable proof of ALLOW, REVIEW and BLOCK decisions.
    """

    submitted_payload_digest = payload_digest(payload)
    if type(content) is not str:
        raise ValueError("content must be a plain string")
    submitted_content_digest = payload_digest({"content": content})

    if provenance is None:
        provenance = InputProvenance(
            source_type=source_type,
            trust_level=TrustLevel.UNKNOWN,
        )
    elif provenance.source_type != source_type:
        raise ValueError("source_type must match provenance.source_type")

    submitted_provenance_digest = payload_digest({
        "source_type": provenance.source_type, "source_id": provenance.source_id,
        "trust_level": provenance.trust_level.value, "content_type": provenance.content_type,
    })

    tool_status, manifest = verify_action_descriptor(action, tool_registry)
    tool_verified = (
        True
        if tool_status is ToolVerificationStatus.VERIFIED
        else False
        if tool_status
        in {ToolVerificationStatus.MISMATCH, ToolVerificationStatus.UNREGISTERED}
        else None
    )

    submitted_effect_digest = None
    if tool_status is ToolVerificationStatus.VERIFIED and manifest is not None:
        submitted_effect_digest = effect_digest_from_payload_digest(
            action=action, submitted_payload_digest=submitted_payload_digest, manifest=manifest,
        )
    effect_status = check_effect_scope(submitted_effect_digest, authorization_scope)
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
            effect_permitted=(
                True if effect_status is ScopeStatus.PERMITTED
                else False if effect_status is ScopeStatus.DENIED
                else None
            ),
        )
    )

    metadata: dict[str, Any] = {
        "evaluation_id": secrets.token_hex(32),
        "content_digest": submitted_content_digest,
        "provenance_digest": submitted_provenance_digest,
        "action_name": action.name,
        "action_digest": action_digest(action),
        "payload_digest": submitted_payload_digest,
        "provenance_trust": provenance.trust_level.value,
        "scope_status": scope_status.value,
        "grant_status": grant_status.value,
        "tool_status": tool_status.value,
        "effect_digest": submitted_effect_digest,
        "effect_status": effect_status.value,
    }
    if authorization_scope is not None:
        material = scope_material(authorization_scope)
        metadata.update(
            {
                "authorization_grant_id": authorization_scope.grant_id,
                "authorization_scope_digest": scope_digest(authorization_scope),
                "authorization_scope_material": material,
                "authorization_issuer": authorization_scope.issuer,
                "authorization_principal": authorization_scope.principal,
                "authorization_tenant": authorization_scope.tenant,
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
    result = PipelineResult(
        detection=detection,
        policy=policy_decision,
        audit_event=event,
    )
    sealed = replace(result, _integrity_tag=_integrity_tag(result))
    if audit_trail is not None:
        audit_trail.append(event)
    return sealed
