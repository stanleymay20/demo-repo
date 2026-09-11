"""Composable AgentShield decision pipeline.

This layer intentionally keeps detector scoring, action classification, policy and audit
separate so that no model output becomes authorization by accident.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .actions import ActionDescriptor, classify_action
from .detectors import DetectionResult, Detector
from .events import AuditEvent, build_audit_event
from .integrity import action_digest, payload_digest
from .policy import PolicyDecision, PolicyInput, decide


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
) -> PipelineResult:
    detection = detector.detect(content)
    action_risk = classify_action(action)
    policy_decision = decide(
        PolicyInput(
            content_risk=detection.content_risk,
            action_risk=action_risk,
        )
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
        metadata={
            "action_name": action.name,
            "action_digest": action_digest(action),
            "payload_digest": payload_digest(payload),
        },
    )
    return PipelineResult(
        detection=detection,
        policy=policy_decision,
        audit_event=event,
    )
