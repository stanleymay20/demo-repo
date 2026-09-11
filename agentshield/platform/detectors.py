"""Detector adapter contract for AgentShield.

Detectors provide risk evidence only. They never authorize actions directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .policy import ContentRisk


@dataclass(frozen=True)
class DetectionResult:
    content_risk: ContentRisk
    score: float | None
    detector_name: str
    detector_version: str
    rationale: str | None = None

    def __post_init__(self) -> None:
        if self.score is not None and not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be between 0 and 1")
        if not self.detector_name.strip():
            raise ValueError("detector_name must be non-empty")
        if not self.detector_version.strip():
            raise ValueError("detector_version must be non-empty")


class Detector(Protocol):
    """Minimal interface implemented by AgentShield detector adapters."""

    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    def detect(self, content: str) -> DetectionResult: ...


def risk_from_threshold(*, score: float, threshold: float) -> ContentRisk:
    """Convert a calibrated detector score into binary content risk.

    Thresholds must come from the detector's frozen configuration/evidence;
    this helper does not select or tune thresholds.
    """

    if not 0.0 <= score <= 1.0:
        raise ValueError("score must be between 0 and 1")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    return ContentRisk.HIGH if score >= threshold else ContentRisk.LOW
