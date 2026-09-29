"""Input provenance metadata for AgentShield."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InputProvenance:
    source_type: str
    source_id: str | None = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    content_type: str | None = None

    def __post_init__(self) -> None:
        if not self.source_type.strip():
            raise ValueError("source_type must be non-empty")

    @property
    def requires_security_screening(self) -> bool:
        return self.trust_level is not TrustLevel.TRUSTED
