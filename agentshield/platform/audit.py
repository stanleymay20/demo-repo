"""Tamper-evident audit envelopes for AgentShield.

Raw untrusted content is intentionally outside this format. The signer authenticates a
canonical event hash and optionally chains each envelope to the previous envelope.
Persistence can be supplied by the host (database, append-only object store, SIEM, etc.).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import hmac
import json
from typing import Any, Mapping


AUDIT_ENVELOPE_SCHEMA_VERSION = "agentshield-audit-envelope-v1"


class AuditVerificationStatus(str, Enum):
    VALID = "valid"
    UNKNOWN_KEY = "unknown_key"
    EVENT_MISMATCH = "event_mismatch"
    CHAIN_MISMATCH = "chain_mismatch"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass(frozen=True)
class AuditEnvelope:
    schema_version: str
    sequence: int
    previous_envelope_hash: str | None
    event_hash: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        if not self.event_hash.strip() or not self.key_id.strip() or not self.signature.strip():
            raise ValueError("event_hash, key_id and signature must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _event_mapping(event: Any) -> Mapping[str, Any]:
    if hasattr(event, "to_dict"):
        value = event.to_dict()
    elif isinstance(event, Mapping):
        value = dict(event)
    else:
        raise TypeError("event must be a mapping or expose to_dict()")
    return value


def event_hash(event: Any) -> str:
    return hashlib.sha256(_canonical_bytes(_event_mapping(event))).hexdigest()


def envelope_hash(envelope: AuditEnvelope) -> str:
    return hashlib.sha256(_canonical_bytes(envelope.to_dict())).hexdigest()


class AuditSigner:
    """HMAC signer with key rotation and previous-envelope chaining."""

    def __init__(self, keys: Mapping[str, bytes], *, active_key_id: str) -> None:
        clean = dict(keys)
        if active_key_id not in clean:
            raise ValueError("active_key_id is not present in keys")
        for key_id, key in clean.items():
            if not key_id.strip():
                raise ValueError("audit key ids must be non-empty")
            if len(key) < 32:
                raise ValueError("audit keys must contain at least 32 bytes")
        self._keys = clean
        self._active_key_id = active_key_id

    @staticmethod
    def _signature_material(
        *,
        schema_version: str,
        sequence: int,
        previous_envelope_hash: str | None,
        event_hash_value: str,
        key_id: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": schema_version,
            "sequence": sequence,
            "previous_envelope_hash": previous_envelope_hash,
            "event_hash": event_hash_value,
            "key_id": key_id,
        }

    def seal(
        self,
        event: Any,
        *,
        sequence: int,
        previous: AuditEnvelope | None = None,
    ) -> AuditEnvelope:
        previous_hash = None if previous is None else envelope_hash(previous)
        ev_hash = event_hash(event)
        material = self._signature_material(
            schema_version=AUDIT_ENVELOPE_SCHEMA_VERSION,
            sequence=sequence,
            previous_envelope_hash=previous_hash,
            event_hash_value=ev_hash,
            key_id=self._active_key_id,
        )
        signature = hmac.new(
            self._keys[self._active_key_id],
            _canonical_bytes(material),
            hashlib.sha256,
        ).hexdigest()
        return AuditEnvelope(
            schema_version=AUDIT_ENVELOPE_SCHEMA_VERSION,
            sequence=sequence,
            previous_envelope_hash=previous_hash,
            event_hash=ev_hash,
            key_id=self._active_key_id,
            signature=signature,
        )

    def verify(
        self,
        envelope: AuditEnvelope,
        event: Any,
        *,
        previous: AuditEnvelope | None = None,
    ) -> AuditVerificationStatus:
        key = self._keys.get(envelope.key_id)
        if key is None:
            return AuditVerificationStatus.UNKNOWN_KEY
        if envelope.event_hash != event_hash(event):
            return AuditVerificationStatus.EVENT_MISMATCH

        expected_previous = None if previous is None else envelope_hash(previous)
        if envelope.previous_envelope_hash != expected_previous:
            return AuditVerificationStatus.CHAIN_MISMATCH
        if previous is not None and envelope.sequence != previous.sequence + 1:
            return AuditVerificationStatus.CHAIN_MISMATCH

        material = self._signature_material(
            schema_version=envelope.schema_version,
            sequence=envelope.sequence,
            previous_envelope_hash=envelope.previous_envelope_hash,
            event_hash_value=envelope.event_hash,
            key_id=envelope.key_id,
        )
        expected_signature = hmac.new(
            key,
            _canonical_bytes(material),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, envelope.signature):
            return AuditVerificationStatus.INVALID_SIGNATURE
        return AuditVerificationStatus.VALID
