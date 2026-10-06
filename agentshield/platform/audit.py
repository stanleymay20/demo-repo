"""Tamper-evident audit envelopes and chained trails for AgentShield.

Raw untrusted content is intentionally outside this format. The signer authenticates a
canonical event hash and chains each envelope to the previous envelope. ``AuditTrail``
serializes appends and can synchronously hand every sealed event to a host persistence
sink (database, append-only object store, SIEM, transparency service, etc.).

HMAC chaining detects modification/reordering. Production deployments should persist and
periodically anchor the latest envelope hash outside the runtime writer's control to make
tail truncation detectable across process loss or compromise.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import hmac
import json
from threading import RLock
from typing import Any, Callable, Mapping


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


AuditSink = Callable[[AuditEnvelope, Any], None]


class AuditTrail:
    """Concurrency-safe append-only envelope chain with optional synchronous persistence.

    The trail keeps a local copy for verification/testing and invokes ``sink`` before the
    append is acknowledged to the caller. A production sink should durably persist both
    envelope and event and separately anchor the head hash on an operational cadence.
    """

    def __init__(self, signer: AuditSigner, *, sink: AuditSink | None = None) -> None:
        self._signer = signer
        self._sink = sink
        self._events: list[Any] = []
        self._envelopes: list[AuditEnvelope] = []
        self._lock = RLock()

    def append(self, event: Any) -> AuditEnvelope:
        with self._lock:
            previous = self._envelopes[-1] if self._envelopes else None
            envelope = self._signer.seal(
                event,
                sequence=len(self._envelopes),
                previous=previous,
            )
            if self._sink is not None:
                self._sink(envelope, event)
            self._events.append(event)
            self._envelopes.append(envelope)
            return envelope

    @property
    def head(self) -> AuditEnvelope | None:
        with self._lock:
            return self._envelopes[-1] if self._envelopes else None

    @property
    def envelopes(self) -> tuple[AuditEnvelope, ...]:
        with self._lock:
            return tuple(self._envelopes)

    @property
    def events(self) -> tuple[Any, ...]:
        with self._lock:
            return tuple(self._events)
