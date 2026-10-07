"""Tamper-evident audit envelopes and chained trails for AgentShield.

Raw untrusted content is intentionally outside this format. The evidence layer supports
both the legacy/internal HMAC signer and an Ed25519 signer/verifier split for evidence
that third parties can verify without receiving a forging secret.

Production deployments should durably persist envelopes/events and periodically anchor
the latest envelope hash outside the runtime writer's control so tail truncation can be
detected across process loss or compromise.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import hmac
import json
from threading import RLock
from typing import Any, Callable, Mapping, Sequence


AUDIT_ENVELOPE_SCHEMA_VERSION = "agentshield-audit-envelope-v2"
HMAC_ALGORITHM = "hmac-sha256"
ED25519_ALGORITHM = "ed25519"


class AuditVerificationStatus(str, Enum):
    VALID = "valid"
    UNKNOWN_KEY = "unknown_key"
    EVENT_MISMATCH = "event_mismatch"
    CHAIN_MISMATCH = "chain_mismatch"
    ALGORITHM_MISMATCH = "algorithm_mismatch"
    SCHEMA_MISMATCH = "schema_mismatch"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass(frozen=True)
class AuditEnvelope:
    schema_version: str
    sequence: int
    previous_envelope_hash: str | None
    event_hash: str
    key_id: str
    signature: str
    algorithm: str = HMAC_ALGORITHM

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        if not self.event_hash.strip() or not self.key_id.strip() or not self.signature.strip():
            raise ValueError("event_hash, key_id and signature must be non-empty")
        if self.algorithm not in {HMAC_ALGORITHM, ED25519_ALGORITHM}:
            raise ValueError("unsupported audit signature algorithm")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ChainVerificationResult:
    status: AuditVerificationStatus
    verified_count: int
    first_invalid_index: int | None = None

    @property
    def valid(self) -> bool:
        return self.status is AuditVerificationStatus.VALID


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


def _signature_material(
    *,
    schema_version: str,
    algorithm: str,
    sequence: int,
    previous_envelope_hash: str | None,
    event_hash_value: str,
    key_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "algorithm": algorithm,
        "sequence": sequence,
        "previous_envelope_hash": previous_envelope_hash,
        "event_hash": event_hash_value,
        "key_id": key_id,
    }


def _cryptography():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - dependency-free install path
        raise RuntimeError(
            "Ed25519 audit evidence requires agentshield-runtime[signing]"
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


class AuditSigner:
    """Legacy/internal HMAC signer.

    HMAC is retained for dependency-free local integrity only. Do not give its secret key
    to an independent auditor: possession of that key also permits forging records.
    Use :class:`Ed25519AuditSigner` for portable third-party-verifiable evidence.
    """

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

    def seal(
        self,
        event: Any,
        *,
        sequence: int,
        previous: AuditEnvelope | None = None,
    ) -> AuditEnvelope:
        previous_hash = None if previous is None else envelope_hash(previous)
        ev_hash = event_hash(event)
        material = _signature_material(
            schema_version=AUDIT_ENVELOPE_SCHEMA_VERSION,
            algorithm=HMAC_ALGORITHM,
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
            algorithm=HMAC_ALGORITHM,
        )

    def verify(
        self,
        envelope: AuditEnvelope,
        event: Any,
        *,
        previous: AuditEnvelope | None = None,
    ) -> AuditVerificationStatus:
        if envelope.schema_version != AUDIT_ENVELOPE_SCHEMA_VERSION:
            return AuditVerificationStatus.SCHEMA_MISMATCH
        if envelope.algorithm != HMAC_ALGORITHM:
            return AuditVerificationStatus.ALGORITHM_MISMATCH
        key = self._keys.get(envelope.key_id)
        if key is None:
            return AuditVerificationStatus.UNKNOWN_KEY
        if envelope.event_hash != event_hash(event):
            return AuditVerificationStatus.EVENT_MISMATCH
        if previous is None and envelope.sequence != 0:
            return AuditVerificationStatus.CHAIN_MISMATCH

        expected_previous = None if previous is None else envelope_hash(previous)
        if envelope.previous_envelope_hash != expected_previous:
            return AuditVerificationStatus.CHAIN_MISMATCH
        if previous is not None and envelope.sequence != previous.sequence + 1:
            return AuditVerificationStatus.CHAIN_MISMATCH

        material = _signature_material(
            schema_version=envelope.schema_version,
            algorithm=envelope.algorithm,
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


class Ed25519AuditSigner:
    """Evidence-writer-only signer holding Ed25519 private keys."""

    def __init__(self, private_keys: Mapping[str, bytes], *, active_key_id: str) -> None:
        _, _, PrivateKey, _ = _cryptography()
        clean = dict(private_keys)
        if not clean or active_key_id not in clean:
            raise ValueError("active_key_id must reference a configured audit private key")
        self._keys = {}
        for key_id, raw in clean.items():
            if not key_id.strip() or len(raw) != 32:
                raise ValueError("Ed25519 private keys must be 32 raw bytes with a non-empty id")
            self._keys[key_id] = PrivateKey.from_private_bytes(raw)
        self._active_key_id = active_key_id

    def seal(
        self,
        event: Any,
        *,
        sequence: int,
        previous: AuditEnvelope | None = None,
    ) -> AuditEnvelope:
        previous_hash = None if previous is None else envelope_hash(previous)
        ev_hash = event_hash(event)
        material = _signature_material(
            schema_version=AUDIT_ENVELOPE_SCHEMA_VERSION,
            algorithm=ED25519_ALGORITHM,
            sequence=sequence,
            previous_envelope_hash=previous_hash,
            event_hash_value=ev_hash,
            key_id=self._active_key_id,
        )
        signature = self._keys[self._active_key_id].sign(_canonical_bytes(material)).hex()
        return AuditEnvelope(
            schema_version=AUDIT_ENVELOPE_SCHEMA_VERSION,
            sequence=sequence,
            previous_envelope_hash=previous_hash,
            event_hash=ev_hash,
            key_id=self._active_key_id,
            signature=signature,
            algorithm=ED25519_ALGORITHM,
        )

    def public_keys(self) -> dict[str, bytes]:
        _, serialization, _, _ = _cryptography()
        return {
            key_id: key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            for key_id, key in self._keys.items()
        }


class Ed25519AuditVerifier:
    """Independent verifier containing only public keys and no signing authority."""

    def __init__(self, public_keys: Mapping[str, bytes]) -> None:
        _, _, _, PublicKey = _cryptography()
        clean = dict(public_keys)
        if not clean:
            raise ValueError("at least one audit public key is required")
        self._keys = {}
        for key_id, raw in clean.items():
            if not key_id.strip() or len(raw) != 32:
                raise ValueError("Ed25519 public keys must be 32 raw bytes with a non-empty id")
            self._keys[key_id] = PublicKey.from_public_bytes(raw)

    def verify(
        self,
        envelope: AuditEnvelope,
        event: Any,
        *,
        previous: AuditEnvelope | None = None,
    ) -> AuditVerificationStatus:
        if envelope.schema_version != AUDIT_ENVELOPE_SCHEMA_VERSION:
            return AuditVerificationStatus.SCHEMA_MISMATCH
        if envelope.algorithm != ED25519_ALGORITHM:
            return AuditVerificationStatus.ALGORITHM_MISMATCH
        key = self._keys.get(envelope.key_id)
        if key is None:
            return AuditVerificationStatus.UNKNOWN_KEY
        if envelope.event_hash != event_hash(event):
            return AuditVerificationStatus.EVENT_MISMATCH
        if previous is None and envelope.sequence != 0:
            return AuditVerificationStatus.CHAIN_MISMATCH

        expected_previous = None if previous is None else envelope_hash(previous)
        if envelope.previous_envelope_hash != expected_previous:
            return AuditVerificationStatus.CHAIN_MISMATCH
        if previous is not None and envelope.sequence != previous.sequence + 1:
            return AuditVerificationStatus.CHAIN_MISMATCH

        material = _signature_material(
            schema_version=envelope.schema_version,
            algorithm=envelope.algorithm,
            sequence=envelope.sequence,
            previous_envelope_hash=envelope.previous_envelope_hash,
            event_hash_value=envelope.event_hash,
            key_id=envelope.key_id,
        )
        try:
            signature = bytes.fromhex(envelope.signature)
        except ValueError:
            return AuditVerificationStatus.INVALID_SIGNATURE
        InvalidSignature, _, _, _ = _cryptography()
        try:
            key.verify(signature, _canonical_bytes(material))
        except InvalidSignature:
            return AuditVerificationStatus.INVALID_SIGNATURE
        return AuditVerificationStatus.VALID


AuditSink = Callable[[AuditEnvelope, Any], None]


class AuditTrail:
    """Concurrency-safe append-only envelope chain with optional synchronous persistence."""

    def __init__(self, signer: Any, *, sink: AuditSink | None = None) -> None:
        if not hasattr(signer, "seal"):
            raise TypeError("audit signer must expose seal()")
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


def verify_chain(
    verifier: Any,
    envelopes: Sequence[AuditEnvelope],
    events: Sequence[Any],
) -> ChainVerificationResult:
    """Verify an entire audit chain and identify the first broken record."""

    if len(envelopes) != len(events):
        return ChainVerificationResult(
            AuditVerificationStatus.CHAIN_MISMATCH,
            verified_count=min(len(envelopes), len(events)),
            first_invalid_index=min(len(envelopes), len(events)),
        )
    previous: AuditEnvelope | None = None
    for index, (envelope, event) in enumerate(zip(envelopes, events)):
        if envelope.sequence != index:
            return ChainVerificationResult(
                AuditVerificationStatus.CHAIN_MISMATCH,
                verified_count=index,
                first_invalid_index=index,
            )
        status = verifier.verify(envelope, event, previous=previous)
        if status is not AuditVerificationStatus.VALID:
            return ChainVerificationResult(status, verified_count=index, first_invalid_index=index)
        previous = envelope
    return ChainVerificationResult(
        AuditVerificationStatus.VALID,
        verified_count=len(envelopes),
        first_invalid_index=None,
    )
