"""Portable AgentShield evidence bundles for independent offline verification.

A bundle contains the exact signed audit events and envelopes, not raw prompts, payloads
or outputs. Public keys are deliberately *not* embedded as trust anchors: an auditor must
obtain the expected Ed25519 public key through an independent channel.

The v1 format is an AgentShield-native receipt profile designed to map cleanly onto
emerging agent-action receipt work. It does not claim conformance to a final IETF standard.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Mapping, Sequence

from .audit import (
    AuditEnvelope,
    AuditVerificationStatus,
    ChainVerificationResult,
    ED25519_ALGORITHM,
    Ed25519AuditVerifier,
    verify_chain,
)


BUNDLE_SCHEMA_VERSION = "agentshield-evidence-bundle-v1"
RECEIPT_PROFILE = "agentshield-verifiable-action-receipt-v1"
SCOPE_SCHEMA_VERSION = "agentshield-scope-v3"
_SCOPE_KEYS = {
    "scope_schema",
    "grant_id",
    "issuer",
    "principal",
    "tenant",
    "allowed_capabilities",
    "allowed_effects",
}
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class EvidenceRecord:
    record_type: str
    event: Mapping[str, Any]
    envelope: AuditEnvelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "event": dict(self.event),
            "envelope": self.envelope.to_dict(),
        }


@dataclass(frozen=True)
class EvidenceBundle:
    schema_version: str
    receipt_profile: str
    exported_at_utc: str
    records: tuple[EvidenceRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_profile": self.receipt_profile,
            "exported_at_utc": self.exported_at_utc,
            "records": [record.to_dict() for record in self.records],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, ensure_ascii=False, allow_nan=False, indent=indent,
        )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _event_mapping(event: Any) -> dict[str, Any]:
    if hasattr(event, "to_dict"):
        value = event.to_dict()
    elif isinstance(event, Mapping):
        value = dict(event)
    else:
        raise TypeError("receipt event must be a mapping or expose to_dict()")
    # Round-trip through JSON to detach custom Mapping/list subclasses and prove that the
    # portable representation contains JSON values only.
    try:
        return json.loads(json.dumps(value, allow_nan=False, ensure_ascii=False))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("receipt event is not portable strict JSON") from exc


def _record_type(event: Mapping[str, Any]) -> str:
    schema = event.get("event_schema_version")
    if schema == "agentshield-audit-event-v1":
        return "policy_decision"
    if isinstance(schema, str) and schema.startswith("agentshield-execution-audit-event-"):
        return "execution_lifecycle"
    return "audit_event"


def _valid_hex_digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(char in _HEX for char in value)


def _valid_scope_material(value: Any) -> bool:
    if type(value) is not dict or set(value) != _SCOPE_KEYS:
        return False
    if value.get("scope_schema") != SCOPE_SCHEMA_VERSION:
        return False
    for field in ("grant_id", "issuer"):
        item = value.get(field)
        if type(item) is not str or not item.strip() or item != item.strip():
            return False
    for field in ("principal", "tenant"):
        item = value.get(field)
        if item is not None and (
            type(item) is not str or not item.strip() or item != item.strip()
        ):
            return False
    capabilities = value.get("allowed_capabilities")
    if type(capabilities) is not list or any(type(item) is not str for item in capabilities):
        return False
    normalized = sorted({item.strip().lower() for item in capabilities if item.strip()})
    if capabilities != normalized:
        return False
    effects = value.get("allowed_effects")
    if type(effects) is not list or any(not _valid_hex_digest(item) for item in effects):
        return False
    return effects == sorted(set(effects))


def _scope_evidence_valid(event: Mapping[str, Any]) -> bool:
    metadata = event.get("metadata")
    if type(metadata) is not dict:
        return True
    digest = metadata.get("authorization_scope_digest")
    material = metadata.get("authorization_scope_material")
    if digest is None and material is None:
        return True
    if not _valid_hex_digest(digest) or not _valid_scope_material(material):
        return False
    if hashlib.sha256(_canonical_bytes(material)).hexdigest() != digest:
        return False
    expected_metadata = {
        "authorization_grant_id": material["grant_id"],
        "authorization_issuer": material["issuer"],
        "authorization_principal": material["principal"],
        "authorization_tenant": material["tenant"],
    }
    return all(metadata.get(field) == value for field, value in expected_metadata.items())


def build_bundle(
    envelopes: Sequence[AuditEnvelope],
    events: Sequence[Any],
    *,
    exported_at_utc: datetime | None = None,
) -> EvidenceBundle:
    """Create a portable bundle from a complete Ed25519 audit chain."""

    if len(envelopes) != len(events):
        raise ValueError("envelopes and events must have the same length")
    if not envelopes:
        raise ValueError("cannot export an empty evidence chain")
    records: list[EvidenceRecord] = []
    for envelope, event in zip(envelopes, events):
        if envelope.algorithm != ED25519_ALGORITHM:
            raise ValueError("independent evidence bundles require Ed25519 audit envelopes")
        mapped = _event_mapping(event)
        records.append(EvidenceRecord(_record_type(mapped), mapped, envelope))
    moment = exported_at_utc or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("exported_at_utc must be timezone-aware")
    return EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        receipt_profile=RECEIPT_PROFILE,
        exported_at_utc=moment.astimezone(timezone.utc).isoformat(),
        records=tuple(records),
    )


def load_bundle(value: str | bytes | Mapping[str, Any]) -> EvidenceBundle:
    """Parse and minimally validate an evidence bundle without trusting its signatures."""

    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        raw = json.loads(value)
    elif isinstance(value, Mapping):
        raw = dict(value)
    else:
        raise TypeError("bundle must be JSON text, bytes or a mapping")
    if raw.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ValueError("unsupported evidence bundle schema")
    if raw.get("receipt_profile") != RECEIPT_PROFILE:
        raise ValueError("unsupported receipt profile")
    exported = raw.get("exported_at_utc")
    if type(exported) is not str or not exported.strip():
        raise ValueError("bundle exported_at_utc is missing")
    records_raw = raw.get("records")
    if type(records_raw) is not list or not records_raw:
        raise ValueError("bundle records must be a non-empty list")
    records: list[EvidenceRecord] = []
    for item in records_raw:
        if type(item) is not dict:
            raise ValueError("bundle record must be an object")
        record_type = item.get("record_type")
        event = item.get("event")
        envelope = item.get("envelope")
        if type(record_type) is not str or not record_type.strip():
            raise ValueError("bundle record_type is missing")
        if type(event) is not dict or type(envelope) is not dict:
            raise ValueError("bundle record requires event and envelope objects")
        records.append(EvidenceRecord(record_type, event, AuditEnvelope(**envelope)))
    return EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        receipt_profile=RECEIPT_PROFILE,
        exported_at_utc=exported,
        records=tuple(records),
    )


def verify_bundle(
    bundle: EvidenceBundle | str | bytes | Mapping[str, Any],
    public_keys: Mapping[str, bytes],
) -> ChainVerificationResult:
    """Verify signed events, authority commitments, semantics and hash-chain links."""

    parsed = bundle if isinstance(bundle, EvidenceBundle) else load_bundle(bundle)
    for index, record in enumerate(parsed.records):
        if record.record_type != _record_type(record.event):
            return ChainVerificationResult(
                AuditVerificationStatus.EVENT_MISMATCH,
                verified_count=index,
                first_invalid_index=index,
            )
        if record.record_type == "policy_decision" and not _scope_evidence_valid(record.event):
            return ChainVerificationResult(
                AuditVerificationStatus.EVENT_MISMATCH,
                verified_count=index,
                first_invalid_index=index,
            )
    envelopes = tuple(record.envelope for record in parsed.records)
    events = tuple(record.event for record in parsed.records)
    if any(envelope.algorithm != ED25519_ALGORITHM for envelope in envelopes):
        return ChainVerificationResult(
            AuditVerificationStatus.ALGORITHM_MISMATCH,
            verified_count=0,
            first_invalid_index=0,
        )
    return verify_chain(Ed25519AuditVerifier(public_keys), envelopes, events)


def bundle_digest(bundle: EvidenceBundle | str | bytes | Mapping[str, Any]) -> str:
    """Return a stable SHA-256 digest suitable for external anchoring."""

    parsed = bundle if isinstance(bundle, EvidenceBundle) else load_bundle(bundle)
    encoded = json.dumps(
        parsed.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
