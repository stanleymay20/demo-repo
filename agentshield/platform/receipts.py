"""Portable AgentShield evidence bundles for independent offline verification.

A bundle contains exact signed audit events/envelopes and, when a REVIEW action executes,
the separately signed human-review approval needed to prove that authorization offline.
Raw prompts, payloads and tool outputs are not exported. Public keys are deliberately not
embedded as trust anchors: auditors obtain audit and review keys independently.

The v1 format is an AgentShield-native draft designed to map cleanly onto emerging signed
agent-action receipt work. It does not claim conformance to a final IETF standard.
"""

from __future__ import annotations

from dataclasses import dataclass
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
from .events import AuditEvent, evaluation_digest
from .review import (
    ReviewApproval,
    ReviewStatus,
    ReviewVerifier,
    load_review_approval,
    review_approval_digest,
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
    review_approvals: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_profile": self.receipt_profile,
            "exported_at_utc": self.exported_at_utc,
            "records": [record.to_dict() for record in self.records],
            "review_approvals": [dict(approval) for approval in self.review_approvals],
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


def _decision_digest(event: Mapping[str, Any]) -> str | None:
    try:
        return evaluation_digest(AuditEvent(**dict(event)))
    except (TypeError, ValueError):
        return None


def _parse_event_time(event: Mapping[str, Any]) -> datetime | None:
    value = event.get("timestamp_utc")
    if type(value) is not str:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return None if moment.tzinfo is None else moment.astimezone(timezone.utc)


def build_bundle(
    envelopes: Sequence[AuditEnvelope],
    events: Sequence[Any],
    *,
    review_approvals: Sequence[ReviewApproval] = (),
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
    proofs: list[dict[str, Any]] = []
    for approval in review_approvals:
        if type(approval) is not ReviewApproval:
            raise TypeError("review_approvals must contain exact ReviewApproval records")
        proofs.append(approval.to_dict())
    moment = exported_at_utc or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("exported_at_utc must be timezone-aware")
    return EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        receipt_profile=RECEIPT_PROFILE,
        exported_at_utc=moment.astimezone(timezone.utc).isoformat(),
        records=tuple(records),
        review_approvals=tuple(proofs),
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
    approvals_raw = raw.get("review_approvals", [])
    if type(approvals_raw) is not list or any(type(item) is not dict for item in approvals_raw):
        raise ValueError("review_approvals must be a list of objects")
    return EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        receipt_profile=RECEIPT_PROFILE,
        exported_at_utc=exported,
        records=tuple(records),
        review_approvals=tuple(dict(item) for item in approvals_raw),
    )


def _verify_review_proofs(
    bundle: EvidenceBundle,
    review_public_keys: Mapping[str, bytes] | None,
) -> ChainVerificationResult | None:
    execution_refs: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
    for index, record in enumerate(bundle.records):
        if record.record_type != "execution_lifecycle":
            continue
        event = record.event
        digest = event.get("review_approval_digest")
        decision = event.get("decision")
        if decision == "review" and not _valid_hex_digest(digest):
            return ChainVerificationResult(
                AuditVerificationStatus.EVENT_MISMATCH, index, index,
            )
        if digest is not None:
            if decision != "review" or not _valid_hex_digest(digest):
                return ChainVerificationResult(
                    AuditVerificationStatus.EVENT_MISMATCH, index, index,
                )
            execution_refs.setdefault(digest, []).append((index, event))

    if not execution_refs:
        if bundle.review_approvals:
            return ChainVerificationResult(
                AuditVerificationStatus.EVENT_MISMATCH,
                verified_count=len(bundle.records),
                first_invalid_index=len(bundle.records),
            )
        return None

    if not review_public_keys:
        first_index = min(index for refs in execution_refs.values() for index, _ in refs)
        return ChainVerificationResult(
            AuditVerificationStatus.UNKNOWN_KEY, first_index, first_index,
        )
    try:
        verifier = ReviewVerifier(review_public_keys)
    except (TypeError, ValueError):
        first_index = min(index for refs in execution_refs.values() for index, _ in refs)
        return ChainVerificationResult(
            AuditVerificationStatus.UNKNOWN_KEY, first_index, first_index,
        )

    proofs: dict[str, ReviewApproval] = {}
    for raw in bundle.review_approvals:
        try:
            approval = load_review_approval(raw)
        except ValueError:
            return ChainVerificationResult(
                AuditVerificationStatus.EVENT_MISMATCH,
                verified_count=len(bundle.records),
                first_invalid_index=len(bundle.records),
            )
        digest = review_approval_digest(approval)
        if digest in proofs:
            return ChainVerificationResult(
                AuditVerificationStatus.EVENT_MISMATCH,
                verified_count=len(bundle.records),
                first_invalid_index=len(bundle.records),
            )
        signature_status = verifier.verify_signature(approval)
        if signature_status is ReviewStatus.UNKNOWN_KEY:
            refs = execution_refs.get(digest, ())
            index = refs[0][0] if refs else len(bundle.records)
            return ChainVerificationResult(AuditVerificationStatus.UNKNOWN_KEY, index, index)
        if signature_status is not ReviewStatus.VALID:
            refs = execution_refs.get(digest, ())
            index = refs[0][0] if refs else len(bundle.records)
            return ChainVerificationResult(AuditVerificationStatus.INVALID_SIGNATURE, index, index)
        proofs[digest] = approval

    if set(proofs) != set(execution_refs):
        missing = set(execution_refs) - set(proofs)
        if missing:
            index = min(execution_refs[digest][0][0] for digest in missing)
            return ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)
        return ChainVerificationResult(
            AuditVerificationStatus.EVENT_MISMATCH,
            verified_count=len(bundle.records),
            first_invalid_index=len(bundle.records),
        )

    decision_records: list[tuple[int, Mapping[str, Any], str]] = []
    for index, record in enumerate(bundle.records):
        if record.record_type != "policy_decision":
            continue
        digest = _decision_digest(record.event)
        if digest is not None:
            decision_records.append((index, record.event, digest))

    for digest, refs in execution_refs.items():
        approval = proofs[digest]
        matching = [
            (index, event)
            for index, event, eval_digest in decision_records
            if event.get("request_id") == approval.request_id
            and event.get("decision") == "review"
            and eval_digest == approval.evaluation_digest
        ]
        if len(matching) != 1:
            index = refs[0][0]
            return ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)
        _, decision_event = matching[0]
        metadata = decision_event.get("metadata")
        if type(metadata) is not dict:
            index = refs[0][0]
            return ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)
        expected = (
            metadata.get("action_digest"),
            metadata.get("payload_digest"),
            metadata.get("authorization_scope_digest"),
            metadata.get("tool_manifest_digest"),
            decision_event.get("policy_version"),
        )
        observed = (
            approval.action_digest,
            approval.payload_digest,
            approval.scope_digest,
            approval.tool_manifest_digest,
            approval.policy_version,
        )
        if observed != expected:
            index = refs[0][0]
            return ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)

        consumed_times: list[datetime] = []
        for index, event in refs:
            if (
                event.get("request_id") != approval.request_id
                or event.get("evaluation_digest") != approval.evaluation_digest
                or event.get("policy_version") != approval.policy_version
            ):
                return ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)
            if event.get("phase") == "grant_consumed" and event.get("status") == "admitted":
                moment = _parse_event_time(event)
                if moment is None:
                    return ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)
                consumed_times.append(moment)
        if len(consumed_times) != 1 or not (
            approval.issued_at_utc <= consumed_times[0] < approval.expires_at_utc
        ):
            index = refs[0][0]
            return ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)
    return None


def verify_bundle(
    bundle: EvidenceBundle | str | bytes | Mapping[str, Any],
    public_keys: Mapping[str, bytes],
    *,
    review_public_keys: Mapping[str, bytes] | None = None,
) -> ChainVerificationResult:
    """Verify audit evidence, scope commitments and any human-review authorization proof."""

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
    chain_result = verify_chain(Ed25519AuditVerifier(public_keys), envelopes, events)
    if not chain_result.valid:
        return chain_result
    review_result = _verify_review_proofs(parsed, review_public_keys)
    return chain_result if review_result is None else review_result


def bundle_digest(bundle: EvidenceBundle | str | bytes | Mapping[str, Any]) -> str:
    """Return a stable SHA-256 digest suitable for external anchoring."""

    parsed = bundle if isinstance(bundle, EvidenceBundle) else load_bundle(bundle)
    encoded = json.dumps(
        parsed.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
