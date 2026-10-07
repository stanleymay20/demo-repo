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
POLICY_EVENT_SCHEMA = "agentshield-audit-event-v1"
EXECUTION_EVENT_SCHEMA = "agentshield-execution-audit-event-v2"
_BUNDLE_KEYS = {"schema_version", "receipt_profile", "exported_at_utc", "records"}
_RECORD_KEYS = {"record_type", "event", "envelope"}
_ENVELOPE_KEYS = {
    "schema_version", "sequence", "previous_envelope_hash", "event_hash", "key_id",
    "signature", "algorithm",
}
_EXECUTION_KEYS = {
    "event_schema_version", "timestamp_utc", "request_id", "evaluation_digest",
    "action_name", "decision", "phase", "status", "grant_id", "effect_digest",
    "policy_version", "grant_record_digest", "review_approval_digest", "exception_class",
}
_PHASE_STATUSES = {
    "grant_consumed": frozenset({"admitted"}),
    "dispatch_completed": frozenset({"executed", "failed"}),
}
SCOPE_SCHEMA_V3 = "agentshield-scope-v3"
SCOPE_SCHEMA_V4 = "agentshield-scope-v4-agent-purpose"
_SCOPE_KEYS_V3 = {
    "scope_schema", "grant_id", "issuer", "principal", "tenant",
    "allowed_capabilities", "allowed_effects",
}
_SCOPE_KEYS_V4 = _SCOPE_KEYS_V3 | {
    "agent_id", "purpose_id", "delegator_agent_id", "delegator_grant_id",
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
    """Derive record semantics from exact, understood signed event schemas only.

    A future ``agentshield-*`` schema is neither silently promoted to v1 execution
    semantics nor silently demoted to an opaque record (which would hide it from the
    execution/review linkage checks). It is ``unsupported`` and fails closed.
    """
    schema = event.get("event_schema_version")
    if schema == POLICY_EVENT_SCHEMA:
        return "policy_decision"
    if schema == EXECUTION_EVENT_SCHEMA:
        return "execution_lifecycle"
    if isinstance(schema, str) and schema.startswith("agentshield-"):
        return "unsupported"
    return "audit_event"


def _valid_hex_digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(char in _HEX for char in value)


def _valid_optional_identity(value: Any) -> bool:
    return value is None or (type(value) is str and bool(value.strip()) and value == value.strip())


def _valid_scope_material(value: Any) -> bool:
    if type(value) is not dict:
        return False
    schema = value.get("scope_schema")
    expected_keys = _SCOPE_KEYS_V4 if schema == SCOPE_SCHEMA_V4 else _SCOPE_KEYS_V3
    if schema not in {SCOPE_SCHEMA_V3, SCOPE_SCHEMA_V4} or set(value) != expected_keys:
        return False
    for field in ("grant_id", "issuer"):
        item = value.get(field)
        if type(item) is not str or not item.strip() or item != item.strip():
            return False
    for field in ("principal", "tenant"):
        if not _valid_optional_identity(value.get(field)):
            return False
    if schema == SCOPE_SCHEMA_V4:
        for field in ("agent_id", "purpose_id"):
            item = value.get(field)
            if type(item) is not str or not item.strip() or item != item.strip():
                return False
        delegator_agent = value.get("delegator_agent_id")
        delegator_grant = value.get("delegator_grant_id")
        if not _valid_optional_identity(delegator_agent) or not _valid_optional_identity(delegator_grant):
            return False
        if (delegator_agent is None) != (delegator_grant is None):
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
        "authorization_agent_id": material.get("agent_id"),
        "authorization_purpose_id": material.get("purpose_id"),
        "authorization_delegator_agent_id": material.get("delegator_agent_id"),
        "authorization_delegator_grant_id": material.get("delegator_grant_id"),
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


def _load_envelope(value: Mapping[str, Any]) -> AuditEnvelope:
    """Parse an envelope with exact field set and exact JSON types, failing as ValueError."""
    if set(value) != _ENVELOPE_KEYS:
        raise ValueError("envelope fields do not match the audit-envelope schema")
    text_fields = ("schema_version", "event_hash", "key_id", "signature", "algorithm")
    if any(type(value[field]) is not str for field in text_fields):
        raise ValueError("envelope text fields must be strings")
    if type(value["sequence"]) is not int:
        raise ValueError("envelope sequence must be an integer")
    previous = value["previous_envelope_hash"]
    if previous is not None and type(previous) is not str:
        raise ValueError("previous_envelope_hash must be a string or null")
    try:
        return AuditEnvelope(**value)
    except (TypeError, ValueError) as exc:
        raise ValueError("envelope is malformed") from exc


def _execution_event_valid(event: Mapping[str, Any]) -> bool:
    if set(event) != _EXECUTION_KEYS:
        return False
    for field in (
        "timestamp_utc", "request_id", "action_name", "decision", "phase", "status",
        "grant_id", "policy_version",
    ):
        value = event.get(field)
        if type(value) is not str or not value.strip():
            return False
    if not all(
        _valid_hex_digest(event.get(field))
        for field in ("evaluation_digest", "effect_digest", "grant_record_digest")
    ):
        return False
    review = event.get("review_approval_digest")
    if review is not None and not _valid_hex_digest(review):
        return False
    if event["decision"] not in {"allow", "review"}:
        return False
    if event["status"] not in _PHASE_STATUSES.get(event["phase"], frozenset()):
        return False
    exception_class = event.get("exception_class")
    if event["status"] == "failed":
        return exception_class is None or (type(exception_class) is str and bool(exception_class.strip()))
    return exception_class is None


def _verify_execution_linkage(bundle: EvidenceBundle) -> ChainVerificationResult | None:
    """Prove every execution transition was authorized by a decision in the same receipt.

    A valid audit signature only proves the writer emitted a record. Independently
    verifiable authority additionally requires that each execution transition resolves
    to exactly one earlier signed policy decision for the same request and evaluation,
    with the same decision, policy version, action, grant and exact effect, and that the
    effect is a member of that decision's independently reconstructed scope commitment.
    """
    decisions: dict[tuple[Any, str], list[tuple[int, Mapping[str, Any]]]] = {}
    for index, record in enumerate(bundle.records):
        if record.record_type == "policy_decision":
            digest = _decision_digest(record.event)
            request_id = record.event.get("request_id")
            if digest is not None and type(request_id) is str:
                decisions.setdefault((request_id, digest), []).append((index, record.event))

    lifecycle: dict[tuple[str, str], set[str]] = {}
    for index, record in enumerate(bundle.records):
        if record.record_type != "execution_lifecycle":
            continue
        failure = ChainVerificationResult(AuditVerificationStatus.EVENT_MISMATCH, index, index)
        event = record.event
        if not _execution_event_valid(event):
            return failure
        key = (event["request_id"], event["evaluation_digest"])
        matches = decisions.get(key, [])
        if len(matches) != 1 or matches[0][0] >= index:
            return failure
        decision_event = matches[0][1]
        metadata = decision_event.get("metadata")
        if type(metadata) is not dict:
            return failure
        material = metadata.get("authorization_scope_material")
        if (
            decision_event.get("decision") != event["decision"]
            or decision_event.get("policy_version") != event["policy_version"]
            or metadata.get("action_name") != event["action_name"]
            or metadata.get("authorization_grant_id") != event["grant_id"]
            or metadata.get("effect_digest") != event["effect_digest"]
            or type(material) is not dict
            or event["effect_digest"] not in material.get("allowed_effects", ())
        ):
            return failure
        phases = lifecycle.setdefault(key, set())
        phase = event["phase"]
        if phase in phases or (phase == "dispatch_completed" and "grant_consumed" not in phases):
            return failure
        phases.add(phase)
    return None


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
        record_type = _record_type(mapped)
        if record_type == "unsupported":
            raise ValueError("cannot export an unsupported AgentShield event schema in a v1 receipt")
        records.append(EvidenceRecord(record_type, mapped, envelope))
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
    if type(raw) is not dict:
        raise ValueError("bundle must be a JSON object")
    # Exact wrapper shape: unsigned extra fields (for example "verified": true or an
    # "audited_by" banner) must not ride along with evidence that verifies.
    if set(raw) - {"review_approvals"} != _BUNDLE_KEYS:
        raise ValueError("bundle fields do not match the v1 receipt profile")
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
        if type(item) is not dict or set(item) != _RECORD_KEYS:
            raise ValueError("bundle record fields do not match the v1 receipt profile")
        record_type = item.get("record_type")
        event = item.get("event")
        envelope = item.get("envelope")
        if type(record_type) is not str or not record_type.strip():
            raise ValueError("bundle record_type is missing")
        if type(event) is not dict or type(envelope) is not dict:
            raise ValueError("bundle record requires event and envelope objects")
        records.append(EvidenceRecord(record_type, event, _load_envelope(envelope)))
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
        if _record_type(record.event) == "unsupported":
            return ChainVerificationResult(
                AuditVerificationStatus.SCHEMA_MISMATCH,
                verified_count=index,
                first_invalid_index=index,
            )
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
    linkage_result = _verify_execution_linkage(parsed)
    if linkage_result is not None:
        return linkage_result
    review_result = _verify_review_proofs(parsed, review_public_keys)
    return chain_result if review_result is None else review_result


def bundle_digest(bundle: EvidenceBundle | str | bytes | Mapping[str, Any]) -> str:
    """Return a SHA-256 digest of one exported bundle document.

    This identifies an export, not the evidence: it covers the unsigned
    ``exported_at_utc`` field, so the same signed chain exported twice yields different
    digests. Anchor the signed chain head (``envelope_hash`` of the last envelope, via
    ``anchors.publish_head_anchor``) when a stable evidence commitment is required.
    """

    parsed = bundle if isinstance(bundle, EvidenceBundle) else load_bundle(bundle)
    encoded = json.dumps(
        parsed.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
