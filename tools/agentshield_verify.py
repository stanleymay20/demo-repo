#!/usr/bin/env python3
"""Standalone AgentShield evidence-bundle verifier.

Dependencies: Python standard library + ``cryptography`` only.
It deliberately does not import the AgentShield runtime, contact a server, or require a
secret key. Audit and human-review public keys are supplied as independent trust anchors.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


BUNDLE_SCHEMA = "agentshield-evidence-bundle-v1"
RECEIPT_PROFILE = "agentshield-verifiable-action-receipt-v1"
ENVELOPE_SCHEMA = "agentshield-audit-envelope-v2"
ALGORITHM = "ed25519"
SCOPE_SCHEMA_V3 = "agentshield-scope-v3"
SCOPE_SCHEMA_V4 = "agentshield-scope-v4-agent-purpose"
REVIEW_SCHEMA = "agentshield-review-v3-ed25519"
SCOPE_KEYS_V3 = {
    "scope_schema", "grant_id", "issuer", "principal", "tenant",
    "allowed_capabilities", "allowed_effects",
}
SCOPE_KEYS_V4 = SCOPE_KEYS_V3 | {
    "agent_id", "purpose_id", "delegator_agent_id", "delegator_grant_id",
}
POLICY_EVENT_SCHEMA = "agentshield-audit-event-v1"
EXECUTION_EVENT_SCHEMA = "agentshield-execution-audit-event-v2"
BUNDLE_KEYS = {"schema_version", "receipt_profile", "exported_at_utc", "records"}
RECORD_KEYS = {"record_type", "event", "envelope"}
EXECUTION_KEYS = {
    "event_schema_version", "timestamp_utc", "request_id", "evaluation_digest",
    "action_name", "decision", "phase", "status", "grant_id", "effect_digest",
    "policy_version", "grant_record_digest", "review_approval_digest", "exception_class",
}
PHASE_STATUSES = {
    "grant_consumed": {"admitted"},
    "dispatch_completed": {"executed", "failed"},
}
REVIEW_KEYS = {
    "review_schema", "evaluation_digest", "approval_id", "request_id",
    "action_digest", "payload_digest", "scope_digest", "tool_manifest_digest",
    "policy_version", "reviewer", "issued_at_utc", "expires_at_utc", "key_id",
    "signature",
}
HEX_CHARS = frozenset("0123456789abcdef")


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def event_hash(event):
    return hashlib.sha256(canonical_bytes(event)).hexdigest()


def envelope_hash(envelope):
    return hashlib.sha256(canonical_bytes(envelope)).hexdigest()


def signature_material(envelope):
    return {
        "schema_version": envelope["schema_version"],
        "algorithm": envelope["algorithm"],
        "sequence": envelope["sequence"],
        "previous_envelope_hash": envelope["previous_envelope_hash"],
        "event_hash": envelope["event_hash"],
        "key_id": envelope["key_id"],
    }


def record_type_for_event(event):
    # Exact understood schemas only. Unknown agentshield-* schemas are unsupported:
    # never promoted to v1 execution semantics, never hidden as opaque records.
    schema = event.get("event_schema_version")
    if schema == POLICY_EVENT_SCHEMA:
        return "policy_decision"
    if schema == EXECUTION_EVENT_SCHEMA:
        return "execution_lifecycle"
    if isinstance(schema, str) and schema.startswith("agentshield-"):
        return "unsupported"
    return "audit_event"


def valid_hex_digest(value):
    return type(value) is str and len(value) == 64 and all(c in HEX_CHARS for c in value)


def valid_ed25519_signature_hex(value):
    return type(value) is str and len(value) == 128 and all(c in HEX_CHARS for c in value)


def valid_optional_identity(value):
    return value is None or (type(value) is str and bool(value.strip()) and value == value.strip())


def valid_scope_material(value):
    if type(value) is not dict:
        return False
    schema = value.get("scope_schema")
    expected_keys = SCOPE_KEYS_V4 if schema == SCOPE_SCHEMA_V4 else SCOPE_KEYS_V3
    if schema not in {SCOPE_SCHEMA_V3, SCOPE_SCHEMA_V4} or set(value) != expected_keys:
        return False
    for field in ("grant_id", "issuer"):
        item = value.get(field)
        if type(item) is not str or not item.strip() or item != item.strip():
            return False
    for field in ("principal", "tenant"):
        if not valid_optional_identity(value.get(field)):
            return False
    if schema == SCOPE_SCHEMA_V4:
        for field in ("agent_id", "purpose_id"):
            item = value.get(field)
            if type(item) is not str or not item.strip() or item != item.strip():
                return False
        delegator_agent = value.get("delegator_agent_id")
        delegator_grant = value.get("delegator_grant_id")
        if not valid_optional_identity(delegator_agent) or not valid_optional_identity(delegator_grant):
            return False
        if (delegator_agent is None) != (delegator_grant is None):
            return False
    caps = value.get("allowed_capabilities")
    if type(caps) is not list or any(type(item) is not str for item in caps):
        return False
    if caps != sorted({item.strip().lower() for item in caps if item.strip()}):
        return False
    effects = value.get("allowed_effects")
    if type(effects) is not list or any(not valid_hex_digest(item) for item in effects):
        return False
    return effects == sorted(set(effects))


def scope_evidence_error(event):
    metadata = event.get("metadata")
    if type(metadata) is not dict:
        return None
    digest = metadata.get("authorization_scope_digest")
    material = metadata.get("authorization_scope_material")
    if digest is None and material is None:
        if any(key.startswith("authorization_") for key in metadata):
            return "displayed authorization identity has no canonical scope commitment"
        return None
    if not valid_hex_digest(digest) or not valid_scope_material(material):
        return "authorization scope proof is malformed or incomplete"
    if hashlib.sha256(canonical_bytes(material)).hexdigest() != digest:
        return "authorization scope digest does not match canonical scope material"
    expected = {
        "authorization_grant_id": material["grant_id"],
        "authorization_issuer": material["issuer"],
        "authorization_principal": material["principal"],
        "authorization_tenant": material["tenant"],
        "authorization_agent_id": material.get("agent_id"),
        "authorization_purpose_id": material.get("purpose_id"),
        "authorization_delegator_agent_id": material.get("delegator_agent_id"),
        "authorization_delegator_grant_id": material.get("delegator_grant_id"),
    }
    if any(metadata.get(field) != value for field, value in expected.items()):
        return "displayed authorization identity does not match canonical scope material"
    return None


def evaluation_digest(event):
    metadata = event.get("metadata")
    if type(metadata) is not dict:
        return None
    for field in ("evaluation_id", "content_digest", "provenance_digest"):
        if not valid_hex_digest(metadata.get(field)):
            return None
    return hashlib.sha256(canonical_bytes({
        "review_schema": "agentshield-review-evaluation-v1",
        "event": event,
    })).hexdigest()


def parse_time(value):
    if type(value) is not str:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return None if moment.tzinfo is None else moment.astimezone(timezone.utc)


def parse_keys(values, *, option, required):
    keys = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"{option} must use KEY_ID=PUBLIC_KEY_HEX")
        key_id, encoded = value.split("=", 1)
        key_id = key_id.strip()
        if not key_id:
            raise ValueError(f"{option} key id must be non-empty")
        try:
            raw = bytes.fromhex(encoded.strip())
        except ValueError as exc:
            raise ValueError(f"public key {key_id!r} is not valid hex") from exc
        if len(raw) != 32:
            raise ValueError(f"public key {key_id!r} must contain 32 raw bytes")
        keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
    if required and not keys:
        raise ValueError(f"at least one {option} trust anchor is required")
    return keys


def review_proof_digest(proof):
    return hashlib.sha256(canonical_bytes(proof)).hexdigest()


def verify_review_signature(proof, keys):
    if type(proof) is not dict or set(proof) != REVIEW_KEYS:
        return False, "malformed review approval proof"
    if proof.get("review_schema") != REVIEW_SCHEMA:
        return False, "unsupported review approval schema"
    for field in (
        "approval_id", "request_id", "action_digest", "payload_digest", "scope_digest",
        "tool_manifest_digest", "policy_version", "evaluation_digest", "reviewer", "key_id",
        "signature",
    ):
        value = proof.get(field)
        if type(value) is not str or not value.strip():
            return False, f"review approval field {field} is invalid"
    if not valid_hex_digest(proof["evaluation_digest"]):
        return False, "review approval evaluation digest is invalid"
    issued = parse_time(proof.get("issued_at_utc"))
    expires = parse_time(proof.get("expires_at_utc"))
    if issued is None or expires is None or expires <= issued:
        return False, "review approval time window is invalid"
    # Canonical signed form only: UTC isoformat timestamps and lowercase 128-hex
    # signature, exactly as the review service emits them.
    if proof["issued_at_utc"] != issued.isoformat() or proof["expires_at_utc"] != expires.isoformat():
        return False, "review approval timestamps are not in canonical signed form"
    if not valid_ed25519_signature_hex(proof["signature"]):
        return False, "review approval signature is not canonical lowercase Ed25519 hex"
    key = keys.get(proof["key_id"])
    if key is None:
        return False, f"unknown review public key id: {proof['key_id']}"
    signature = bytes.fromhex(proof["signature"])
    material = dict(proof)
    material.pop("signature")
    try:
        key.verify(signature, canonical_bytes(material))
    except InvalidSignature:
        return False, "invalid human-review Ed25519 signature"
    return True, None


def verify_review_proofs(bundle, records, review_keys):
    approvals = bundle.get("review_approvals", [])
    if type(approvals) is not list or any(type(item) is not dict for item in approvals):
        return "review_approvals must be a list of objects", len(records)

    refs = {}
    for index, record in enumerate(records):
        if record.get("record_type") != "execution_lifecycle":
            continue
        event = record["event"]
        digest = event.get("review_approval_digest")
        decision = event.get("decision")
        if decision == "review" and not valid_hex_digest(digest):
            return "executed REVIEW evidence lacks a valid review approval digest", index
        if digest is not None:
            if decision != "review" or not valid_hex_digest(digest):
                return "review approval digest is inconsistent with execution decision", index
            refs.setdefault(digest, []).append((index, event))

    if not refs:
        if approvals:
            return "bundle contains unreferenced human-review approval proofs", len(records)
        return None, None
    if not review_keys:
        return "human-review public key trust anchor is required", min(v[0][0] for v in refs.values())

    proofs = {}
    for proof in approvals:
        digest = review_proof_digest(proof)
        if digest in proofs:
            return "duplicate human-review approval proof", len(records)
        valid, reason = verify_review_signature(proof, review_keys)
        if not valid:
            index = refs[digest][0][0] if digest in refs else len(records)
            return reason, index
        proofs[digest] = proof

    if set(proofs) != set(refs):
        missing = set(refs) - set(proofs)
        if missing:
            return "portable receipt is missing the referenced human-review proof", min(refs[d][0][0] for d in missing)
        return "bundle contains unreferenced human-review approval proofs", len(records)

    decisions = []
    for index, record in enumerate(records):
        if record.get("record_type") != "policy_decision":
            continue
        digest = evaluation_digest(record["event"])
        if digest:
            decisions.append((index, record["event"], digest))

    for digest, linked_events in refs.items():
        proof = proofs[digest]
        matches = [
            event for _, event, eval_digest in decisions
            if event.get("request_id") == proof["request_id"]
            and event.get("decision") == "review"
            and eval_digest == proof["evaluation_digest"]
        ]
        if len(matches) != 1:
            return "human-review proof does not resolve to exactly one signed REVIEW decision", linked_events[0][0]
        decision_event = matches[0]
        metadata = decision_event.get("metadata")
        if type(metadata) is not dict:
            return "signed REVIEW decision lacks binding metadata", linked_events[0][0]
        expected = (
            metadata.get("action_digest"),
            metadata.get("payload_digest"),
            metadata.get("authorization_scope_digest"),
            metadata.get("tool_manifest_digest"),
            decision_event.get("policy_version"),
        )
        observed = (
            proof["action_digest"], proof["payload_digest"], proof["scope_digest"],
            proof["tool_manifest_digest"], proof["policy_version"],
        )
        if observed != expected:
            return "human-review proof does not match signed decision authority", linked_events[0][0]

        consumed = []
        for index, event in linked_events:
            if (
                event.get("request_id") != proof["request_id"]
                or event.get("evaluation_digest") != proof["evaluation_digest"]
                or event.get("policy_version") != proof["policy_version"]
            ):
                return "human-review proof does not match signed execution evidence", index
            if event.get("phase") == "grant_consumed" and event.get("status") == "admitted":
                moment = parse_time(event.get("timestamp_utc"))
                if moment is None:
                    return "reviewed execution timestamp is invalid", index
                consumed.append(moment)
        issued = parse_time(proof["issued_at_utc"])
        expires = parse_time(proof["expires_at_utc"])
        if len(consumed) != 1 or not (issued <= consumed[0] < expires):
            return "human-review approval was not valid at grant consumption", linked_events[0][0]
    return None, None


def execution_event_valid(event):
    if set(event) != EXECUTION_KEYS:
        return False
    for field in (
        "timestamp_utc", "request_id", "action_name", "decision", "phase", "status",
        "grant_id", "policy_version",
    ):
        value = event.get(field)
        if type(value) is not str or not value.strip():
            return False
    for field in ("evaluation_digest", "effect_digest", "grant_record_digest"):
        if not valid_hex_digest(event.get(field)):
            return False
    review = event.get("review_approval_digest")
    if review is not None and not valid_hex_digest(review):
        return False
    if event["decision"] not in {"allow", "review"}:
        return False
    if event["status"] not in PHASE_STATUSES.get(event["phase"], set()):
        return False
    exception_class = event.get("exception_class")
    if event["status"] == "failed":
        return exception_class is None or (type(exception_class) is str and bool(exception_class.strip()))
    return exception_class is None


def verify_execution_linkage(records):
    """Every execution transition must resolve to one earlier signed authorizing decision."""
    decisions = {}
    for index, record in enumerate(records):
        if record["record_type"] != "policy_decision":
            continue
        digest = evaluation_digest(record["event"])
        request_id = record["event"].get("request_id")
        if digest and type(request_id) is str:
            decisions.setdefault((request_id, digest), []).append((index, record["event"]))

    lifecycle = {}
    for index, record in enumerate(records):
        if record["record_type"] != "execution_lifecycle":
            continue
        event = record["event"]
        if not execution_event_valid(event):
            return "execution evidence does not match the v2 execution-event schema", index
        key = (event["request_id"], event["evaluation_digest"])
        matches = decisions.get(key, [])
        if len(matches) != 1 or matches[0][0] >= index:
            return "execution evidence does not resolve to exactly one earlier signed decision", index
        decision_event = matches[0][1]
        metadata = decision_event.get("metadata")
        if type(metadata) is not dict:
            return "authorizing decision lacks binding metadata", index
        material = metadata.get("authorization_scope_material")
        if (
            decision_event.get("decision") != event["decision"]
            or decision_event.get("policy_version") != event["policy_version"]
            or metadata.get("action_name") != event["action_name"]
            or metadata.get("authorization_grant_id") != event["grant_id"]
            or metadata.get("effect_digest") != event["effect_digest"]
        ):
            return "execution evidence does not match its authorizing decision", index
        if type(material) is not dict or event["effect_digest"] not in material.get("allowed_effects", []):
            return "executed effect is not committed by the authorizing scope", index
        phases = lifecycle.setdefault(key, set())
        phase = event["phase"]
        if phase in phases or (phase == "dispatch_completed" and "grant_consumed" not in phases):
            return "execution lifecycle transitions are duplicated or out of order", index
        phases.add(phase)
    return None, None


def verify(bundle, keys, review_keys=None):
    if type(bundle) is not dict:
        return False, "bundle is not a JSON object", 0, None
    if set(bundle) - {"review_approvals"} != BUNDLE_KEYS:
        return False, "bundle fields do not match the v1 receipt profile", 0, None
    if bundle.get("schema_version") != BUNDLE_SCHEMA:
        return False, "unsupported bundle schema", 0, None
    if bundle.get("receipt_profile") != RECEIPT_PROFILE:
        return False, "unsupported receipt profile", 0, None
    records = bundle.get("records")
    if type(records) is not list or not records:
        return False, "bundle contains no records", 0, None

    previous = None
    for index, record in enumerate(records):
        if type(record) is not dict:
            return False, "record is not an object", index, None
        if set(record) != RECORD_KEYS:
            return False, "record fields do not match the v1 receipt profile", index, None
        record_type = record.get("record_type")
        event = record.get("event")
        envelope = record.get("envelope")
        if type(record_type) is not str or not record_type.strip():
            return False, "record_type is missing", index, None
        if type(event) is not dict or type(envelope) is not dict:
            return False, "record lacks event/envelope objects", index, None
        if record_type_for_event(event) == "unsupported":
            return False, "unsupported AgentShield event schema for the v1 receipt profile", index, None
        if record_type != record_type_for_event(event):
            return False, "record_type does not match signed event schema", index, None
        required = {
            "schema_version", "sequence", "previous_envelope_hash", "event_hash",
            "key_id", "signature", "algorithm",
        }
        if set(envelope) != required:
            return False, "envelope fields do not match schema", index, None
        if (
            any(type(envelope[f]) is not str for f in ("schema_version", "event_hash", "key_id", "signature", "algorithm"))
            or type(envelope["sequence"]) is not int
            or (envelope["previous_envelope_hash"] is not None
                and type(envelope["previous_envelope_hash"]) is not str)
        ):
            return False, "envelope field types do not match schema", index, None
        if envelope["schema_version"] != ENVELOPE_SCHEMA:
            return False, "unsupported envelope schema", index, None
        if envelope["algorithm"] != ALGORITHM:
            return False, "non-Ed25519 envelope is not independently verifiable", index, None
        if not valid_ed25519_signature_hex(envelope.get("signature")):
            return False, "signature is not canonical lowercase Ed25519 hex", index, None
        if envelope["sequence"] != index:
            return False, "envelope sequence is not contiguous from zero", index, None
        expected_previous = None if previous is None else envelope_hash(previous)
        if envelope["previous_envelope_hash"] != expected_previous:
            return False, "hash-chain link mismatch", index, None
        if envelope["event_hash"] != event_hash(event):
            return False, "event hash mismatch", index, None
        key = keys.get(envelope["key_id"])
        if key is None:
            return False, f"unknown public key id: {envelope['key_id']}", index, None
        try:
            signature = bytes.fromhex(envelope["signature"])
        except (TypeError, ValueError):
            return False, "signature is not valid hex", index, None
        try:
            key.verify(signature, canonical_bytes(signature_material(envelope)))
        except InvalidSignature:
            return False, "invalid Ed25519 signature", index, None
        if record_type == "policy_decision":
            semantic_error = scope_evidence_error(event)
            if semantic_error:
                return False, semantic_error, index, None
        previous = envelope

    linkage_error, linkage_index = verify_execution_linkage(records)
    if linkage_error:
        return False, linkage_error, linkage_index, None
    review_error, review_index = verify_review_proofs(bundle, records, review_keys or {})
    if review_error:
        return False, review_error, review_index, None
    head = envelope_hash(previous)
    return True, "valid", len(records), head


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify AgentShield audit evidence and human-review proofs offline."
    )
    parser.add_argument("bundle", help="Path to AgentShield evidence bundle JSON")
    parser.add_argument(
        "--pubkey", action="append", default=[], metavar="KEY_ID=HEX",
        help="Trusted raw audit Ed25519 public key; repeat for key rotation",
    )
    parser.add_argument(
        "--review-pubkey", action="append", default=[], metavar="KEY_ID=HEX",
        help="Trusted raw human-review Ed25519 public key; required for REVIEW execution proofs",
    )
    args = parser.parse_args(argv)
    try:
        keys = parse_keys(args.pubkey, option="--pubkey", required=True)
        review_keys = parse_keys(args.review_pubkey, option="--review-pubkey", required=False)
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        valid, reason, verified, head = verify(bundle, keys, review_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
        # Hostile input must yield a structured "invalid" verdict, never a traceback.
        print(json.dumps({"valid": False, "error": str(exc)}), file=sys.stderr)
        return 2

    result = {
        "valid": valid,
        "verified_records": verified,
        "reason": reason,
        "head_envelope_hash": head,
    }
    stream = sys.stdout if valid else sys.stderr
    print(json.dumps(result, sort_keys=True), file=stream)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
