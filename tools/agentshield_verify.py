#!/usr/bin/env python3
"""Standalone AgentShield evidence-bundle verifier.

Dependencies: Python standard library + ``cryptography`` only.
It deliberately does not import the AgentShield runtime, contact a server, or require a
secret key. The verifier accepts trust anchors explicitly as ``KEY_ID=PUBLIC_KEY_HEX``.
"""

from __future__ import annotations

import argparse
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
    schema = event.get("event_schema_version")
    if schema == "agentshield-audit-event-v1":
        return "policy_decision"
    if isinstance(schema, str) and schema.startswith("agentshield-execution-audit-event-"):
        return "execution_lifecycle"
    return "audit_event"


def parse_keys(values):
    keys = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--pubkey must use KEY_ID=PUBLIC_KEY_HEX")
        key_id, encoded = value.split("=", 1)
        key_id = key_id.strip()
        if not key_id:
            raise ValueError("public key id must be non-empty")
        try:
            raw = bytes.fromhex(encoded.strip())
        except ValueError as exc:
            raise ValueError(f"public key {key_id!r} is not valid hex") from exc
        if len(raw) != 32:
            raise ValueError(f"public key {key_id!r} must contain 32 raw bytes")
        keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
    if not keys:
        raise ValueError("at least one --pubkey trust anchor is required")
    return keys


def verify(bundle, keys):
    if type(bundle) is not dict:
        return False, "bundle is not a JSON object", 0, None
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
        record_type = record.get("record_type")
        event = record.get("event")
        envelope = record.get("envelope")
        if type(record_type) is not str or not record_type.strip():
            return False, "record_type is missing", index, None
        if type(event) is not dict or type(envelope) is not dict:
            return False, "record lacks event/envelope objects", index, None
        if record_type != record_type_for_event(event):
            return False, "record_type does not match signed event schema", index, None
        required = {
            "schema_version", "sequence", "previous_envelope_hash", "event_hash",
            "key_id", "signature", "algorithm",
        }
        if not required.issubset(envelope):
            return False, "envelope is missing required fields", index, None
        if envelope["schema_version"] != ENVELOPE_SCHEMA:
            return False, "unsupported envelope schema", index, None
        if envelope["algorithm"] != ALGORITHM:
            return False, "non-Ed25519 envelope is not independently verifiable", index, None
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
        previous = envelope

    head = envelope_hash(previous)
    return True, "valid", len(records), head


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify an AgentShield evidence bundle offline with Ed25519 public keys."
    )
    parser.add_argument("bundle", help="Path to AgentShield evidence bundle JSON")
    parser.add_argument(
        "--pubkey", action="append", default=[], metavar="KEY_ID=HEX",
        help="Trusted raw Ed25519 public key (32-byte hex); repeat for key rotation",
    )
    args = parser.parse_args(argv)
    try:
        keys = parse_keys(args.pubkey)
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        valid, reason, verified, head = verify(bundle, keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
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
