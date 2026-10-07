import unittest
from dataclasses import replace
from datetime import datetime, timezone

from agentshield.platform.anchors import (
    AnchorPublication,
    anchor_statement_digest,
    build_head_anchor_statement,
    publish_head_anchor,
)
from agentshield.platform.audit import AuditSigner, AuditTrail, Ed25519AuditSigner, envelope_hash


class RecordingPublisher:
    def __init__(self):
        self.statements = []

    def publish(self, statement):
        self.statements.append(statement)
        return AnchorPublication(
            external_reference="transparency://entry/123",
            committed_statement_digest=anchor_statement_digest(statement),
        )


class WrongCommitmentPublisher:
    def publish(self, _statement):
        return AnchorPublication(
            external_reference="transparency://entry/wrong",
            committed_statement_digest="0" * 64,
        )


class LegacyStringPublisher:
    def publish(self, _statement):
        return "transparency://entry/legacy"


class HeadAnchorTests(unittest.TestCase):
    def test_statement_binds_stream_sequence_head_hash_and_key(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1", "decision": "block"})
        trail.append({"request_id": "r2", "decision": "allow"})
        observed = datetime(2026, 10, 7, 16, 0, tzinfo=timezone.utc)

        statement = build_head_anchor_statement(
            stream_id="tenant-a:agent-1", head=trail.head, observed_at_utc=observed,
        )
        self.assertEqual(statement.sequence, 1)
        self.assertEqual(statement.head_envelope_hash, envelope_hash(trail.head))
        self.assertEqual(statement.audit_key_id, "audit")
        self.assertEqual(statement.observed_at_utc, observed.isoformat())
        self.assertEqual(len(anchor_statement_digest(statement)), 64)

    def test_stream_identity_is_part_of_external_commitment(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1"})
        observed = datetime(2026, 10, 7, 16, 0, tzinfo=timezone.utc)
        first = build_head_anchor_statement(
            stream_id="tenant-a:agent-1", head=trail.head, observed_at_utc=observed,
        )
        second = build_head_anchor_statement(
            stream_id="tenant-b:agent-1", head=trail.head, observed_at_utc=observed,
        )
        self.assertNotEqual(anchor_statement_digest(first), anchor_statement_digest(second))

    def test_publication_returns_reference_and_exact_statement_commitment(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1", "decision": "block"})
        publisher = RecordingPublisher()
        receipt = publish_head_anchor(
            stream_id="tenant-a:agent-1", head=trail.head, publisher=publisher,
        )
        self.assertEqual(receipt.external_reference, "transparency://entry/123")
        self.assertEqual(receipt.statement_digest, anchor_statement_digest(receipt.statement))
        self.assertEqual(len(publisher.statements), 1)

    def test_hmac_chain_cannot_be_presented_as_independent_external_anchor(self):
        trail = AuditTrail(AuditSigner({"legacy": b"x" * 32}, active_key_id="legacy"))
        trail.append({"request_id": "r1"})
        with self.assertRaises(ValueError):
            build_head_anchor_statement(stream_id="stream", head=trail.head)

    def test_unsupported_audit_schema_cannot_be_anchored(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1"})
        unsupported = replace(
            trail.head,
            schema_version="agentshield-audit-envelope-v999",
        )
        with self.assertRaisesRegex(ValueError, "unsupported audit envelope schema"):
            build_head_anchor_statement(stream_id="stream", head=unsupported)

    def test_provider_commitment_mismatch_fails_closed(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1"})
        with self.assertRaisesRegex(RuntimeError, "different statement digest"):
            publish_head_anchor(
                stream_id="stream", head=trail.head, publisher=WrongCommitmentPublisher(),
            )

    def test_legacy_reference_only_publisher_is_rejected(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1"})
        with self.assertRaisesRegex(RuntimeError, "AnchorPublication"):
            publish_head_anchor(
                stream_id="stream", head=trail.head, publisher=LegacyStringPublisher(),
            )


if __name__ == "__main__":
    unittest.main()
