import unittest
from datetime import datetime, timezone

from agentshield.platform.anchors import build_head_anchor_statement, publish_head_anchor
from agentshield.platform.audit import AuditSigner, AuditTrail, Ed25519AuditSigner, envelope_hash


class RecordingPublisher:
    def __init__(self):
        self.statements = []

    def publish(self, statement):
        self.statements.append(statement)
        return "transparency://entry/123"


class EmptyReferencePublisher:
    def publish(self, _statement):
        return ""


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

    def test_publication_returns_external_reference(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1", "decision": "block"})
        publisher = RecordingPublisher()
        receipt = publish_head_anchor(
            stream_id="tenant-a:agent-1", head=trail.head, publisher=publisher,
        )
        self.assertEqual(receipt.external_reference, "transparency://entry/123")
        self.assertEqual(len(publisher.statements), 1)

    def test_hmac_chain_cannot_be_presented_as_independent_external_anchor(self):
        trail = AuditTrail(AuditSigner({"legacy": b"x" * 32}, active_key_id="legacy"))
        trail.append({"request_id": "r1"})
        with self.assertRaises(ValueError):
            build_head_anchor_statement(stream_id="stream", head=trail.head)

    def test_missing_durable_external_reference_fails(self):
        signer = Ed25519AuditSigner({"audit": b"h" * 32}, active_key_id="audit")
        trail = AuditTrail(signer)
        trail.append({"request_id": "r1"})
        with self.assertRaises(RuntimeError):
            publish_head_anchor(
                stream_id="stream", head=trail.head, publisher=EmptyReferencePublisher(),
            )


if __name__ == "__main__":
    unittest.main()
