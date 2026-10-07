"""PostgreSQL evidence fidelity regressions (forensic finding N4).

At e7c64ea, PostgresAuditTrail persisted events JSONB could not store byte-faithfully.
The append committed, but the reloaded event hashed differently, so the durable stream
failed verification from that record onward with no error at write time.
"""

import os
import unittest
import uuid

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.audit import Ed25519AuditSigner, Ed25519AuditVerifier, verify_chain
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk
from agentshield.platform.postgres_audit import PostgresAuditTrail
from agentshield.platform.receipts import build_bundle, verify_bundle


class PostgresEvidenceFidelityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = os.environ.get("AGENTSHIELD_TEST_POSTGRES_DSN")
        if not cls.dsn:
            raise unittest.SkipTest("AGENTSHIELD_TEST_POSTGRES_DSN is not configured")
        import psycopg
        cls.psycopg = psycopg

    def setUp(self):
        self.table = "agentshield_fidelity_" + uuid.uuid4().hex[:12]
        self.signer = Ed25519AuditSigner({"audit": b"f" * 32}, active_key_id="audit")
        self.verifier = Ed25519AuditVerifier(self.signer.public_keys())
        self.trail = PostgresAuditTrail(
            self._connect, self.signer, stream_id="tenant-a:fidelity", table_name=self.table,
        )
        self.trail.ensure_schema()

    def tearDown(self):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"DROP TABLE IF EXISTS {self.table}")
            conn.commit()

    def _connect(self):
        return self.psycopg.connect(self.dsn, autocommit=False)

    def _stream_verifies(self):
        envelopes, events = self.trail.load()
        return verify_chain(self.verifier, envelopes, events).valid, len(envelopes)

    def test_lossy_event_is_refused_instead_of_silently_breaking_the_stream(self):
        self.trail.append({"event_schema_version": "host-event-v1", "n": 1})
        for lossy in (1e16, -0.0, 1.5e300):
            with self.subTest(value=lossy):
                with self.assertRaisesRegex(ValueError, "losslessly"):
                    self.trail.append({"event_schema_version": "host-event-v1", "amount": lossy})
                # nothing committed, and the stream still verifies and remains appendable
                self.assertEqual(self._stream_verifies(), (True, 1))
        self.trail.append({"event_schema_version": "host-event-v1", "amount": 1e-7})
        self.assertEqual(self._stream_verifies(), (True, 2))

    def test_pipeline_negative_zero_detector_score_keeps_durable_receipt_verifiable(self):
        class NegativeZero:
            def detect(self, _content):
                return DetectionResult(ContentRisk.LOW, -0.0, "calibrated-detector", "1")

        for request_id in ("r1", "r2"):
            evaluate_request(
                request_id=request_id, source_type="user", content="c",
                action=ActionDescriptor("docs.read", ("read_data",)), detector=NegativeZero(),
                audit_trail=self.trail,
            )
        envelopes, events = self.trail.load()
        self.assertTrue(verify_bundle(build_bundle(envelopes, events), self.signer.public_keys()).valid)


if __name__ == "__main__":
    unittest.main()
