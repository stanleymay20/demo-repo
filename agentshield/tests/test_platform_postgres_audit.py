import os
from concurrent.futures import ThreadPoolExecutor
import unittest
import uuid

from agentshield.platform.audit import Ed25519AuditSigner, Ed25519AuditVerifier, verify_chain
from agentshield.platform.postgres_audit import PostgresAuditTrail


class PostgresAuditTrailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = os.environ.get("AGENTSHIELD_TEST_POSTGRES_DSN")
        if not cls.dsn:
            raise unittest.SkipTest("AGENTSHIELD_TEST_POSTGRES_DSN is not configured")
        import psycopg
        cls.psycopg = psycopg

    def setUp(self):
        self.table = "agentshield_audit_test_" + uuid.uuid4().hex[:12]
        self.stream = "tenant-a:agent-1"
        self.private_key = b"p" * 32
        self.signer = Ed25519AuditSigner({"audit": self.private_key}, active_key_id="audit")
        self.verifier = Ed25519AuditVerifier(self.signer.public_keys())
        self.trail = PostgresAuditTrail(
            self._connect, self.signer, stream_id=self.stream, table_name=self.table,
        )
        self.trail.ensure_schema()

    def tearDown(self):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"DROP TABLE IF EXISTS {self.table}")
            conn.commit()

    def _connect(self):
        return self.psycopg.connect(self.dsn, autocommit=False)

    def _new_trail(self):
        signer = Ed25519AuditSigner({"audit": self.private_key}, active_key_id="audit")
        return PostgresAuditTrail(
            self._connect, signer, stream_id=self.stream, table_name=self.table,
        )

    def test_chain_persists_across_process_like_instances(self):
        first = self.trail.append({"event_schema_version": "decision", "request_id": "r1", "decision": "block"})
        second = self._new_trail().append({"event_schema_version": "decision", "request_id": "r2", "decision": "allow"})
        self.assertEqual((first.sequence, second.sequence), (0, 1))

        envelopes, events = self._new_trail().load()
        result = verify_chain(self.verifier, envelopes, events)
        self.assertTrue(result.valid)
        self.assertEqual(result.verified_count, 2)
        self.assertEqual(self._new_trail().head_hash, self.trail.head_hash)

    def test_concurrent_workers_serialize_one_chain(self):
        count = 12

        def append(index):
            return self._new_trail().append({
                "event_schema_version": "decision",
                "request_id": f"r-{index}",
                "decision": "block" if index % 2 else "allow",
            }).sequence

        with ThreadPoolExecutor(max_workers=6) as pool:
            sequences = list(pool.map(append, range(count)))

        self.assertEqual(sorted(sequences), list(range(count)))
        envelopes, events = self.trail.load()
        self.assertEqual([item.sequence for item in envelopes], list(range(count)))
        self.assertTrue(verify_chain(self.verifier, envelopes, events).valid)

    def test_database_event_tamper_is_detected_offline(self):
        self.trail.append({"event_schema_version": "decision", "request_id": "r1", "decision": "block"})
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE {self.table} SET event_json = %s::jsonb "
                    "WHERE stream_id = %s AND sequence = 0",
                    ('{"event_schema_version":"decision","request_id":"r1","decision":"allow"}', self.stream),
                )
            conn.commit()
        envelopes, events = self.trail.load()
        result = verify_chain(self.verifier, envelopes, events)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid_index, 0)


if __name__ == "__main__":
    unittest.main()
