import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Event
import time

from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.grants import GrantStatus
from agentshield.platform.postgres_grants import PostgresGrantAuthority
from agentshield.tests.test_platform_delegation import DelegationContract


DSN = os.getenv("AGENTSHIELD_TEST_POSTGRES_DSN")


@unittest.skipUnless(DSN, "AGENTSHIELD_TEST_POSTGRES_DSN is not configured")
class PostgresGrantAuthorityTests(DelegationContract, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg

        cls.psycopg = psycopg

    def setUp(self):
        def connect():
            return self.psycopg.connect(DSN)

        self.connect = connect
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS agentshield_grants")
            conn.commit()
        finally:
            conn.close()

        self.authority = PostgresGrantAuthority(self.connect)
        self.authority.ensure_schema()
        self.scope = AuthorizationScope(
            "pg-grant-1",
            ("read_data", "transform_text"),
            issuer="integration-test",
            allowed_effects=("a" * 64, "b" * 64),
        )

    def test_grant_persists_across_authority_instances(self):
        self.authority.issue(self.scope)
        other = PostgresGrantAuthority(self.connect)
        self.assertIs(other.verify(self.scope)[0], GrantStatus.VALID)

    def test_atomic_single_use_consume_allows_exactly_one_worker(self):
        self.authority.issue(self.scope)
        a = PostgresGrantAuthority(self.connect)
        b = PostgresGrantAuthority(self.connect)

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(
                pool.map(
                    lambda authority: authority.consume(self.scope)[0],
                    (a, b),
                )
            )

        self.assertEqual(statuses.count(GrantStatus.VALID), 1)
        self.assertEqual(statuses.count(GrantStatus.CONSUMED), 1)
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.CONSUMED)

    def test_revocation_is_shared(self):
        self.authority.issue(self.scope)
        other = PostgresGrantAuthority(self.connect)
        self.assertTrue(other.revoke(self.scope.grant_id))
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.REVOKED)

    def test_effect_expansion_is_rejected_across_workers_without_consumption(self):
        self.authority.issue(self.scope)
        other = PostgresGrantAuthority(self.connect)
        forged = replace(self.scope, allowed_effects=("a" * 64, "b" * 64, "c" * 64))
        self.assertIs(other.verify(forged)[0], GrantStatus.MISMATCH)
        self.assertIs(other.consume(forged)[0], GrantStatus.MISMATCH)
        self.assertIs(other.consume(self.scope)[0], GrantStatus.VALID)

    def test_autocommit_connections_cannot_bypass_transactional_locks(self):
        self.authority.issue(self.scope)
        unsafe = PostgresGrantAuthority(lambda: self.psycopg.connect(DSN, autocommit=True))
        with self.assertRaises(ValueError):
            unsafe.consume(self.scope)
        with self.assertRaises(ValueError):
            unsafe.delegate(self.scope, self.child_scope())
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_expiry_is_checked_after_waiting_for_a_row_lock(self):
        record = self.authority.issue(self.scope, ttl=timedelta(seconds=2))
        locker = self.connect()
        ready = Event()
        def connect_waiter():
            conn = self.connect()
            ready.set()
            return conn
        waiter = PostgresGrantAuthority(connect_waiter)
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                with locker.cursor() as cur:
                    cur.execute("SELECT grant_id FROM agentshield_grants WHERE grant_id = %s FOR UPDATE",
                                (self.scope.grant_id,))
                future = pool.submit(waiter.consume, self.scope)
                self.assertTrue(ready.wait(timeout=5))
                with locker.cursor() as cur:
                    cur.execute("SELECT clock_timestamp()")
                    current = cur.fetchone()[0]
                self.assertLess(current, record.expires_at_utc)
                self.assertFalse(future.done())
                time.sleep((record.expires_at_utc - current).total_seconds() + 0.05)
            finally:
                locker.rollback()
                locker.close()
            self.assertIs(future.result(timeout=10)[0], GrantStatus.EXPIRED)
        self.assertIsNone(self.authority.get(self.scope.grant_id).consumed_at_utc)

    def test_schema_upgrade_preserves_legacy_rows_and_rejects_old_scope_hash(self):
        import hashlib
        import json
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DROP TABLE agentshield_grants")
                cur.execute("""CREATE TABLE agentshield_grants (
                    grant_id TEXT PRIMARY KEY, scope_digest TEXT NOT NULL, issuer TEXT NOT NULL,
                    nonce TEXT NOT NULL, issued_at_utc TIMESTAMPTZ NOT NULL,
                    expires_at_utc TIMESTAMPTZ NOT NULL, single_use BOOLEAN NOT NULL,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE, consumed_at_utc TIMESTAMPTZ NULL)
                """)
                material = {"grant_id": self.scope.grant_id, "issuer": self.scope.issuer,
                            "allowed_capabilities": list(self.scope.allowed_capabilities),
                            "allowed_effects": list(self.scope.allowed_effects)}
                old_hash = hashlib.sha256(json.dumps(material, sort_keys=True,
                    separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
                cur.execute("""INSERT INTO agentshield_grants
                    VALUES (%s,%s,%s,'legacy-nonce',clock_timestamp(),
                            clock_timestamp()+interval '5 minutes',TRUE,FALSE,NULL)""",
                    (self.scope.grant_id, old_hash, self.scope.issuer))
        self.authority.ensure_schema()
        self.authority.ensure_schema()
        self.assertIsNotNone(self.authority.get(self.scope.grant_id))
        self.assertIs(self.authority.consume(self.scope)[0], GrantStatus.MISMATCH)
        fresh = replace(self.scope, grant_id="migrated-root")
        self.authority.issue(fresh)
        child = self.child_scope()
        self.authority.delegate(fresh, child)
        self.assertIs(self.authority.consume(child)[0], GrantStatus.VALID)


if __name__ == "__main__":
    unittest.main()
