import os
import unittest
from concurrent.futures import ThreadPoolExecutor

from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.grants import GrantStatus
from agentshield.platform.postgres_grants import PostgresGrantAuthority


DSN = os.getenv("AGENTSHIELD_TEST_POSTGRES_DSN")


@unittest.skipUnless(DSN, "AGENTSHIELD_TEST_POSTGRES_DSN is not configured")
class PostgresGrantAuthorityTests(unittest.TestCase):
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
            ("read_data",),
            issuer="integration-test",
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


if __name__ == "__main__":
    unittest.main()
