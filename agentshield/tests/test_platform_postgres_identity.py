import os
from dataclasses import replace
import unittest
import uuid

from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.grants import GrantStatus
from agentshield.platform.postgres_grants import PostgresGrantAuthority


DSN = os.getenv("AGENTSHIELD_TEST_POSTGRES_DSN")


@unittest.skipUnless(DSN, "AGENTSHIELD_TEST_POSTGRES_DSN is not configured")
class PostgresIdentityBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        cls.psycopg = psycopg

    def setUp(self):
        self.table = "agentshield_identity_" + uuid.uuid4().hex[:12]
        self.authority = PostgresGrantAuthority(self._connect, table_name=self.table)
        self.authority.ensure_schema()
        self.scope = AuthorizationScope(
            "root", ("read_data", "transform_text"), issuer="policy-service",
            allowed_effects=("a" * 64, "b" * 64),
            principal="employee-42", tenant="company-7",
        )

    def tearDown(self):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(f"DROP TABLE IF EXISTS {self.table}")
            conn.commit()
        finally:
            conn.close()

    def _connect(self):
        return self.psycopg.connect(DSN, autocommit=False)

    def test_forged_identity_is_scope_mismatch_across_workers(self):
        self.authority.issue(self.scope)
        other = PostgresGrantAuthority(self._connect, table_name=self.table)
        for forged in (
            replace(self.scope, principal="attacker"),
            replace(self.scope, tenant="company-8"),
        ):
            with self.subTest(forged=forged):
                self.assertIs(other.verify(forged)[0], GrantStatus.MISMATCH)
                self.assertIs(other.consume(forged)[0], GrantStatus.MISMATCH)
        self.assertIs(other.verify(self.scope)[0], GrantStatus.VALID)

    def test_delegation_preserves_principal_and_tenant(self):
        self.authority.issue(self.scope)
        child = replace(
            self.scope, grant_id="child", allowed_capabilities=("read_data",),
            allowed_effects=("a" * 64,),
        )
        with self.assertRaises(ValueError):
            self.authority.delegate(self.scope, replace(child, principal="attacker"))
        with self.assertRaises(ValueError):
            self.authority.delegate(self.scope, replace(child, tenant="company-8"))
        self.authority.delegate(self.scope, child)
        self.assertIs(self.authority.verify(child)[0], GrantStatus.VALID)


if __name__ == "__main__":
    unittest.main()
