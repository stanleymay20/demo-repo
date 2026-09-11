import unittest
from datetime import datetime, timedelta, timezone

from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.grants import GrantAuthority, GrantStatus, grant_record_digest


class GrantAuthorityTests(unittest.TestCase):
    def scope(self, grant_id="g1"):
        return AuthorizationScope(grant_id, ("read_data",), issuer="test-user")

    def test_single_use_grant_is_valid_then_consumed(self):
        authority = GrantAuthority()
        scope = self.scope()
        record = authority.issue(scope, ttl=timedelta(minutes=5))
        self.assertEqual(authority.verify(scope)[0], GrantStatus.VALID)
        self.assertEqual(authority.consume(scope)[0], GrantStatus.VALID)
        self.assertEqual(authority.verify(scope)[0], GrantStatus.CONSUMED)
        self.assertNotEqual(grant_record_digest(record), grant_record_digest(authority.get("g1")))

    def test_expired_grant_is_rejected(self):
        authority = GrantAuthority()
        scope = self.scope()
        old = datetime.now(timezone.utc) - timedelta(minutes=10)
        authority.issue(scope, ttl=timedelta(minutes=1), now=old)
        self.assertEqual(authority.verify(scope)[0], GrantStatus.EXPIRED)

    def test_revoked_grant_is_rejected(self):
        authority = GrantAuthority()
        scope = self.scope()
        authority.issue(scope)
        self.assertTrue(authority.revoke(scope.grant_id))
        self.assertEqual(authority.verify(scope)[0], GrantStatus.REVOKED)

    def test_unknown_grant_is_rejected(self):
        authority = GrantAuthority()
        self.assertEqual(authority.verify(self.scope())[0], GrantStatus.UNKNOWN)

    def test_changed_scope_with_same_id_is_mismatch(self):
        authority = GrantAuthority()
        scope = self.scope()
        authority.issue(scope)
        changed = AuthorizationScope("g1", ("send_message",), issuer="test-user")
        self.assertEqual(authority.verify(changed)[0], GrantStatus.MISMATCH)

    def test_duplicate_grant_id_cannot_be_reissued(self):
        authority = GrantAuthority()
        scope = self.scope()
        authority.issue(scope)
        with self.assertRaises(ValueError):
            authority.issue(scope)

    def test_multi_use_grant_remains_valid_after_consume(self):
        authority = GrantAuthority()
        scope = self.scope()
        authority.issue(scope, single_use=False)
        self.assertEqual(authority.consume(scope)[0], GrantStatus.VALID)
        self.assertEqual(authority.verify(scope)[0], GrantStatus.VALID)


if __name__ == "__main__":
    unittest.main()
