import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.grants import GrantAuthority, GrantStatus, grant_record_digest


class MutableClock:
    def __init__(self, current):
        self.current = current

    def __call__(self):
        return self.current


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

    def test_expired_grant_is_rejected_using_authority_clock(self):
        start = datetime.now(timezone.utc) - timedelta(minutes=10)
        clock = MutableClock(start)
        authority = GrantAuthority(clock=clock)
        scope = self.scope()
        authority.issue(scope, ttl=timedelta(minutes=1))
        clock.current = start + timedelta(minutes=10)
        self.assertEqual(authority.verify(scope)[0], GrantStatus.EXPIRED)
        self.assertEqual(authority.consume(scope)[0], GrantStatus.EXPIRED)

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

    def test_legacy_reusable_grant_is_not_executable(self):
        authority = GrantAuthority()
        scope = self.scope()
        record = authority.issue(scope)
        authority._records[scope.grant_id] = replace(record, single_use=False)
        self.assertEqual(authority.verify(scope)[0], GrantStatus.REUSABLE_UNSUPPORTED)
        self.assertEqual(authority.consume(scope)[0], GrantStatus.REUSABLE_UNSUPPORTED)

    def test_caller_cannot_override_verify_or_consume_clock(self):
        authority = GrantAuthority()
        scope = self.scope()
        authority.issue(scope)
        fake = datetime.now(timezone.utc) - timedelta(days=1)
        with self.assertRaises(TypeError):
            authority.verify(scope, now=fake)
        with self.assertRaises(TypeError):
            authority.consume(scope, now=fake)


if __name__ == "__main__":
    unittest.main()
