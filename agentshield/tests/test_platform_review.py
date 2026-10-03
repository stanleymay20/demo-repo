import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from agentshield.platform.review import ReviewAuthority, ReviewStatus


class ReviewAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.authority = ReviewAuthority(
            {"k1": b"a" * 32, "old": b"b" * 32},
            active_key_id="k1",
        )
        self.kwargs = dict(
            request_id="req-1",
            action_digest="a" * 64,
            payload_digest="b" * 64,
            scope_digest="c" * 64,
            tool_manifest_digest="d" * 64,
            policy_version="agentshield-policy-v7",
            evaluation_digest="e" * 64,
        )

    def test_valid_approval_verifies(self):
        approval = self.authority.issue(**self.kwargs, reviewer="human@example")
        self.assertIs(
            self.authority.verify(approval, **self.kwargs),
            ReviewStatus.VALID,
        )

    def test_tampered_approval_fails_signature(self):
        approval = self.authority.issue(**self.kwargs, reviewer="human@example")
        tampered = replace(approval, reviewer="attacker")
        self.assertIs(
            self.authority.verify(tampered, **self.kwargs),
            ReviewStatus.INVALID_SIGNATURE,
        )

    def test_approval_is_bound_to_exact_payload(self):
        approval = self.authority.issue(**self.kwargs, reviewer="human@example")
        changed = dict(self.kwargs)
        changed["payload_digest"] = "e" * 64
        self.assertIs(
            self.authority.verify(approval, **changed),
            ReviewStatus.MISMATCH,
        )

    def test_evaluation_binding_is_signed_and_compared(self):
        approval = self.authority.issue(**self.kwargs, reviewer="human@example")
        self.assertIs(self.authority.verify(replace(approval, evaluation_digest="f" * 64),
                                           **self.kwargs), ReviewStatus.INVALID_SIGNATURE)
        changed = dict(self.kwargs, evaluation_digest="f" * 64)
        self.assertIs(self.authority.verify(approval, **changed), ReviewStatus.MISMATCH)

    def test_missing_or_invalid_evaluation_digest_cannot_be_issued(self):
        for value in ("", "short", "z" * 64, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.authority.issue(**dict(self.kwargs, evaluation_digest=value), reviewer="human")
        legacy = dict(self.kwargs)
        del legacy["evaluation_digest"]
        with self.assertRaises(TypeError):
            self.authority.issue(**legacy, reviewer="human")

    def test_future_approval_is_not_yet_valid(self):
        now = datetime.now(timezone.utc)
        approval = self.authority.issue(**self.kwargs, reviewer="human", now=now + timedelta(minutes=1))
        self.assertIs(self.authority.verify(approval, **self.kwargs, now=now), ReviewStatus.NOT_YET_VALID)

    def test_expired_approval_fails_closed(self):
        issued = datetime.now(timezone.utc) - timedelta(minutes=10)
        approval = self.authority.issue(
            **self.kwargs,
            reviewer="human@example",
            ttl=timedelta(minutes=1),
            now=issued,
        )
        self.assertIs(
            self.authority.verify(approval, **self.kwargs),
            ReviewStatus.EXPIRED,
        )


if __name__ == "__main__":
    unittest.main()
