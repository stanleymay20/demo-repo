import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from agentshield.platform.review import ReviewSigner, ReviewVerifier, ReviewStatus


class MutableClock:
    def __init__(self, current):
        self.current = current

    def __call__(self):
        return self.current


class ReviewAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.clock = MutableClock(datetime.now(timezone.utc))
        self.signer = ReviewSigner(
            {"k1": b"a" * 32, "old": b"b" * 32},
            active_key_id="k1",
            clock=self.clock,
        )
        self.verifier = ReviewVerifier(self.signer.public_keys(), clock=self.clock)
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
        approval = self.signer.issue(**self.kwargs, reviewer="human@example")
        self.assertIs(
            self.verifier.verify(approval, **self.kwargs),
            ReviewStatus.VALID,
        )

    def test_verifier_contains_no_private_signing_api(self):
        self.assertFalse(hasattr(self.verifier, "issue"))
        self.assertFalse(hasattr(self.verifier, "_private_keys"))

    def test_tampered_approval_fails_signature(self):
        approval = self.signer.issue(**self.kwargs, reviewer="human@example")
        tampered = replace(approval, reviewer="attacker")
        self.assertIs(
            self.verifier.verify(tampered, **self.kwargs),
            ReviewStatus.INVALID_SIGNATURE,
        )

    def test_approval_is_bound_to_exact_payload(self):
        approval = self.signer.issue(**self.kwargs, reviewer="human@example")
        changed = dict(self.kwargs)
        changed["payload_digest"] = "f" * 64
        self.assertIs(
            self.verifier.verify(approval, **changed),
            ReviewStatus.MISMATCH,
        )

    def test_evaluation_binding_is_signed_and_compared(self):
        approval = self.signer.issue(**self.kwargs, reviewer="human@example")
        self.assertIs(self.verifier.verify(replace(approval, evaluation_digest="f" * 64),
                                           **self.kwargs), ReviewStatus.INVALID_SIGNATURE)
        changed = dict(self.kwargs, evaluation_digest="f" * 64)
        self.assertIs(self.verifier.verify(approval, **changed), ReviewStatus.MISMATCH)

    def test_missing_or_invalid_evaluation_digest_cannot_be_issued(self):
        for value in ("", "short", "z" * 64, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.signer.issue(**dict(self.kwargs, evaluation_digest=value), reviewer="human")
        legacy = dict(self.kwargs)
        del legacy["evaluation_digest"]
        with self.assertRaises(TypeError):
            self.signer.issue(**legacy, reviewer="human")

    def test_future_approval_is_not_yet_valid(self):
        now = self.clock.current
        self.clock.current = now + timedelta(minutes=1)
        approval = self.signer.issue(**self.kwargs, reviewer="human")
        self.clock.current = now
        self.assertIs(self.verifier.verify(approval, **self.kwargs), ReviewStatus.NOT_YET_VALID)

    def test_expired_approval_fails_closed(self):
        now = self.clock.current
        self.clock.current = now - timedelta(minutes=10)
        approval = self.signer.issue(
            **self.kwargs,
            reviewer="human@example",
            ttl=timedelta(minutes=1),
        )
        self.clock.current = now
        self.assertIs(
            self.verifier.verify(approval, **self.kwargs),
            ReviewStatus.EXPIRED,
        )


if __name__ == "__main__":
    unittest.main()
