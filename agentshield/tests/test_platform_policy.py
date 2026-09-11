import unittest

from agentshield.platform.policy import (
    ActionRisk,
    ContentRisk,
    Decision,
    POLICY_VERSION,
    PolicyInput,
    decide,
)
from agentshield.platform.provenance import TrustLevel


class PolicyV2Tests(unittest.TestCase):
    def scoped(self, content_risk, action_risk, trust=TrustLevel.TRUSTED):
        return PolicyInput(
            content_risk=content_risk,
            action_risk=action_risk,
            trust_level=trust,
            scope_permitted=True,
            tool_verified=True,
        )

    def test_low_content_normal_action_allows_when_all_boundaries_pass(self):
        result = decide(self.scoped(ContentRisk.LOW, ActionRisk.NORMAL))
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.policy_version, POLICY_VERSION)
        self.assertEqual(POLICY_VERSION, "agentshield-policy-v2")

    def test_known_untrusted_low_normal_can_allow_when_explicitly_scoped(self):
        result = decide(
            self.scoped(
                ContentRisk.LOW,
                ActionRisk.NORMAL,
                trust=TrustLevel.UNTRUSTED,
            )
        )
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_high_content_sensitive_action_blocks(self):
        result = decide(self.scoped(ContentRisk.HIGH, ActionRisk.SENSITIVE))
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_low_content_sensitive_action_reviews(self):
        result = decide(self.scoped(ContentRisk.LOW, ActionRisk.SENSITIVE))
        self.assertEqual(result.decision, Decision.REVIEW)

    def test_unverified_tool_blocks(self):
        result = decide(
            PolicyInput(
                content_risk=ContentRisk.LOW,
                action_risk=ActionRisk.NORMAL,
                trust_level=TrustLevel.TRUSTED,
                scope_permitted=True,
                tool_verified=False,
            )
        )
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_missing_tool_verification_reviews(self):
        result = decide(
            PolicyInput(
                content_risk=ContentRisk.LOW,
                action_risk=ActionRisk.NORMAL,
                trust_level=TrustLevel.TRUSTED,
                scope_permitted=True,
                tool_verified=None,
            )
        )
        self.assertEqual(result.decision, Decision.REVIEW)

    def test_out_of_scope_action_blocks_even_if_content_is_low(self):
        result = decide(
            PolicyInput(
                content_risk=ContentRisk.LOW,
                action_risk=ActionRisk.NORMAL,
                trust_level=TrustLevel.TRUSTED,
                scope_permitted=False,
                tool_verified=True,
            )
        )
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_missing_scope_never_auto_allows(self):
        result = decide(
            PolicyInput(
                content_risk=ContentRisk.LOW,
                action_risk=ActionRisk.NORMAL,
                trust_level=TrustLevel.TRUSTED,
                scope_permitted=None,
                tool_verified=True,
            )
        )
        self.assertEqual(result.decision, Decision.REVIEW)

    def test_unknown_provenance_never_auto_allows(self):
        result = decide(
            PolicyInput(
                content_risk=ContentRisk.LOW,
                action_risk=ActionRisk.NORMAL,
                trust_level=TrustLevel.UNKNOWN,
                scope_permitted=True,
                tool_verified=True,
            )
        )
        self.assertEqual(result.decision, Decision.REVIEW)

    def test_unknown_content_never_allows(self):
        for action_risk in ActionRisk:
            result = decide(self.scoped(ContentRisk.UNKNOWN, action_risk))
            self.assertNotEqual(result.decision, Decision.ALLOW)

    def test_unknown_action_never_allows(self):
        for content_risk in ContentRisk:
            result = decide(self.scoped(content_risk, ActionRisk.UNKNOWN))
            self.assertNotEqual(result.decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
