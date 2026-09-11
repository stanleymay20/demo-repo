import unittest

from agentshield.platform.policy import (
    ActionRisk,
    ContentRisk,
    Decision,
    POLICY_VERSION,
    PolicyInput,
    decide,
)


class PolicyV1Tests(unittest.TestCase):
    def test_low_content_normal_action_allows(self):
        result = decide(PolicyInput(ContentRisk.LOW, ActionRisk.NORMAL))
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.policy_version, POLICY_VERSION)

    def test_high_content_sensitive_action_blocks(self):
        result = decide(PolicyInput(ContentRisk.HIGH, ActionRisk.SENSITIVE))
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_high_content_normal_action_reviews(self):
        result = decide(PolicyInput(ContentRisk.HIGH, ActionRisk.NORMAL))
        self.assertEqual(result.decision, Decision.REVIEW)

    def test_low_content_sensitive_action_reviews(self):
        result = decide(PolicyInput(ContentRisk.LOW, ActionRisk.SENSITIVE))
        self.assertEqual(result.decision, Decision.REVIEW)

    def test_unknown_content_never_allows(self):
        for action_risk in ActionRisk:
            result = decide(PolicyInput(ContentRisk.UNKNOWN, action_risk))
            self.assertNotEqual(result.decision, Decision.ALLOW)

    def test_unknown_action_never_allows(self):
        for content_risk in ContentRisk:
            result = decide(PolicyInput(content_risk, ActionRisk.UNKNOWN))
            self.assertNotEqual(result.decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
