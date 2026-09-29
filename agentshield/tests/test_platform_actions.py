import unittest

from agentshield.platform.actions import ActionDescriptor, classify_action, normalize_capabilities
from agentshield.platform.policy import ActionRisk


class ActionRiskTests(unittest.TestCase):
    def test_sensitive_capability_is_sensitive(self):
        result = classify_action(
            ActionDescriptor(name="mail.send", capabilities=("send_message",))
        )
        self.assertEqual(result, ActionRisk.SENSITIVE)

    def test_declared_non_sensitive_capability_is_normal(self):
        result = classify_action(
            ActionDescriptor(name="text.summarize", capabilities=("transform_text",))
        )
        self.assertEqual(result, ActionRisk.NORMAL)

    def test_missing_capabilities_are_unknown(self):
        result = classify_action(ActionDescriptor(name="mystery.tool"))
        self.assertEqual(result, ActionRisk.UNKNOWN)

    def test_capabilities_normalize_deterministically(self):
        self.assertEqual(
            normalize_capabilities([" Publish ", "publish", "transform_text"]),
            ("publish", "transform_text"),
        )


if __name__ == "__main__":
    unittest.main()
