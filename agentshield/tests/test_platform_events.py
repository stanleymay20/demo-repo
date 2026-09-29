import unittest

from agentshield.platform.events import EVENT_SCHEMA_VERSION, build_audit_event
from agentshield.platform.policy import (
    ActionRisk,
    ContentRisk,
    Decision,
    PolicyInput,
    decide,
)


class AuditEventTests(unittest.TestCase):
    def test_event_records_versioned_policy_decision(self):
        policy_decision = decide(PolicyInput(ContentRisk.HIGH, ActionRisk.SENSITIVE))
        event = build_audit_event(
            request_id="req-1",
            source_type="web",
            content_risk=ContentRisk.HIGH,
            action_risk=ActionRisk.SENSITIVE,
            policy_decision=policy_decision,
            detector_name="example-detector",
            detector_version="1",
            detector_score=0.97,
        )
        self.assertEqual(event.event_schema_version, EVENT_SCHEMA_VERSION)
        self.assertEqual(event.decision, Decision.BLOCK.value)
        self.assertEqual(event.policy_version, policy_decision.policy_version)
        self.assertEqual(event.detector_score, 0.97)

    def test_invalid_detector_score_is_rejected(self):
        policy_decision = decide(PolicyInput(ContentRisk.LOW, ActionRisk.NORMAL))
        with self.assertRaises(ValueError):
            build_audit_event(
                request_id="req-2",
                source_type="document",
                content_risk=ContentRisk.LOW,
                action_risk=ActionRisk.NORMAL,
                policy_decision=policy_decision,
                detector_score=1.1,
            )

    def test_empty_request_id_is_rejected(self):
        policy_decision = decide(PolicyInput(ContentRisk.LOW, ActionRisk.NORMAL))
        with self.assertRaises(ValueError):
            build_audit_event(
                request_id=" ",
                source_type="document",
                content_risk=ContentRisk.LOW,
                action_risk=ActionRisk.NORMAL,
                policy_decision=policy_decision,
            )


if __name__ == "__main__":
    unittest.main()
