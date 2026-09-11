import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel


class FakeDetector:
    name = "fake"
    version = "1"

    def __init__(self, risk: ContentRisk, score: float):
        self._risk = risk
        self._score = score

    def detect(self, content: str) -> DetectionResult:
        return DetectionResult(
            content_risk=self._risk,
            score=self._score,
            detector_name=self.name,
            detector_version=self.version,
        )


class PipelineTests(unittest.TestCase):
    def provenance(self, source_type, trust=TrustLevel.UNTRUSTED):
        return InputProvenance(source_type=source_type, trust_level=trust)

    def scope(self, *capabilities):
        return AuthorizationScope(
            grant_id="grant-test",
            allowed_capabilities=tuple(capabilities),
            issuer="test-user",
        )

    def test_high_risk_sensitive_action_blocks_and_audits(self):
        result = evaluate_request(
            request_id="r1",
            source_type="web",
            content="untrusted content",
            action=ActionDescriptor(name="mail.send", capabilities=("send_message",)),
            detector=FakeDetector(ContentRisk.HIGH, 0.98),
            provenance=self.provenance("web"),
            authorization_scope=self.scope("send_message"),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.decision, Decision.BLOCK.value)
        self.assertEqual(result.audit_event.metadata["action_name"], "mail.send")
        self.assertEqual(result.audit_event.metadata["scope_status"], "permitted")
        self.assertEqual(
            result.audit_event.metadata["authorization_grant_id"], "grant-test"
        )

    def test_low_risk_normal_action_allows_when_explicitly_scoped(self):
        result = evaluate_request(
            request_id="r2",
            source_type="document",
            content="benign content",
            action=ActionDescriptor(name="text.summarize", capabilities=("transform_text",)),
            detector=FakeDetector(ContentRisk.LOW, 0.05),
            provenance=self.provenance("document"),
            authorization_scope=self.scope("transform_text"),
        )
        self.assertEqual(result.policy.decision, Decision.ALLOW)

    def test_unknown_action_cannot_silently_allow(self):
        result = evaluate_request(
            request_id="r3",
            source_type="web",
            content="benign-looking content",
            action=ActionDescriptor(name="unknown.tool"),
            detector=FakeDetector(ContentRisk.LOW, 0.05),
            provenance=self.provenance("web"),
            authorization_scope=self.scope("read_data"),
        )
        self.assertEqual(result.policy.decision, Decision.REVIEW)

    def test_missing_scope_cannot_auto_allow(self):
        result = evaluate_request(
            request_id="r4",
            source_type="user_input",
            content="read my calendar",
            action=ActionDescriptor(name="calendar.read", capabilities=("read_data",)),
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
        )
        self.assertEqual(result.policy.decision, Decision.REVIEW)
        self.assertEqual(result.audit_event.metadata["scope_status"], "unknown")

    def test_out_of_scope_capability_escalation_blocks(self):
        result = evaluate_request(
            request_id="r5",
            source_type="tool_output",
            content="benign-looking content",
            action=ActionDescriptor(name="mail.send", capabilities=("send_message",)),
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("tool_output"),
            authorization_scope=self.scope("read_data"),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["scope_status"], "denied")

    def test_source_type_must_match_provenance(self):
        with self.assertRaises(ValueError):
            evaluate_request(
                request_id="r6",
                source_type="email",
                content="content",
                action=ActionDescriptor(name="read", capabilities=("read_data",)),
                detector=FakeDetector(ContentRisk.LOW, 0.01),
                provenance=self.provenance("web"),
                authorization_scope=self.scope("read_data"),
            )


if __name__ == "__main__":
    unittest.main()
