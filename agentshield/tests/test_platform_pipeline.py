import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision


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
    def test_high_risk_sensitive_action_blocks_and_audits(self):
        result = evaluate_request(
            request_id="r1",
            source_type="web",
            content="untrusted content",
            action=ActionDescriptor(name="mail.send", capabilities=("send_message",)),
            detector=FakeDetector(ContentRisk.HIGH, 0.98),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.decision, Decision.BLOCK.value)
        self.assertEqual(result.audit_event.metadata["action_name"], "mail.send")

    def test_low_risk_normal_action_allows(self):
        result = evaluate_request(
            request_id="r2",
            source_type="document",
            content="benign content",
            action=ActionDescriptor(name="text.summarize", capabilities=("transform_text",)),
            detector=FakeDetector(ContentRisk.LOW, 0.05),
        )
        self.assertEqual(result.policy.decision, Decision.ALLOW)

    def test_unknown_action_cannot_silently_allow(self):
        result = evaluate_request(
            request_id="r3",
            source_type="web",
            content="benign-looking content",
            action=ActionDescriptor(name="unknown.tool"),
            detector=FakeDetector(ContentRisk.LOW, 0.05),
        )
        self.assertEqual(result.policy.decision, Decision.REVIEW)


if __name__ == "__main__":
    unittest.main()
