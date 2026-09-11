import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.tools import ToolManifest, ToolRegistry


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

    def registry(self, name, *capabilities):
        return ToolRegistry((ToolManifest(name, tuple(capabilities), version="1"),))

    def test_high_risk_sensitive_action_blocks_and_audits(self):
        action = ActionDescriptor(name="mail.send", capabilities=("send_message",))
        result = evaluate_request(
            request_id="r1",
            source_type="web",
            content="untrusted content",
            action=action,
            detector=FakeDetector(ContentRisk.HIGH, 0.98),
            provenance=self.provenance("web"),
            authorization_scope=self.scope("send_message"),
            tool_registry=self.registry("mail.send", "send_message"),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["scope_status"], "permitted")
        self.assertEqual(result.audit_event.metadata["tool_status"], "verified")

    def test_low_risk_normal_action_allows_when_explicitly_scoped_and_verified(self):
        action = ActionDescriptor(name="text.summarize", capabilities=("transform_text",))
        result = evaluate_request(
            request_id="r2",
            source_type="document",
            content="benign content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.05),
            provenance=self.provenance("document"),
            authorization_scope=self.scope("transform_text"),
            tool_registry=self.registry("text.summarize", "transform_text"),
        )
        self.assertEqual(result.policy.decision, Decision.ALLOW)

    def test_unknown_action_cannot_silently_allow(self):
        action = ActionDescriptor(name="unknown.tool")
        result = evaluate_request(
            request_id="r3",
            source_type="web",
            content="benign-looking content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.05),
            provenance=self.provenance("web"),
            authorization_scope=self.scope("read_data"),
            tool_registry=ToolRegistry(()),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["tool_status"], "unregistered")

    def test_missing_scope_cannot_auto_allow(self):
        action = ActionDescriptor(name="calendar.read", capabilities=("read_data",))
        result = evaluate_request(
            request_id="r4",
            source_type="user_input",
            content="read my calendar",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
            tool_registry=self.registry("calendar.read", "read_data"),
        )
        self.assertEqual(result.policy.decision, Decision.REVIEW)
        self.assertEqual(result.audit_event.metadata["scope_status"], "unknown")

    def test_out_of_scope_capability_escalation_blocks(self):
        action = ActionDescriptor(name="mail.send", capabilities=("send_message",))
        result = evaluate_request(
            request_id="r5",
            source_type="tool_output",
            content="benign-looking content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("tool_output"),
            authorization_scope=self.scope("read_data"),
            tool_registry=self.registry("mail.send", "send_message"),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["scope_status"], "denied")

    def test_agent_cannot_underdeclare_authoritative_tool_capabilities(self):
        action = ActionDescriptor(name="mail.send", capabilities=("read_data",))
        result = evaluate_request(
            request_id="r6",
            source_type="tool_output",
            content="benign-looking content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("tool_output"),
            authorization_scope=self.scope("read_data"),
            tool_registry=self.registry("mail.send", "send_message"),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["tool_status"], "mismatch")

    def test_missing_tool_registry_cannot_auto_allow(self):
        action = ActionDescriptor(name="calendar.read", capabilities=("read_data",))
        result = evaluate_request(
            request_id="r7",
            source_type="user_input",
            content="read my calendar",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
            authorization_scope=self.scope("read_data"),
        )
        self.assertEqual(result.policy.decision, Decision.REVIEW)
        self.assertEqual(result.audit_event.metadata["tool_status"], "unknown")


if __name__ == "__main__":
    unittest.main()
