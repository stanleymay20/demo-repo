import unittest
from datetime import datetime, timedelta, timezone

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.grants import GrantAuthority
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

    def scope(self, *capabilities, grant_id="grant-test"):
        return AuthorizationScope(
            grant_id=grant_id,
            allowed_capabilities=tuple(capabilities),
            issuer="test-user",
        )

    def registry(self, name, *capabilities):
        return ToolRegistry((ToolManifest(name, tuple(capabilities), version="1"),))

    def authority(self, scope, *, expired=False, revoked=False, consumed=False):
        authority = GrantAuthority()
        if expired:
            old = datetime.now(timezone.utc) - timedelta(minutes=10)
            authority.issue(scope, ttl=timedelta(minutes=1), now=old)
        else:
            authority.issue(scope)
        if revoked:
            authority.revoke(scope.grant_id)
        if consumed:
            authority.consume(scope)
        return authority

    def test_high_risk_sensitive_action_blocks_and_audits(self):
        action = ActionDescriptor(name="mail.send", capabilities=("send_message",))
        scope = self.scope("send_message")
        result = evaluate_request(
            request_id="r1",
            source_type="web",
            content="untrusted content",
            action=action,
            detector=FakeDetector(ContentRisk.HIGH, 0.98),
            provenance=self.provenance("web"),
            authorization_scope=scope,
            tool_registry=self.registry("mail.send", "send_message"),
            grant_authority=self.authority(scope),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["scope_status"], "permitted")
        self.assertEqual(result.audit_event.metadata["grant_status"], "valid")
        self.assertEqual(result.audit_event.metadata["tool_status"], "verified")

    def test_low_risk_normal_action_allows_when_grant_scope_and_tool_are_valid(self):
        action = ActionDescriptor(name="text.summarize", capabilities=("transform_text",))
        scope = self.scope("transform_text")
        result = evaluate_request(
            request_id="r2",
            source_type="document",
            content="benign content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.05),
            provenance=self.provenance("document"),
            authorization_scope=scope,
            tool_registry=self.registry("text.summarize", "transform_text"),
            grant_authority=self.authority(scope),
        )
        self.assertEqual(result.policy.decision, Decision.ALLOW)
        self.assertEqual(result.audit_event.metadata["grant_status"], "valid")
        self.assertIn("grant_record_digest", result.audit_event.metadata)

    def test_expired_grant_blocks(self):
        action = ActionDescriptor("calendar.read", ("read_data",))
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="expired",
            source_type="user_input",
            content="read calendar",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
            authorization_scope=scope,
            tool_registry=self.registry("calendar.read", "read_data"),
            grant_authority=self.authority(scope, expired=True),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["grant_status"], "expired")

    def test_revoked_grant_blocks(self):
        action = ActionDescriptor("calendar.read", ("read_data",))
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="revoked",
            source_type="user_input",
            content="read calendar",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
            authorization_scope=scope,
            tool_registry=self.registry("calendar.read", "read_data"),
            grant_authority=self.authority(scope, revoked=True),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["grant_status"], "revoked")

    def test_consumed_grant_blocks_replay_at_evaluation(self):
        action = ActionDescriptor("calendar.read", ("read_data",))
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="consumed",
            source_type="user_input",
            content="read calendar",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
            authorization_scope=scope,
            tool_registry=self.registry("calendar.read", "read_data"),
            grant_authority=self.authority(scope, consumed=True),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["grant_status"], "consumed")

    def test_unknown_grant_blocks(self):
        action = ActionDescriptor("calendar.read", ("read_data",))
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="unknown-grant",
            source_type="user_input",
            content="read calendar",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
            authorization_scope=scope,
            tool_registry=self.registry("calendar.read", "read_data"),
            grant_authority=GrantAuthority(),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["grant_status"], "unknown")

    def test_missing_grant_authority_cannot_auto_allow(self):
        action = ActionDescriptor("calendar.read", ("read_data",))
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="missing-authority",
            source_type="user_input",
            content="read calendar",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("user_input", TrustLevel.TRUSTED),
            authorization_scope=scope,
            tool_registry=self.registry("calendar.read", "read_data"),
        )
        self.assertEqual(result.policy.decision, Decision.REVIEW)

    def test_unknown_action_cannot_silently_allow(self):
        action = ActionDescriptor(name="unknown.tool")
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="r3",
            source_type="web",
            content="benign-looking content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.05),
            provenance=self.provenance("web"),
            authorization_scope=scope,
            tool_registry=ToolRegistry(()),
            grant_authority=self.authority(scope),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["tool_status"], "unregistered")

    def test_out_of_scope_capability_escalation_blocks(self):
        action = ActionDescriptor(name="mail.send", capabilities=("send_message",))
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="r5",
            source_type="tool_output",
            content="benign-looking content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("tool_output"),
            authorization_scope=scope,
            tool_registry=self.registry("mail.send", "send_message"),
            grant_authority=self.authority(scope),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["scope_status"], "denied")

    def test_agent_cannot_underdeclare_authoritative_tool_capabilities(self):
        action = ActionDescriptor(name="mail.send", capabilities=("read_data",))
        scope = self.scope("read_data")
        result = evaluate_request(
            request_id="r6",
            source_type="tool_output",
            content="benign-looking content",
            action=action,
            detector=FakeDetector(ContentRisk.LOW, 0.01),
            provenance=self.provenance("tool_output"),
            authorization_scope=scope,
            tool_registry=self.registry("mail.send", "send_message"),
            grant_authority=self.authority(scope),
        )
        self.assertEqual(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["tool_status"], "mismatch")


if __name__ == "__main__":
    unittest.main()
