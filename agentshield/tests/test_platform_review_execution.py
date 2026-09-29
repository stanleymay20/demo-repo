import unittest
from datetime import timedelta

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority
from agentshield.platform.integrity import action_digest, payload_digest, scope_digest, tool_manifest_digest
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.review import ReviewAuthority
from agentshield.platform.tools import ToolManifest, ToolRegistry


class FixedDetector:
    name = "review-test"
    version = "1"

    def detect(self, content):
        return DetectionResult(
            content_risk=ContentRisk.LOW,
            score=0.01,
            detector_name=self.name,
            detector_version=self.version,
        )


class Recorder:
    def __init__(self):
        self.calls = []

    def execute(self, *, action_name, payload):
        self.calls.append((action_name, dict(payload)))
        return {"ok": True}


class ReviewExecutionTests(unittest.TestCase):
    def setUp(self):
        self.action = ActionDescriptor("mail.send", ("send_message",))
        self.payload = {"to": "approved@example", "body": "status"}
        self.scope = AuthorizationScope(
            "review-grant-1",
            ("send_message",),
            issuer="test-user",
        )
        self.authority = GrantAuthority()
        self.authority.issue(self.scope, ttl=timedelta(minutes=5))
        self.manifest = ToolManifest("mail.send", ("send_message",), version="1")
        self.registry = ToolRegistry((self.manifest,))
        self.pipeline = evaluate_request(
            request_id="review-req-1",
            source_type="user_input",
            content="send the approved status",
            action=self.action,
            detector=FixedDetector(),
            payload=self.payload,
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=self.scope,
            tool_registry=self.registry,
            grant_authority=self.authority,
        )
        self.review_authority = ReviewAuthority(
            {"review-key": b"r" * 32},
            active_key_id="review-key",
        )

    def approval(self):
        return self.review_authority.issue(
            request_id=self.pipeline.audit_event.request_id,
            action_digest=action_digest(self.action),
            payload_digest=payload_digest(self.payload),
            scope_digest=scope_digest(self.scope),
            tool_manifest_digest=tool_manifest_digest(self.manifest),
            policy_version=self.pipeline.policy.policy_version,
            reviewer="human-reviewer",
        )

    def test_review_is_held_without_approval(self):
        executor = Recorder()
        result = enforce_and_execute(
            pipeline_result=self.pipeline,
            action=self.action,
            payload=self.payload,
            executor=executor,
            authorization_scope=self.scope,
            tool_registry=self.registry,
            grant_authority=self.authority,
        )
        self.assertIs(self.pipeline.policy.decision, Decision.REVIEW)
        self.assertIs(result.status, ExecutionStatus.HELD_FOR_REVIEW)
        self.assertEqual(executor.calls, [])

    def test_exact_review_approval_resumes_and_consumes_grant(self):
        executor = Recorder()
        approval = self.approval()
        result = enforce_and_execute(
            pipeline_result=self.pipeline,
            action=self.action,
            payload=self.payload,
            executor=executor,
            authorization_scope=self.scope,
            tool_registry=self.registry,
            grant_authority=self.authority,
            review_approval=approval,
            review_authority=self.review_authority,
        )
        self.assertIs(result.status, ExecutionStatus.EXECUTED)
        self.assertEqual(result.review_approval_id, approval.approval_id)
        self.assertEqual(len(executor.calls), 1)
        self.assertEqual(self.authority.verify(self.scope)[0].value, "consumed")

    def test_approval_cannot_authorize_mutated_payload(self):
        executor = Recorder()
        approval = self.approval()
        result = enforce_and_execute(
            pipeline_result=self.pipeline,
            action=self.action,
            payload={"to": "attacker@example", "body": "status"},
            executor=executor,
            authorization_scope=self.scope,
            tool_registry=self.registry,
            grant_authority=self.authority,
            review_approval=approval,
            review_authority=self.review_authority,
        )
        self.assertIs(result.status, ExecutionStatus.BLOCKED)
        self.assertIn("payload changed", result.reason)
        self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
