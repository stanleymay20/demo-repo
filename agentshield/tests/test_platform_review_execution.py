import unittest
from datetime import timedelta
from dataclasses import replace

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.events import evaluation_digest
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
        self.manifest = ToolManifest("mail.send", ("send_message",), version="1")
        self.scope = AuthorizationScope(
            "review-grant-1",
            ("send_message",),
            issuer="test-user",
            allowed_effects=(effect_digest(action=self.action, payload=self.payload,
                manifest=self.manifest),),
        )
        self.authority = GrantAuthority()
        self.authority.issue(self.scope, ttl=timedelta(minutes=5))
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
            evaluation_digest=evaluation_digest(self.pipeline.audit_event),
            reviewer="human-reviewer",
        )

    def execute_review(self, pipeline, approval):
        executor = Recorder()
        result = enforce_and_execute(
            pipeline_result=pipeline, action=self.action, payload=self.payload,
            executor=executor, authorization_scope=self.scope, tool_registry=self.registry,
            grant_authority=self.authority, review_approval=approval,
            review_authority=self.review_authority,
        )
        return result, executor

    def test_approval_cannot_follow_reused_request_id_into_new_evidence(self):
        approval = self.approval()
        cases = (
            ("changed instructions", InputProvenance("user_input", trust_level=TrustLevel.TRUSTED)),
            ("send the approved status", InputProvenance("user_input", source_id="new-source",
                                                        trust_level=TrustLevel.UNTRUSTED)),
            ("send the approved status", InputProvenance("user_input", trust_level=TrustLevel.TRUSTED)),
        )
        for content, provenance in cases:
            with self.subTest(content=content, provenance=provenance):
                pipeline = evaluate_request(
                    request_id=self.pipeline.audit_event.request_id,
                    source_type="user_input", content=content, action=self.action,
                    detector=FixedDetector(), payload=self.payload, provenance=provenance,
                    authorization_scope=self.scope, tool_registry=self.registry,
                    grant_authority=self.authority,
                )
                self.assertIs(pipeline.policy.decision, Decision.REVIEW)
                result, executor = self.execute_review(pipeline, approval)
                self.assertIs(result.status, ExecutionStatus.BLOCKED)
                self.assertIn("mismatch", result.reason)
                self.assertEqual(executor.calls, [])
                self.assertEqual(self.authority.verify(self.scope)[0].value, "valid")
        # Rejected reuse does not destroy the original reviewed execution right.
        result, executor = self.execute_review(self.pipeline, approval)
        self.assertIs(result.status, ExecutionStatus.EXECUTED)
        self.assertEqual(len(executor.calls), 1)

    def test_review_rejects_changed_evidence_even_with_same_evaluation_id(self):
        approval = self.approval()
        event = self.pipeline.audit_event
        variants = [replace(event, detector_version="changed"),
                    replace(event, detector_score=0.4), replace(event, reason="changed")]
        for key in ("content_digest", "provenance_digest", "provenance_trust"):
            metadata = dict(event.metadata)
            metadata[key] = "f" * 64 if key.endswith("digest") else "unknown"
            variants.append(replace(event, metadata=metadata))
        for changed in variants:
            with self.subTest(event=changed):
                result, executor = self.execute_review(replace(self.pipeline, audit_event=changed), approval)
                self.assertIs(result.status, ExecutionStatus.BLOCKED)
                self.assertEqual(executor.calls, [])
                self.assertEqual(self.authority.verify(self.scope)[0].value, "valid")

    def test_legacy_evaluation_missing_bindings_cannot_execute_with_approval(self):
        approval = self.approval()
        for key in ("content_digest", "provenance_digest", "evaluation_id"):
            metadata = dict(self.pipeline.audit_event.metadata)
            del metadata[key]
            pipeline = replace(self.pipeline, audit_event=replace(self.pipeline.audit_event, metadata=metadata))
            result, executor = self.execute_review(pipeline, approval)
            self.assertIs(result.status, ExecutionStatus.BLOCKED)
            self.assertIn("bindings", result.reason)
            self.assertEqual(executor.calls, [])
        self.assertEqual(self.authority.verify(self.scope)[0].value, "valid")

    def test_content_and_provenance_bindings_do_not_log_raw_content(self):
        metadata = self.pipeline.audit_event.metadata
        self.assertEqual(metadata["content_digest"], payload_digest({"content": "send the approved status"}))
        self.assertEqual(metadata["provenance_digest"], payload_digest({
            "source_type": "user_input", "source_id": None, "trust_level": "trusted", "content_type": None,
        }))
        self.assertNotIn("send the approved status", str(self.pipeline.audit_event.to_dict()))

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

    def test_review_approval_rejects_multi_use_grant(self):
        scope = AuthorizationScope(
            "review-grant-multi",
            ("send_message",),
            issuer="test-user",
            allowed_effects=self.scope.allowed_effects,
        )
        authority = GrantAuthority()
        authority.issue(scope, ttl=timedelta(minutes=5), single_use=False)
        pipeline = evaluate_request(
            request_id="review-req-multi",
            source_type="user_input",
            content="send the approved status",
            action=self.action,
            detector=FixedDetector(),
            payload=self.payload,
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=scope,
            tool_registry=self.registry,
            grant_authority=authority,
        )
        approval = self.review_authority.issue(
            request_id=pipeline.audit_event.request_id,
            action_digest=action_digest(self.action),
            payload_digest=payload_digest(self.payload),
            scope_digest=scope_digest(scope),
            tool_manifest_digest=tool_manifest_digest(self.manifest),
            policy_version=pipeline.policy.policy_version,
            evaluation_digest=evaluation_digest(pipeline.audit_event),
            reviewer="human-reviewer",
        )
        executor = Recorder()
        result = enforce_and_execute(
            pipeline_result=pipeline,
            action=self.action,
            payload=self.payload,
            executor=executor,
            authorization_scope=scope,
            tool_registry=self.registry,
            grant_authority=authority,
            review_approval=approval,
            review_authority=self.review_authority,
        )
        self.assertIs(result.status, ExecutionStatus.BLOCKED)
        self.assertIn("single-use", result.reason)
        self.assertEqual(executor.calls, [])

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

    def test_approved_recipient_snapshot_survives_mutation_during_consumption(self):
        executor = Recorder()
        approval = self.approval()
        consume = self.authority.consume

        def mutate_recipient(scope, **kwargs):
            self.payload["to"] = "attacker@example"
            return consume(scope, **kwargs)

        self.authority.consume = mutate_recipient
        result = enforce_and_execute(
            pipeline_result=self.pipeline, action=self.action, payload=self.payload,
            executor=executor, authorization_scope=self.scope, tool_registry=self.registry,
            grant_authority=self.authority, review_approval=approval,
            review_authority=self.review_authority,
        )
        self.assertIs(result.status, ExecutionStatus.EXECUTED)
        self.assertEqual(executor.calls, [("mail.send", {"to": "approved@example", "body": "status"})])


if __name__ == "__main__":
    unittest.main()
