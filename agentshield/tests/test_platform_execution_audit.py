import unittest
from datetime import timedelta

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.audit import AuditSigner, AuditTrail, AuditVerificationStatus
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority, GrantStatus
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.tools import ToolManifest, ToolRegistry


class LowDetector:
    name = "execution-audit-test"
    version = "1"

    def detect(self, content):
        return DetectionResult(ContentRisk.LOW, 0.01, self.name, self.version)


class Recorder:
    def __init__(self, *, fail=False):
        self.calls = []
        self.fail = fail

    def execute(self, *, action_name, payload):
        self.calls.append((action_name, dict(payload)))
        if self.fail:
            raise LookupError("simulated tool failure with sensitive details")
        return {"secret": "do-not-audit", "ok": True}


class ExecutionAuditTests(unittest.TestCase):
    def fixture(self):
        action = ActionDescriptor("calendar.read", ("read_data",))
        payload = {"calendar": "private-work-calendar"}
        manifest = ToolManifest(action.name, action.capabilities, version="1")
        scope = AuthorizationScope(
            "audit-execution-grant", action.capabilities, issuer="host",
            allowed_effects=(effect_digest(action=action, payload=payload, manifest=manifest),),
        )
        authority = GrantAuthority()
        authority.issue(scope, ttl=timedelta(minutes=5))
        registry = ToolRegistry((manifest,))
        result = evaluate_request(
            request_id="audit-execution-request", source_type="user_input",
            content="read my work calendar", action=action, detector=LowDetector(), payload=payload,
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=scope, tool_registry=registry, grant_authority=authority,
        )
        return action, payload, scope, authority, registry, result

    def trail(self):
        signer = AuditSigner({"audit-k1": b"x" * 32}, active_key_id="audit-k1")
        persisted = []
        trail = AuditTrail(signer, sink=lambda envelope, event: persisted.append((envelope, event)))
        return signer, trail, persisted

    def test_success_records_consumption_and_dispatch_without_raw_data(self):
        action, payload, scope, authority, registry, pipeline = self.fixture()
        signer, trail, persisted = self.trail()
        executor = Recorder()
        result = enforce_and_execute(
            pipeline_result=pipeline, action=action, payload=payload, executor=executor,
            authorization_scope=scope, tool_registry=registry, grant_authority=authority,
            audit_trail=trail,
        )
        self.assertIs(result.status, ExecutionStatus.EXECUTED)
        self.assertEqual([e.phase for e in result.audit_events], ["grant_consumed", "dispatch_completed"])
        self.assertEqual([e.status for e in result.audit_events], ["admitted", "executed"])
        self.assertTrue(all(e.policy_version == pipeline.policy.policy_version for e in result.audit_events))
        self.assertEqual(len(persisted), 2)
        first, second = result.audit_envelopes
        self.assertIs(signer.verify(first, result.audit_events[0]), AuditVerificationStatus.VALID)
        self.assertIs(
            signer.verify(second, result.audit_events[1], previous=first),
            AuditVerificationStatus.VALID,
        )
        serialized = str([event.to_dict() for event in result.audit_events])
        self.assertNotIn("private-work-calendar", serialized)
        self.assertNotIn("do-not-audit", serialized)
        self.assertNotIn("secret", serialized)

    def test_executor_exception_is_recorded_by_class_and_grant_stays_consumed(self):
        action, payload, scope, authority, registry, pipeline = self.fixture()
        _, trail, persisted = self.trail()
        result = enforce_and_execute(
            pipeline_result=pipeline, action=action, payload=payload, executor=Recorder(fail=True),
            authorization_scope=scope, tool_registry=registry, grant_authority=authority,
            audit_trail=trail,
        )
        self.assertIs(result.status, ExecutionStatus.FAILED)
        self.assertEqual(result.audit_events[-1].status, "failed")
        self.assertEqual(result.audit_events[-1].exception_class, "LookupError")
        self.assertNotIn("sensitive details", str(result.audit_events[-1].to_dict()))
        self.assertEqual(len(persisted), 2)
        self.assertIs(authority.verify(scope)[0], GrantStatus.CONSUMED)

    def test_pre_dispatch_audit_sink_failure_prevents_side_effect(self):
        action, payload, scope, authority, registry, pipeline = self.fixture()
        signer = AuditSigner({"audit-k1": b"x" * 32}, active_key_id="audit-k1")
        trail = AuditTrail(signer, sink=lambda _envelope, _event: (_ for _ in ()).throw(OSError("down")))
        executor = Recorder()
        result = enforce_and_execute(
            pipeline_result=pipeline, action=action, payload=payload, executor=executor,
            authorization_scope=scope, tool_registry=registry, grant_authority=authority,
            audit_trail=trail,
        )
        self.assertIs(result.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])
        self.assertIs(authority.verify(scope)[0], GrantStatus.CONSUMED)


if __name__ == "__main__":
    unittest.main()
