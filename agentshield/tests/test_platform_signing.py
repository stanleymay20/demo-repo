import unittest
from dataclasses import replace
from datetime import timedelta

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority, GrantStatus
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.signing import EvaluationSigner, EvaluationVerifier
from agentshield.platform.tools import ToolManifest, ToolRegistry


class LowDetector:
    name = "signing-test"
    version = "1"

    def detect(self, content):
        return DetectionResult(ContentRisk.LOW, 0.01, self.name, self.version)


class Recorder:
    def __init__(self):
        self.calls = []

    def execute(self, *, action_name, payload):
        self.calls.append((action_name, dict(payload)))
        return {"ok": True}


class DetachedEvaluationSigningTests(unittest.TestCase):
    def setUp(self):
        self.action = ActionDescriptor("calendar.read", ("read_data",))
        self.payload = {"calendar": "work"}
        self.manifest = ToolManifest(self.action.name, self.action.capabilities, version="1")
        self.scope = AuthorizationScope(
            "signed-grant", self.action.capabilities, issuer="host",
            allowed_effects=(effect_digest(action=self.action, payload=self.payload,
                                           manifest=self.manifest),),
        )
        self.authority = GrantAuthority()
        self.authority.issue(self.scope, ttl=timedelta(minutes=5))
        self.registry = ToolRegistry((self.manifest,))
        self.pipeline = evaluate_request(
            request_id="signed-request", source_type="user_input", content="read calendar",
            action=self.action, detector=LowDetector(), payload=self.payload,
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=self.scope, tool_registry=self.registry,
            grant_authority=self.authority,
        )
        self.assertIs(self.pipeline.policy.decision, Decision.ALLOW)
        self.signer = EvaluationSigner({"eval-k1": b"e" * 32}, active_key_id="eval-k1")
        self.verifier = EvaluationVerifier(self.signer.public_keys())

    def execute(self, result, *, signature=None, verifier=None):
        recorder = Recorder()
        outcome = enforce_and_execute(
            pipeline_result=result, action=self.action, payload=self.payload,
            executor=recorder, authorization_scope=self.scope,
            tool_registry=self.registry, grant_authority=self.authority,
            evaluation_signature=signature, evaluation_verifier=verifier,
        )
        return outcome, recorder

    def test_unsigned_detached_allow_fails_closed_without_consuming_grant(self):
        detached = replace(self.pipeline, _integrity_tag="")
        outcome, recorder = self.execute(detached)
        self.assertIs(outcome.status, ExecutionStatus.BLOCKED)
        self.assertIn("unsigned", outcome.reason)
        self.assertEqual(recorder.calls, [])
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_valid_signed_detached_allow_executes_once(self):
        detached = replace(self.pipeline, _integrity_tag="")
        signature = self.signer.sign(detached)
        outcome, recorder = self.execute(detached, signature=signature, verifier=self.verifier)
        self.assertIs(outcome.status, ExecutionStatus.EXECUTED)
        self.assertEqual(len(recorder.calls), 1)
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.CONSUMED)

    def test_signed_evaluation_cannot_be_modified_after_signing(self):
        detached = replace(self.pipeline, _integrity_tag="")
        signature = self.signer.sign(detached)
        tampered = replace(detached, policy=replace(detached.policy, reason="forged reason"))
        outcome, recorder = self.execute(tampered, signature=signature, verifier=self.verifier)
        self.assertIs(outcome.status, ExecutionStatus.BLOCKED)
        self.assertEqual(recorder.calls, [])
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_execution_verifier_cannot_sign(self):
        self.assertFalse(hasattr(self.verifier, "sign"))
        self.assertFalse(hasattr(self.verifier, "_private_keys"))


if __name__ == "__main__":
    unittest.main()
