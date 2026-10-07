import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.audit import (
    AuditTrail,
    AuditVerificationStatus,
    Ed25519AuditSigner,
    Ed25519AuditVerifier,
    verify_chain,
)
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.grants import GrantAuthority
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.tools import ToolManifest, ToolRegistry


class FixedDetector:
    def __init__(self, risk):
        self.risk = risk

    def detect(self, _content):
        return DetectionResult(self.risk, 0.99 if self.risk is ContentRisk.HIGH else 0.01, "fixed", "1")


class VerifiableDecisionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519AuditSigner({"audit": b"e" * 32}, active_key_id="audit")
        self.verifier = Ed25519AuditVerifier(self.signer.public_keys())
        self.trail = AuditTrail(self.signer)

    def _evaluate(self, *, action, capabilities, payload, risk):
        manifest = ToolManifest(action.name, tuple(capabilities), "1")
        scope = AuthorizationScope(
            "grant-" + action.name,
            tuple(capabilities),
            issuer="host",
            allowed_effects=(effect_digest(action=action, payload=payload, manifest=manifest),),
        )
        authority = GrantAuthority()
        authority.issue(scope)
        result = evaluate_request(
            request_id="req-" + action.name,
            source_type="user_input",
            content="candidate instruction",
            action=action,
            payload=payload,
            detector=FixedDetector(risk),
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=scope,
            grant_authority=authority,
            tool_registry=ToolRegistry((manifest,)),
            audit_trail=self.trail,
        )
        return result

    def test_block_review_and_allow_are_all_chained_and_publicly_verifiable(self):
        blocked = self._evaluate(
            action=ActionDescriptor("mail.send", ("send_message",)),
            capabilities=("send_message",), payload={"to": "outside@example.test"},
            risk=ContentRisk.HIGH,
        )
        reviewed = self._evaluate(
            action=ActionDescriptor("mail.send.second", ("send_message",)),
            capabilities=("send_message",), payload={"to": "inside@example.test"},
            risk=ContentRisk.LOW,
        )
        allowed = self._evaluate(
            action=ActionDescriptor("records.read", ("read_data",)),
            capabilities=("read_data",), payload={"record": "r1"},
            risk=ContentRisk.LOW,
        )

        self.assertIs(blocked.policy.decision, Decision.BLOCK)
        self.assertIs(reviewed.policy.decision, Decision.REVIEW)
        self.assertIs(allowed.policy.decision, Decision.ALLOW)
        self.assertEqual([event.decision for event in self.trail.events], ["block", "review", "allow"])
        verified = verify_chain(self.verifier, self.trail.envelopes, self.trail.events)
        self.assertTrue(verified.valid)
        self.assertEqual(verified.verified_count, 3)

    def test_block_receipt_cannot_be_rewritten_to_allow(self):
        blocked = self._evaluate(
            action=ActionDescriptor("mail.send", ("send_message",)),
            capabilities=("send_message",), payload={"to": "outside@example.test"},
            risk=ContentRisk.HIGH,
        )
        original = self.trail.events[0]
        forged = original.to_dict()
        forged["decision"] = "allow"
        self.assertIs(
            self.verifier.verify(self.trail.envelopes[0], forged),
            AuditVerificationStatus.EVENT_MISMATCH,
        )
        self.assertIs(blocked.policy.decision, Decision.BLOCK)

    def test_durable_sink_failure_prevents_evaluation_from_returning(self):
        def fail(_envelope, _event):
            raise RuntimeError("evidence store unavailable")

        trail = AuditTrail(self.signer, sink=fail)
        action = ActionDescriptor("records.read", ("read_data",))
        manifest = ToolManifest(action.name, action.capabilities, "1")
        payload = {"record": "r1"}
        scope = AuthorizationScope(
            "grant-fail", action.capabilities, issuer="host",
            allowed_effects=(effect_digest(action=action, payload=payload, manifest=manifest),),
        )
        authority = GrantAuthority()
        authority.issue(scope)
        with self.assertRaises(RuntimeError):
            evaluate_request(
                request_id="req-fail", source_type="user_input", content="read it",
                action=action, payload=payload, detector=FixedDetector(ContentRisk.LOW),
                provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
                authorization_scope=scope, grant_authority=authority,
                tool_registry=ToolRegistry((manifest,)), audit_trail=trail,
            )
        self.assertEqual(trail.envelopes, ())


if __name__ == "__main__":
    unittest.main()
