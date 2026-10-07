import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.audit import AuditTrail, AuditVerificationStatus, Ed25519AuditSigner
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.events import evaluation_digest
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.receipts import build_bundle, verify_bundle
from agentshield.platform.review import ReviewSigner, ReviewVerifier
from agentshield.platform.tools import ToolManifest, ToolRegistry


class LowDetector:
    def detect(self, _content):
        return DetectionResult(ContentRisk.LOW, 0.01, "review-receipt-test", "1")


class Recorder:
    def __init__(self):
        self.calls = []

    def execute(self, *, action_name, payload):
        self.calls.append((action_name, dict(payload)))
        return {"ok": True}


class PortableReviewReceiptTests(unittest.TestCase):
    def fixture(self):
        action = ActionDescriptor("mail.send", ("send_message",))
        payload = {"to": "customer@example.test", "template": "approved-template"}
        manifest = ToolManifest(action.name, action.capabilities, "1")
        scope = AuthorizationScope(
            "review-receipt-grant",
            action.capabilities,
            issuer="policy-service",
            principal="employee-42",
            tenant="company-7",
            allowed_effects=(effect_digest(action=action, payload=payload, manifest=manifest),),
        )
        authority = GrantAuthority()
        authority.issue(scope)
        registry = ToolRegistry((manifest,))

        audit_signer = Ed25519AuditSigner({"audit-k1": b"a" * 32}, active_key_id="audit-k1")
        trail = AuditTrail(audit_signer)
        pipeline = evaluate_request(
            request_id="review-receipt-request",
            source_type="user_input",
            content="send the approved customer message",
            action=action,
            payload=payload,
            detector=LowDetector(),
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=scope,
            tool_registry=registry,
            grant_authority=authority,
            audit_trail=trail,
        )
        self.assertIs(pipeline.policy.decision, Decision.REVIEW)

        review_signer = ReviewSigner({"review-k1": b"r" * 32}, active_key_id="review-k1")
        review_verifier = ReviewVerifier(review_signer.public_keys())
        metadata = pipeline.audit_event.metadata
        approval = review_signer.issue(
            request_id=pipeline.audit_event.request_id,
            action_digest=metadata["action_digest"],
            payload_digest=metadata["payload_digest"],
            scope_digest=metadata["authorization_scope_digest"],
            tool_manifest_digest=metadata["tool_manifest_digest"],
            policy_version=pipeline.policy.policy_version,
            evaluation_digest=evaluation_digest(pipeline.audit_event),
            reviewer="human-reviewer@example.test",
        )

        executor = Recorder()
        execution = enforce_and_execute(
            pipeline_result=pipeline,
            action=action,
            payload=payload,
            executor=executor,
            authorization_scope=scope,
            tool_registry=registry,
            grant_authority=authority,
            review_approval=approval,
            review_verifier=review_verifier,
            audit_trail=trail,
        )
        self.assertIs(execution.status, ExecutionStatus.EXECUTED)
        self.assertEqual(len(executor.calls), 1)
        bundle = build_bundle(
            trail.envelopes,
            trail.events,
            review_approvals=(approval,),
        )
        return bundle, audit_signer, review_signer

    def test_review_receipt_verifies_with_separate_audit_and_review_keys(self):
        bundle, audit_signer, review_signer = self.fixture()
        result = verify_bundle(
            bundle,
            audit_signer.public_keys(),
            review_public_keys=review_signer.public_keys(),
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.verified_count, 3)
        self.assertEqual(len(bundle.review_approvals), 1)

    def test_review_execution_fails_portable_verification_without_review_proof(self):
        bundle, audit_signer, review_signer = self.fixture()
        raw = bundle.to_dict()
        raw["review_approvals"] = []
        result = verify_bundle(
            raw,
            audit_signer.public_keys(),
            review_public_keys=review_signer.public_keys(),
        )
        self.assertIs(result.status, AuditVerificationStatus.EVENT_MISMATCH)

    def test_review_execution_requires_independent_review_key(self):
        bundle, audit_signer, _ = self.fixture()
        result = verify_bundle(bundle, audit_signer.public_keys())
        self.assertIs(result.status, AuditVerificationStatus.UNKNOWN_KEY)

    def test_tampered_review_proof_fails_even_when_audit_chain_is_untouched(self):
        bundle, audit_signer, review_signer = self.fixture()
        raw = bundle.to_dict()
        raw["review_approvals"][0]["reviewer"] = "attacker@example.test"
        result = verify_bundle(
            raw,
            audit_signer.public_keys(),
            review_public_keys=review_signer.public_keys(),
        )
        self.assertIs(result.status, AuditVerificationStatus.INVALID_SIGNATURE)

    def test_standalone_verifier_checks_both_trust_anchors(self):
        bundle, audit_signer, review_signer = self.fixture()
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
            json.dump(bundle.to_dict(), handle)
            path = Path(handle.name)
        try:
            command = [
                sys.executable,
                "tools/agentshield_verify.py",
                str(path),
                "--pubkey",
                f"audit-k1={audit_signer.public_keys()['audit-k1'].hex()}",
                "--review-pubkey",
                f"review-k1={review_signer.public_keys()['review-k1'].hex()}",
            ]
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["valid"])
            self.assertEqual(result["verified_records"], 3)

            no_review_key = subprocess.run(
                command[:-2], text=True, capture_output=True, check=False
            )
            self.assertEqual(no_review_key.returncode, 1)
            failed = json.loads(no_review_key.stderr)
            self.assertFalse(failed["valid"])
            self.assertEqual(failed["reason"], "human-review public key trust anchor is required")
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
