import json
import unittest

from agentshield.platform.audit import (
    AuditTrail,
    AuditVerificationStatus,
    Ed25519AuditSigner,
)
from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.receipts import (
    build_bundle,
    bundle_digest,
    load_bundle,
    verify_bundle,
)
from agentshield.platform.tools import ToolManifest, ToolRegistry


class _LowDetector:
    def detect(self, _content):
        return DetectionResult(ContentRisk.LOW, 0.01, "receipt-test", "1")


class _Recorder:
    def execute(self, *, action_name, payload):
        return {"ok": True}


class ReceiptBundleTests(unittest.TestCase):
    def setUp(self):
        # A genuine governed flow: signed ALLOW decision, then the gateway's signed
        # grant-consumption and dispatch-completion transitions. A receipt containing an
        # execution transition without its authorizing decision is not a valid receipt.
        self.signer = Ed25519AuditSigner({"audit": b"r" * 32}, active_key_id="audit")
        self.public_keys = self.signer.public_keys()
        self.trail = AuditTrail(self.signer)
        action = ActionDescriptor("docs.read", ("read_data",))
        payload = {"doc": "q3-report"}
        manifest = ToolManifest(action.name, action.capabilities, "1")
        scope = AuthorizationScope(
            "receipt-grant", action.capabilities, issuer="policy-service",
            principal="employee-42", tenant="company-7",
            allowed_effects=(effect_digest(action=action, payload=payload, manifest=manifest),),
        )
        authority = GrantAuthority()
        authority.issue(scope)
        registry = ToolRegistry((manifest,))
        pipeline = evaluate_request(
            request_id="r2", source_type="user_input", content="read the report",
            action=action, payload=payload, detector=_LowDetector(),
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=scope, tool_registry=registry, grant_authority=authority,
            audit_trail=self.trail,
        )
        executed = enforce_and_execute(
            pipeline_result=pipeline, action=action, payload=payload, executor=_Recorder(),
            authorization_scope=scope, tool_registry=registry, grant_authority=authority,
            audit_trail=self.trail,
        )
        assert executed.status is ExecutionStatus.EXECUTED

    def test_bundle_round_trip_verifies_with_public_key_only(self):
        bundle = build_bundle(self.trail.envelopes, self.trail.events)
        text = bundle.to_json()
        parsed = load_bundle(text)
        result = verify_bundle(parsed, self.public_keys)
        self.assertTrue(result.valid)
        self.assertEqual(result.verified_count, 3)
        self.assertEqual([r.record_type for r in parsed.records], [
            "policy_decision", "execution_lifecycle", "execution_lifecycle",
        ])

    def test_bundle_tamper_reports_first_broken_record(self):
        bundle = json.loads(build_bundle(self.trail.envelopes, self.trail.events).to_json())
        bundle["records"][1]["event"]["status"] = "failed"
        result = verify_bundle(bundle, self.public_keys)
        self.assertIs(result.status, AuditVerificationStatus.EVENT_MISMATCH)
        self.assertEqual(result.first_invalid_index, 1)
        self.assertEqual(result.verified_count, 1)

    def test_bundle_rejects_semantic_record_type_relabeling(self):
        bundle = json.loads(build_bundle(self.trail.envelopes, self.trail.events).to_json())
        bundle["records"][1]["record_type"] = "policy_decision"
        result = verify_bundle(bundle, self.public_keys)
        self.assertIs(result.status, AuditVerificationStatus.EVENT_MISMATCH)
        self.assertEqual(result.first_invalid_index, 1)
        self.assertEqual(result.verified_count, 1)

    def test_bundle_rejects_signed_inconsistent_authorization_scope_proof(self):
        trail = AuditTrail(self.signer)
        material = {
            "scope_schema": "agentshield-scope-v3",
            "grant_id": "g1",
            "issuer": "policy-service",
            "principal": "employee-42",
            "tenant": "company-7",
            "allowed_capabilities": ["read_data"],
            "allowed_effects": ["a" * 64],
        }
        trail.append({
            "event_schema_version": "agentshield-audit-event-v1",
            "request_id": "scope-proof",
            "decision": "allow",
            "policy_version": "agentshield-policy-v7",
            "metadata": {
                "authorization_grant_id": "g1",
                "authorization_issuer": "policy-service",
                "authorization_principal": "employee-42",
                "authorization_tenant": "company-7",
                "authorization_scope_material": material,
                "authorization_scope_digest": "0" * 64,
            },
        })
        bundle = build_bundle(trail.envelopes, trail.events)
        result = verify_bundle(bundle, self.public_keys)
        self.assertIs(result.status, AuditVerificationStatus.EVENT_MISMATCH)
        self.assertEqual(result.first_invalid_index, 0)
        self.assertEqual(result.verified_count, 0)

    def test_bundle_rejects_hmac_as_independent_evidence(self):
        from agentshield.platform.audit import AuditSigner

        trail = AuditTrail(AuditSigner({"legacy": b"x" * 32}, active_key_id="legacy"))
        trail.append({"event_schema_version": "agentshield-audit-event-v1", "request_id": "r"})
        with self.assertRaises(ValueError):
            build_bundle(trail.envelopes, trail.events)

    def test_digest_changes_if_bundle_changes(self):
        bundle = build_bundle(self.trail.envelopes, self.trail.events)
        original = bundle_digest(bundle)
        raw = json.loads(bundle.to_json())
        raw["exported_at_utc"] = "2030-01-01T00:00:00+00:00"
        self.assertNotEqual(original, bundle_digest(raw))


if __name__ == "__main__":
    unittest.main()
