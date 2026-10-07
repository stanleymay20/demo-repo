import json
import unittest

from agentshield.platform.audit import (
    AuditTrail,
    AuditVerificationStatus,
    Ed25519AuditSigner,
)
from agentshield.platform.receipts import (
    build_bundle,
    bundle_digest,
    load_bundle,
    verify_bundle,
)


class ReceiptBundleTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519AuditSigner({"audit": b"r" * 32}, active_key_id="audit")
        self.public_keys = self.signer.public_keys()
        self.trail = AuditTrail(self.signer)
        self.trail.append({
            "event_schema_version": "agentshield-audit-event-v1",
            "request_id": "r1",
            "decision": "block",
            "policy_version": "agentshield-policy-v7",
        })
        self.trail.append({
            "event_schema_version": "agentshield-execution-audit-event-v2",
            "request_id": "r2",
            "decision": "allow",
            "phase": "dispatch_completed",
            "status": "executed",
        })

    def test_bundle_round_trip_verifies_with_public_key_only(self):
        bundle = build_bundle(self.trail.envelopes, self.trail.events)
        text = bundle.to_json()
        parsed = load_bundle(text)
        result = verify_bundle(parsed, self.public_keys)
        self.assertTrue(result.valid)
        self.assertEqual(result.verified_count, 2)
        self.assertEqual([r.record_type for r in parsed.records], [
            "policy_decision", "execution_lifecycle",
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
