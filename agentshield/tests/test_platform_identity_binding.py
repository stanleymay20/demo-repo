import unittest
from dataclasses import replace

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.audit import AuditTrail, Ed25519AuditSigner, Ed25519AuditVerifier, verify_chain
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.grants import GrantAuthority, GrantStatus
from agentshield.platform.integrity import scope_digest, scope_material
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.receipts import build_bundle, verify_bundle
from agentshield.platform.tools import ToolManifest, ToolRegistry


class LowRiskDetector:
    def detect(self, _content):
        return DetectionResult(ContentRisk.LOW, 0.01, "fixed", "1")


class IdentityBindingTests(unittest.TestCase):
    def test_scope_digest_binds_principal_and_tenant(self):
        base = AuthorizationScope(
            "g1", ("read_data",), issuer="host",
            allowed_effects=("a" * 64,), principal="user-123", tenant="tenant-a",
        )
        self.assertNotEqual(scope_digest(base), scope_digest(replace(base, principal="user-456")))
        self.assertNotEqual(scope_digest(base), scope_digest(replace(base, tenant="tenant-b")))
        self.assertEqual(scope_material(base)["scope_schema"], "agentshield-scope-v3")

    def test_machine_identity_requires_agent_and_purpose_together(self):
        with self.assertRaises(ValueError):
            AuthorizationScope("g", ("read_data",), agent_id="agent-1")
        with self.assertRaises(ValueError):
            AuthorizationScope("g", ("read_data",), purpose_id="task-1")
        with self.assertRaises(ValueError):
            AuthorizationScope("g", ("read_data",), delegator_agent_id="agent-0")

    def test_scope_v4_binds_agent_purpose_and_delegator(self):
        base = AuthorizationScope(
            "g-agent", ("read_data",), issuer="host",
            allowed_effects=("a" * 64,), principal="user-123", tenant="tenant-a",
            agent_id="research-agent", purpose_id="case-8842",
        )
        material = scope_material(base)
        self.assertEqual(material["scope_schema"], "agentshield-scope-v4-agent-purpose")
        for forged in (
            replace(base, agent_id="other-agent"),
            replace(base, purpose_id="other-purpose"),
            replace(base, delegator_agent_id="orchestrator"),
        ):
            with self.subTest(forged=forged):
                self.assertNotEqual(scope_digest(base), scope_digest(forged))

    def test_grant_rejects_same_id_with_forged_identity(self):
        scope = AuthorizationScope(
            "g1", ("read_data",), issuer="host",
            allowed_effects=("a" * 64,), principal="user-123", tenant="tenant-a",
        )
        authority = GrantAuthority()
        authority.issue(scope)
        for forged in (
            replace(scope, principal="attacker"),
            replace(scope, tenant="tenant-b"),
        ):
            with self.subTest(forged=forged):
                self.assertIs(authority.verify(forged)[0], GrantStatus.MISMATCH)
                self.assertIs(authority.consume(forged)[0], GrantStatus.MISMATCH)
        self.assertIs(authority.verify(scope)[0], GrantStatus.VALID)

    def test_legacy_delegation_cannot_swap_acting_identity(self):
        parent = AuthorizationScope(
            "root", ("read_data", "transform_text"), issuer="host",
            allowed_effects=("a" * 64, "b" * 64),
            principal="user-123", tenant="tenant-a",
        )
        authority = GrantAuthority()
        authority.issue(parent)
        child = replace(
            parent, grant_id="child", allowed_capabilities=("read_data",),
            allowed_effects=("a" * 64,),
        )
        for forged in (
            replace(child, principal="attacker"),
            replace(child, tenant="tenant-b"),
        ):
            with self.subTest(forged=forged), self.assertRaises(ValueError):
                authority.delegate(parent, forged)
            self.assertIs(authority.verify(parent)[0], GrantStatus.VALID)
        authority.delegate(parent, child)
        self.assertIs(authority.verify(child)[0], GrantStatus.VALID)

    def test_machine_delegation_changes_agent_but_preserves_purpose_and_lineage(self):
        parent = AuthorizationScope(
            "machine-root", ("read_data", "transform_text"), issuer="policy-service",
            allowed_effects=("a" * 64, "b" * 64), principal="employee-42", tenant="company-7",
            agent_id="orchestrator-agent", purpose_id="incident-2026-441",
        )
        child = replace(
            parent,
            grant_id="machine-child",
            allowed_capabilities=("read_data",),
            allowed_effects=("a" * 64,),
            agent_id="research-agent",
            delegator_agent_id="orchestrator-agent",
        )
        authority = GrantAuthority()
        authority.issue(parent)
        for forged in (
            replace(child, purpose_id="unrelated-purpose"),
            replace(child, delegator_agent_id="attacker-agent"),
            replace(child, agent_id=None, purpose_id=None, delegator_agent_id=None),
        ):
            with self.subTest(forged=forged), self.assertRaises(ValueError):
                authority.delegate(parent, forged)
            self.assertIs(authority.verify(parent)[0], GrantStatus.VALID)
        authority.delegate(parent, child)
        self.assertIs(authority.verify(child)[0], GrantStatus.VALID)
        material = scope_material(child)
        self.assertEqual(material["agent_id"], "research-agent")
        self.assertEqual(material["purpose_id"], "incident-2026-441")
        self.assertEqual(material["delegator_agent_id"], "orchestrator-agent")

    def test_legacy_delegation_cannot_acquire_machine_identity(self):
        parent = AuthorizationScope(
            "legacy-root", ("read_data",), issuer="host",
            allowed_effects=("a" * 64,), principal="user", tenant="tenant",
        )
        child = replace(
            parent,
            grant_id="child",
            agent_id="new-agent",
            purpose_id="new-purpose",
            delegator_agent_id="legacy-agent",
        )
        authority = GrantAuthority()
        authority.issue(parent)
        with self.assertRaises(ValueError):
            authority.delegate(parent, child)
        self.assertIs(authority.verify(parent)[0], GrantStatus.VALID)

    def test_signed_decision_evidence_surfaces_bound_machine_identity(self):
        action = ActionDescriptor("records.read", ("read_data",))
        manifest = ToolManifest(action.name, action.capabilities, "1")
        payload = {"record": "r1"}
        scope = AuthorizationScope(
            "g-evidence", action.capabilities, issuer="policy-service",
            allowed_effects=(effect_digest(action=action, payload=payload, manifest=manifest),),
            principal="employee-42", tenant="company-7",
            agent_id="records-agent-9", purpose_id="case-8842",
        )
        authority = GrantAuthority()
        authority.issue(scope)
        signer = Ed25519AuditSigner({"audit": b"i" * 32}, active_key_id="audit")
        verifier = Ed25519AuditVerifier(signer.public_keys())
        trail = AuditTrail(signer)

        result = evaluate_request(
            request_id="identity-evidence", source_type="user_input", content="read record",
            action=action, payload=payload, detector=LowRiskDetector(),
            provenance=InputProvenance("user_input", trust_level=TrustLevel.TRUSTED),
            authorization_scope=scope, grant_authority=authority,
            tool_registry=ToolRegistry((manifest,)), audit_trail=trail,
        )
        self.assertIs(result.policy.decision, Decision.ALLOW)
        metadata = trail.events[0].metadata
        self.assertEqual(metadata["authorization_issuer"], "policy-service")
        self.assertEqual(metadata["authorization_principal"], "employee-42")
        self.assertEqual(metadata["authorization_tenant"], "company-7")
        self.assertEqual(metadata["authorization_agent_id"], "records-agent-9")
        self.assertEqual(metadata["authorization_purpose_id"], "case-8842")
        self.assertIsNone(metadata["authorization_delegator_agent_id"])
        self.assertEqual(metadata["authorization_scope_digest"], scope_digest(scope))
        self.assertTrue(verify_chain(verifier, trail.envelopes, trail.events).valid)

        bundle = build_bundle(trail.envelopes, trail.events)
        self.assertTrue(verify_bundle(bundle, signer.public_keys()).valid)
        material = bundle.records[0].event["metadata"]["authorization_scope_material"]
        self.assertEqual(material["scope_schema"], "agentshield-scope-v4-agent-purpose")
        self.assertEqual(material["agent_id"], "records-agent-9")
        self.assertEqual(material["purpose_id"], "case-8842")


if __name__ == "__main__":
    unittest.main()
