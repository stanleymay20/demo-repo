"""Consequence authorization under deliberate detector misses and forged scopes."""

import unittest
from dataclasses import replace

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority, GrantStatus
from agentshield.platform.integrity import action_digest, payload_digest, scope_digest, tool_manifest_digest
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.review import ReviewAuthority
from agentshield.platform.tools import ToolManifest, ToolRegistry


class MissedAttackDetector:
    def detect(self, content):
        return DetectionResult(ContentRisk.LOW, 0.0, "intentional-miss", "1")


class Recorder:
    def __init__(self):
        self.calls = []

    def execute(self, *, action_name, payload):
        self.calls.append((action_name, payload))


class EffectAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = ToolManifest("records.read", ("read_data",), "1")
        self.action = self.manifest.descriptor
        self.approved = {"tenant": "team-a", "record": "report-1", "destination": "local"}
        self.scope = AuthorizationScope("intent-1", ("read_data",), issuer="trusted-host",
            allowed_effects=(self.digest(self.approved),))
        self.authority = GrantAuthority()
        self.authority.issue(self.scope)
        self.registry = ToolRegistry((self.manifest,))
        self.executor = Recorder()

    def digest(self, payload, *, manifest=None):
        manifest = manifest or self.manifest
        return effect_digest(action=manifest.descriptor, payload=payload, manifest=manifest)

    def evaluate(self, payload, *, scope=None, manifest=None):
        manifest = manifest or self.manifest
        return evaluate_request(
            request_id="effect-request", source_type="web", content="detector misses this attack",
            action=manifest.descriptor, payload=payload, detector=MissedAttackDetector(),
            provenance=InputProvenance("web", trust_level=TrustLevel.UNTRUSTED),
            authorization_scope=scope or self.scope, grant_authority=self.authority,
            tool_registry=ToolRegistry((manifest,)),
        )

    def execute(self, result, payload, *, scope=None, approval=None, reviewer=None):
        return enforce_and_execute(
            pipeline_result=result, action=self.action, payload=payload, executor=self.executor,
            authorization_scope=scope or self.scope, grant_authority=self.authority,
            tool_registry=self.registry, review_approval=approval, review_authority=reviewer,
        )

    def test_exact_approved_effect_executes(self):
        result = self.evaluate(self.approved)
        self.assertIs(result.policy.decision, Decision.ALLOW)
        self.assertIs(self.execute(result, self.approved).status, ExecutionStatus.EXECUTED)
        self.assertEqual(self.executor.calls, [(self.action.name, self.approved)])

    def test_reevaluating_changed_resources_cannot_expand_grant(self):
        for field, value in (("tenant", "team-b"), ("record", "private-key"),
                             ("destination", "external.example")):
            with self.subTest(field=field):
                proposed = {**self.approved, field: value}
                result = self.evaluate(proposed)
                self.assertIs(result.policy.decision, Decision.BLOCK)
                self.assertEqual(result.audit_event.metadata["effect_status"], "denied")
                self.assertIs(self.execute(result, proposed).status, ExecutionStatus.BLOCKED)
        self.assertEqual(self.executor.calls, [])
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_changed_recipient_amount_path_or_hidden_argument_changes_effect(self):
        for field in ("recipient", "amount", "path", "redirect", "headers"):
            with self.subTest(field=field):
                result = self.evaluate({**self.approved, field: "attacker-value"})
                self.assertIs(result.policy.decision, Decision.BLOCK)

    def test_same_capability_different_tool_is_not_authorized(self):
        other = ToolManifest("secrets.read", ("read_data",))
        result = self.evaluate(self.approved, manifest=other)
        self.assertIs(result.policy.decision, Decision.BLOCK)

    def test_manifest_upgrade_requires_new_approval(self):
        result = self.evaluate(self.approved, manifest=replace(self.manifest, version="2"))
        self.assertIs(result.policy.decision, Decision.BLOCK)

    def test_agent_cannot_append_an_effect_to_an_issued_scope(self):
        proposed = {**self.approved, "tenant": "team-b"}
        forged = replace(self.scope, allowed_effects=self.scope.allowed_effects + (self.digest(proposed),))
        result = self.evaluate(proposed, scope=forged)
        self.assertIs(result.policy.decision, Decision.BLOCK)
        self.assertEqual(result.audit_event.metadata["grant_status"], "mismatch")
        self.assertIs(self.execute(result, proposed, scope=forged).status, ExecutionStatus.BLOCKED)
        self.assertEqual(self.executor.calls, [])

    def test_capability_only_grant_requires_reissuance_even_with_human_approval(self):
        legacy = replace(self.scope, grant_id="legacy", allowed_effects=())
        self.authority.issue(legacy)
        result = self.evaluate(self.approved, scope=legacy)
        self.assertIs(result.policy.decision, Decision.REVIEW)
        reviewer = ReviewAuthority({"key": b"r" * 32}, active_key_id="key")
        approval = reviewer.issue(
            request_id=result.audit_event.request_id, action_digest=action_digest(self.action),
            payload_digest=payload_digest(self.approved), scope_digest=scope_digest(legacy),
            tool_manifest_digest=tool_manifest_digest(self.manifest),
            policy_version=result.policy.policy_version, reviewer="human",
        )
        outcome = self.execute(result, self.approved, scope=legacy, approval=approval, reviewer=reviewer)
        self.assertIs(outcome.status, ExecutionStatus.BLOCKED)
        self.assertEqual(self.executor.calls, [])
        self.assertIs(self.authority.verify(legacy)[0], GrantStatus.VALID)

    def test_old_policy_decision_cannot_resume_under_new_policy(self):
        result = self.evaluate(self.approved)
        old = replace(result, policy=replace(result.policy, policy_version="agentshield-policy-v4"))
        self.assertIs(self.execute(old, self.approved).status, ExecutionStatus.BLOCKED)
        self.assertEqual(self.executor.calls, [])

    def test_missing_recorded_effect_binding_blocks_dispatch(self):
        result = self.evaluate(self.approved)
        metadata = dict(result.audit_event.metadata)
        del metadata["effect_digest"]
        forged = replace(result, audit_event=replace(result.audit_event, metadata=metadata))
        self.assertIs(self.execute(forged, self.approved).status, ExecutionStatus.BLOCKED)
        self.assertEqual(self.executor.calls, [])

    def test_finite_allowlist_permits_only_approved_effects(self):
        second = {**self.approved, "record": "report-2"}
        scope = replace(self.scope, grant_id="two-options",
            allowed_effects=(self.digest(self.approved), self.digest(second)))
        self.authority.issue(scope)
        self.assertIs(self.evaluate(second, scope=scope).policy.decision, Decision.ALLOW)
        self.assertIs(self.evaluate({**second, "record": "report-3"}, scope=scope).policy.decision, Decision.BLOCK)
        self.assertIs(self.execute(self.evaluate(second, scope=scope), second, scope=scope).status, ExecutionStatus.EXECUTED)
        self.assertIs(self.evaluate(self.approved, scope=scope).policy.decision, Decision.BLOCK)

    def test_effect_digest_preserves_values_but_ignores_object_key_order(self):
        self.assertEqual(self.digest(self.approved), self.digest(dict(reversed(list(self.approved.items())))))
        self.assertNotEqual(self.digest({"value": True}), self.digest({"value": 1}))
        self.assertNotEqual(self.digest({"path": "/safe"}), self.digest({"path": "/safe/../secret"}))

    def test_scope_effects_are_detached_normalized_and_validated(self):
        effects = list(self.scope.allowed_effects) * 2
        copied = replace(self.scope, allowed_effects=effects)
        effects.clear()
        self.assertEqual(copied.allowed_effects, self.scope.allowed_effects)
        self.assertEqual(scope_digest(copied), scope_digest(self.scope))
        for bad in ("*", "A" * 64, "g" * 64, "a" * 63, None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                replace(self.scope, allowed_effects=(bad,))

    def test_tool_name_whitespace_is_not_a_dispatch_alias(self):
        with self.assertRaises(ValueError):
            effect_digest(action=ActionDescriptor(" records.read ", ("read_data",)),
                payload=self.approved, manifest=self.manifest)


if __name__ == "__main__":
    unittest.main()
