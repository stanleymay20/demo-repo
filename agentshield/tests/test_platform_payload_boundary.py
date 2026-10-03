"""Adversarial regressions for the payload authorization/dispatch boundary."""

import unittest
from dataclasses import replace

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority, GrantStatus
from agentshield.platform.integrity import payload_digest
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.tools import ToolManifest, ToolRegistry


class LowDetector:
    def detect(self, content):
        # Model misses are deliberate: integrity must not depend on detection.
        return DetectionResult(ContentRisk.LOW, 0.0, "miss-fixture", "1")


class Recorder:
    def __init__(self):
        self.payload = None

    def execute(self, *, action_name, payload):
        self.payload = payload
        return payload


class PayloadBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.action = ActionDescriptor("lookup", ("read_data",))
        self.scope = AuthorizationScope("payload-test", ("read_data",))
        self.registry = ToolRegistry((ToolManifest("lookup", ("read_data",)),))
        self.authority = GrantAuthority()
        self.authority.issue(self.scope)
        self.executor = Recorder()

    def evaluate(self, payload, *, detector=None):
        # This fixture models explicit trusted approval of its initial request.
        self.scope = replace(self.scope, allowed_effects=(effect_digest(
            action=self.action, payload=payload, manifest=self.registry.resolve(self.action.name)),))
        self.authority = GrantAuthority()
        self.authority.issue(self.scope)
        return evaluate_request(
            request_id="payload-test", source_type="web", content="attack missed",
            action=self.action, payload=payload, detector=detector or LowDetector(),
            provenance=InputProvenance("web", trust_level=TrustLevel.UNTRUSTED),
            authorization_scope=self.scope, tool_registry=self.registry,
            grant_authority=self.authority,
        )

    def execute(self, result, payload):
        return enforce_and_execute(
            pipeline_result=result, action=self.action, payload=payload,
            executor=self.executor, authorization_scope=self.scope,
            tool_registry=self.registry, grant_authority=self.authority,
        )

    def test_mutation_during_consume_cannot_change_dispatched_effect(self):
        payload = {"query": {"tenant": "permitted", "ids": [1, 2]}}
        result = self.evaluate(payload)
        consume = self.authority.consume

        def mutate_after_check(scope, **kwargs):
            payload["query"]["tenant"] = "other-tenant"
            payload["query"]["ids"].append(999)
            return consume(scope, **kwargs)

        self.authority.consume = mutate_after_check
        outcome = self.execute(result, payload)
        self.assertIs(outcome.status, ExecutionStatus.EXECUTED)
        self.assertEqual(self.executor.payload, {"query": {"tenant": "permitted", "ids": [1, 2]}})
        self.assertIsNot(self.executor.payload, payload)

    def test_evaluation_freezes_payload_before_detector_callback(self):
        payload = {"tenant": "permitted"}

        class MutatingDetector(LowDetector):
            def detect(self, content):
                payload["tenant"] = "other-tenant"
                return super().detect(content)

        result = self.evaluate(payload, detector=MutatingDetector())
        outcome = self.execute(result, payload)
        self.assertIs(outcome.status, ExecutionStatus.BLOCKED)
        self.assertIsNone(self.executor.payload)
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_integer_key_cannot_alias_authorized_string_key(self):
        result = self.evaluate({"1": "permitted"})
        outcome = self.execute(result, {1: "permitted"})
        self.assertIs(outcome.status, ExecutionStatus.BLOCKED)
        self.assertIsNone(self.executor.payload)
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_python_values_with_json_aliases_are_rejected(self):
        for payload in ({1: "x"}, {True: "x"}, {None: "x"},
                        {"nested": {2: "x"}}, {"ids": (1, 2)}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                payload_digest(payload)

    def test_stateful_dict_subclass_cannot_rewrite_serialized_values(self):
        class RewritingDict(dict):
            def items(self):
                return [("tenant", "different")]

        with self.assertRaises(ValueError):
            payload_digest({"query": RewritingDict(tenant="permitted")})

    def test_non_json_payload_at_dispatch_is_blocked_without_consumption(self):
        result = self.evaluate({"query": "ok"})
        for payload in ({"value": float("nan")}, {"value": object()}, ["not-object"]):
            with self.subTest(payload=payload):
                outcome = self.execute(result, payload)
                self.assertIs(outcome.status, ExecutionStatus.BLOCKED)
                self.assertIsNone(self.executor.payload)
                self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_cyclic_and_excessively_nested_payloads_fail_closed(self):
        cyclic = {}
        cyclic["self"] = cyclic
        deep = {}
        cursor = deep
        for _ in range(200):
            cursor["next"] = {}
            cursor = cursor["next"]
        for payload in (cyclic, deep):
            with self.subTest(kind="cyclic" if payload is cyclic else "deep"):
                with self.assertRaises(ValueError):
                    payload_digest(payload)

    def test_valid_json_preserves_types_and_is_detached_at_every_level(self):
        payload = {"unicode": "Ghana \u2192 Berlin", "values": [None, True, 1, 1.5, {"x": "y"}]}
        result = self.evaluate(payload)
        outcome = self.execute(result, payload)
        self.assertIs(outcome.status, ExecutionStatus.EXECUTED)
        self.assertEqual(self.executor.payload, payload)
        self.assertIsNot(self.executor.payload["values"], payload["values"])
        self.assertIsNot(self.executor.payload["values"][4], payload["values"][4])
        self.assertIs(type(self.executor.payload["values"][1]), bool)
        self.assertIs(type(self.executor.payload["values"][2]), int)

    def test_dictionary_order_does_not_change_authorized_effect(self):
        result = self.evaluate({"a": 1, "b": {"x": 2, "y": 3}})
        outcome = self.execute(result, {"b": {"y": 3, "x": 2}, "a": 1})
        self.assertIs(outcome.status, ExecutionStatus.EXECUTED)

    def test_invalid_evaluation_never_reaches_detector(self):
        class NeverDetector:
            def detect(self, content):
                raise AssertionError("invalid payload reached detector")

        with self.assertRaises(ValueError):
            self.evaluate({"value": object()}, detector=NeverDetector())
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_unpaired_unicode_surrogate_is_rejected_before_dispatch(self):
        result = self.evaluate({"query": "ok"})
        outcome = self.execute(result, {"query": "\ud800"})
        self.assertIs(outcome.status, ExecutionStatus.BLOCKED)
        self.assertIsNone(self.executor.payload)


if __name__ == "__main__":
    unittest.main()
