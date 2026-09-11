import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.tools import ToolManifest, ToolRegistry


class FixedDetector:
    def __init__(self, risk: ContentRisk, score: float):
        self._risk = risk
        self._score = score

    @property
    def name(self):
        return "fixed-test-detector"

    @property
    def version(self):
        return "1"

    def detect(self, content: str):
        return DetectionResult(
            content_risk=self._risk,
            score=self._score,
            detector_name=self.name,
            detector_version=self.version,
        )


class RecorderExecutor:
    def __init__(self):
        self.calls = []

    def execute(self, *, action_name, payload):
        self.calls.append((action_name, dict(payload)))
        return {"ok": True, "action": action_name}


class ExecutionBoundaryTests(unittest.TestCase):
    def scope_for(self, action, *, grant_id="grant-test", extra=()):
        return AuthorizationScope(
            grant_id=grant_id,
            allowed_capabilities=tuple(action.capabilities) + tuple(extra),
            issuer="test-user",
        )

    def registry_for(self, action, *, version="1", capabilities=None):
        caps = tuple(action.capabilities) if capabilities is None else tuple(capabilities)
        return ToolRegistry((ToolManifest(action.name, caps, version=version),))

    def evaluate(self, *, risk, action, payload=None, scope=None, registry=None):
        payload = {} if payload is None else payload
        scope = self.scope_for(action) if scope is None else scope
        registry = self.registry_for(action) if registry is None else registry
        result = evaluate_request(
            request_id="req-test",
            source_type="unit-test",
            content="untrusted content",
            action=action,
            detector=FixedDetector(risk, 0.9 if risk is ContentRisk.HIGH else 0.1),
            payload=payload,
            provenance=InputProvenance(
                source_type="unit-test",
                trust_level=TrustLevel.UNTRUSTED,
            ),
            authorization_scope=scope,
            tool_registry=registry,
        )
        return result, scope, registry, payload

    def execute(self, *, result, action, payload, scope, registry):
        executor = RecorderExecutor()
        execution = enforce_and_execute(
            pipeline_result=result,
            action=action,
            payload=payload,
            executor=executor,
            authorization_scope=scope,
            tool_registry=registry,
        )
        return execution, executor

    def test_low_risk_normal_action_executes(self):
        action = ActionDescriptor(name="read_calendar", capabilities=("read_data",))
        result, scope, registry, payload = self.evaluate(
            risk=ContentRisk.LOW, action=action, payload={"date": "2026-09-11"}
        )
        execution, executor = self.execute(
            result=result, action=action, payload=payload, scope=scope, registry=registry
        )
        self.assertIs(result.policy.decision, Decision.ALLOW)
        self.assertIs(execution.status, ExecutionStatus.EXECUTED)
        self.assertEqual(len(executor.calls), 1)

    def test_sensitive_action_is_held_even_if_detector_is_low(self):
        action = ActionDescriptor(name="send_email", capabilities=("send_message",))
        result, scope, registry, payload = self.evaluate(
            risk=ContentRisk.LOW,
            action=action,
            payload={"to": "example@example.com"},
        )
        execution, executor = self.execute(
            result=result, action=action, payload=payload, scope=scope, registry=registry
        )
        self.assertIs(result.policy.decision, Decision.REVIEW)
        self.assertIs(execution.status, ExecutionStatus.HELD_FOR_REVIEW)
        self.assertEqual(executor.calls, [])

    def test_high_risk_sensitive_action_is_blocked(self):
        action = ActionDescriptor(name="delete_account", capabilities=("delete_data",))
        result, scope, registry, payload = self.evaluate(
            risk=ContentRisk.HIGH, action=action, payload={}
        )
        execution, executor = self.execute(
            result=result, action=action, payload=payload, scope=scope, registry=registry
        )
        self.assertIs(result.policy.decision, Decision.BLOCK)
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])

    def test_action_swap_after_evaluation_fails_closed(self):
        evaluated_action = ActionDescriptor("read_calendar", ("read_data",))
        result, scope, registry, payload = self.evaluate(
            risk=ContentRisk.LOW,
            action=evaluated_action,
            payload={"date": "2026-09-11"},
        )
        swapped_action = ActionDescriptor("send_email", ("send_message",))
        execution, executor = self.execute(
            result=result,
            action=swapped_action,
            payload=payload,
            scope=scope,
            registry=registry,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])

    def test_capability_swap_with_same_action_name_fails_closed(self):
        evaluated_action = ActionDescriptor("lookup", ("read_data",))
        result, scope, registry, payload = self.evaluate(
            risk=ContentRisk.LOW,
            action=evaluated_action,
            payload={"query": "status"},
        )
        changed_action = ActionDescriptor("lookup", ("read_data", "network_access"))
        execution, executor = self.execute(
            result=result,
            action=changed_action,
            payload=payload,
            scope=scope,
            registry=registry,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("descriptor changed", execution.reason)
        self.assertEqual(executor.calls, [])

    def test_payload_mutation_after_evaluation_fails_closed(self):
        action = ActionDescriptor("read_calendar", ("read_data",))
        result, scope, registry, _ = self.evaluate(
            risk=ContentRisk.LOW,
            action=action,
            payload={"date": "2026-09-11", "calendar": "work"},
        )
        execution, executor = self.execute(
            result=result,
            action=action,
            payload={"date": "2026-09-12", "calendar": "work"},
            scope=scope,
            registry=registry,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("payload changed", execution.reason)
        self.assertEqual(executor.calls, [])

    def test_missing_scope_at_execution_fails_closed(self):
        action = ActionDescriptor("read_calendar", ("read_data",))
        result, _, registry, payload = self.evaluate(
            risk=ContentRisk.LOW, action=action, payload={}
        )
        executor = RecorderExecutor()
        execution = enforce_and_execute(
            pipeline_result=result,
            action=action,
            payload=payload,
            executor=executor,
            authorization_scope=None,
            tool_registry=registry,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("scope missing", execution.reason)
        self.assertEqual(executor.calls, [])

    def test_scope_swap_after_evaluation_fails_closed(self):
        action = ActionDescriptor("read_calendar", ("read_data",))
        result, scope, registry, payload = self.evaluate(
            risk=ContentRisk.LOW, action=action, payload={}
        )
        changed_scope = AuthorizationScope(
            grant_id="grant-other",
            allowed_capabilities=scope.allowed_capabilities,
            issuer=scope.issuer,
        )
        execution, executor = self.execute(
            result=result,
            action=action,
            payload=payload,
            scope=changed_scope,
            registry=registry,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("grant changed", execution.reason)
        self.assertEqual(executor.calls, [])

    def test_missing_registry_at_execution_fails_closed(self):
        action = ActionDescriptor("read_calendar", ("read_data",))
        result, scope, _, payload = self.evaluate(
            risk=ContentRisk.LOW, action=action, payload={}
        )
        executor = RecorderExecutor()
        execution = enforce_and_execute(
            pipeline_result=result,
            action=action,
            payload=payload,
            executor=executor,
            authorization_scope=scope,
            tool_registry=None,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("registry missing", execution.reason)
        self.assertEqual(executor.calls, [])

    def test_manifest_change_after_evaluation_fails_closed(self):
        action = ActionDescriptor("read_calendar", ("read_data",))
        result, scope, _, payload = self.evaluate(
            risk=ContentRisk.LOW, action=action, payload={}
        )
        changed_registry = self.registry_for(action, version="2")
        execution, executor = self.execute(
            result=result,
            action=action,
            payload=payload,
            scope=scope,
            registry=changed_registry,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("manifest changed", execution.reason)
        self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
