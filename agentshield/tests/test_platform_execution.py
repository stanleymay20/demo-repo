import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision


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
    def evaluate(self, *, risk, action, payload=None):
        return evaluate_request(
            request_id="req-test",
            source_type="unit-test",
            content="untrusted content",
            action=action,
            detector=FixedDetector(risk, 0.9 if risk is ContentRisk.HIGH else 0.1),
            payload={} if payload is None else payload,
        )

    def test_low_risk_normal_action_executes(self):
        action = ActionDescriptor(name="read_calendar", capabilities=("read_data",))
        payload = {"date": "2026-09-11"}
        result = self.evaluate(risk=ContentRisk.LOW, action=action, payload=payload)
        executor = RecorderExecutor()

        execution = enforce_and_execute(
            pipeline_result=result,
            action=action,
            payload=payload,
            executor=executor,
        )

        self.assertIs(result.policy.decision, Decision.ALLOW)
        self.assertIs(execution.status, ExecutionStatus.EXECUTED)
        self.assertEqual(len(executor.calls), 1)

    def test_sensitive_action_is_held_even_if_detector_is_low(self):
        action = ActionDescriptor(name="send_email", capabilities=("send_message",))
        payload = {"to": "example@example.com"}
        result = self.evaluate(risk=ContentRisk.LOW, action=action, payload=payload)
        executor = RecorderExecutor()

        execution = enforce_and_execute(
            pipeline_result=result,
            action=action,
            payload=payload,
            executor=executor,
        )

        self.assertIs(result.policy.decision, Decision.REVIEW)
        self.assertIs(execution.status, ExecutionStatus.HELD_FOR_REVIEW)
        self.assertEqual(executor.calls, [])

    def test_high_risk_sensitive_action_is_blocked(self):
        action = ActionDescriptor(name="delete_account", capabilities=("delete_data",))
        result = self.evaluate(risk=ContentRisk.HIGH, action=action, payload={})
        executor = RecorderExecutor()

        execution = enforce_and_execute(
            pipeline_result=result,
            action=action,
            payload={},
            executor=executor,
        )

        self.assertIs(result.policy.decision, Decision.BLOCK)
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])

    def test_action_swap_after_evaluation_fails_closed(self):
        evaluated_action = ActionDescriptor(
            name="read_calendar", capabilities=("read_data",)
        )
        payload = {"date": "2026-09-11"}
        result = self.evaluate(
            risk=ContentRisk.LOW, action=evaluated_action, payload=payload
        )
        swapped_action = ActionDescriptor(
            name="send_email", capabilities=("send_message",)
        )
        executor = RecorderExecutor()

        execution = enforce_and_execute(
            pipeline_result=result,
            action=swapped_action,
            payload=payload,
            executor=executor,
        )

        self.assertIs(result.policy.decision, Decision.ALLOW)
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])

    def test_capability_swap_with_same_action_name_fails_closed(self):
        evaluated_action = ActionDescriptor("lookup", ("read_data",))
        payload = {"query": "status"}
        result = self.evaluate(
            risk=ContentRisk.LOW, action=evaluated_action, payload=payload
        )
        changed_action = ActionDescriptor("lookup", ("read_data", "network_access"))
        executor = RecorderExecutor()

        execution = enforce_and_execute(
            pipeline_result=result,
            action=changed_action,
            payload=payload,
            executor=executor,
        )

        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("descriptor changed", execution.reason)
        self.assertEqual(executor.calls, [])

    def test_payload_mutation_after_evaluation_fails_closed(self):
        action = ActionDescriptor("read_calendar", ("read_data",))
        evaluated_payload = {"date": "2026-09-11", "calendar": "work"}
        result = self.evaluate(
            risk=ContentRisk.LOW,
            action=action,
            payload=evaluated_payload,
        )
        executor = RecorderExecutor()

        execution = enforce_and_execute(
            pipeline_result=result,
            action=action,
            payload={"date": "2026-09-12", "calendar": "work"},
            executor=executor,
        )

        self.assertIs(result.policy.decision, Decision.ALLOW)
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertIn("payload changed", execution.reason)
        self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
