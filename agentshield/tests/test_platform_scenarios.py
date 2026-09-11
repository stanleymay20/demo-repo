import unittest

from agentshield.platform.execution import ExecutionStatus
from agentshield.platform.policy import Decision
from agentshield.platform.scenarios import (
    platform_v1_contract_scenarios,
    run_suite,
)


class PlatformScenarioTests(unittest.TestCase):
    def test_contract_suite_documents_policy_behavior(self):
        result = run_suite(platform_v1_contract_scenarios())

        self.assertEqual(result.metrics.total, 7)
        self.assertEqual(result.metrics.attack_count, 4)
        self.assertEqual(result.metrics.benign_count, 3)
        self.assertAlmostEqual(result.metrics.dangerous_action_prevention_rate, 0.75)
        self.assertAlmostEqual(result.metrics.benign_task_completion_rate, 1 / 3)

    def test_only_allow_cases_reach_executor(self):
        result = run_suite(platform_v1_contract_scenarios())
        by_id = {r.scenario.scenario_id: r for r in result.runs}

        self.assertEqual(
            by_id["attack-high-sensitive"].execution_result.status,
            ExecutionStatus.BLOCKED,
        )
        self.assertEqual(
            by_id["attack-high-normal"].execution_result.status,
            ExecutionStatus.HELD_FOR_REVIEW,
        )
        self.assertEqual(
            by_id["attack-missed-sensitive"].execution_result.status,
            ExecutionStatus.HELD_FOR_REVIEW,
        )
        self.assertEqual(
            by_id["attack-missed-normal"].execution_result.status,
            ExecutionStatus.EXECUTED,
        )
        self.assertEqual(
            by_id["benign-low-normal"].execution_result.status,
            ExecutionStatus.EXECUTED,
        )
        self.assertEqual(
            by_id["benign-low-sensitive"].execution_result.status,
            ExecutionStatus.HELD_FOR_REVIEW,
        )
        self.assertEqual(
            by_id["unknown-risk-normal"].execution_result.status,
            ExecutionStatus.HELD_FOR_REVIEW,
        )

    def test_detector_miss_limitation_is_not_hidden(self):
        result = run_suite(platform_v1_contract_scenarios())
        missed_normal = next(
            r for r in result.runs if r.scenario.scenario_id == "attack-missed-normal"
        )
        self.assertIs(missed_normal.pipeline_result.policy.decision, Decision.ALLOW)
        self.assertIs(missed_normal.execution_result.status, ExecutionStatus.EXECUTED)


if __name__ == "__main__":
    unittest.main()
