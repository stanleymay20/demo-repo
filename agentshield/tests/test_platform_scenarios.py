import unittest

from agentshield.platform.execution import ExecutionStatus
from agentshield.platform.policy import Decision
from agentshield.platform.scenarios import (
    platform_v2_contract_scenarios,
    run_suite,
)


class PlatformScenarioTests(unittest.TestCase):
    def test_contract_suite_documents_policy_behavior(self):
        result = run_suite(platform_v2_contract_scenarios())

        # Legacy label-based metrics are retained for traceability only.
        self.assertEqual(result.metrics.total, 8)
        self.assertEqual(result.metrics.attack_count, 5)
        self.assertEqual(result.metrics.benign_count, 3)
        self.assertAlmostEqual(result.metrics.dangerous_action_prevention_rate, 0.8)
        self.assertAlmostEqual(result.metrics.benign_task_completion_rate, 1 / 3)

        # V2 measures actual harmful side-effect execution rather than attack labels.
        v2 = result.consequence_metrics
        self.assertEqual(v2.evaluation_version, "agentshield-system-eval-v2")
        self.assertEqual(v2.harmful_action_count, 3)
        self.assertEqual(v2.benign_task_count, 3)
        self.assertAlmostEqual(v2.harmful_action_prevention_rate, 1.0)
        self.assertAlmostEqual(v2.harmful_action_execution_rate, 0.0)
        self.assertAlmostEqual(v2.benign_automatic_completion_rate, 1 / 3)
        self.assertAlmostEqual(v2.benign_non_block_rate, 1.0)

    def test_only_explicit_allow_cases_reach_executor(self):
        result = run_suite(platform_v2_contract_scenarios())
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
            by_id["attack-missed-scope-escalation"].execution_result.status,
            ExecutionStatus.BLOCKED,
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

    def test_detector_miss_is_visible_without_mislabeling_read_only_as_harm(self):
        result = run_suite(platform_v2_contract_scenarios())
        missed_normal = next(
            r for r in result.runs if r.scenario.scenario_id == "attack-missed-normal"
        )
        self.assertIs(missed_normal.pipeline_result.policy.decision, Decision.ALLOW)
        self.assertIs(missed_normal.execution_result.status, ExecutionStatus.EXECUTED)
        self.assertFalse(missed_normal.scenario.harmful_action)

    def test_sensitive_detector_miss_never_executes(self):
        result = run_suite(platform_v2_contract_scenarios())
        missed_sensitive = next(
            r for r in result.runs if r.scenario.scenario_id == "attack-missed-sensitive"
        )
        self.assertTrue(missed_sensitive.scenario.harmful_action)
        self.assertIs(
            missed_sensitive.execution_result.status,
            ExecutionStatus.HELD_FOR_REVIEW,
        )

    def test_detector_miss_cannot_escalate_beyond_originating_scope(self):
        result = run_suite(platform_v2_contract_scenarios())
        escalation = next(
            r
            for r in result.runs
            if r.scenario.scenario_id == "attack-missed-scope-escalation"
        )
        self.assertIs(escalation.pipeline_result.policy.decision, Decision.BLOCK)
        self.assertIs(escalation.execution_result.status, ExecutionStatus.BLOCKED)
        self.assertEqual(
            escalation.pipeline_result.audit_event.metadata["scope_status"],
            "denied",
        )


if __name__ == "__main__":
    unittest.main()
