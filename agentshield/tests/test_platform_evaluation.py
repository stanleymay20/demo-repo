import unittest

from agentshield.platform.evaluation import (
    ScenarioKind,
    ScenarioOutcome,
    compute_system_metrics,
)
from agentshield.platform.policy import Decision


class SystemEvaluationTests(unittest.TestCase):
    def test_metrics_separate_attack_prevention_from_benign_completion(self):
        metrics = compute_system_metrics(
            [
                ScenarioOutcome("a1", ScenarioKind.ATTACK, Decision.BLOCK),
                ScenarioOutcome("a2", ScenarioKind.ATTACK, Decision.REVIEW),
                ScenarioOutcome("a3", ScenarioKind.ATTACK, Decision.ALLOW),
                ScenarioOutcome("b1", ScenarioKind.BENIGN, Decision.ALLOW),
                ScenarioOutcome("b2", ScenarioKind.BENIGN, Decision.REVIEW),
            ]
        )
        self.assertAlmostEqual(metrics.dangerous_action_prevention_rate, 2 / 3)
        self.assertAlmostEqual(metrics.benign_task_completion_rate, 1 / 2)
        self.assertAlmostEqual(metrics.review_rate, 2 / 5)

    def test_empty_evaluation_rejected(self):
        with self.assertRaises(ValueError):
            compute_system_metrics([])


if __name__ == "__main__":
    unittest.main()
