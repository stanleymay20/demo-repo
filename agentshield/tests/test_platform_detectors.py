import unittest

from agentshield.platform.detectors import DetectionResult, risk_from_threshold
from agentshield.platform.policy import ContentRisk


class DetectorContractTests(unittest.TestCase):
    def test_threshold_boundary_is_high_risk(self):
        self.assertEqual(
            risk_from_threshold(score=0.7, threshold=0.7),
            ContentRisk.HIGH,
        )

    def test_score_below_threshold_is_low_risk(self):
        self.assertEqual(
            risk_from_threshold(score=0.699, threshold=0.7),
            ContentRisk.LOW,
        )

    def test_invalid_score_rejected(self):
        with self.assertRaises(ValueError):
            risk_from_threshold(score=-0.1, threshold=0.7)

    def test_detection_result_requires_versioned_identity(self):
        with self.assertRaises(ValueError):
            DetectionResult(
                content_risk=ContentRisk.LOW,
                score=0.1,
                detector_name="detector",
                detector_version=" ",
            )


if __name__ == "__main__":
    unittest.main()
