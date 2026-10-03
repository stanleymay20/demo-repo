import unittest
from dataclasses import replace

from agentshield.platform.audit import (
    AuditSigner,
    AuditVerificationStatus,
)


class AuditSignerTests(unittest.TestCase):
    def setUp(self):
        self.signer = AuditSigner({"k1": b"x" * 32}, active_key_id="k1")

    def test_chained_events_verify(self):
        first_event = {"request_id": "r1", "decision": "allow"}
        second_event = {"request_id": "r2", "decision": "review"}
        first = self.signer.seal(first_event, sequence=0)
        second = self.signer.seal(second_event, sequence=1, previous=first)
        self.assertIs(
            self.signer.verify(first, first_event),
            AuditVerificationStatus.VALID,
        )
        self.assertIs(
            self.signer.verify(second, second_event, previous=first),
            AuditVerificationStatus.VALID,
        )

    def test_event_tamper_is_detected(self):
        event = {"request_id": "r1", "decision": "allow"}
        envelope = self.signer.seal(event, sequence=0)
        self.assertIs(
            self.signer.verify(
                envelope,
                {"request_id": "r1", "decision": "block"},
            ),
            AuditVerificationStatus.EVENT_MISMATCH,
        )

    def test_envelope_tamper_is_detected(self):
        event = {"request_id": "r1", "decision": "allow"}
        envelope = self.signer.seal(event, sequence=0)
        tampered = replace(envelope, sequence=9)
        self.assertIs(
            self.signer.verify(tampered, event),
            AuditVerificationStatus.INVALID_SIGNATURE,
        )


if __name__ == "__main__":
    unittest.main()
