import unittest
from dataclasses import replace

from agentshield.platform.audit import (
    AuditSigner,
    AuditTrail,
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

    def test_trail_serializes_and_persists_before_acknowledging(self):
        persisted = []
        trail = AuditTrail(self.signer, sink=lambda envelope, event: persisted.append((envelope, event)))
        first_event = {"request_id": "r1", "phase": "grant_consumed"}
        second_event = {"request_id": "r1", "phase": "dispatch_completed"}
        first = trail.append(first_event)
        second = trail.append(second_event)
        self.assertEqual([e.sequence for e in trail.envelopes], [0, 1])
        self.assertEqual(len(persisted), 2)
        self.assertIs(self.signer.verify(first, first_event), AuditVerificationStatus.VALID)
        self.assertIs(
            self.signer.verify(second, second_event, previous=first),
            AuditVerificationStatus.VALID,
        )

    def test_failed_sink_does_not_advance_local_chain(self):
        def fail(_envelope, _event):
            raise RuntimeError("storage unavailable")

        trail = AuditTrail(self.signer, sink=fail)
        with self.assertRaises(RuntimeError):
            trail.append({"request_id": "r1"})
        self.assertEqual(trail.envelopes, ())
        self.assertIsNone(trail.head)


if __name__ == "__main__":
    unittest.main()
