import unittest
from dataclasses import replace

from agentshield.platform.audit import (
    AuditSigner,
    AuditTrail,
    AuditVerificationStatus,
    Ed25519AuditSigner,
    Ed25519AuditVerifier,
    verify_chain,
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

    def test_envelope_signature_tamper_is_detected(self):
        event = {"request_id": "r1", "decision": "allow"}
        envelope = self.signer.seal(event, sequence=0)
        tampered = replace(envelope, signature="0" * len(envelope.signature))
        self.assertIs(
            self.signer.verify(tampered, event),
            AuditVerificationStatus.INVALID_SIGNATURE,
        )

    def test_first_envelope_sequence_tamper_is_chain_mismatch(self):
        event = {"request_id": "r1", "decision": "allow"}
        envelope = self.signer.seal(event, sequence=0)
        tampered = replace(envelope, sequence=9)
        self.assertIs(
            self.signer.verify(tampered, event),
            AuditVerificationStatus.CHAIN_MISMATCH,
        )

    def test_unsupported_envelope_schema_fails_closed(self):
        event = {"request_id": "r1", "decision": "allow"}
        envelope = self.signer.seal(event, sequence=0)
        unsupported = replace(envelope, schema_version="agentshield-audit-envelope-v999")
        self.assertIs(
            self.signer.verify(unsupported, event),
            AuditVerificationStatus.SCHEMA_MISMATCH,
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


class PublicAuditEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519AuditSigner({"audit-2026": b"a" * 32}, active_key_id="audit-2026")
        self.verifier = Ed25519AuditVerifier(self.signer.public_keys())

    def test_public_verifier_checks_chain_without_private_signing_api(self):
        self.assertFalse(hasattr(self.verifier, "seal"))
        self.assertFalse(hasattr(self.verifier, "sign"))
        trail = AuditTrail(self.signer)
        events = [
            {"request_id": "r1", "phase": "decision_recorded", "decision": "block"},
            {"request_id": "r2", "phase": "decision_recorded", "decision": "allow"},
        ]
        for event in events:
            trail.append(event)
        result = verify_chain(self.verifier, trail.envelopes, trail.events)
        self.assertTrue(result.valid)
        self.assertEqual(result.verified_count, 2)

    def test_public_verifier_rejects_event_tamper(self):
        trail = AuditTrail(self.signer)
        trail.append({"request_id": "r1", "decision": "block"})
        result = verify_chain(
            self.verifier,
            trail.envelopes,
            ({"request_id": "r1", "decision": "allow"},),
        )
        self.assertIs(result.status, AuditVerificationStatus.EVENT_MISMATCH)
        self.assertEqual(result.first_invalid_index, 0)

    def test_public_verifier_rejects_chain_reordering(self):
        trail = AuditTrail(self.signer)
        trail.append({"request_id": "r1", "decision": "block"})
        trail.append({"request_id": "r2", "decision": "allow"})
        result = verify_chain(
            self.verifier,
            tuple(reversed(trail.envelopes)),
            tuple(reversed(trail.events)),
        )
        self.assertIs(result.status, AuditVerificationStatus.CHAIN_MISMATCH)

    def test_public_verifier_rejects_unsupported_envelope_schema(self):
        event = {"request_id": "r1", "decision": "block"}
        envelope = self.signer.seal(event, sequence=0)
        unsupported = replace(envelope, schema_version="agentshield-audit-envelope-v999")
        self.assertIs(
            self.verifier.verify(unsupported, event),
            AuditVerificationStatus.SCHEMA_MISMATCH,
        )

    def test_public_verifier_rejects_noncanonical_signature_hex(self):
        event = {"request_id": "r1", "decision": "block"}
        envelope = self.signer.seal(event, sequence=0)
        noncanonical = replace(
            envelope,
            signature=envelope.signature[:64] + " " + envelope.signature[64:],
        )
        self.assertIs(
            self.verifier.verify(noncanonical, event),
            AuditVerificationStatus.INVALID_SIGNATURE,
        )


if __name__ == "__main__":
    unittest.main()
