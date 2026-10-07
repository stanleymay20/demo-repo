import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from agentshield.platform.audit import AuditTrail, Ed25519AuditSigner
from agentshield.platform.receipts import build_bundle


class StandaloneVerifierTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519AuditSigner({"audit": b"v" * 32}, active_key_id="audit")
        self.public_key = self.signer.public_keys()["audit"]
        trail = AuditTrail(self.signer)
        trail.append({
            "event_schema_version": "agentshield-audit-event-v1",
            "request_id": "demo-block",
            "decision": "block",
            "policy_version": "agentshield-policy-v7",
        })
        self.bundle = build_bundle(trail.envelopes, trail.events)
        self.script = Path("tools/agentshield_verify.py")

    def _run(self, raw):
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
            json.dump(raw, handle)
            path = handle.name
        try:
            return subprocess.run(
                [
                    sys.executable, str(self.script), path,
                    "--pubkey", f"audit={self.public_key.hex()}",
                ],
                text=True, capture_output=True, check=False,
            )
        finally:
            Path(path).unlink(missing_ok=True)

    def test_outsider_can_verify_block_bundle_without_agentshield_keys_or_service(self):
        completed = self._run(self.bundle.to_dict())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_records"], 1)
        self.assertTrue(result["head_envelope_hash"])

    def test_outsider_detects_tampered_block_receipt(self):
        raw = self.bundle.to_dict()
        raw["records"][0]["event"]["decision"] = "allow"
        completed = self._run(raw)
        self.assertEqual(completed.returncode, 1)
        result = json.loads(completed.stderr)
        self.assertFalse(result["valid"])
        self.assertEqual(result["verified_records"], 0)


if __name__ == "__main__":
    unittest.main()
