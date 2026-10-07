import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class VerifiableBlockDemoTests(unittest.TestCase):
    def test_demo_generates_block_receipt_verifiable_by_standalone_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "block.json"
            generated = subprocess.run(
                [sys.executable, "examples/agentshield_verifiable_block_demo.py", "--output", str(receipt)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertIn("decision=BLOCK", generated.stdout)
            self.assertTrue(receipt.exists())

            public_line = next(
                line for line in generated.stdout.splitlines() if line.startswith("public_key=")
            )
            key_arg = public_line.removeprefix("public_key=")
            verified = subprocess.run(
                [sys.executable, "tools/agentshield_verify.py", str(receipt), "--pubkey", key_arg],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            result = json.loads(verified.stdout)
            self.assertTrue(result["valid"])
            self.assertEqual(result["verified_records"], 1)

            bundle = json.loads(receipt.read_text(encoding="utf-8"))
            event = bundle["records"][0]["event"]
            self.assertEqual(event["decision"], "block")
            self.assertEqual(event["metadata"]["authorization_principal"], "demo-operator")
            self.assertEqual(event["metadata"]["authorization_tenant"], "demo-company")
            # No raw prompt or destructive payload is persisted in the portable receipt.
            serialized = receipt.read_text(encoding="utf-8")
            self.assertNotIn("Ignore previous rules", serialized)
            self.assertNotIn('"where": "*"', serialized)


if __name__ == "__main__":
    unittest.main()
