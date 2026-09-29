import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.tools import (
    ToolManifest,
    ToolRegistry,
    ToolVerificationStatus,
    verify_action_descriptor,
)


class ToolRegistryTests(unittest.TestCase):
    def test_verified_descriptor_matches_manifest(self):
        registry = ToolRegistry((ToolManifest("calendar.read", ("read_data",)),))
        status, manifest = verify_action_descriptor(
            ActionDescriptor("calendar.read", ("read_data",)), registry
        )
        self.assertIs(status, ToolVerificationStatus.VERIFIED)
        self.assertIsNotNone(manifest)

    def test_underdeclared_capability_is_mismatch(self):
        registry = ToolRegistry((ToolManifest("mail.send", ("send_message",)),))
        status, _ = verify_action_descriptor(
            ActionDescriptor("mail.send", ("read_data",)), registry
        )
        self.assertIs(status, ToolVerificationStatus.MISMATCH)

    def test_unregistered_tool_is_rejected(self):
        registry = ToolRegistry(())
        status, manifest = verify_action_descriptor(
            ActionDescriptor("unknown", ("read_data",)), registry
        )
        self.assertIs(status, ToolVerificationStatus.UNREGISTERED)
        self.assertIsNone(manifest)

    def test_missing_registry_is_unknown(self):
        status, manifest = verify_action_descriptor(
            ActionDescriptor("calendar.read", ("read_data",)), None
        )
        self.assertIs(status, ToolVerificationStatus.UNKNOWN)
        self.assertIsNone(manifest)

    def test_duplicate_tool_manifest_is_rejected(self):
        with self.assertRaises(ValueError):
            ToolRegistry(
                (
                    ToolManifest("calendar.read", ("read_data",)),
                    ToolManifest("calendar.read", ("read_data",)),
                )
            )


if __name__ == "__main__":
    unittest.main()
