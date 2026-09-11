import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.authorization import (
    AuthorizationScope,
    ScopeStatus,
    check_action_scope,
)


class AuthorizationScopeTests(unittest.TestCase):
    def test_scope_normalizes_capabilities(self):
        scope = AuthorizationScope(
            grant_id="g1",
            allowed_capabilities=(" Read_Data ", "read_data", "send_message"),
        )
        self.assertEqual(scope.allowed_capabilities, ("read_data", "send_message"))

    def test_subset_is_permitted(self):
        scope = AuthorizationScope("g1", ("read_data", "transform_text"))
        action = ActionDescriptor("summarize", ("read_data",))
        self.assertIs(check_action_scope(action, scope), ScopeStatus.PERMITTED)

    def test_capability_escalation_is_denied(self):
        scope = AuthorizationScope("g1", ("read_data",))
        action = ActionDescriptor("send", ("send_message",))
        self.assertIs(check_action_scope(action, scope), ScopeStatus.DENIED)

    def test_missing_scope_is_unknown(self):
        action = ActionDescriptor("read", ("read_data",))
        self.assertIs(check_action_scope(action, None), ScopeStatus.UNKNOWN)

    def test_missing_action_capabilities_is_unknown(self):
        scope = AuthorizationScope("g1", ("read_data",))
        self.assertIs(
            check_action_scope(ActionDescriptor("mystery"), scope),
            ScopeStatus.UNKNOWN,
        )

    def test_empty_grant_id_is_rejected(self):
        with self.assertRaises(ValueError):
            AuthorizationScope(" ", ("read_data",))


if __name__ == "__main__":
    unittest.main()
