"""Shared authority contract: one execution credit survives bounded delegation."""

import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier

from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.grants import GrantAuthority, GrantStatus, MAX_DELEGATION_DEPTH


class DelegationContract:
    def child_scope(self, grant_id="child"):
        return replace(self.scope, grant_id=grant_id, allowed_capabilities=("read_data",),
                       allowed_effects=("a" * 64,))

    def test_delegation_transfers_one_credit_and_disables_parent_execution(self):
        self.authority.issue(self.scope)
        child = self.child_scope()
        record = self.authority.delegate(self.scope, child)
        self.assertEqual(record.parent_grant_id, self.scope.grant_id)
        self.assertEqual(self.authority.get(self.scope.grant_id).delegated_to, child.grant_id)
        self.assertIs(self.authority.consume(self.scope)[0], GrantStatus.DELEGATED)
        self.assertIs(self.authority.consume(child)[0], GrantStatus.VALID)
        self.assertIs(self.authority.consume(child)[0], GrantStatus.CONSUMED)
        with self.assertRaises(ValueError):
            self.authority.delegate(self.scope, self.child_scope("second"))

    def test_delegation_rejects_authority_expansion_and_issuer_swap(self):
        self.authority.issue(self.scope)
        for child in (
            replace(self.child_scope(), allowed_capabilities=("read_data", "write_data")),
            replace(self.child_scope(), allowed_effects=("c" * 64,)),
            replace(self.child_scope(), issuer="another-principal"),
            replace(self.child_scope(), allowed_effects=()),
            replace(self.child_scope(), allowed_capabilities=()),
        ):
            with self.subTest(child=child), self.assertRaises(ValueError):
                self.authority.delegate(self.scope, child)
            self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)
            self.assertIsNone(self.authority.get(child.grant_id))

    def test_forged_parent_scope_cannot_delegate(self):
        self.authority.issue(self.scope)
        forged = replace(self.scope, allowed_effects=("a" * 64, "b" * 64, "c" * 64))
        with self.assertRaises(ValueError):
            self.authority.delegate(forged, self.child_scope())
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_child_expiry_is_clamped_and_future_grants_cannot_execute(self):
        now = datetime.now(timezone.utc)
        root = self.authority.issue(self.scope, ttl=timedelta(seconds=10), now=now)
        child = self.child_scope()
        record = self.authority.delegate(self.scope, child, ttl=timedelta(hours=1), now=now)
        self.assertEqual(record.expires_at_utc, root.expires_at_utc)
        self.assertIs(self.authority.consume(child, now=now - timedelta(seconds=1))[0], GrantStatus.NOT_YET_VALID)
        self.assertIs(self.authority.consume(child, now=root.expires_at_utc)[0], GrantStatus.EXPIRED)
        self.assertIsNone(self.authority.get(child.grant_id).consumed_at_utc)

    def test_revocation_of_any_ancestor_invalidates_descendant(self):
        self.authority.issue(self.scope)
        child = self.child_scope()
        leaf = self.child_scope("leaf")
        self.authority.delegate(self.scope, child)
        self.authority.delegate(child, leaf)
        self.authority.revoke(self.scope.grant_id)
        self.assertIs(self.authority.verify(leaf)[0], GrantStatus.ANCESTOR_INVALID)
        self.assertIs(self.authority.consume(leaf)[0], GrantStatus.ANCESTOR_INVALID)
        self.assertIsNone(self.authority.get(leaf.grant_id).consumed_at_utc)

    def test_child_revocation_and_invalid_parent_states_cannot_mint_grants(self):
        now = datetime.now(timezone.utc)
        for state in ("revoked", "consumed", "expired", "future"):
            parent = replace(self.scope, grant_id="parent-" + state)
            issued = now - timedelta(minutes=10) if state == "expired" else now
            if state == "future":
                issued = now + timedelta(minutes=10)
            self.authority.issue(parent, now=issued)
            if state == "revoked":
                self.authority.revoke(parent.grant_id)
            if state == "consumed":
                self.authority.consume(parent, now=now)
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.authority.delegate(parent, self.child_scope("invalid-" + state), now=now)
            self.assertIsNone(self.authority.get("invalid-" + state))

    def test_duplicate_child_failure_rolls_back_parent_transfer(self):
        self.authority.issue(self.scope)
        child = self.child_scope()
        self.authority.issue(child)
        with self.assertRaises(ValueError):
            self.authority.delegate(self.scope, child)
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)
        self.assertIsNone(self.authority.get(self.scope.grant_id).delegated_to)
        self.assertIsNone(self.authority.get(child.grant_id).parent_grant_id)

    def test_reusable_parent_self_delegation_and_nonpositive_ttl_rejected(self):
        self.authority.issue(self.scope)
        with self.assertRaises(ValueError):
            self.authority.delegate(self.scope, self.scope)
        with self.assertRaises(ValueError):
            self.authority.delegate(self.scope, self.child_scope(), ttl=timedelta(0))
        reusable = replace(self.scope, grant_id="reusable")
        self.authority.issue(reusable, single_use=False)
        with self.assertRaises(ValueError):
            self.authority.delegate(reusable, self.child_scope())
        self.assertIs(self.authority.verify(self.scope)[0], GrantStatus.VALID)

    def test_bounded_chain_cannot_expand_depth_and_middle_revocation_propagates(self):
        self.authority.issue(self.scope)
        parent = self.scope
        scopes = [parent]
        for depth in range(MAX_DELEGATION_DEPTH):
            child = self.child_scope("depth-" + str(depth))
            self.authority.delegate(parent, child)
            scopes.append(child)
            parent = child
        with self.assertRaises(ValueError):
            self.authority.delegate(parent, self.child_scope("too-deep"))
        self.assertIs(self.authority.verify(parent)[0], GrantStatus.VALID)
        self.authority.revoke(scopes[3].grant_id)
        self.assertIs(self.authority.consume(parent)[0], GrantStatus.ANCESTOR_INVALID)

    def test_concurrent_children_cannot_duplicate_parent_budget(self):
        self.authority.issue(self.scope)
        barrier = Barrier(4)
        def attempt(index):
            child = self.child_scope("race-" + str(index))
            barrier.wait(timeout=10)
            try:
                self.authority.delegate(self.scope, child)
                return child
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(attempt, range(4)))
        winners = [child for child in outcomes if child is not None]
        self.assertEqual(len(winners), 1)
        self.assertIs(self.authority.consume(winners[0])[0], GrantStatus.VALID)
        self.assertIs(self.authority.consume(self.scope)[0], GrantStatus.DELEGATED)

    def test_execute_racing_delegate_cannot_spend_two_credits(self):
        self.authority.issue(self.scope)
        child = self.child_scope()
        barrier = Barrier(2)
        def execute():
            barrier.wait(timeout=10)
            return self.authority.consume(self.scope)[0] is GrantStatus.VALID
        def delegate():
            barrier.wait(timeout=10)
            try:
                self.authority.delegate(self.scope, child)
                return self.authority.consume(child)[0] is GrantStatus.VALID
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(execute), pool.submit(delegate)
            self.assertEqual(int(a.result()) + int(b.result()), 1)


class InMemoryDelegationTests(DelegationContract, unittest.TestCase):
    def setUp(self):
        self.authority = GrantAuthority()
        self.scope = AuthorizationScope("root", ("read_data", "transform_text"),
            allowed_effects=("a" * 64, "b" * 64))

    def test_missing_or_cyclic_ancestry_fails_closed(self):
        self.authority.issue(self.scope)
        child = self.child_scope()
        self.authority.delegate(self.scope, child)
        original = self.authority.get(child.grant_id)
        for parent_id in ("missing", child.grant_id):
            self.authority._records[child.grant_id] = replace(original, parent_grant_id=parent_id)
            self.assertIs(self.authority.consume(child)[0], GrantStatus.ANCESTOR_INVALID)


if __name__ == "__main__":
    unittest.main()
