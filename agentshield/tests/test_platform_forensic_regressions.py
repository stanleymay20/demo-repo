"""Regressions for the independent PR #10 forensic audit (findings N1-N8).

Each test reproduces an exploit that succeeded at e7c64ea5155d8b2717ed8b3cbb3de85010541e7d.
Evidence-layer tests run the runtime verifier and the standalone verifier (as a separate
process that does not import AgentShield) so the two independent verifiers cannot drift.
"""

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from agentshield.platform.actions import ActionDescriptor
from agentshield.platform.audit import AuditTrail, AuditVerificationStatus, Ed25519AuditSigner
from agentshield.platform.authorization import AuthorizationScope
from agentshield.platform.detectors import DetectionResult
from agentshield.platform.effects import effect_digest
from agentshield.platform.events import build_execution_audit_event, evaluation_digest
from agentshield.platform.execution import ExecutionStatus, enforce_and_execute
from agentshield.platform.grants import GrantAuthority
from agentshield.platform.integrity import payload_digest
from agentshield.platform.pipeline import evaluate_request
from agentshield.platform.policy import ContentRisk, Decision
from agentshield.platform.provenance import InputProvenance, TrustLevel
from agentshield.platform.receipts import build_bundle, load_bundle, verify_bundle
from agentshield.platform.review import ReviewSigner, ReviewStatus, ReviewVerifier
from agentshield.platform.tools import ToolManifest, ToolRegistry

SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "agentshield_verify.py"


class _Low:
    def detect(self, _content):
        return DetectionResult(ContentRisk.LOW, 0.01, "forensic", "1")


class _Recorder:
    def __init__(self):
        self.calls = []

    def execute(self, *, action_name, payload):
        self.calls.append((action_name, dict(payload)))
        return {"ok": True}


class _LyingText(str):
    """A str whose comparisons always succeed while its content stays genuine."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


READ = ToolManifest("docs.read", ("read_data",), "1")
TRANSFER = ToolManifest("funds.transfer", ("transfer_funds",), "1")
MAIL = ToolManifest("mail.send", ("send_message",), "1")
REGISTRY = ToolRegistry((READ, TRANSFER, MAIL))


def _govern(request_id, manifest, payload, *, grant_id, extra_effects=(), trail=None):
    action = manifest.descriptor
    effects = (effect_digest(action=action, payload=payload, manifest=manifest),) + tuple(extra_effects)
    scope = AuthorizationScope(
        grant_id, action.capabilities, issuer="host", principal="alice", tenant="tenant-1",
        allowed_effects=effects,
    )
    authority = GrantAuthority()
    authority.issue(scope)
    result = evaluate_request(
        request_id=request_id, source_type="user", content="governed request", action=action,
        payload=payload, detector=_Low(),
        provenance=InputProvenance("user", trust_level=TrustLevel.TRUSTED),
        authorization_scope=scope, tool_registry=REGISTRY, grant_authority=authority,
        audit_trail=trail,
    )
    return action, scope, authority, result


def _review_signer():
    return ReviewSigner({"review": b"r" * 32}, active_key_id="review")


def _approve(signer, result, reviewer="reviewer@example.test"):
    metadata = result.audit_event.metadata
    return signer.issue(
        request_id=result.audit_event.request_id,
        action_digest=metadata["action_digest"],
        payload_digest=metadata["payload_digest"],
        scope_digest=metadata["authorization_scope_digest"],
        tool_manifest_digest=metadata["tool_manifest_digest"],
        policy_version=result.policy.policy_version,
        evaluation_digest=evaluation_digest(result.audit_event),
        reviewer=reviewer,
    )


class GatewayTypeConfusionTests(unittest.TestCase):
    """N1: caller-supplied objects must not answer checks and dispatch differently."""

    def test_action_whose_name_changes_between_check_and_dispatch_is_blocked(self):
        # Exploit: an ActionDescriptor subclass reports the evaluated low-risk tool on every
        # check, then the high-consequence tool on the dispatch read. At e7c64ea a
        # read_data grant dispatched funds.transfer with no review.
        class Probe(ActionDescriptor):
            reads = 0

            def __getattribute__(self, item):
                if item == "name":
                    type(self).reads += 1
                return object.__getattribute__(self, item)

        # Calibrate: count honest ``name`` reads in one gateway run. The last three are
        # grant-consumed evidence, the executor dispatch, then completion evidence.
        action, scope, authority, result = _govern(
            "req-probe", READ, {"doc": "q3"}, grant_id="g-probe")
        enforce_and_execute(
            pipeline_result=result, action=Probe("docs.read", ("read_data",)),
            payload={"doc": "q3"}, executor=_Recorder(), authorization_scope=scope,
            tool_registry=REGISTRY, grant_authority=authority,
        )
        honest_reads_before_dispatch = Probe.reads - 2

        action, scope, authority, result = _govern(
            "req-shift", READ, {"doc": "q3"}, grant_id="g-shift")
        self.assertIs(result.policy.decision, Decision.ALLOW)

        class ShapeShifter(ActionDescriptor):
            reads = 0

            def __getattribute__(self, item):
                if item == "name":
                    type(self).reads += 1
                    if type(self).reads > honest_reads_before_dispatch:
                        return "funds.transfer"
                    return "docs.read"
                return object.__getattribute__(self, item)

        executor = _Recorder()
        execution = enforce_and_execute(
            pipeline_result=result, action=ShapeShifter("docs.read", ("read_data",)),
            payload={"doc": "q3"}, executor=executor, authorization_scope=scope,
            tool_registry=REGISTRY, grant_authority=authority,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])
        self.assertIs(authority.verify(scope)[0].value, "valid", "grant must not be burned")

    def test_review_approval_with_lying_fields_cannot_authorize_another_request(self):
        # Exploit: a reviewer signs request A. The approval's fields are re-wrapped in a
        # str subclass that compares equal to anything; signature verification still sees
        # A's genuine bytes, while the binding comparison accepts request B.
        signer = _review_signer()
        _, _, _, approved = _govern(
            "req-A", MAIL, {"to": "team@corp.test"}, grant_id="g-A")
        approval_for_a = _approve(signer, approved)
        action, scope_b, authority_b, held_b = _govern(
            "req-B", MAIL, {"to": "press@rival.test"}, grant_id="g-B")
        self.assertIs(held_b.policy.decision, Decision.REVIEW)
        forged = replace(
            approval_for_a,
            request_id=_LyingText(approval_for_a.request_id),
            payload_digest=_LyingText(approval_for_a.payload_digest),
            scope_digest=_LyingText(approval_for_a.scope_digest),
        )
        object.__setattr__(forged, "evaluation_digest", _LyingText(approval_for_a.evaluation_digest))

        executor = _Recorder()
        execution = enforce_and_execute(
            pipeline_result=held_b, action=action, payload={"to": "press@rival.test"},
            executor=executor, authorization_scope=scope_b, tool_registry=REGISTRY,
            grant_authority=authority_b, review_approval=forged,
            review_verifier=ReviewVerifier(signer.public_keys()),
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])

    def test_scope_with_lying_grant_id_is_blocked(self):
        action, scope, authority, result = _govern(
            "req-scope", READ, {"doc": "q3"}, grant_id="g-scope")
        forged = copy.copy(scope)
        object.__setattr__(forged, "grant_id", _LyingText(scope.grant_id))
        executor = _Recorder()
        execution = enforce_and_execute(
            pipeline_result=result, action=action, payload={"doc": "q3"}, executor=executor,
            authorization_scope=forged, tool_registry=REGISTRY, grant_authority=authority,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])

    def test_metadata_swapped_back_before_seal_check_cannot_execute_unevaluated_payload(self):
        # Exploit (models a concurrent thread): forged payload/effect digests are read by
        # the binding checks, then the sealed metadata is restored before the seal check.
        # The host grant authorizes two exact effects; only the first was evaluated.
        evaluated, unevaluated = {"doc": "q3"}, {"doc": "board-minutes"}
        other_effect = effect_digest(action=READ.descriptor, payload=unevaluated, manifest=READ)
        action, scope, authority, result = _govern(
            "req-race", READ, evaluated, grant_id="g-race", extra_effects=(other_effect,))
        genuine = copy.deepcopy(dict(result.audit_event.metadata))
        result.audit_event.metadata["payload_digest"] = payload_digest(unevaluated)
        result.audit_event.metadata["effect_digest"] = other_effect

        class RacingAuthority:
            def verify(self, checked_scope):
                result.audit_event.metadata.clear()
                result.audit_event.metadata.update(genuine)
                return authority.verify(checked_scope)

            def consume(self, checked_scope):
                return authority.consume(checked_scope)

        executor = _Recorder()
        execution = enforce_and_execute(
            pipeline_result=result, action=action, payload=unevaluated, executor=executor,
            authorization_scope=scope, tool_registry=REGISTRY, grant_authority=RacingAuthority(),
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])

    def test_genuine_flows_still_execute_after_snapshotting(self):
        action, scope, authority, result = _govern(
            "req-ok", READ, {"doc": "q3"}, grant_id="g-ok")
        executor = _Recorder()
        execution = enforce_and_execute(
            pipeline_result=result, action=action, payload={"doc": "q3"}, executor=executor,
            authorization_scope=scope, tool_registry=REGISTRY, grant_authority=authority,
        )
        self.assertIs(execution.status, ExecutionStatus.EXECUTED)
        self.assertEqual(executor.calls, [("docs.read", {"doc": "q3"})])


class ReviewSignatureCanonicalizationTests(unittest.TestCase):
    """N5: one signed approval must have exactly one accepted representation."""

    def test_gateway_rejects_uppercase_review_signature(self):
        signer = _review_signer()
        action, scope, authority, held = _govern(
            "req-upper", MAIL, {"to": "a@example.test"}, grant_id="g-upper")
        approval = _approve(signer, held)
        verifier = ReviewVerifier(signer.public_keys())
        self.assertIs(verifier.verify_signature(approval), ReviewStatus.VALID)
        for encoded in (approval.signature.upper(), approval.signature[:64] + " " + approval.signature[64:]):
            with self.subTest(encoded=encoded[:8]):
                self.assertIs(
                    verifier.verify_signature(replace(approval, signature=encoded)),
                    ReviewStatus.INVALID_SIGNATURE,
                )
        executor = _Recorder()
        execution = enforce_and_execute(
            pipeline_result=held, action=action, payload={"to": "a@example.test"},
            executor=executor, authorization_scope=scope, tool_registry=REGISTRY,
            grant_authority=authority,
            review_approval=replace(approval, signature=approval.signature.upper()),
            review_verifier=verifier,
        )
        self.assertIs(execution.status, ExecutionStatus.BLOCKED)
        self.assertEqual(executor.calls, [])


class _EvidenceCase(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519AuditSigner({"audit": b"a" * 32}, active_key_id="audit")
        self.keys = self.signer.public_keys()
        self.review = _review_signer()
        self.review_keys = self.review.public_keys()

    def _cli(self, raw, *, review=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bundle.json")
            path.write_text(json.dumps(raw), encoding="utf-8")
            command = [sys.executable, "-I", str(SCRIPT), str(path),
                       "--pubkey", f"audit={self.keys['audit'].hex()}"]
            if review:
                command += ["--review-pubkey", f"review={self.review_keys['review'].hex()}"]
            return subprocess.run(command, text=True, capture_output=True, check=False)

    def _assert_both_reject(self, raw, *, review=False):
        try:
            library = verify_bundle(raw, self.keys, review_public_keys=self.review_keys if review else None)
            self.assertFalse(library.valid, "runtime verifier accepted the forged receipt")
        except ValueError:
            pass  # rejected while parsing; still a fail-closed verdict
        completed = self._cli(raw, review=review)
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)

    def _assert_both_accept(self, raw, *, review=False):
        library = verify_bundle(raw, self.keys, review_public_keys=self.review_keys if review else None)
        self.assertTrue(library.valid, library)
        completed = self._cli(raw, review=review)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def _executed_allow_trail(self):
        trail = AuditTrail(self.signer)
        action, scope, authority, result = _govern(
            "req-allow", READ, {"doc": "q3"}, grant_id="g-allow", trail=trail)
        enforce_and_execute(
            pipeline_result=result, action=action, payload={"doc": "q3"}, executor=_Recorder(),
            authorization_scope=scope, tool_registry=REGISTRY, grant_authority=authority,
            audit_trail=trail,
        )
        return trail

    def _reviewed_trail(self):
        trail = AuditTrail(self.signer)
        action, scope, authority, held = _govern(
            "req-review", MAIL, {"to": "a@example.test"}, grant_id="g-review", trail=trail)
        approval = _approve(self.review, held)
        executed = enforce_and_execute(
            pipeline_result=held, action=action, payload={"to": "a@example.test"},
            executor=_Recorder(), authorization_scope=scope, tool_registry=REGISTRY,
            grant_authority=authority, review_approval=approval,
            review_verifier=ReviewVerifier(self.review_keys), audit_trail=trail,
        )
        self.assertIs(executed.status, ExecutionStatus.EXECUTED)
        return trail, approval


class ExecutionLinkageTests(_EvidenceCase):
    """N2: a receipt must prove each execution transition was authorized in-receipt."""

    def test_genuine_allow_and_review_receipts_verify(self):
        trail = self._executed_allow_trail()
        self._assert_both_accept(build_bundle(trail.envelopes, trail.events).to_dict())
        trail, approval = self._reviewed_trail()
        self._assert_both_accept(
            build_bundle(trail.envelopes, trail.events, review_approvals=(approval,)).to_dict(),
            review=True,
        )

    def _forge_execution(self, trail, *, decision_result, **overrides):
        values = dict(
            request_id=decision_result.audit_event.request_id,
            evaluation_digest=evaluation_digest(decision_result.audit_event),
            action_name=decision_result.audit_event.metadata["action_name"],
            decision=decision_result.policy.decision.value,
            grant_id=decision_result.audit_event.metadata["authorization_grant_id"],
            effect_digest=decision_result.audit_event.metadata["effect_digest"],
            grant_record_digest="e" * 64,
        )
        values.update(overrides)
        for phase, status in (("grant_consumed", "admitted"), ("dispatch_completed", "executed")):
            trail.append(build_execution_audit_event(phase=phase, status=status, **values))

    def test_review_decision_cannot_be_receipted_as_allow_execution(self):
        # Exploit: a REVIEW-held request appears executed under ALLOW with no approval.
        # Every record is validly signed; at e7c64ea both verifiers accepted it.
        trail = AuditTrail(self.signer)
        _, _, _, held = _govern("req-held", MAIL, {"to": "x@example.test"}, grant_id="g-held", trail=trail)
        self.assertIs(held.policy.decision, Decision.REVIEW)
        self._forge_execution(trail, decision_result=held, decision="allow")
        self._assert_both_reject(build_bundle(trail.envelopes, trail.events).to_dict())

    def test_block_decision_cannot_be_followed_by_execution(self):
        trail = AuditTrail(self.signer)
        action = READ.descriptor
        scope = AuthorizationScope("g-block", action.capabilities, issuer="host",
                                   allowed_effects=("c" * 64,))
        authority = GrantAuthority(); authority.issue(scope)
        blocked = evaluate_request(
            request_id="req-block", source_type="user", content="x", action=action,
            payload={"doc": "q3"}, detector=_Low(),
            provenance=InputProvenance("user", trust_level=TrustLevel.TRUSTED),
            authorization_scope=scope, tool_registry=REGISTRY, grant_authority=authority,
            audit_trail=trail,
        )
        self.assertIs(blocked.policy.decision, Decision.BLOCK)
        self._forge_execution(trail, decision_result=blocked, decision="allow")
        self._assert_both_reject(build_bundle(trail.envelopes, trail.events).to_dict())

    def test_execution_with_substituted_grant_or_effect_is_rejected(self):
        for override in ({"grant_id": "someone-elses-grant"}, {"effect_digest": "f" * 64},
                         {"action_name": "funds.transfer"}):
            with self.subTest(override=override):
                trail = AuditTrail(self.signer)
                _, _, _, allowed = _govern("req-sub", READ, {"doc": "q3"}, grant_id="g-sub", trail=trail)
                self._forge_execution(trail, decision_result=allowed, **override)
                self._assert_both_reject(build_bundle(trail.envelopes, trail.events).to_dict())

    def test_execution_without_any_authorizing_decision_is_rejected(self):
        trail = AuditTrail(self.signer)
        _, _, _, allowed = _govern("req-orphan", READ, {"doc": "q3"}, grant_id="g-orphan")
        self._forge_execution(trail, decision_result=allowed)
        self._assert_both_reject(build_bundle(trail.envelopes, trail.events).to_dict())

    def test_dispatch_without_grant_consumption_or_twice_is_rejected(self):
        trail = AuditTrail(self.signer)
        _, _, _, allowed = _govern("req-order", READ, {"doc": "q3"}, grant_id="g-order", trail=trail)
        common = dict(
            request_id="req-order", evaluation_digest=evaluation_digest(allowed.audit_event),
            action_name="docs.read", decision="allow", grant_id="g-order",
            effect_digest=allowed.audit_event.metadata["effect_digest"], grant_record_digest="e" * 64,
        )
        trail.append(build_execution_audit_event(phase="dispatch_completed", status="executed", **common))
        self._assert_both_reject(build_bundle(trail.envelopes, trail.events).to_dict())

        trail = self._executed_allow_trail()
        last = trail.events[-1]
        trail.append(replace(last))  # a second "executed" transition for one consumed grant
        self._assert_both_reject(build_bundle(trail.envelopes, trail.events).to_dict())


class SchemaAndWrapperTests(_EvidenceCase):
    """N3/N6/N7: unknown schemas, unsigned wrappers and malformed input fail closed."""

    def test_unknown_future_execution_schema_is_not_given_v1_semantics(self):
        trail = AuditTrail(self.signer)
        trail.append({
            "event_schema_version": "agentshield-execution-audit-event-v999",
            "request_id": "r", "decision": "allow", "phase": "dispatch_completed",
            "status": "executed", "action_name": "funds.transfer",
        })
        with self.assertRaises(ValueError):
            build_bundle(trail.envelopes, trail.events)
        # hand-assemble the bundle the e7c64ea exporter produced for the v999 record
        raw = {
            "schema_version": "agentshield-evidence-bundle-v1",
            "receipt_profile": "agentshield-verifiable-action-receipt-v1",
            "exported_at_utc": "2026-10-07T20:00:00+00:00",
            "review_approvals": [],
            "records": [{
                "record_type": "execution_lifecycle",
                "event": trail.events[0],
                "envelope": trail.envelopes[0].to_dict(),
            }],
        }
        self._assert_both_reject(raw)
        raw["records"][0]["record_type"] = "audit_event"  # nor hidden as an opaque record
        self._assert_both_reject(raw)
        result = verify_bundle(
            {**raw, "records": [{**raw["records"][0], "record_type": "unsupported"}]}, self.keys)
        self.assertIs(result.status, AuditVerificationStatus.SCHEMA_MISMATCH)

    def test_unsigned_bundle_and_record_wrapper_fields_are_rejected(self):
        trail = self._executed_allow_trail()
        raw = build_bundle(trail.envelopes, trail.events).to_dict()
        self._assert_both_accept(raw)
        banner = copy.deepcopy(raw)
        banner["independently_audited_by"] = "Big Four"
        self._assert_both_reject(banner)
        stamped = copy.deepcopy(raw)
        stamped["records"][0]["verified"] = True
        self._assert_both_reject(stamped)

    def test_malformed_envelope_values_yield_a_verdict_not_a_crash(self):
        trail = self._executed_allow_trail()
        raw = build_bundle(trail.envelopes, trail.events).to_dict()
        for field, value in (("key_id", ["audit"]), ("sequence", True), ("sequence", "0"),
                             ("signature", 7), ("previous_envelope_hash", 0)):
            with self.subTest(field=field, value=value):
                forged = copy.deepcopy(raw)
                forged["records"][0]["envelope"][field] = value
                with self.assertRaises(ValueError):
                    load_bundle(forged)
                self._assert_both_reject(forged)


class ReviewProofEncodingTests(_EvidenceCase):
    """N5: verifiers must agree, and only the exact signed bytes are accepted."""

    def test_reencoded_review_proof_rejected_by_both_verifiers(self):
        trail, approval = self._reviewed_trail()
        raw = build_bundle(trail.envelopes, trail.events, review_approvals=(approval,)).to_dict()
        self._assert_both_accept(raw, review=True)
        proof = raw["review_approvals"][0]
        same_instant_other_offset = datetime.fromisoformat(proof["expires_at_utc"]).astimezone(
            timezone(timedelta(hours=1))).isoformat()
        reencodings = {
            "space separator timestamp": ("issued_at_utc", proof["issued_at_utc"].replace("T", " ")),
            "same instant, +01:00 offset": ("expires_at_utc", same_instant_other_offset),
        }
        for label, (field, value) in reencodings.items():
            with self.subTest(label=label):
                forged = copy.deepcopy(raw)
                forged["review_approvals"][0][field] = value
                self._assert_both_reject(forged, review=True)

    def test_uppercase_review_signature_in_receipt_rejected(self):
        trail, approval = self._reviewed_trail()
        raw = build_bundle(trail.envelopes, trail.events, review_approvals=(approval,)).to_dict()
        raw["review_approvals"][0]["signature"] = approval.signature.upper()
        self._assert_both_reject(raw, review=True)


class InterruptedDispatchEvidenceTests(unittest.TestCase):
    """N8: an interrupt during dispatch must not leave evidence ending at 'admitted'."""

    def test_keyboard_interrupt_records_failed_completion_then_propagates(self):
        trail = AuditTrail(Ed25519AuditSigner({"audit": b"a" * 32}, active_key_id="audit"))
        action, scope, authority, result = _govern(
            "req-int", READ, {"doc": "q3"}, grant_id="g-int", trail=trail)

        class Interrupting:
            def execute(self, *, action_name, payload):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            enforce_and_execute(
                pipeline_result=result, action=action, payload={"doc": "q3"},
                executor=Interrupting(), authorization_scope=scope, tool_registry=REGISTRY,
                grant_authority=authority, audit_trail=trail,
            )
        last = trail.events[-1]
        self.assertEqual((last.phase, last.status, last.exception_class),
                         ("dispatch_completed", "failed", "KeyboardInterrupt"))


class DetectorScoreTests(unittest.TestCase):
    def test_negative_zero_score_is_normalized(self):
        score = DetectionResult(ContentRisk.LOW, -0.0, "d", "1").score
        self.assertEqual(json.dumps(score), "0.0")


if __name__ == "__main__":
    unittest.main()
