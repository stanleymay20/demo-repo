# AgentShield continuation — 1 October 2026

## Verified starting state

- Canonical repository: `stanleymay20/demo-repo`.
- Runtime integration: open PR #6, branch
  `agentshield-ga-integration-2026-09-29`, starting head
  `7884995123f0f16dcc0061b87cbac6736a5ca5d1`.
- Starting head had successful GA and CodeQL runs `36552110852` and
  `36552111062`; those results do not validate later commits.
- Frozen v28 branch: `agentshield-v28-exhaustive-segment-mil`, head
  `3351b68eac824075e8e179ec712f881016249e08`. It contains a predeclared
  protocol, not a v28 trainer/workflow or completed v28 benchmark result.
- The v27 rerun at execution head
  `189b619cb72bf62c4644fb64526870c2cc2a23f9`, run `36729589330`, completed.
  Its published evidence in issue #8 says the promotion gate failed: the
  validation winner was the anchor itself (641 TP, 180 FN, 5 FP, 830 TN).
  These are validation counts, not a new comparative-audit performance claim.
  The conditional workflow requires audit materialization/scoring to remain
  false when promotion fails. The full artifact should accompany any formal
  research publication; the issue summary is not a substitute for that bundle.

## Reproduced execution-boundary failures

The existing 87-test suite passed locally (84 passes, three PostgreSQL skips).
New adversarial tests then demonstrated:

1. A nested caller-owned payload could be mutated during grant consumption,
   after its digest check, and the executor received the mutated effect.
2. JSON serialization could alias integer/boolean/null object keys with string
   keys; an integer-key payload passed the digest for a string-key payload.
3. A detector callback could mutate the submitted payload before its first
   recorded digest, silently binding the changed request.

These tests deliberately use a detector that reports LOW risk. The security
property being tested is independent of classifier recall.

## Implemented correction

- Capture the submitted payload digest before detector/authority callbacks.
- Snapshot strict JSON objects recursively, preserving scalar types and
  detaching every nested dict/list from the caller's objects.
- Reject non-string object keys, tuples, custom Python subclasses, non-finite
  numbers, cycles, invalid Unicode and excessive nesting.
- At execution, hash and dispatch the same private snapshot.
- Return BLOCKED on malformed execution input before consuming the grant.
- Preserve existing grant, manifest, review-approval and policy checks.
- Add regressions for normal ALLOW execution and exact human-approved REVIEW
  execution, including recipient mutation during consumption.

Local verification: 99 tests discovered, 96 passed and three PostgreSQL tests
skipped because no local PostgreSQL service was present. Compilation and
`git diff --check` passed. Exact-head CI must additionally pass the existing
Python 3.11–3.14 matrix, live PostgreSQL concurrency tests, wheel/SBOM, dependency
vulnerability audit and CodeQL before this update is considered validated.

## Remaining authority-plane work

Payload integrity binds a request to dispatch; capability grants alone do not
authorize the resources named in that request. The next architecture milestone
must bind trusted intent to canonical effects with resource/tenant/recipient/path
and destination constraints, conserved delegation and provenance over time.
Executor semantics and coverage of every external action must be demonstrated.

The host must keep pipeline results, tool manifests, grant/review authorities,
signing keys and executors outside the untrusted agent's control. This library
does not create OS/container isolation or defend a compromised host authority.
Branch integration, review, license and administrative release gates remain.

## Research continuation

Implement v28 against the frozen protocol without modifying v18–v27 evidence.
Resolve and freeze the specified model revision; fail closed if access is missing.
Build channel extraction, overlapping windows, strict OOF weighting, training-only
augmentation and contamination screening, MIL/domain adaptation, constrained fusion,
candidate manifests, and separate promotion-gated audit execution.

The actual frozen budgets are validation FPR <=0.6%, and internal comparative
audit recall >=95.999% with FPR <=1%. On 821 attacks/835 benign, the internal
engineering milestone is at least 789 TP and at most 8 FP. Neither this runtime
change nor a synthetic regression pass establishes detector efficacy or a
99.999% unauthorized-consequence prevention rate. That eventual claim requires
a defined operating distribution, denominator, confidence bound, unseen external
red-team evaluation, benign-completion/SLA measurements and deployment evidence.
