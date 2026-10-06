# AgentShield GA Readiness Contract

This document separates **runtime-platform GA** from **detector research claims**.

## Runtime GA invariants

A GA release must demonstrate all of the following on the exact release commit:

- fail-closed ALLOW / REVIEW / BLOCK policy;
- server-owned tool manifests;
- least-privilege authorization scopes;
- mandatory exact-effect authorization and rejection of resource/destination changes,
  including attempts to expand an issued effect allowlist;
- durable atomic grant verification/consumption across workers;
- every executable GA grant is single-use; legacy reusable grants fail closed;
- replay, expiry and revocation enforcement with authority-owned time;
- PostgreSQL validity sampled from database time after lineage locking;
- action, payload, scope and manifest integrity binding;
- detached strict-JSON payload snapshots across evaluation and dispatch, including
  mutation-during-consumption and Python/JSON type-alias adversarial regressions;
- authenticated execution authority: trusted in-process evaluations carry an integrity
  seal and detached ALLOW/REVIEW evaluations require Ed25519 authentication;
- cryptographically bound, short-lived Ed25519 human-review approval for REVIEW resumes;
- review signing private keys are separated from execution-side public verification keys;
- execution-admission and execution-outcome audit events are chained into tamper-evident
  envelopes without raw prompt/payload/output or exception text;
- a durable production audit sink can reject dispatch if pre-dispatch evidence cannot be
  persisted; post-dispatch audit failures are surfaced distinctly because execution may
  already have occurred;
- no raw untrusted payload persistence by default;
- package install/build smoke test, including a dependency-free core wheel;
- Python unit tests and PostgreSQL concurrency integration tests;
- CodeQL and dependency-vulnerability audit gates;
- immutable-SHA GitHub Action references in GA workflows;
- documented security reporting and contribution rules.

## Required adversarial regression evidence

The exact release commit must keep the PR #6 forensic regressions green:

- a forged BLOCK/REVIEW → ALLOW `PipelineResult` cannot execute;
- an unsigned detached ALLOW/REVIEW evaluation cannot execute;
- a signed detached evaluation cannot be modified after signing;
- one executable grant cannot dispatch twice, including concurrent attempts;
- a legacy reusable grant cannot execute;
- caller-controlled historical time cannot resurrect an expired grant;
- review verifiers cannot mint approvals;
- executor failure after grant consumption is recorded without leaking exception text;
- exact-effect containment survives detector misses and decision-layer attacks.

The original vulnerable evidence is preserved before the repair in the remediation
branch history; do not rewrite that lineage.

## Audit durability boundary

`AuditTrail` provides a serialized, signed chain and can call a synchronous host sink.
Production deployments must configure durable persistence and periodically anchor the
latest envelope hash outside the runtime writer's control (for example, separate storage,
object-lock storage or a transparency service). HMAC chaining detects modification and
reordering but, by itself, cannot prove that the tail of a locally controlled log was not
truncated after compromise.

The built-in process-local audit trail is a safe development fallback and returned
execution evidence, **not** a GA durability claim.

## Detector / research claim boundary

The runtime can be released independently of a universal prompt-injection claim. Detector metrics must remain attached to their exact frozen protocol and dataset. Historical internal audit data is corroborating evidence, not a pristine external holdout.

A detector marketed as production-validated still requires a genuinely unseen contamination-screened external holdout, predeclared gates, confidence intervals and independent adversarial reproduction. v27's failed promotion gate and any later experiment remain research evidence, not runtime release proof.

No internal, synthetic or repository test suite justifies a universal "100% secure" or
"99.999% prevention" statement. Any measured reliability claim must state its exact
threat model, denominator, confidence interval, environment and independence assumptions.

## Administrative release gates

Before the first GA tag:

- make `main` the canonical AgentShield implementation through reviewed PRs;
- require the GA workflow and CodeQL checks on protected `main`;
- require pull-request review for security-sensitive changes;
- enable secret scanning / push protection where the GitHub plan supports it;
- choose and add the repository license (this is an owner/legal decision, not a code fix);
- decide whether to rename the legacy `demo-repo` repository;
- obtain at least one independent human/security review of the final GA diff;
- create an annotated release tag and preserve its build artifacts/SBOM/provenance.

These repository-admin controls are release gates even though they are not runtime code.
