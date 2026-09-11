# AgentShield Platform Upgrade Status

Branch: `agentshield-platform-v1`
Original platform base snapshot: `6ddd85d618a4bcd69ac70b2c993e6d9c07ad80be`

## Preserved scientific state

The platform branch does not alter the historical meaning of E01, E02, E03 or the independent E04 experiment.

E03 completed successfully at the workflow level under run `34573086538`, execution commit `9ec122e6907f57e2d4adf6b3a9a218cc6f7b8c14`. Its verified internal-audit result was a valid negative result: recall 5.603% at observed FPR 0.838%. It remains preserved on the research lineage without post-hoc threshold tuning.

E04 runs independently on `agentshield-e04-wolf-small-v2`. No E04 result is part of this platform branch until its evidence is complete and separately verified.

## Current platform security contract

Current policy version: `agentshield-policy-v2`.

Automatic execution now requires:

- low detector content risk;
- normal action consequence;
- known host-supplied provenance;
- exact match against a server-owned `ToolManifest`;
- an explicit `AuthorizationScope` containing every requested capability;
- unchanged action descriptor, payload, grant and tool manifest at execution time.

Missing/unknown security state does not silently become ALLOW.

## Implemented platform components

- `ARCHITECTURE_V1.md` — preserved historical architecture contract.
- `ARCHITECTURE_V2.md` — current scope/registry/integrity architecture.
- `THREAT_MODEL_V1.md` — explicit trust boundaries and attacker capabilities.
- `EVALUATION_CONTRACT_V1.md` — detector/system metric separation.
- `ADVERSARIAL_SCENARIO_SUITE_V1.md` — preserved historical synthetic suite.
- `ADVERSARIAL_SCENARIO_SUITE_V2.md` — current nine-case scope/registry contract suite.
- `platform/policy.py` — deterministic versioned ALLOW / REVIEW / BLOCK policy.
- `platform/provenance.py` — trust-aware input provenance primitives.
- `platform/authorization.py` — least-privilege capability grants.
- `platform/tools.py` — authoritative server-owned tool manifests/registry.
- `platform/detectors.py` — detector adapter contract; detectors provide evidence only.
- `platform/pipeline.py` — composable evaluation and audit binding.
- `platform/integrity.py` — canonical SHA-256 bindings for action, payload, scope and tool manifest.
- `platform/execution.py` — fail-closed dispatch boundary.
- `platform/evaluation.py` / `evaluation_v2.py` — legacy and consequence-aware system metrics.
- `platform/scenarios.py` — deterministic adversarial/benign contract harness.
- structured audit events that avoid raw payload persistence by default.
- isolated platform CI with policy, provenance, detector, authorization, tool-registry, pipeline, execution and scenario tests.

## Verified platform behavior

The current synthetic suite intentionally keeps detector misses visible. It demonstrates that a detector miss may still permit an explicitly scoped read-only action, while separately verifying that:

- scope escalation is blocked;
- capability under-declaration against a server-owned manifest is blocked;
- REVIEW/BLOCK never dispatch;
- post-authorization action, payload, grant or manifest mutation fails closed;
- all declared harmful side-effect cases in the synthetic v2 suite remain non-executing.

These are platform contract results, not detector recall/FPR claims.

## Next controlled engineering stages

1. host-issued grant authenticity / replay and expiry controls;
2. explicit human-review approval artifact and secure resume path;
3. adaptive attack corpus and hard-negative suite;
4. latency/cost instrumentation across detector and policy stages;
5. privacy-aware persistence and tamper-evident audit storage;
6. external untouched holdout protocol;
7. production deployment hardening and independent red-team reproduction.

## Rule

Platform engineering may proceed independently of E04, but no running experiment may be retuned, reinterpreted or overwritten. Every new detector experiment requires a distinct experiment identifier, predeclared protocol and evidence lineage.