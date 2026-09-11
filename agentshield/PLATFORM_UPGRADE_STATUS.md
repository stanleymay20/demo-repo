# AgentShield Platform Upgrade Status

Branch: `agentshield-platform-v1`
Base research snapshot: `6ddd85d618a4bcd69ac70b2c993e6d9c07ad80be`

## Preserved scientific state

The platform branch does not alter the historical meaning of E01, E02 or E03.

E03 remains bound to GitHub Actions run `34573086538` at execution commit `9ec122e6907f57e2d4adf6b3a9a218cc6f7b8c14`. Its result must be interpreted only from its completed preserved evidence.

## Added in platform v1

- `ARCHITECTURE_V1.md` — layered security architecture and non-contamination boundary.
- `THREAT_MODEL_V1.md` — explicit trust boundaries, attacker capabilities, invariants and out-of-scope threats.
- `EVALUATION_CONTRACT_V1.md` — separates detector quality from system-level protection metrics.
- `platform/policy.py` — deterministic versioned ALLOW / REVIEW / BLOCK policy engine.
- `platform/events.py` — structured versioned audit-event primitive without raw-content logging by default.
- `tests/test_platform_policy.py` — policy invariants and fail-safe UNKNOWN behavior.
- `tests/test_platform_events.py` — structured audit-event validation tests.
- isolated platform CI workflow.

## Next controlled engineering stages

1. Content provenance/extraction interface.
2. Detector adapter contract so experimental models cannot directly authorize actions.
3. Action-risk taxonomy and mapper.
4. Policy decision API/service boundary.
5. Scenario harness for dangerous-action prevention and benign-task completion.
6. Adaptive attack corpus and hard-negative suite.
7. Latency/cost instrumentation.
8. Persistence with privacy-aware audit records.
9. External untouched holdout protocol.
10. Production deployment hardening and independent red-team reproduction.

## Rule

Platform upgrades may proceed while E03 runs, but E03 itself remains frozen. Any new experiment must receive a new experiment identifier, protocol record and evidence lineage.
