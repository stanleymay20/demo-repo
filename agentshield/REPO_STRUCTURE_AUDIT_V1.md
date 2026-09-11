# AgentShield Repository Structure Audit v1

## Goal
Separate historical academic/research assets from the emerging platform so future engineering does not accidentally treat experiment scripts as production components.

## Current categories

### Controlled research evidence — preserve
- `EXPERIMENT_LEDGER.md`
- `HIGH_RECALL_RESEARCH_PLAN.md`
- `high_recall_linear_v1.py`
- `high_recall_modernbert_v1.py`
- `high_recall_protectai_v1.py`
- `candidate_model_config_audit.py`
- `modernbert_label_audit.py`

These files define experiment lineage or model-semantics checks. They should not be rewritten merely to make the platform cleaner.

### Academic / baseline lineage — preserve but do not treat as platform core
- `agentshield_eval.py`
- `agentshield_final_test.py`
- `agentshield_v13_5_cleanrun.py`

These remain useful for provenance and comparison but should not be imported by the platform package unless a deliberate compatibility adapter is created.

### Platform core — active
- `platform/policy.py`
- `platform/actions.py`
- `platform/detectors.py`
- `platform/events.py`
- `platform/pipeline.py`
- `platform/provenance.py`

### Platform evidence / design contracts — active
- `ARCHITECTURE_V1.md`
- `THREAT_MODEL_V1.md`
- `ACTION_RISK_V1.md`
- `EVALUATION_CONTRACT_V1.md`
- `PLATFORM_UPGRADE_STATUS.md`

### Platform tests — active
- `tests/test_platform_policy.py`
- `tests/test_platform_actions.py`
- `tests/test_platform_detectors.py`
- `tests/test_platform_events.py`
- `tests/test_platform_pipeline.py`
- `tests/test_platform_provenance.py`

## Structural risks found

1. Research scripts and platform code currently share the same top-level `agentshield/` directory. This is acceptable for the controlled transition but should eventually be reorganized or clearly documented so production imports never depend on mutable experiment scripts.
2. Historical filenames such as `agentshield_final_test.py` may sound authoritative even though the project has moved beyond that state. Preserve them for lineage; do not silently rename history.
3. Experiment-specific threshold logic must remain inside frozen experiment evidence/configuration and must not be copied into platform policy as an unversioned magic number.
4. Detector output must remain a risk signal. Authorization belongs to `platform/policy.py` plus action-risk context.
5. The platform still needs a scenario harness before claims about dangerous-action prevention can be made.

## Recommended next reorganization after E03 closes

Create explicit subtrees while preserving Git history:
- `agentshield/research/` for future experiment implementations;
- `agentshield/platform/` for production-facing security primitives;
- `agentshield/evaluation/` for detector and system-level evaluation harnesses;
- `agentshield/docs/` for architecture, threat model and scientific contracts;
- `agentshield/evidence/` or immutable release artifacts outside source control for frozen experiment outputs.

Do not perform mass moves until E03 is complete and its evidence is safely captured, because path churn during a live experiment makes forensic comparison harder.
