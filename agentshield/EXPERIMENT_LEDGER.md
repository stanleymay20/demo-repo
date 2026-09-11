# AgentShield High-Recall Experiment Ledger

This ledger records experiments on branch `agentshield-high-recall-research`. It is intentionally separate from the frozen M508 submission baseline.

## Scientific rules
- Primary metric: attack recall subject to observed FPR <= 1%.
- Model selection and threshold selection use validation only.
- Internal audit is one-shot after configuration freeze.
- BrowseSafe benchmark labels are not used for development on this branch.
- Any benchmark already exposed historically is treated as benchmark evidence, not a pristine holdout.
- No result is promoted from logs alone without preserved configuration and evidence files.
- Unexpectedly strong results trigger leakage/contamination checks before interpretation.
- 99.9% is a stretch hypothesis, not a required outcome.

## E01 — sparse high-recall search
- Script: `agentshield/high_recall_linear_v1.py`
- Workflow: `AgentShield high-recall linear v1`
- Run ID: `34571996510`
- Head SHA: `47bae83e482bccb410788a9fd51947d38df1e79b`
- Status at ledger creation: in progress
- Method: word + character + hidden/attribute TF-IDF; LinearSVC and Logistic Regression; validation-only hyperparameter/threshold selection; one-shot internal audit.
- Benchmark labels accessed: no.
- Result: pending; do not infer performance before the evidence artifact is available.

## E02 — pretrained ModernBERT specialist, planned
- Script: `agentshield/high_recall_modernbert_v1.py`
- Status: not promoted / not yet treated as valid evidence.
- Required pre-run check: verify model label semantics and probability transformation from the model configuration before execution. Do not assume a logit column corresponds to injection without verification.
- Purpose: test chunk-level aggregation (first/max/top-2 mean) without fine-tuning on BrowseSafe.

## Promotion gates
50%, 70%, 85%, 90%, 95%, 99%, and 99.9% recall are descriptive milestones only. Every gate also requires observed FPR <=1% on the relevant frozen audit/holdout and clean integrity checks.
