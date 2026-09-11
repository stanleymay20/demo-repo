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
- Status: in progress at last check.
- Method: word + character + hidden/attribute TF-IDF; LinearSVC and Logistic Regression; validation-only hyperparameter/threshold selection; one-shot internal audit.
- Benchmark labels accessed: no.
- Result: pending; do not infer performance before the evidence artifact is available.

## E02 — pretrained `dannyliv/agent-guard-modernbert-base`
- Script: `agentshield/high_recall_modernbert_v1.py`
- Workflow run: `34572178470`.
- Status: **invalid for interpretation; do not promote any metric from this run.**
- Reason: pre-run label audit showed the checkpoint is a 17-label multi-label classifier with generic labels `LABEL_0`…`LABEL_16`; the injection class cannot be uniquely identified from the model configuration.
- Label-audit run: `34572301543`.
- Verified config: `num_labels=17`, `problem_type=multi_label_classification`, tokenizer max length `8192`.
- Consequence: the original E02 script's use of `logits[:,0]` cannot be treated as a prompt-injection probability without authoritative label semantics. Any output from E02 is quarantined as methodologically invalid.

## Candidate configuration audit
- Run: `34572477725`.
- `siberiancat/modernbert-prompt-injection`: binary, but generic `LABEL_0/LABEL_1`; semantics not sufficiently explicit for scoring without an authoritative mapping.
- `patronus-studio/wolf-defender-prompt-injection`: binary; config explicitly maps `0=benign`, `1=injection`; tokenizer max length 8192. Scientifically usable.
- `protectai/deberta-v3-base-prompt-injection-v2`: binary; config explicitly maps `0=SAFE`, `1=INJECTION`. Scientifically usable.

## E03 — verified ProtectAI specialist
- Script: `agentshield/high_recall_protectai_v1.py`
- Workflow run: `34572666744`.
- Head SHA: `0cabefb31780b09ed09d4b2ee82d1927bdc399f4`.
- Status: in progress at last check.
- Runtime asserts semantic labels before scoring and uses softmax probability for the verified `INJECTION` class.
- Validation chooses document aggregation (`first`, `max`, or `top2mean`) and threshold; audit remains one-shot.
- BrowseSafe benchmark labels accessed: no.
- Result: pending.

## Promotion gates
50%, 70%, 85%, 90%, 95%, 99%, and 99.9% recall are descriptive milestones only. Every gate also requires observed FPR <=1% on the relevant frozen audit/holdout and clean integrity checks.
