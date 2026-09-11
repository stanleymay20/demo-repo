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
- Repeated use of the same internal audit across model families makes it corroborating evidence, not a pristine final holdout; any breakthrough claim requires a new untouched external holdout.

## E01 — sparse high-recall search
- Script: `agentshield/high_recall_linear_v1.py`
- Workflow: `AgentShield high-recall linear v1`
- Run ID: `34571996510`
- Head SHA: `47bae83e482bccb410788a9fd51947d38df1e79b`
- Status: **completed successfully**.
- Method: word + character + hidden/attribute TF-IDF; LinearSVC and Logistic Regression; validation-only hyperparameter/threshold selection; one-shot internal audit.
- Data hygiene: 1 normalized training duplicate removed and 1 normalized train/benchmark overlap removed; development/validation/audit = 7725/1656/1656.
- Validation winner: `LogReg_C1_pw1`, threshold `0.6231860540`; recall **62.97%** at observed FPR **0.958%**, precision 98.48%, ROC-AUC 0.9279 (517 TP, 304 FN, 8 FP, 827 TN).
- Frozen-threshold internal audit: recall **57.25%** at observed FPR **1.078%**, precision 98.12%, ROC-AUC 0.9127 (470 TP, 351 FN, 9 FP, 826 TN). Recall 95% CI 53.84–60.59%; FPR 95% CI 0.568–2.036%.
- Gate A (>=50% recall AND observed FPR <=1% on audit): **FAIL** because audit FPR is 1.078%, despite the large recall improvement.
- Benchmark labels accessed: no.
- Evidence artifact: ID `10188873481`, SHA-256 `8a8227f85058ff29f69f5b43b044087a4eac89ecfe1e53a683b9f2421d620acc`.
- Interpretation: this is a genuine improvement over the frozen baseline, but it is **not promoted** under the predeclared <=1% audit-FPR gate. The audit threshold is not retuned after seeing this result.

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
- Script: `agentshield/high_recall_protectai_v1.py`.
- Initial run: `34572666744` at SHA `0cabefb31780b09ed09d4b2ee82d1927bdc399f4`.
- Initial result: **no performance result produced**. The model labels were correctly verified (`0=SAFE`, `1=INJECTION`), but execution stopped before validation scoring because Transformers 5.x `DebertaV2Tokenizer` does not expose `prepare_for_model`.
- Repair: commit `9cecaf999e6e6b40bda50984840e9871174c3319` manually constructs CLS/SEP inputs, pins and records the exact Hugging Face model revision, and records dataset fingerprints.
- CI hardening: commit `9ec122e6907f57e2d4adf6b3a9a218cc6f7b8c14` adds `set -o pipefail` so Python failures cannot be hidden by `tee`, and installs CPU-only PyTorch on the CPU runner.
- Controlled rerun: `34573086538`.
- Status: in progress at last check; result pending.
- Validation chooses document aggregation (`first`, `max`, or `top2mean`) and threshold; audit remains one-shot.
- BrowseSafe benchmark labels accessed: no.

## Promotion gates
50%, 70%, 85%, 90%, 95%, 99%, and 99.9% recall are descriptive milestones only. Every gate also requires observed FPR <=1% on the relevant frozen audit/holdout and clean integrity checks.
