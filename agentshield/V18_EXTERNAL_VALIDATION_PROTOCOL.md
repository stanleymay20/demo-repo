# AgentShield v18 External Validation Protocol

Status: FROZEN BEFORE EXTERNAL SCORING

## Purpose
This programme evaluates the already-established AgentShield v18 champion on previously unused external data. It is not an optimization programme. v18 must not be retrained, retuned, re-thresholded, feature-engineered, or otherwise adapted using any external evaluation result.

## Frozen reference
- Repository: stanleymay20/demo-repo
- v18 champion commit: 92b5e23d143397d8732673ee2e5715b5c81e82c1
- Internal comparative-audit reference: TP=600, FN=221, FP=7, TN=828
- Reference recall: 600/821 = 0.7308160779537149
- Reference FPR: 7/835 = 0.008383233532934132
- Internal validation target FPR used by v18: 0.006
- Operating FPR ceiling: 0.01

A reconstruction is valid only if it reproduces the exact internal comparative-audit confusion matrix above. If it does not, external scoring must abort.

## External suites

### Suite A — primary direct external classification
Dataset: `v1adam/Comparison_Dataset`.
Rationale: dataset card describes it as an independently constructed evaluation set for prompt injection, jailbreak and sensitive-data-exposure detection with benign examples from a different distribution.

The exact Hugging Face dataset revision must be resolved and recorded before predictions are generated. Predictions are produced before label-based scoring. No threshold is selected on this dataset.

### Suite B — secondary transfer classification
Dataset: `deepset/prompt-injections`.
Rationale: public prompt-injection classification set used only as an additional transfer stress test.

This suite must not be described as independent unless contamination screening against all BrowseSafe train/test text passes. Exact and near-duplicate exclusions are reported. It is never used to change v18.

### Suite C — indirect agent/tool injection stress test
Dataset source: `uiuc-kang-lab/InjecAgent` pinned to commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`.
Files:
- `data/test_cases_dh_base.json`
- `data/test_cases_ds_base.json`

Each published injected `Tool Response` is scored as an attack example. A matched clean-control response is constructed only for diagnostic paired analysis by taking the published `Tool Response Template` and replacing `<Attacker Instruction>` with an empty string. Clean controls are synthetic matched controls, not native benchmark negatives, and must be reported separately from native external-classification metrics.

### Reserved Suite D — BIPIA
Repository: `microsoft/BIPIA`, pinned to commit `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`.
BIPIA is reserved for a subsequent indirect-injection phase because some task contexts require source-data reconstruction under their original usage terms. No BIPIA score may be claimed until those contexts are reproduced according to the benchmark instructions.

## Prediction/scoring separation
External validation runs in two logical phases:
1. Reconstruct frozen v18, verify exact internal champion confusion matrix, resolve/pin external dataset revisions, perform contamination screening, generate external predictions, and seal predictions with SHA-256. No external labels are used for model adaptation or threshold selection.
2. Reload the sealed predictions and the same pinned external revisions, verify row/text hashes, then read labels and compute metrics.

Public datasets are not cryptographically secret, so this is a blind-style procedural separation rather than a claim that labels were inaccessible to the infrastructure.

## Contamination screening
Every external text is normalized using the same lowercase-whitespace-normalization family used in the AgentShield benchmark cleaning logic and compared against all BrowseSafe train and test text.

Required checks:
- exact SHA-256 normalized-text match;
- near-duplicate screen using hashed character n-gram cosine similarity;
- near-duplicate threshold fixed at cosine similarity >= 0.92.

Rows meeting either criterion are excluded from the clean external-generalization estimate and reported separately. The pre-exclusion and post-exclusion counts must both be preserved.

## Metrics
For native labeled datasets report:
- TP, FN, FP, TN;
- recall, FPR, precision, F1;
- ROC-AUC when both classes are present;
- Wilson 95% CI for recall and FPR;
- exact number and fraction excluded by contamination screening.

For InjecAgent report separately:
- attack detection rate on injected responses;
- false-positive rate on matched synthetic clean controls;
- paired outcome counts: detected attack / clean accepted, detected both, missed attack / clean accepted, missed attack / clean flagged;
- results by attack type where available.

## Scientific interpretation gates
The external programme does not create a new v18 version. Possible conclusions are:
- `GENERALIZATION_SUPPORTED`: v18 remains within <=1% observed FPR on at least one genuinely independent native labeled external dataset and retains materially non-trivial recall; stronger wording requires consistency across more than one independent dataset.
- `TRANSFER_SUPPORTED_ONLY`: performance is useful on secondary or paired stress tests but independent native external evidence is insufficient.
- `GENERALIZATION_NOT_SUPPORTED`: external recall collapses materially and/or external FPR exceeds the 1% operating ceiling.
- `INCONCLUSIVE`: insufficient native negative examples, excessive contamination, schema ambiguity, or other validity failure.

No state-of-the-art or breakthrough claim may be made from these results alone. Comparisons against published baselines under the same operating constraint and additional untouched external evaluations are still required.

## Non-negotiable controls
- Never tune v18 from external metrics.
- Never select a new external threshold.
- Never discard a dataset because performance is poor.
- Preserve failed, negative and invalid external runs.
- Preserve exact dataset revisions, repository commits, code commit, runtime manifest, row hashes, prediction SHA-256 and final evidence SHA-256.
- If any reconstruction, revision, row-hash or contamination-control check fails, stop fail-closed and do not report performance as valid.
