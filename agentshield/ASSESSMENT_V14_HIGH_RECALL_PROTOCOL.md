# AgentShield Assessment v14 — High-Recall Research Protocol

## Status

This is a **research-only experimental successor** to the frozen M508 assessment notebook. It must not overwrite v13.7 and must not be treated as submission-ready unless module rules independently permit its use.

## Question

Can a stronger lightweight sparse-text/HTML detector materially improve attack recall while keeping **observed validation FPR <= 1%**, and does that improvement survive a one-shot internal audit?

## Stretch target

- Desired research target: >= 90% attack recall with observed FPR <= 1%.
- This is a target, not a quota. A lower genuine result is preserved exactly.
- No threshold may be loosened after seeing audit performance.

## Data and contamination controls

- Dataset: `perplexity-ai/browsesafe-bench`.
- BrowseSafe `train` is used for development, validation and internal audit.
- BrowseSafe test **labels are not accessed** by this experiment.
- Test content hashes may be used only to remove train/test normalized-content overlap.
- Normalized duplicates inside training are removed before splitting.
- Seed: 42.
- Split procedure is the same deterministic procedure used by E01: 70% development / 15% validation / 15% audit after cleaning.

## Representations

Three sparse feature families are tested:

1. **semantic** — parsed/hidden combined word TF-IDF + character TF-IDF + hidden-evidence character TF-IDF;
2. **raw_html** — raw-HTML character TF-IDF to preserve markup/instruction morphology;
3. **hybrid** — concatenation of semantic and raw-HTML sparse features.

No benchmark labels are used to select features, models, fusion weights or thresholds.

## Models

- `LinearSVC` over each feature family with a predeclared grid of C and positive-class weights.
- `LogisticRegression` over semantic and hybrid feature families with a smaller predeclared grid.
- After base-model validation, the best validation candidate from each feature family is eligible for a validation-only linear score fusion sweep.
- Fusion scores are standardized using validation score mean/std only. The same stored transforms are applied on audit.

## Selection

For every validation candidate:

1. choose the highest threshold-specific recall achievable at observed FPR <= 1%;
2. break ties by ROC-AUC, then precision, then stricter threshold;
3. select the single winning base/fusion configuration using validation only.

## Audit

The selected configuration is evaluated **exactly once** on the internal audit split with the frozen validation-selected threshold and any frozen fusion parameters.

Report:

- precision;
- recall;
- F1;
- ROC-AUC;
- observed FPR;
- confusion matrix;
- Wilson 95% CI for recall and FPR.

## Gates

Research gates are descriptive only:

- A: audit recall >= 50% and observed audit FPR <= 1%;
- B: >= 70% and <= 1%;
- C: >= 85% and <= 1%;
- D: >= 90% and <= 1%;
- Stretch: >= 99.9% and <= 1%.

Passing D would be an excellent result but still would not establish production security or an untouched external breakthrough because BrowseSafe has historical exposure in the wider project.

## Integrity rules

- Never manufacture or reconstruct a result.
- Never retune from audit.
- Never call 90% recall successful if it requires FPR > 1% under the declared objective.
- Preserve failed, negative or lower-than-hoped results.
- Do not modify v13.7 academic baseline files.
