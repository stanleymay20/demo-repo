# AgentShield Assessment v21 — Chunk-Residual Protocol

## Status
Research-only successor to the verified v18 champion. The frozen assessment notebook and prior controlled results remain untouched.

## Governing objective
Maximize attack recall subject to an observed false-positive rate (FPR) ceiling of 1.0% on the comparative audit. Validation selection reserves headroom at <=0.6% observed FPR.

## Motivation
v18 reached 73.0816% comparative-audit recall at 0.8383% FPR. v19 multi-view stacking became more conservative but lost recall. v20 generic semantic rescue tied v18 recall while increasing FPR. The next hypothesis is therefore structural rather than generic-semantic: remaining attacks may be localized within long pages and diluted by whole-page representations.

## Frozen reference champion
v18 comparative audit: TP=600, FN=221, FP=7, TN=828; recall=600/821=0.730816077953715; FPR=7/835=0.008383233532934132.

## Hypothesis
A bounded raw-HTML chunk specialist can recover localized prompt-injection cues that are weak at whole-page level. Location-preserving chunk labels (head/middle/tail) and max/top-k page aggregation should provide complementary signal. A constrained three-way validation search can allocate a fixed false-positive budget across the v18 hard sparse expert, v18 adversarial sparse expert, and the chunk specialist.

## Data discipline
- Dataset: perplexity-ai/browsesafe-bench.
- Seed: 42.
- Reuse the exact v18 split logic and train/test overlap removal.
- Development only is used to fit all base and chunk specialists.
- Validation only selects configurations and thresholds.
- The comparative audit is evaluated once after the validation winner is frozen; it is explicitly non-pristine because prior experiments have already observed it.
- BrowseSafe benchmark/test labels are never accessed. Test content may be used only for train/test overlap hashing, matching the established protocol.
- No audit-informed retuning is allowed.

## Anchor
Reconstruct the v18-style sparse anchor from development data using OOF hard-example mining and adversarial augmentation. Search the same conservative validation-FPR regime used by v18 and select the best hard and adversarial family representatives before fusion.

## Chunk specialist
1. Use raw HTML/content from each development page.
2. Normalize whitespace but retain markup, attributes, comments and scripts.
3. Split each page into overlapping character windows of 1400 characters with 700-character stride, capped at 10 windows per page using deterministic coverage of head, middle and tail.
4. Prefix each window with a deterministic location marker: [HEAD], [MID] or [TAIL].
5. Train a character n-gram LinearSVC specialist on development chunks only.
6. Normalize per-page chunk weights so long pages do not dominate. Upweight chunks from development-only OOF-hard positive and hard-negative pages.
7. Aggregate chunk scores back to the page using both maximum score and mean of the top two chunk scores.

## Candidate search
- Hard sparse family: conservative grid around v18.
- Adversarial sparse family: v18-style adversarially augmented models.
- Chunk LinearSVC: C in {0.05, 0.1, 0.25, 0.5}; hard-positive multiplier in {1,2,4}; hard-negative multiplier in {1,2,4}; aggregation in {max, top2_mean}.
- Validation single-model thresholds are selected at <=0.6% FPR.
- Constrained three-way OR search jointly allocates at most floor(0.006 * N_benign_validation) false positives across the selected hard, adversarial and chunk specialists.
- The validation winner is chosen by recall, then precision, then lower FPR.

## Promotion rule
v21 is promotable only if its comparative-audit recall is strictly greater than the exact v18 reference 600/821 and its observed audit FPR is <=1.0%. Equality in recall is not promotion. Numeric comparison must use the exact ratio, not a rounded decimal.

## Milestones
- Gate B: >=70% recall at <=1% observed FPR.
- Gate C: >=85% recall at <=1% observed FPR.
- Gate D: >=90% recall at <=1% observed FPR.
- Gate E: >=95% recall at <=1% observed FPR.
- 99.9% remains a scientific stretch hypothesis, never a manufactured target.

## Evidence requirements
Persist validation table, exact winner, comparative-audit confusion matrix and metrics, Wilson intervals, split sizes, fingerprints, hard-example counts, chunk statistics, runtime manifest, source files and a strict JSON evidence record. Failed or negative outcomes are preserved exactly.
