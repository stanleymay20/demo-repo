# AgentShield v26 — Development-Only Residual Forensics Protocol

Status: PREDECLARED BEFORE RESULTS  
Research only. The submitted M508 artifact and all frozen v18-v25 evidence remain immutable.

## Program objective

Long-run stretch objective:

**>=99.99% attack recall while maintaining <=1.00% observed benign FPR on genuinely unseen, contamination-screened external evaluation data.**

This is a research target, not a current claim. It must never be manufactured by audit-driven retuning, threshold relaxation after seeing test labels, selective reporting, or repeated evaluation against a nominally "held-out" set.

With zero observed misses, roughly 29,956 independent attack examples are required before the one-sided 95% lower confidence bound itself reaches approximately 99.99%. Smaller internal splits can guide engineering but cannot substantiate 99.99% generalization.

## Immediate v26 objective

Build a failure map of **development-only out-of-fold false negatives** from the controlled BrowseSafe training split.

v26 does NOT:
- materialize, inspect, or score comparative-audit examples;
- use comparative-audit labels for redesign;
- access BrowseSafe public benchmark/test labels;
- access reserved external-validation examples, labels, scores, or failures.

The full cleaned-training label vector is used only to reproduce the already-established stratified development / validation / comparative-audit index split with seed 42. Only development rows are then materialized for forensic analysis.

The purpose is to learn what kinds of attacks the current sparse family misses without contaminating validation, comparative audit, or future external validation.

## Frozen lineage

Reference scientific baseline remains v18:
- commit `92b5e23d143397d8732673ee2e5715b5c81e82c1`;
- comparative audit: TP=600, FN=221, FP=7, TN=828;
- recall 73.08%;
- FPR 0.838%.

The submitted professor-facing execution reconstructed 599 TP rather than 600. That one-example drift remains disclosed and is not altered by v26.

v25 remains a separate frozen research experiment. v26 is branched from v25 only to preserve code lineage; no v25 evidence is rewritten.

## Data controls

Dataset: `perplexity-ai/browsesafe-bench`.

Use the established deterministic cleanup and split logic:
- seed 42;
- remove normalized duplicate training rows;
- remove training rows overlapping public benchmark/test **content** by normalized hash;
- expected development / validation / comparative-audit sizes: 7,725 / 1,656 / 1,656;
- expected dataset fingerprints:
  - train_raw: `596f8fb7871901b9`
  - public test content source: `9a9a7f691f87832e`.

Public benchmark/test labels MUST NOT be accessed.

Validation and comparative-audit rows MUST NOT be materialized in v26.

## OOF residual definition

Use the established sparse representation:
- word TF-IDF;
- character TF-IDF;
- hidden/attribute-evidence character TF-IDF;
- NB log-count-ratio scaling;
- logistic regression, C=1;
- five stratified folds, seed 42.

For strict leakage control, each OOF fold independently fits:
- every TF-IDF vocabulary and IDF;
- the NB log-count ratio;
- the logistic-regression classifier.

Generate exactly one out-of-fold score for every development row.

Choose a single development OOF threshold that maximizes development OOF recall subject to observed development OOF FPR <=0.6%.

A **development residual positive** is:
- development label = injection; and
- OOF prediction = benign at the fixed development-only OOF threshold.

This threshold is diagnostic only. It is not a candidate production threshold and is never applied to comparative audit or external evaluation in v26.

## Structural forensic features

For every development row compute label-independent structural features from raw HTML and the existing parser:

- raw character length;
- visible word count;
- hidden/evidence word count;
- script word count;
- HTML tag count;
- markup-to-visible ratio;
- non-ASCII character ratio;
- Unicode control/format character count;
- punctuation ratio;
- digit ratio;
- maximum repeated-character run;
- URL-like token count;
- whether hidden evidence is present;
- whether script evidence is present.

No attack phrase dictionary, audit-derived keyword list, or external-failure taxonomy may be used.

## Residual slices

Report residual rates for deterministic structural slices:

- visible length: 0-29, 30-99, 100-299, 300-999, >=1000 words;
- raw HTML size: <2 KB, 2-10 KB, 10-50 KB, >=50 KB;
- hidden evidence: absent / present;
- script evidence: absent / present;
- non-ASCII ratio: 0, (0,1%], (1%,5%], >5%;
- markup-to-visible ratio quartiles computed on development only.

For each slice report:
- positive count;
- OOF residual count;
- residual rate;
- median OOF score;
- median raw size;
- median visible words.

## Residual exemplars

To support engineering without reproducing raw public-dataset payloads in artifacts, emit only:
- development-local row index;
- normalized SHA-256 prefix;
- OOF score;
- structural metrics;
- parser-view lengths and slice labels.

Do not emit full raw HTML or full document text into the evidence artifact.

## Evidence

Produce:
- `agentshield/results/v26_residual_rows.csv`
- `agentshield/results/v26_slice_summary.csv`
- `agentshield/results/v26_evidence.json`
- `agentshield/results/v26_runtime.txt`
- `agentshield/results/v26_run.log`

The evidence JSON must explicitly state:
- comparative-audit examples materialized = false;
- comparative-audit scored = false;
- comparative-audit examples inspected = false;
- comparative-audit labels used for redesign = false;
- full cleaned-training labels used only to reproduce the established stratified split = true;
- benchmark labels accessed = false;
- external validation datasets accessed = false;
- submitted assessment modified = false;
- raw residual payloads emitted = false;
- exact dataset fingerprints;
- split-index digests;
- strict fold-local OOF threshold and confusion counts;
- residual count;
- protocol/source SHA-256.

## Interpretation rules

v26 is diagnostic. It cannot be promoted as a model.

A large residual concentration in one or more structural slices may justify a subsequent v27 specialist, but v27 must be specified before validation scoring and must not use comparative-audit or reserved external examples during development.

The 99.99% objective remains a research target until a frozen candidate is evaluated once on genuinely unseen, contamination-screened data of adequate size.
