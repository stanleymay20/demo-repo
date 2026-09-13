# AgentShield Assessment v24 — Pairwise Residual Ranking Protocol

## Status
Research-only successor experiment. The frozen M508 assessment notebook remains untouched. The exact v18 scientific champion commit `92b5e23d143397d8732673ee2e5715b5c81e82c1` remains the reference champion unless v24 strictly promotes under the rule below.

## Scientific question
Can the remaining development false negatives be recovered more effectively by learning a *relative ranking* between residual attacks and hard benign examples, rather than fitting another absolute classifier boundary?

v23 showed that direct residual-only ELECTRA classification produced essentially no useful discrimination. v24 therefore changes the learning formulation, not merely the backbone.

## Dataset and split discipline
- Dataset: `perplexity-ai/browsesafe-bench`.
- Use the established duplicate-removal and train/test-content-overlap cleanup from the controlled research lineage.
- Seed: 42.
- Preserve the established deterministic split: development 7,725; validation 1,656; comparative audit 1,656.
- BrowseSafe test/benchmark labels must never be accessed.
- Validation labels may be used only for threshold/system selection after the pairwise ranker is frozen.
- Comparative audit is non-pristine and may be evaluated exactly once after validation freeze.

## Reference champion and operating point
v18 exact comparative-audit reference:
- TP 600, FN 221, FP 7, TN 828.
- Recall = `600 / 821 = 0.730816077953715`.
- FPR = `7 / 835 = 0.008383233532934131`.

Validation target FPR: <= 0.006.
Promotion operating FPR ceiling: <= 0.01.

Promotion requires both:
1. exact audit recall strictly greater than v18 by more than 1e-12; and
2. audit FPR <= 0.01.

On the current audit this means at least 601 TP and no more than 8 FP. A tie does not promote.

## Anchor and residual discovery
Recreate the established v18-style sparse representation and five-fold OOF NB-logistic development scoring using the controlled helpers.

Development residual positives are attack rows whose OOF score falls below the development OOF threshold selected under observed FPR <= 0.006.

Hard benigns are development benign rows in the top 5% of OOF scores. No validation or audit examples may alter residual membership, hard-benign membership, representation choice, pair construction, model choice, or training hyperparameters.

## Pairwise representation
Model ID is fixed to `BAAI/bge-small-en-v1.5`.

The exact Hugging Face model revision is resolved once in stage 1 *before pair construction or validation use*, written into the stage-1 checkpoint, and every later stage must load that exact SHA. No alternate backbone is permitted in v24.

The encoder remains frozen. It is used only to produce normalized mean-pooled sequence embeddings from the established AgentShield `context` view, which preserves visible text plus hidden/script cues. Maximum token length is fixed at 384.

## Deterministic hard-pair construction
For every development residual positive:
1. compute cosine similarity against all development hard benign embeddings;
2. select the four most similar hard benign examples;
3. create four ordered `(attack, benign)` pairs.

Ties are resolved by stable index order. No validation or audit embedding participates in pair construction.

## Ranking head
Train a single linear scoring vector `s(x) = w^T e(x)` over frozen normalized embeddings.

Loss for each pair `(p, n)`:
`softplus(-(s(p) - s(n)))`

Fixed training settings:
- optimizer: AdamW;
- epochs: 80;
- learning rate: 0.03;
- weight decay: 0.01;
- batch size: 256 pairs;
- gradient clip: 1.0;
- seed: 42.

There is no architecture sweep, learning-rate sweep, epoch sweep, pair-count sweep, or backbone sweep in v24.

## Validation selection
After the ranking head is frozen, reconstruct the established v18-style hard-NB and adversarial-NB anchor families on development and validation.

Evaluate exactly three eligible systems on validation:
1. sparse anchor OR only;
2. pairwise ranker only;
3. constrained sparse-anchor OR pairwise-ranker union.

Thresholds are selected under observed validation FPR <= 0.006. Winner selection is recall first, then precision, then lower FPR. Exact selected thresholds and members are frozen before any comparative-audit scoring.

## Comparative audit
After validation freeze, score the comparative audit exactly once with the frozen winner. Compute exact confusion matrix, precision, recall, F1, FPR, Wilson 95% intervals, and promotion decision versus exact v18.

The comparative audit remains non-pristine and cannot support an external generalization claim.

## Evidence and fail-closed controls
The run must be split into three jobs to avoid the runner-lifetime failure observed in v22:
1. residual discovery + exact model-revision resolution + frozen development embeddings;
2. deterministic pair construction + ranker training;
3. validation freeze + one comparative-audit evaluation.

Each transport checkpoint must include SHA-256 manifests. Later stages must fail closed on any mismatch in protocol SHA, dataset fingerprints, cleanup counts, split indices, labels, model identity/revision, embeddings, or checkpoint hashes.

Final evidence must include:
- protocol and source hashes;
- dataset fingerprints and cleanup counts;
- exact split sizes;
- OOF residual threshold/metrics and residual/hard-benign counts;
- resolved BGE revision;
- embedding dimension and hashes;
- deterministic pair count and pair-index hash;
- epoch losses and pairwise training accuracy/margin summary;
- validation rows and frozen winner;
- exact audit confusion matrix and Wilson intervals;
- exact v18 promotion comparison;
- runtime/package versions;
- explicit flags that benchmark labels were not accessed and the audit is comparative/non-pristine.

## Interpretation guardrail
A negative, tied, or invalid result must be preserved exactly. No post-hoc threshold tuning on audit, no model substitution, and no promotion from rounded metrics are permitted.
