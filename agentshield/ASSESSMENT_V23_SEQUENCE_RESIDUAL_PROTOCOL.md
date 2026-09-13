# AgentShield Assessment v23 — Residual Sequence Specialist Protocol

Status: FROZEN BEFORE RESULTS
Research only. This experiment does not modify the frozen assessment notebook.

## Scientific question

Can a genuinely fine-tuned sequence encoder recover prompt-injection attacks that the verified v18 sparse anchor systematically misses, while preserving the observed false-positive operating constraint?

v22 showed that handcrafted canonicalization and taxonomy features added no validation true positives beyond the v18-style anchor. v23 therefore tests a different source of signal: end-to-end sequence learning on development-only residual attacks.

## Reference champion

Exact scientific reference:
- Version: v18
- Commit: `92b5e23d143397d8732673ee2e5715b5c81e82c1`
- Comparative audit confusion matrix: TP=600, FN=221, FP=7, TN=828
- Recall: `600 / 821 = 0.730816077953715`
- FPR: `7 / 835 = 0.008383233532934131`

Promotion requires BOTH:
1. comparative-audit recall strictly greater than exact v18 recall; and
2. comparative-audit observed FPR <= 0.01.

Equality does not promote. On the current comparative audit split, this means at minimum 601 TP and at most 8 FP.

## Data controls

Dataset: `perplexity-ai/browsesafe-bench`.

Use the exact v18 cleanup and split logic:
- seed 42;
- remove exact normalized duplicates inside train;
- remove train rows whose normalized content hash overlaps benchmark/test content;
- development / validation / comparative-audit split produced by the existing v18 stratified split logic;
- benchmark/test labels MUST NOT be accessed;
- benchmark/test content may be used only for overlap hashing;
- comparative audit is non-pristine and comparative only because it has been observed in earlier experiments.

Expected split sizes under the known dataset state are 7725 development, 1656 validation, 1656 comparative audit. Any mismatch is fail-closed.

## Development-only residual discovery

Use the existing v18 sparse representation and 5-fold OOF NB-log-count-ratio logistic scoring on development only.

Define the OOF residual threshold with the same conservative target used by v18:
- observed development OOF FPR target <= 0.006.

Residual positives are development attacks whose OOF score falls below that OOF threshold.

Hard benign examples are development benign rows in the top 5% of OOF attack scores.

No validation or audit example may influence residual membership, training weights, text construction, optimizer settings, epoch count, or model choice.

## Sequence specialist

Fixed base model:
- model id: `google/electra-small-discriminator`
- exact Hugging Face revision: `fa8239aadc095e9164941d05878b98afe9b953c3`
- architecture: ELECTRA-small discriminator encoder adapted to binary sequence classification.

Rationale: this is a compact discriminative encoder and represents a materially different learned representation from the sparse, frozen-embedding, chunk, canonicalization and taxonomy approaches already tested.

### Training population

The rescue specialist is trained only on:
- all development residual positives; and
- all development benign examples.

Development positives already recovered by the OOF anchor are excluded from specialist training. They remain attacks in validation/audit evaluation and are never relabeled.

This creates an explicitly residual task rather than another full-dataset generic classifier.

### Example weights

- Residual-positive base weight = `n_benign / n_residual_positive`, computed from development only, so positive and benign total class mass are approximately balanced.
- Hard-benign rows receive an additional x2 multiplier.
- No other dynamic weighting or tuning is permitted.

### Input representation

Reuse the deterministic v16 `sample_context` representation:
- visible-text head/middle/tail sample;
- bounded hidden/attribute evidence;
- bounded script cues.

No audit-derived prompt templates, keywords, categories, or hand edits are allowed.

### Fixed fine-tuning hyperparameters

- max sequence length: 256
- epochs: 2
- optimizer: AdamW
- learning rate: 3e-5
- weight decay: 0.01
- batch size: 16
- gradient accumulation: 1
- warmup ratio: 0.06
- gradient clipping: 1.0
- seed: 42
- CPU-compatible deterministic execution; runtime/device recorded in evidence.

There is no learning-rate grid, epoch grid, architecture sweep, or validation-based early stopping.

## Validation selection

After training is complete, score validation once with the frozen sequence specialist.

Independently reproduce the v18 sparse hard and adversarial families on development, then select their family winners using validation exactly as in the prior controlled protocol.

Candidate operating systems are:
1. v18-style hard/adversarial constrained OR anchor;
2. ELECTRA residual specialist alone;
3. constrained three-way OR of hard + adversarial + ELECTRA.

For every candidate, threshold selection is validation-only.

Constrained OR search must obey observed validation FPR <= 0.006. Selection order:
1. highest recall;
2. highest precision;
3. lower FPR.

The validation winner and every threshold must be frozen before any comparative-audit representation or score is produced.

## Comparative audit

Only after validation freeze:
- build comparative-audit representations;
- score the exact frozen selected system once;
- report precision, recall, F1, observed FPR, confusion matrix, ROC-AUC where defined, and 95% Wilson intervals for recall and FPR;
- compare to exact v18 counts, not rounded percentages.

Do not inspect individual comparative-audit false negatives for model redesign inside v23.

## Infrastructure design

Because prior v22 monolithic jobs were repeatedly terminated by the hosted runner, v23 is intentionally split into three deterministic jobs without changing scientific logic:

1. `residual-discovery`: reproduce splits, build sparse development/validation representations, generate OOF residual masks, and checkpoint all deterministic state needed downstream.
2. `train-sequence`: verify the checkpoint, fine-tune the fixed ELECTRA residual specialist, score validation, and checkpoint the exact model/tokenizer plus validation specialist scores.
3. `select-and-audit`: verify both checkpoint hashes and dataset fingerprints, reproduce the v18 anchor families from the checkpoint, freeze validation selection, then evaluate comparative audit once and emit final evidence.

Every transport artifact must carry a SHA-256 manifest and be verified before use. Split indices, development/validation labels, cleanup counts, dataset fingerprints and model revision must match fail-closed expectations.

## Evidence requirements

Final artifact must contain:
- this frozen protocol;
- all v23 scripts;
- runtime manifests for every stage;
- checkpoint SHA-256 manifests;
- training log and epoch losses;
- residual counts and OOF metrics;
- validation candidate table;
- frozen validation winner;
- comparative-audit metrics and Wilson intervals;
- exact promotion decision against v18;
- explicit `benchmark_labels_accessed: false`;
- explicit `audit_is_pristine: false`;
- exact base-model id and revision;
- dependency/runtime versions.

A failed or interrupted run is preserved as failed. Infrastructure repairs may change execution packaging only; they may not change the scientific protocol under the same version number.
