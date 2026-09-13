# AgentShield Assessment v25 — Multi-Instance Residual Fusion Protocol

Status: FROZEN BEFORE RESULTS
Research only. This experiment does not modify v18, v23, or v24 evidence.

## Objective

Push AgentShield toward a future frozen-model target of >=99% recall at <=1% FPR on genuinely unseen, contamination-screened external datasets without using any external evaluation labels, examples, thresholds, or failure cases during v25 development.

v25 is an internal development experiment only. It may become an external-validation candidate only if it is frozen first and passes the predeclared internal promotion controls below.

## Scientific question

Can a trainable document-level multi-instance contextual specialist recover attacks missed by the v18 sparse anchor while preserving a low false-positive operating point, when the specialist is trained on all development examples but gives extra weight to development-only OOF residual positives and hard benigns?

This changes the learning formulation rather than merely changing the encoder:
- v23 used one bounded 256-token context and trained only on residual positives vs benigns;
- v24 used a frozen BGE encoder plus a linear pairwise ranker;
- earlier pretrained chunk detectors were not fine-tuned on the controlled development distribution and performed poorly at <=1% FPR.

v25 instead performs bag-level learning across six deterministic views of every document and trains the contextual encoder end-to-end with a document-level objective.

## Reference champion

Exact reference remains frozen v18:
- commit `92b5e23d143397d8732673ee2e5715b5c81e82c1`
- comparative audit TP=600, FN=221, FP=7, TN=828
- recall `0.730816077953715`
- FPR `0.008383233532934131`

v24 tied v18 exactly and is not promoted.

Comparative-audit promotion requires BOTH:
1. TP >= 601; and
2. FP <= 8.

Equality with v18 does not promote.

## Data controls

Dataset: `perplexity-ai/browsesafe-bench`.

Use the exact established cleanup and split logic:
- seed 42;
- remove exact normalized internal duplicates;
- remove train rows overlapping benchmark/test content by normalized hash;
- expected development / validation / comparative-audit sizes: 7725 / 1656 / 1656;
- benchmark/test labels MUST NOT be accessed;
- benchmark/test content may be used only for overlap hashing;
- comparative audit is non-pristine and comparative only.

Expected dataset fingerprints:
- train_raw `596f8fb7871901b9`
- test_content_source `9a9a7f691f87832e`

Any mismatch is fail-closed.

## Development-only residual weighting

Use the established 5-fold OOF NB-log-count-ratio logistic model on development only.

Define:
- residual positives: development positives missed at the OOF threshold selected under observed OOF FPR <= 0.006;
- hard benigns: top 5% of development benign OOF attack scores.

Unlike v23, v25 trains on ALL development positives and ALL development benigns.

Fixed document weights:
- ordinary positive: 1.0
- residual positive: 4.0
- ordinary benign: 1.0
- hard benign: 2.0

No validation or audit sample may affect these weights.

## Multi-instance document representation

For each document, construct exactly six deterministic views using only the existing parser and text content:
1. established v16 `sample_context` view;
2. visible-text head window;
3. visible-text middle window;
4. visible-text tail window;
5. hidden/comment/attribute evidence view;
6. script-cue view.

Visible windows are word-position based and label-independent. No attack keyword list, taxonomy, audit-derived phrase, or external benchmark content may be used to choose spans.

Each view is independently tokenized to max length 256.

## Contextual specialist

Fixed encoder:
- model id: `google/electra-small-discriminator`
- exact revision: `fa8239aadc095e9164941d05878b98afe9b953c3`
- binary document classifier trained end-to-end.

For a batch of documents, flatten the six instances through the encoder, obtain one attack logit per instance, then aggregate to a document score with normalized log-mean-exp pooling:

`bag_logit = tau * (logsumexp(instance_logits / tau) - log(6))`

Fixed `tau = 0.5`.

This allows a localized suspicious view to raise the bag score while retaining a smooth document-level training objective.

### Fixed training hyperparameters

- max sequence length: 256
- six views per document
- epochs: 3
- AdamW learning rate: 2e-5
- weight decay: 0.01
- document batch size: 8
- gradient accumulation: 2
- warmup ratio: 0.06
- gradient clipping: 1.0
- pooling temperature tau: 0.5
- seed: 42
- no architecture, learning-rate, epoch, pooling, or weighting sweep
- no validation-based early stopping

The exact trained state_dict and tokenizer metadata must be checkpointed and hashed.

## Sparse anchor

Reproduce the established hard/adversarial sparse families using development and validation only. Select the hard-family and adversarial-family winners exactly as in the controlled v18/v24 lineage.

The sparse anchor is their constrained OR under observed validation FPR <= 0.006.

## Validation selection

After the multi-instance specialist is completely trained and frozen, score validation once.

Eligible systems:
1. sparse anchor;
2. multi-instance specialist alone;
3. constrained OR of sparse hard + sparse adversarial + multi-instance specialist.

Thresholds and OR configuration are selected on validation only under observed validation FPR <= 0.006.

Selection order:
1. highest recall;
2. highest precision;
3. lower FPR;
4. simpler system if exact tie.

### Pre-audit gate

The comparative audit MUST NOT be scored unless the selected v25 system strictly exceeds the sparse anchor's validation TP count while satisfying validation FPR <= 0.006.

If the specialist adds zero validation true positives, or the selected system does not strictly improve validation recall, v25 ends as a valid negative without touching the comparative audit.

## Frozen candidate bundle

Before any comparative-audit representation or scoring:
- serialize the exact selected sparse vectorizers/models/count ratios;
- serialize the exact selected thresholds and system definition;
- save the ELECTRA tokenizer metadata and exact trained state_dict if the specialist is selected;
- save deterministic view-construction version metadata;
- create a SHA-256 manifest over the complete candidate bundle.

The resulting bundle is the only model object eligible for comparative audit and, if promoted, later external validation. No retraining or reconstruction is permitted after bundle freeze.

## Comparative audit

Only if the pre-audit gate passes:
- load the frozen candidate bundle in a separate stage;
- verify every SHA-256 entry;
- build comparative-audit views;
- score once;
- report TP/FN/FP/TN, precision, recall, F1, observed FPR, and 95% Wilson intervals;
- compare against exact v18 counts.

Do not inspect individual audit false negatives for redesign inside v25.

## External-validation firewall

During v25 development, training, validation selection, and comparative audit:
- do not load, score, inspect, or tune against Comparison_Dataset, deepset/prompt-injections, InjecAgent, BIPIA, WildGuardTest, or any other reserved external-validation set;
- do not use external labels or external failure cases;
- do not modify thresholds after candidate-bundle freeze.

If v25 is promoted, external evaluation must use the exact frozen bundle hash produced before any external dataset is scored.

The eventual external target is >=99% recall at <=1% FPR, but v25 must report whatever result occurs and may not claim that target unless independently observed on genuinely unseen contamination-screened data.

## Staged execution

1. `prepare-development`: verify dataset fingerprints/splits, build development/validation parsed views, OOF residual masks, sparse representations and anchor candidates; checkpoint deterministic state.
2. `train-multi-instance`: verify stage 1, train the fixed six-view ELECTRA specialist and save exact model/tokenizer state plus validation specialist scores.
3. `freeze-candidate`: verify stages 1/2, select validation winner, enforce pre-audit gate, serialize and SHA-freeze the exact candidate bundle without accessing comparative audit.
4. `audit-frozen-candidate`: only when pre-audit gate passes, verify the frozen bundle and score the comparative audit once.

Every stage artifact must include a SHA-256 manifest and fail closed on mismatch.

## Evidence requirements

Final evidence must include:
- this frozen protocol and protocol SHA-256;
- source/workflow SHA-256;
- exact dataset fingerprints and cleanup counts;
- split sizes and index digests;
- OOF residual and hard-benign counts;
- six-view construction metadata;
- exact ELECTRA model id/revision;
- training losses and runtime;
- validation candidate table and frozen winner;
- pre-audit gate decision;
- frozen candidate-bundle SHA-256 manifest;
- comparative-audit result only if gate passed;
- explicit `benchmark_labels_accessed: false`;
- explicit `external_validation_datasets_accessed: false`;
- explicit `audit_is_pristine: false`;
- exact promotion decision against v18.

Failures, interrupted runs, ties, and negative results remain part of the scientific record.
