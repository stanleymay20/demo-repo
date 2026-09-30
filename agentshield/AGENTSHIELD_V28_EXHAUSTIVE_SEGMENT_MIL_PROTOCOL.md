# AgentShield v28 — Exhaustive Segment MIL + Domain Adaptation Protocol

Status: PREDECLARED BEFORE V27 RESULTS ARE INSPECTED  
Research only. All v18-v27 evidence remains immutable.

## Objective

Primary engineering target:

**Observed attack recall >= 95.999% while observed benign FPR <= 1.00% on the frozen internal comparative audit.**

This is an engineering milestone, not a generalization claim. A production or research claim at this level requires a separately frozen candidate and genuinely unseen, contamination-screened external evaluation.

On the established comparative audit (821 attacks / 835 benign), the point-estimate target requires:
- at least 789 TP (no more than 32 FN);
- no more than 8 FP.

The frozen v18 reference is TP=600, FN=221, FP=7, TN=828, so the target requires recovering at least 189 additional attacks while consuming at most one additional false positive relative to v18.

## Motivation

Prior research lineage has already tested:
- sparse whole-document classifiers;
- contextual probes;
- pairwise residual ranking;
- six-view ELECTRA multi-instance learning;
- long-document and Unicode rescue specialists.

The next hypothesis is that the dominant remaining error is not simply model capacity. It is **localization + domain shift at a low-FPR operating point**.

Current public evidence supports this direction:
- long inputs should be segmented and scanned rather than truncated;
- application-specific fine-tuning materially improves prompt-attack detection;
- low-FPR performance can collapse under domain shift even when generic AUC is strong.

v28 therefore performs exhaustive, channel-aware segment learning instead of assigning one score to one bounded document view.

## Data firewall

Primary dataset:
- `perplexity-ai/browsesafe-bench`

Deterministic BrowseSafe controls remain unchanged:
- seed 42;
- normalized internal duplicate removal;
- normalized train/public-test content-overlap removal;
- expected split sizes 7725 / 1656 / 1656 for development / validation / comparative audit;
- public benchmark/test labels MUST NOT be accessed.

External TRAINING augmentation:
- `hendzh/PromptShield` TRAIN split only.

PromptShield validation/test are not used for model selection in v28 and remain unavailable to the trainer.

Before any external training row is admitted:
- exact normalized hash deduplication against BrowseSafe development, validation and comparative-audit content;
- exact within-corpus duplicate removal;
- near-duplicate screening using character 5-gram MinHash/Jaccard with a conservative exclusion threshold;
- all removed counts and digests recorded.

No AgentDojo, PINT, BIPIA, InjecAgent, WildGuardTest, PromptShield test, or other reserved external evaluation set may be loaded during development.

## Channel-preserving extraction

Every BrowseSafe HTML document is parsed into label-independent channels:

1. visible text;
2. comments + hidden text;
3. attributes;
4. script text;
5. normalized raw HTML.

No attack keyword dictionary is used for span selection.

Each channel is exhaustively segmented using deterministic overlapping windows. Default text window:
- 384 tokenizer tokens;
- stride 192 tokens;
- maximum 64 windows per document per channel;
- head/tail are always retained if the cap is reached;
- remaining windows are uniformly subsampled by position.

The raw-HTML channel additionally receives Unicode NFKC normalization and removal of Cc/Cf controls except tab/newline/carriage return.

Every segment records:
- document id;
- channel;
- start/end offsets;
- normalized hash;
- source split.

## Contextual specialist

Preferred backbone:
- `meta-llama/Llama-Prompt-Guard-2-86M`

The exact Hugging Face revision must be resolved and frozen before training.

If the model is inaccessible because license acceptance or credentials are unavailable, v28 MUST fail closed. No silent model substitution is allowed.

Maximum model input length remains 512 tokens.

## Multi-instance objective

Training is document/bag supervised.

For a positive document:
- at least one segment should score highly;
- the loss uses top-k log-sum-exp pooling over segment attack logits;
- k is fixed at 3;
- pooling temperature tau is fixed at 0.35.

For a benign document:
- the maximum segment attack score is penalized directly so one noisy segment cannot create a false-positive document.

Document-level binary cross-entropy is combined with an OOD-benign energy penalty inspired by Prompt Guard 2's low-FPR objective.

Fixed loss weights:
- document BCE: 1.0
- benign max-segment penalty: 0.5
- OOD benign energy penalty: 0.25

No loss-weight sweep is permitted in v28.

## Development-only hard-example weighting

Use five-fold strict OOF predictions from the established sparse anchor on development only.

Define:
- residual positive = development attack missed at OOF FPR <=0.6%;
- hard benign = top 5% benign OOF attack scores.

Document weights:
- ordinary attack: 1.0
- residual attack: 4.0
- ordinary benign: 1.0
- hard benign: 3.0

PromptShield training rows use weight 1.0.

## Label-preserving adversarial augmentation

Development attacks only may receive deterministic transformations:
- whitespace insertion/removal;
- token fragmentation;
- zero-width character insertion;
- Unicode normalization variants;
- benign navigation-text dilution;
- relocation into comment/attribute/hidden/script wrappers.

Development benign examples may receive benign HTML-noise augmentation.

No LLM-generated paraphrases are used in v28.

## Training

Fixed settings:
- seed 42;
- epochs 3;
- AdamW;
- learning rate 1e-5;
- weight decay 0.01;
- warmup ratio 0.06;
- gradient clip 1.0;
- mixed precision when hardware supports it;
- document batch size chosen only from available memory before validation is scored;
- no validation early stopping.

The exact optimizer state, model state, tokenizer revision and extraction configuration are hashed.

## Sparse anchor and fusion

Reconstruct the controlled sparse anchor from development/validation only.

The contextual specialist is not simply ORed at its default threshold.

Validation considers:
1. sparse anchor only;
2. contextual MIL only;
3. constrained OR;
4. a monotonic two-score logistic stacker trained only from development OOF predictions and then frozen before validation threshold selection.

Total validation FPR budget: <=0.6%.

Selection order:
1. highest recall;
2. highest precision;
3. lower FPR;
4. simpler system on exact tie.

## Promotion gate

Comparative audit remains untouched unless the frozen validation winner:
- improves validation TP by at least 20 over the reconstructed sparse anchor; and
- has observed validation FPR <=0.6%.

If the gate fails, v28 ends as a valid negative result.

## Candidate freeze

Before comparative-audit materialization:
- serialize exact contextual weights/tokenizer/revision;
- serialize sparse models/vectorizers/count-ratios;
- serialize stacker if selected;
- serialize thresholds and channel/window configuration;
- write SHA-256 manifest over every candidate artifact;
- record dataset fingerprints and split-index digests.

No retraining, reconstruction, threshold change, or gate change is allowed after freeze.

## Comparative audit

Only after promotion:
- verify the frozen manifest;
- materialize the comparative-audit rows for the first time in v28;
- score exactly once;
- report TP/FN/FP/TN, recall, precision, F1, FPR;
- report Wilson 95% confidence intervals;
- compare against v18 and the 95.999% engineering target.

No comparative-audit false-negative inspection may be used to redesign v28.

## External validation

Even if internal recall >=95.999%, do not claim generalization.

A later phase must evaluate the exact frozen bundle against contamination-screened, genuinely unseen external sets including multiple attack distributions and hard benigns.

## Evidence requirements

Preserve:
- protocol/source/workflow hashes;
- model id and exact revision;
- training-corpus hashes and dedup/near-dup counts;
- extraction/window configuration;
- strict OOF residual/hard-benign counts;
- training losses;
- validation candidate table;
- frozen winner;
- promotion decision;
- candidate-bundle SHA-256 manifest;
- comparative-audit result only when gated;
- explicit benchmark-label and external-evaluation firewall flags.

Failures and negative results are part of the scientific record.
