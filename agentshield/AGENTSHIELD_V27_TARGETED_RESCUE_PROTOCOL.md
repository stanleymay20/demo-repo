# AgentShield v27 — Targeted Long-Context + Unicode Rescue Protocol

Status: PREDECLARED BEFORE RESULTS  
Research only. The submitted M508 artifact and frozen v18-v26 evidence remain immutable.

## Program objective

Long-run stretch objective:

**>=99.99% attack recall while maintaining <=1.00% observed benign FPR on genuinely unseen, contamination-screened external evaluation data.**

This remains a research target, not a present performance claim.

## Why v27 exists

The v26 development-only strict OOF forensic run completed green on commit
`03f2e28199611d9c0b75edbbe93ec575039f30a4`.

v26 identified 1,062 development OOF false negatives at observed OOF FPR 0.565%.
The strongest sufficiently populated residual concentrations were:

- non-ASCII ratio >5%: 100 / 259 residuals = 38.61%;
- raw HTML >=50 KB: 569 / 1,735 residuals = 32.80%;
- visible text 30-99 words: 78 / 245 residuals = 31.84%;
- visible text >=1,000 words: 520 / 1,660 residuals = 31.33%.

The script-present slice showed 5 / 9 residuals but is too small to justify a dedicated v27 architecture.

v27 therefore targets two mechanisms only:

1. **long-document / dilution rescue**;
2. **Unicode / obfuscation rescue**.

No comparative-audit example, validation failure case, external example, or benchmark/test label is used to choose these mechanisms.

## Frozen lineage

Historical reference remains the v18 FPR-stable sparse fusion:
- controlled commit `92b5e23d143397d8732673ee2e5715b5c81e82c1`;
- comparative audit TP=600, FN=221, FP=7, TN=828;
- recall 73.08%;
- observed FPR 0.838%.

The submitted professor-facing reconstruction produced 599 TP rather than 600. That one-example drift remains disclosed and is not rewritten.

v26 evidence artifact:
- run 35382014841;
- artifact ID 10564995832;
- artifact ZIP SHA-256 `4626b3ac8ee5f1c4041f4beec9bb93582d4551e7f6e738a3720bbbb744898d26`.

## Data controls

Dataset: `perplexity-ai/browsesafe-bench`.

Use the established deterministic controls:
- seed 42;
- remove normalized internal duplicate rows;
- remove training rows overlapping public benchmark/test content by normalized hash;
- expected split sizes: development 7,725 / validation 1,656 / comparative audit 1,656;
- expected dataset fingerprints:
  - train_raw `596f8fb7871901b9`;
  - public test content source `9a9a7f691f87832e`.

Public benchmark/test labels MUST NOT be accessed.

During v27 development:
- comparative-audit rows are not materialized;
- reserved external-validation datasets are not accessed;
- only development and validation are materialized.

## Development-only residual discovery

Reproduce the v26 strict five-fold OOF diagnostic model on development only.

Each fold independently fits:
- word TF-IDF;
- character TF-IDF;
- hidden/attribute-evidence character TF-IDF;
- NB log-count ratio;
- logistic regression, C=1.

Define the development OOF threshold as the threshold maximizing OOF recall subject to observed OOF FPR <=0.6%.

Define:
- **residual positive** = development injection missed at that OOF threshold;
- **hard benign** = top 5% of development benign OOF attack scores.

These masks may influence development training weights only.

## Sparse anchor

v27 reconstructs the established v18-style sparse anchor from development and validation only.

### Hard family

Representation:
- word TF-IDF;
- character TF-IDF;
- hidden/attribute-evidence character TF-IDF;
- NB log-count-ratio scaling.

Candidate grid:
- C in {0.5, 1.0, 2.0};
- hard-positive multiplier in {1, 2, 4};
- hard-benign multiplier in {4, 6, 8}.

Hardness comes only from development OOF scores.

For the hard family:
- **hard positive** means the residual-positive mask defined above;
- **hard benign** means the top-5% benign OOF-score mask defined above;
- every row starts with weight 1.0;
- residual-positive rows are multiplied by the candidate hard-positive multiplier;
- hard-benign rows are multiplied by the candidate hard-benign multiplier.

### Adversarial family

Development-only label-preserving augmentation of hard positive examples:
- deterministic alphabetic-token fragmentation;
- benign-navigation-text dilution.

Candidate C in {0.5, 1.0, 2.0, 4.0}.

Fixed adversarial weights:
- original ordinary development row: 1.0;
- original residual-positive row: 2.0;
- original hard-benign row: 4.0;
- every synthetic adversarial row: 1.5.

The best hard-family and adversarial-family members are selected on validation under observed validation FPR <=0.6%.

The **anchor** is the constrained OR of those two family winners under the same total validation FPR budget.

## Long-context rescue specialist

The long specialist is designed specifically for dilution/position effects.

### Gate

The specialist is eligible to fire only when at least one condition is true:

- raw HTML size >=50 KB; OR
- visible text length >=1,000 words.

The gate is fixed from v26 before validation scoring.

### Views

For every eligible document create five deterministic visible-text windows:

1. head;
2. 25%-position;
3. middle;
4. 75%-position;
5. tail.

Each window contains at most 320 visible words.

Window positions depend only on document length, never on labels, keywords, scores, or audit behavior.

### Model

Train one shared window classifier on development windows:

- word TF-IDF;
- ngram_range=(1,2);
- max_features=60,000;
- sublinear TF;
- logistic regression C=1;
- liblinear solver;
- seed 42.

Every window inherits its document label.

Document score = maximum attack probability across the five windows.

Development sample weights:
- ordinary row: 1.0;
- residual-positive document: 4.0;
- hard-benign document: 2.0.

All windows from a document inherit that document weight.

Outside the fixed long-document gate, the specialist score is treated as negative infinity and cannot fire.

## Unicode / obfuscation rescue specialist

### Gate

The specialist is eligible to fire only when:

- non-ASCII character ratio >1%.

The >1% threshold is fixed before validation because v26 showed elevated residual rates in both the 1%-5% and >5% bins.

### Representation

Construct a deterministic normalized raw-HTML view:

1. Unicode NFKC normalization;
2. remove Unicode Cc/Cf control/format characters except tab/newline/carriage return;
3. lowercase;
4. collapse whitespace;
5. append a label-independent Unicode-category skeleton for non-ASCII characters.

No transliteration dictionary, attack keyword dictionary, or external taxonomy is used.

### Model

- character TF-IDF;
- analyzer=char;
- ngram_range=(2,6);
- max_features=100,000;
- sublinear TF;
- logistic regression C=1;
- liblinear solver;
- seed 42.

Development weights:
- ordinary row: 1.0;
- residual-positive document: 4.0;
- hard-benign document: 2.0.

Outside the fixed Unicode gate, the specialist score is treated as negative infinity and cannot fire.

## Validation-only candidate selection

After all models are fully trained from development only, score validation exactly once for selection.

Eligible systems:

1. sparse anchor;
2. anchor OR long specialist;
3. anchor OR Unicode specialist;
4. anchor OR long specialist OR Unicode specialist.

For every eligible system, search only thresholds that keep **total observed validation FPR <=0.6%**.

Selection is lexicographic:

1. highest validation recall;
2. highest validation precision;
3. lower observed validation FPR;
4. fewer specialist members if exact tie.

No validation example is used to change:
- gates;
- window positions;
- feature representations;
- vocabulary limits;
- weighting rules;
- model C;
- augmentation scheme.

## Promotion gate before comparative audit

The comparative audit must remain untouched unless the frozen v27 validation winner satisfies BOTH:

1. validation TP count >= sparse-anchor validation TP count + 5; and
2. observed validation FPR <=0.6%.

If this gate fails, v27 ends as a valid negative result and the comparative audit is not materialized.

## Candidate freeze

Before any comparative-audit row is materialized:

- serialize exact sparse vectorizers/models/count ratios;
- serialize exact long-specialist vectorizer/model;
- serialize exact Unicode-specialist vectorizer/model;
- serialize thresholds, gates, selection metadata and model membership;
- save development/validation index digests;
- create a SHA-256 manifest over the complete candidate bundle.

The bundle hash is the model identity for any later scoring.

No retraining, reconstruction, threshold change, or gate change is permitted after freeze.

## Comparative audit

Only if the promotion gate passes:

- load the exact frozen candidate bundle in a separate workflow job;
- verify all manifest hashes;
- reproduce the established comparative-audit split;
- materialize comparative-audit rows only at this stage;
- score once;
- report TP/FN/FP/TN, precision, recall, F1, FPR and Wilson 95% intervals;
- compare with the historical v18 counts.

The audit is explicitly **comparative internal evidence**, not pristine external validation.

No audit false-negative inspection is permitted for redesign inside v27.

## External-validation firewall

v27 must not load, inspect, score, or tune against any reserved external-validation dataset, including any future mixture intended to support the 99.99% claim.

A later external-validation phase must use an already-frozen candidate and contamination screening.

## Evidence requirements

Stage-one/freeze evidence must include:

- protocol/source/workflow SHA-256;
- exact dataset fingerprints;
- cleanup counts;
- split sizes and digests;
- strict OOF metrics and residual/hard-benign counts;
- validation metrics for anchor and every eligible fused system;
- exact frozen winner;
- promotion-gate decision;
- candidate-bundle manifest SHA-256;
- explicit contamination-firewall booleans.

If audit is permitted, final evidence must additionally include:

- exact verified candidate-bundle manifest SHA-256;
- comparative-audit confusion counts and metrics;
- Wilson intervals;
- delta versus historical v18;
- explicit `audit_is_pristine: false`;
- explicit `external_validation_datasets_accessed: false`.

Failures, ties, and negative results remain part of the scientific record.

## Interpretation

v27 is successful only if it produces a frozen, validation-improved candidate without violating the low-FPR objective.

Even a 100% result on the 821-positive comparative audit would not support a 99.99% generalization claim. The long-run target requires genuinely unseen contamination-screened external evidence at much larger scale.
