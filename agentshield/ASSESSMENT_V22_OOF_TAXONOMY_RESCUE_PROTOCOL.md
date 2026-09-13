# AgentShield Assessment v22 — OOF Taxonomy Rescue Protocol

## Status
Research-only successor experiment. The frozen assessment notebook is untouched. v18 remains the verified champion unless v22 strictly improves audit recall while remaining within the declared operating false-positive ceiling.

## Scientific objective
Test whether development-only false negatives are concentrated in recoverable attack subtypes that are obscured by the current sparse anchor. v22 must not use validation or comparative-audit labels to define the taxonomy, feature transformations, model families, hyperparameter grids, or promotion rule.

## Data and split discipline
- Dataset: `perplexity-ai/browsesafe-bench`.
- Preserve the established duplicate and train/test-overlap cleanup.
- Preserve seed 42 and the established development / validation / comparative-audit split.
- BrowseSafe benchmark/test labels remain untouched.
- Comparative audit is non-pristine and is evaluated only after validation freeze.

## Development-only residual discovery
1. Fit the established sparse representation on development data.
2. Generate 5-fold out-of-fold sparse NB-logistic scores over development rows.
3. Select an OOF operating threshold under observed development FPR <= 0.6%.
4. Define residual positives strictly as development attacks missed by this OOF detector.
5. Summarize those residual positives with a predeclared taxonomy only; no validation or audit examples may alter taxonomy definitions.

## Predeclared taxonomy
The following categories are deterministic lexical/structural indicators, not labels:
- `role_control`: system/developer/assistant role language, prompt/instruction override language.
- `exfiltration`: secrets, credentials, tokens, environment, private/system prompt retrieval.
- `tool_action`: tool/function/browser/shell/API/click/download/send/execute action language.
- `jailbreak_override`: ignore/disregard/forget/bypass/override/previous instructions/jailbreak language.
- `encoding_obfuscation`: base64-like payloads, percent escapes, unicode/hex escapes, zero-width characters, spaced-letter obfuscation.
- `hidden_markup`: comments, hidden elements, attributes, scripts, display/visibility hiding cues.
- `instructional`: imperative/action verbs and second-person directives.
- `long_diluted`: long-document indicator where suspicious cues are sparse relative to page length.

A row may belong to multiple categories. The evidence file must report category counts for all development attacks and for development OOF residual positives.

## Canonicalization specialist
Build a deterministic canonical view from raw HTML/content using only fixed transformations:
- Unicode NFKC normalization;
- HTML entity unescape;
- up to two URL percent-decoding passes;
- removal of zero-width/control separators;
- decoding of textual `\\xNN` and `\\uNNNN` escapes where valid;
- safe decoding of printable ASCII/UTF-8 base64-like spans (bounded length/count);
- punctuation normalization and whitespace collapse;
- append extracted hidden/comment/script/attribute evidence from the established parser.

Train a character TF-IDF residual specialist on this canonical view. Development sample weights emphasize OOF residual positives and high-scoring OOF benign examples. Grid is frozen before validation.

## Taxonomy-feature specialist
Create a small deterministic numeric feature vector from the predeclared taxonomy counts/ratios and page-length/evidence-length statistics. Train regularized logistic regression with development-only residual-positive weighting. Grid is frozen before validation.

## Anchor and selection
Recreate the established v18-style hard-NB and adversarial-NB anchor families. Select each family on validation under the stricter target FPR <= 0.6%. Select the canonical and taxonomy specialists under the same target. Search constrained OR combinations among:
- hard anchor + adversarial anchor;
- anchor pair + canonical specialist;
- anchor pair + taxonomy specialist;
- anchor pair + canonical + taxonomy specialists.

The total observed validation FPR must remain <= 0.6%. Choose the candidate with maximum recall, then precision, then lower FPR. Freeze that exact configuration and thresholds before comparative-audit scoring.

## Promotion rule
Reference champion v18 exact audit counts: TP=600, FN=221, FP=7, TN=828.
- Exact v18 recall = 600 / 821.
- Exact v18 FPR = 7 / 835.
- v22 is promotable only if audit recall is strictly greater than `600/821` by more than numerical tolerance and observed audit FPR <= 1%.
- A tie in recall is not an improvement.
- If the result is worse, flat, or exceeds the FPR ceiling, preserve it exactly as a valid negative result.

## Gates
- B: recall >=70% and FPR <=1%.
- C: recall >=85% and FPR <=1%.
- D: recall >=90% and FPR <=1%.
- E: recall >=95% and FPR <=1%.

## Reproducibility evidence
Record dataset fingerprints, cleanup counts, split sizes, seed, OOF threshold and confusion counts, taxonomy counts, residual-positive count, specialist hyperparameters, validation winner, frozen audit specification, Wilson 95% intervals, runtime versions, and exact promotion decision.
