# AgentShield Assessment v19 — OOF Multi-View Stack Protocol

## Status
Research-only controlled successor to v18. The assessment notebook, v16, v17 and v18 remain frozen. BrowseSafe benchmark/test labels are not used for training, threshold selection, model selection, or comparative-audit tuning.

## Motivation
v18 became the verified champion at 73.08% comparative-audit recall with 0.838% observed FPR, but its winning hard-NB and adversarial-NB experts are highly correlated. Simple logit fusion did not create a new recall frontier. A larger gain therefore requires genuinely different representations rather than another small threshold search.

## Hypothesis
Prompt-injection evidence is distributed across different page views: visible text, hidden attributes/comments, script content, and compressed contextual summaries. Independent experts trained on these views may make complementary errors. A meta-detector trained only on out-of-fold expert predictions can learn when to trust each view without in-sample stacking leakage.

## Fixed data doctrine
- Dataset: `perplexity-ai/browsesafe-bench`.
- Remove the same one internal duplicate and one train/test overlap as earlier controlled experiments.
- Reuse deterministic seed 42 and the established development/validation/comparative-audit split.
- Benchmark/test labels remain untouched.
- The internal validation and comparative audit are no longer pristine; validation is developmental and audit is comparative only.

## Architecture
Five sparse experts:
1. combined multi-view NB-logistic,
2. combined multi-view plain logistic regression,
3. visible-text word/character logistic regression,
4. hidden-evidence + script NB-logistic,
5. contextual-summary word/character logistic regression.

Five-fold stratified OOF predictions from all five experts form the meta-training matrix. No meta-training row uses an expert prediction from a model fitted on that row.

Candidate meta-detectors:
- standardized logistic stacking at C = 0.1, 1, 10,
- histogram gradient boosting with 5, 9, or 15 leaves,
- simple mean/max/top-two-mean fusion baselines.

## Operating constraint
Validation selection targets observed FPR <= 0.6%, preserving headroom under the programme's production ceiling of observed FPR <= 1%.

The winner is selected only by validation: highest recall, then precision, then lower FPR. Its frozen threshold is then applied once to the comparative audit. No audit-informed retuning is allowed.

## Gates
- B: >=70% recall at <=1% observed FPR.
- C: >=85% recall at <=1% observed FPR.
- D: >=90% recall at <=1% observed FPR.
- E: >=95% recall at <=1% observed FPR.

Wilson 95% intervals are recorded for comparative-audit recall and FPR. Any lower, negative, or invalid result is preserved exactly.
