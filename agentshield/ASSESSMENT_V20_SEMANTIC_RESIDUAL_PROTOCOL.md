# AgentShield Assessment v20 — Semantic Residual Rescue Protocol

## Status
Research-only successor. The verified v18 champion remains frozen and authoritative unless v20 beats it under the declared operating objective. The assessment notebook is untouched.

## Governing objective
Maximize attack recall subject to **observed comparative-audit FPR <= 1%**. v18 remains the reference frontier at 73.08% comparative-audit recall and 0.838% observed FPR.

## Hypothesis
The v18/v19 sparse family is plateauing because its experts largely reuse lexical and HTML-derived signals. A frozen semantic encoder trained only through a lightweight downstream classifier may recover attacks that the sparse anchor systematically misses. The semantic model is therefore used as a **residual rescue specialist**, not as a replacement security boundary.

## Data discipline
- Dataset: `perplexity-ai/browsesafe-bench`.
- Reuse the same deterministic cleanup and train split logic as the controlled predecessors.
- Development / validation / comparative-audit partitions use the same seed and split ratios as v18.
- Test/benchmark **labels are never accessed**. Test content is used only by the pre-existing overlap-removal procedure.
- The internal audit has been observed in prior experiments and is therefore comparative only, not pristine external evidence.
- No audit-informed threshold or model retuning is permitted.

## Sparse anchor
Reconstruct the v18 FPR-stable sparse family on development/validation only:
1. OOF hard-example scoring on development.
2. Stable hard-weighted NB-logistic family.
3. Development-only adversarially augmented NB-logistic family.
4. Constrained OR search under a validation FPR target of **0.6%**, preserving headroom below the 1% operating ceiling.

## New semantic residual specialist
- Encoder: `BAAI/bge-small-en-v1.5`.
- Resolve and record the exact Hugging Face revision at runtime, then load that immutable revision.
- Encoder weights remain frozen.
- Encode the controlled contextual view that already contains visible text, hidden evidence and script cues.
- Mean-pool masked token embeddings and L2-normalize.
- Train only lightweight logistic classifiers on development labels.
- Use development OOF sparse hardness to up-weight hard positives and selected hard negatives.
- Search a bounded classifier grid on validation only.

## Candidate rescue mechanisms
Validation compares:
1. v18-style sparse anchor.
2. Semantic specialist alone.
3. Three-way constrained OR between hard sparse, adversarial sparse and semantic specialist.
4. Residual-gated semantic rescue: the semantic specialist may fire only when a smooth sparse confidence signal is above a validation-selected, label-independent quantile gate. This is intended to prevent semantic false positives from consuming the low-FPR budget.

All thresholds/configurations are selected **only on validation** under observed validation FPR <= 0.6%. Tie-break order is recall, then precision, then lower FPR.

## Comparative audit
After validation selection, freeze the complete configuration and evaluate it exactly once on the comparative audit split. Record precision, recall, F1, observed FPR, TP/FN/FP/TN, and Wilson 95% intervals for recall and FPR.

## Promotion rule
v20 may replace v18 only if its comparative-audit point estimate:
- has observed FPR <= 1%, and
- exceeds v18 recall (73.08%).

Milestone C passes only at recall >= 85% with observed FPR <= 1%. A spectacular result requires leakage and reproducibility checks before any scientific claim.

## Reproducibility evidence
Record:
- commit and branch via runtime manifest,
- dataset fingerprints,
- removed duplicate/overlap counts,
- split sizes,
- seed,
- semantic model ID and resolved revision,
- encoder max length and batch size,
- OOF hardness cutoffs/counts,
- semantic classifier grid winner,
- validation winner and frozen thresholds/gates,
- comparative-audit metrics and Wilson intervals,
- runtime/package versions.

Negative, lower-than-v18, or failed results must be preserved exactly. No benchmark/test-label tuning and no audit retuning.