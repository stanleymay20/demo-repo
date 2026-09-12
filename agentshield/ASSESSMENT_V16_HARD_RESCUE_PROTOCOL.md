# AgentShield Assessment v16 — Hard-Example Rescue Protocol

## Status
Research-only successor experiment. The frozen assessment notebook is not modified.

## Objective
Maximise attack recall subject to observed validation FPR <= 1%. The next milestone is >=70% comparative-audit recall at observed FPR <=1%, followed by 85% and 90% milestones.

## Scientific controls
- Dataset: `perplexity-ai/browsesafe-bench`.
- BrowseSafe benchmark/test labels are never accessed.
- Benchmark/test content hashes may be used only to remove train/test overlap.
- Seed: 42.
- Same deterministic development/validation/comparative-audit split lineage as v14/v15.
- Validation alone selects model/cascade thresholds.
- The comparative audit is scored only after the validation winner is frozen.
- The comparative audit is explicitly **not pristine** because it has been observed in earlier experiments.
- No desired-performance assertion can fail the run; negative results are preserved.
- Wilson 95% intervals are recorded for final recall and FPR.

## v16 hypothesis
v15 showed that NB-logistic sparse modelling carries most of the low-FPR signal, while a weak contextual detector still rescued complementary attacks in an OR cascade. v16 therefore targets residual error rather than adding generic feature volume.

v16 tests:
1. Frozen v15-style NB-logistic sparse baseline.
2. Hard-example weighted NB-logistic variants. Development-only base scores define:
   - hard positives: low-scoring attacks;
   - hard negatives: high-scoring benign pages.
   Weight multipliers are predeclared and validation selects among them.
3. A residual contextual MiniLM specialist trained with development-only example weights so it focuses on sparse-model misses and dangerous benign lookalikes.
4. Pairwise OR cascades under the integer validation false-positive budget.
5. A three-way OR cascade across base NB, best hard-weighted NB, and contextual rescue scores. The union must remain within the same <=1% observed validation FPR constraint.

## Hard-example definition
After fitting the development-only NB baseline:
- hard-positive cutoff = 45th percentile of attack scores on development;
- hard-negative cutoff = 95th percentile of benign scores on development.
No validation labels are used to define these cutoffs.

Sparse hard-weight grid:
- hard-positive multipliers: 2, 4, 6;
- hard-negative multipliers: 1, 2, 4;
- C: 0.5, 1.0, 2.0.

Contextual specialist fixed training:
- model: `microsoft/MiniLM-L12-H384-uncased`, exact revision resolved and recorded before training;
- max length: 256;
- 3 epochs;
- learning rate: 2e-5;
- weight decay: 0.01;
- gradient accumulation: 2;
- hard-positive multiplier: 4;
- hard-negative multiplier: 2.

## Promotion gates
A result is not promoted merely because the workflow succeeds.
- B: recall >=70% and observed FPR <=1%
- C: recall >=85% and observed FPR <=1%
- D: recall >=90% and observed FPR <=1%
- stretch: recall >=99.9% and observed FPR <=1%

Even if a comparative-audit gate passes, a breakthrough claim still requires an untouched external evaluation after the full configuration is frozen.
