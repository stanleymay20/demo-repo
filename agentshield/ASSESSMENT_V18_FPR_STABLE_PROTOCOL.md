# AgentShield Assessment v18 — FPR-Stable Sparse Fusion Protocol

## Purpose
v17 improved validation recall but realized 1.437% FPR on the comparative audit, violating the fixed observed-FPR ceiling of 1%. v18 is therefore not a raw recall chase. It tests whether explicit FPR headroom and smoother sparse-model fusion can preserve or improve recall while restoring audit FPR control.

## Scientific status
Research-only successor. The frozen assessment notebook and v16 champion remain untouched. The benchmark/test labels are never used for model selection, thresholding, or reporting. The internal audit has been observed in prior experiments and is therefore comparative, not pristine external evidence.

## Fixed data protocol
Use the same cleaned BrowseSafe training pool and the same seed/splits as v16/v17: development 7,725; validation 1,656; comparative audit 1,656. Remove the known duplicate and train-test overlap using content hashes before splitting.

## Selection rule
The production ceiling remains observed FPR <=1%, but v18 reserves headroom by requiring **validation FPR <=0.6%**. Candidate selection is lexicographic: maximize validation recall, then precision, then prefer lower FPR. The comparative audit is evaluated only after the validation winner is frozen. No audit retuning is allowed.

## Candidate families
1. OOF-hard NB-logistic models using 5-fold out-of-fold development hardness scores.
2. Development-only adversarial NB-logistic models using deterministic token fragmentation and benign-noise dilution of hard positive examples.
3. A conservative OR cascade of the best hard and adversarial sparse models under the 0.6% validation FPR budget.
4. Smooth logit-space score fusion between those two family winners, with alpha selected on validation under the same 0.6% budget.

The weak v17 residual SVM is deliberately removed. This is an evidence-led ablation, not a silent deletion.

## Gates
- Gate B: comparative-audit recall >=70% and observed FPR <=1%.
- Gate C: recall >=85% and observed FPR <=1%.
- Gate D: recall >=90% and observed FPR <=1%.
- Gate E: recall >=95% and observed FPR <=1%.

Confidence intervals are reported for comparative-audit recall and FPR. A higher recall with FPR >1% is a failure under the declared objective.

## Integrity
Failed, negative, and lower-performing results are preserved. No benchmark/test labels are accessed. The comparative audit is explicitly not presented as pristine external validation. Scientific-breakthrough language remains reserved for a frozen model evaluated on untouched external data with strong baselines and reproducibility.
