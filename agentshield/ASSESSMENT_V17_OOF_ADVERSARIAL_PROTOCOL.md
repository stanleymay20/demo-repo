# AgentShield Assessment v17 — OOF Hardness + Adversarial Sparse Rescue

Status: research-only successor experiment. The frozen assessment notebook remains untouched.

## Scientific objective
Improve the low-FPR frontier beyond v16 without relaxing the operating constraint. Primary target remains maximum attack recall subject to observed validation FPR <= 1%. Milestones are 70%, 85%, 90%, 95%, 99%, and 99.9% stretch; no milestone may be manufactured.

## Integrity controls
- Dataset: `perplexity-ai/browsesafe-bench`.
- Test/benchmark labels are never accessed.
- Test content hashes may be used only to remove train/test content overlap before splitting.
- One normalized internal duplicate and one train/test overlap are expected from prior controlled runs; actual counts are recorded fresh.
- Seed: 42.
- Development, validation and comparative-audit split logic is identical to v16.
- Validation alone selects model configuration and thresholds.
- The internal audit has already been observed in prior experiments and is therefore comparative evidence, not a pristine holdout.
- No post-audit retuning is permitted inside v17.
- Failed, flat, or worse results must be preserved exactly.

## v17 changes
1. Replace fitted-in-sample hard-example discovery with 5-fold out-of-fold development predictions.
2. Train an OOF-hard weighted NB-logistic family.
3. Create development-only, label-preserving variants of hard positives using deterministic token fragmentation and benign-noise dilution; no validation/audit row is augmented.
4. Train a separate adversarially augmented NB-logistic family.
5. Train a complementary raw-character residual SVM family with OOF-hard weighting.
6. Use validation-only constrained OR-cascade search across family winners, with the union required to remain at observed FPR <= 1%.
7. Freeze the validation winner, then score the comparative audit once.

## Interpretation guardrails
A v17 improvement is an engineering/research-programme result. It is not a field-level breakthrough claim. Scientific breakthrough language requires a frozen system evaluated on untouched external data, strong baselines, uncertainty, robustness testing and reproducibility.
