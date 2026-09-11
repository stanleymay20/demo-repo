# AgentShield High-Recall Research Protocol

## Objective
Push prompt-injection detection recall as high as scientifically defensible while preserving a strict low-false-positive operating point.

Primary target: maximize attack recall subject to observed FPR <= 1%.
Stretch target: >=99.9% recall at observed FPR <=1%, but only if reproduced on genuinely untouched external data.

## Non-negotiable scientific controls
- Keep the M508 v13.6.1 submission baseline frozen.
- Never tune on the final external holdout.
- Remove duplicate/near-duplicate leakage before training.
- Select thresholds on validation only.
- Report Wilson confidence intervals for recall and FPR.
- Treat suspiciously perfect results as a leakage/contamination signal until disproved.
- Record all seeds, data hashes, model versions, hyperparameters and checkpoints.

## Baseline
M1 parsed-text TF-IDF + Logistic Regression:
- BrowseSafe benchmark recall ~27.9%
- observed FPR ~0.92%
- precision ~96.8%

M4 frozen MiniLM contextual probe improves ranking but not low-FPR recall; it is not a fully fine-tuned Transformer ceiling.

## Experimental ladder
1. Task-specific long-context Transformer fine-tuning on BrowseSafe training data.
2. Chunk-aware multiple-instance learning: max/top-k/attention aggregation instead of mean-diluting local attacks.
3. Hard-negative mining from benign pages with attack-like instructions/HTML.
4. Hard-positive mining from false negatives and context-aware visible rewrites.
5. Cost-sensitive/focal/objective variants optimized for Recall@FPR<=1%, not headline accuracy.
6. Ensemble/cascade: lightweight M1 first stage + contextual specialist second stage.
7. Action-aware runtime policy evaluation for system-level attack interception.
8. External untouched holdout and adversarial/generalization evaluation.

## Promotion gates
- Gate A: >=50% recall at observed FPR <=1%
- Gate B: >=70%
- Gate C: >=85%
- Gate D: >=90%
- Gate E: >=95%
- Gate F: >=99%
- Stretch: >=99.9%

A model is promoted only if it improves the primary low-FPR metric without data leakage and reproduces on audit data.

## Success definition
A breakthrough claim requires more than high benchmark recall. It must include low FPR, untouched external evaluation, reproducibility, robustness to adaptive attacks/domain shift, and a transparent comparison to strong published baselines.