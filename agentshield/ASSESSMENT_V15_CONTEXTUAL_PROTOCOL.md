# AgentShield Assessment v15 — Task-Specific Contextual Protocol

Status: research-only successor experiment. It does not modify or replace the frozen assessment notebook.

## Objective

Increase attack recall while preserving the same scientific operating constraint:

- primary: maximize attack recall subject to observed validation FPR <= 1%;
- milestones: >=70%, >=85%, >=90% recall at observed FPR <=1%;
- never promote a result merely because recall is high when the false-positive constraint is violated.

## Why v15

v14 materially improved the sparse baseline, reaching 63.82% validation recall and 58.59% comparative-audit recall at 0.958% observed FPR, but raw-HTML features, hybrid features and linear score fusion did not improve the frontier. v15 therefore changes model class rather than simply adding more sparse features.

## Data integrity

- Dataset: `perplexity-ai/browsesafe-bench`.
- Benchmark/test labels MUST NOT be accessed anywhere in this experiment.
- Benchmark/test content hashes may be used only to remove exact normalized train/test overlap.
- Remove normalized duplicates from the training split before splitting.
- Seed: 42.
- Use the same development/validation/audit partition recipe as v14 for direct comparability.
- The audit split has been observed in earlier experiments and is therefore a **comparative audit**, not a pristine final holdout.
- No audit metric may influence model, hyperparameter, fusion, cascade, epoch or threshold selection.

## Candidate systems

1. **Sparse-v14 baseline**: semantic TF-IDF stack with Logistic Regression C=1, class weight 1, frozen from v14.
2. **NB-logistic sparse model**: class-conditional log-count-ratio reweighting of the same sparse semantic representation, learned from development data only, followed by Logistic Regression.
3. **Task-specific contextual model**: fine-tune `microsoft/MiniLM-L12-H384-uncased` for binary page classification using development data only. Resolve and pin the exact Hugging Face revision before training.
4. **Validation-only score fusion** between sparse and contextual candidates using standardized scores and a fixed alpha grid.
5. **Validation-only constrained OR cascade**: select thresholds for two complementary models to maximize recall while the union of validation false positives remains within the <=1% budget.

## Context representation

Use parsed visible text plus explicit hidden/comment/attribute evidence. For long pages, use a deterministic head/middle/tail word sampler before tokenization so the model does not see only the start of a long page. This is not vendor Smooth-Max and no claim of full-document coverage is permitted.

## Contextual training

- model: `microsoft/MiniLM-L12-H384-uncased` pinned to resolved revision;
- max token length: 256;
- epochs: 3 fixed in advance;
- learning rate: 2e-5;
- AdamW, weight decay 0.01;
- train batch size 8;
- gradient accumulation: 2;
- warmup ratio: 0.06;
- no validation-based early stopping;
- seed 42;
- CPU execution is acceptable; no requirement to hit a target number.

## Selection

- Development data fit representations and models.
- Validation labels select the winner and operating threshold/cascade configuration.
- The winner is selected by highest validation recall subject to observed FPR <=1%, then lower FPR, then precision.
- Once selected, freeze the complete configuration.
- Evaluate the frozen winner exactly once on the comparative audit split.

## Evidence

Record dataset fingerprints, duplicate/overlap counts, split sizes, exact model revision, runtime, all fixed training hyperparameters, every validation candidate, the frozen winner, comparative-audit confusion matrix/metrics, Wilson 95% CIs and milestone gates.

## Interpretation

A workflow success is not a model success. A 90% recall result counts only if the same frozen configuration also satisfies the stated <=1% observed FPR criterion on the relevant evaluation. The benchmark remains untouched for later external-style evaluation.
