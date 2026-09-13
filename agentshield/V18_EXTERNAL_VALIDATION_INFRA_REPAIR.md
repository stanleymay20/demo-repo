# AgentShield v18 external validation — infrastructure repair

## Status of Attempt 1

Workflow run `34748655363` is preserved as an invalid/incomplete external-validation attempt.

The fail-closed reconstruction gate stopped before any external labels were scored because the fresh reconstruction produced:

- TP 599
- FN 222
- FP 7
- TN 828

The frozen v18 champion evidence is:

- TP 600
- FN 221
- FP 7
- TN 828

Therefore Attempt 1 did **not** produce an accepted external-validation result.

## Forensic comparison

The original successful v18 run (`34708162861`, commit `92b5e23d143397d8732673ee2e5715b5c81e82c1`) and Attempt 1 used the same GitHub hosted-runner image family and the same resolved package versions, including Python 3.11.16, NumPy 2.4.6, SciPy 1.17.1, scikit-learn 1.9.1, datasets 5.0.1, pandas 3.0.5, BeautifulSoup 4.15.0 and lxml 6.1.3.

One execution-environment difference was identified: Attempt 1 added `PYTHONHASHSEED=42`, whereas the original successful v18 workflow did not set `PYTHONHASHSEED`.

The inherited v18 feature construction and adversarial augmentation do not require this variable for their scientific random seed. The explicit scientific seed remains `SEED=42`, and deterministic token fragmentation uses SHA-256.

## Repair scope

This repair is execution-only. It removes the extra `PYTHONHASHSEED` setting so the external-validation workflow more closely matches the original successful v18 runtime contract.

The repair does **not** change:

- v18 source logic;
- BrowseSafe cleanup or split logic;
- `SEED=42` in the scientific code;
- sparse representations;
- hard-example mining;
- adversarial augmentation;
- model families or hyperparameters;
- validation winner selection;
- frozen v18 thresholds;
- expected champion confusion matrix;
- external datasets;
- contamination-screening rules;
- external predictions or labels;
- the requirement that the external-scoring stage remain inaccessible until exact v18 reproduction succeeds.

If the exact `600/221/7/828` gate still fails, the run remains invalid/incomplete and external scoring must remain skipped. No tolerance, threshold adjustment, or one-sample exception is permitted as part of this repair.
