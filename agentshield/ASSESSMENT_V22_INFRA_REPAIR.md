# AgentShield v22 — Infrastructure-Only Resume Repair

Status: controlled implementation repair; scientific protocol unchanged.

## Why this exists

The original v22 workflow was interrupted twice by hosted-runner shutdowns (exit 143) after the deterministic OOF/taxonomy and anchor-family work had completed. Attempts 1 and 2 are preserved as invalid/incomplete runs. No validation winner, comparative-audit metric, or promotion decision was produced by either interrupted attempt.

## Repair boundary

This repair changes orchestration only. It does **not** change:

- dataset or cleanup logic;
- development / validation / comparative-audit splits;
- random seed;
- OOF folds;
- taxonomy definitions;
- canonicalization rules;
- hard-example or adversarial model families;
- specialist model families;
- hyperparameter grids;
- weighting rules;
- validation FPR target (0.6%);
- operating FPR ceiling (1%);
- validation selection objective or tie-breaks;
- v18 reference metrics;
- promotion criterion;
- benchmark/test-label access policy.

## Orchestration change

The exact v22 computation is split at the already-existing `ANCHOR FAMILY WINNERS` boundary:

1. **Stage 1** reproduces the deterministic OOF residual discovery, taxonomy counts, hard family, and adversarial family, then serializes the fitted objects and validation scores required to continue.
2. **Stage 2** reloads that checkpoint, verifies dataset fingerprints/splits/counts, trains the canonicalization and taxonomy specialists using the original v22 grids, performs the original constrained validation search, freezes the validation winner, and evaluates the comparative audit once.

The checkpoint is an implementation transport mechanism only; it is not used to alter model selection or scientific logic.

## Fail-closed requirements

- Stage 2 must refuse to continue if dataset fingerprints, duplicate/overlap counts, split indices, or labels differ from the checkpoint.
- Final evidence must record that execution used the infrastructure-resume path.
- Benchmark/test labels remain untouched.
- No scientific promotion is permitted unless the original v22 criterion is met: comparative-audit recall strictly greater than exact v18 recall `600/821` and observed comparative-audit FPR <= 1%.
