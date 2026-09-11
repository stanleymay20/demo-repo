# AgentShield Platform Architecture v1

## Purpose
AgentShield is being evolved from an experimental prompt-injection detector into a layered agent-security platform while preserving the scientific integrity of the frozen E03 experiment.

## Non-contamination rule
The running E03 experiment (GitHub Actions run 34573086538, execution commit 9ec122e6907f57e2d4adf6b3a9a218cc6f7b8c14) is immutable evidence. This platform branch must not reinterpret, retune, overwrite, or silently replace its thresholds, data splits, aggregation choices, audit protocol, logs, or results.

## Security pipeline

1. **Input provenance** — identify source, trust boundary, channel and content type.
2. **Content extraction** — preserve visible text plus relevant hidden/attribute surfaces.
3. **Fast risk sensor** — low-cost first-stage detector for broad screening.
4. **Contextual specialist** — stronger prompt-injection specialist for escalated inputs.
5. **Action-risk classifier** — classify the requested downstream action by consequence/sensitivity.
6. **Policy engine** — combine content risk, action risk and confidence into ALLOW / REVIEW / BLOCK.
7. **Human approval boundary** — require explicit approval for high-impact actions where policy demands it.
8. **Audit evidence** — record model/config version, decision factors, policy path, timestamps and outcome.
9. **Evaluation layer** — measure classifier quality and system-level prevention quality separately.

## Initial policy matrix

| Content risk | Action risk | Decision |
|---|---|---|
| low | normal | ALLOW |
| high | normal | REVIEW |
| low | sensitive | REVIEW |
| high | sensitive | BLOCK |

This matrix is intentionally simple. Future versions may introduce calibrated intermediate states, but only with explicit versioning and evaluation.

## Evaluation dimensions

AgentShield must report more than detector accuracy:

- attack recall at an observed low-FPR operating point;
- observed false-positive rate;
- precision and ROC-AUC where relevant;
- Wilson confidence intervals for recall and FPR;
- dangerous-action prevention rate;
- benign-task completion rate;
- human-review rate;
- latency by pipeline stage;
- cost by pipeline stage;
- robustness to hidden, indirect, obfuscated and adaptive prompt injection;
- domain-shift performance;
- reproducibility from a frozen configuration.

## Scientific boundaries

- 99.9% recall is a stretch hypothesis, never a quota.
- Validation selects thresholds/configuration; frozen audit is one-shot.
- Repeatedly reused audit sets are corroborating evidence, not pristine final holdouts.
- Benchmark labels exposed during development cannot later be described as untouched.
- Spectacular results trigger leakage/contamination investigation before promotion.
- Failed and invalid experiments remain part of the permanent evidence record.

## Branch purpose

`agentshield-platform-v1` is for architecture, production interfaces, policy logic, system-level evaluation and hardening. It must not mutate the historical meaning of E01, E02 or E03.
