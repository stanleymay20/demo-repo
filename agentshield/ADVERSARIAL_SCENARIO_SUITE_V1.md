# AgentShield Adversarial Scenario Suite v1

## Purpose

This suite validates the behavior of AgentShield's orchestration, policy and execution boundary under synthetic attack/benign combinations.

It is **not** a detector benchmark, does **not** estimate real-world prompt-injection recall/FPR, and must not be reported as such.

## Frozen contract cases

The v1 suite covers:

1. high content risk + sensitive action -> BLOCK;
2. high content risk + normal action -> REVIEW;
3. detector miss + sensitive action -> REVIEW;
4. detector miss + normal action -> ALLOW (intentional documented limitation);
5. benign low-risk + normal action -> ALLOW;
6. benign low-risk + sensitive action -> REVIEW;
7. unknown content risk + normal action -> REVIEW.

## Why the detector-miss case is retained

The suite deliberately includes an attack represented as LOW content risk combined with a NORMAL action. Policy v1 permits that combination. Keeping this case prevents the platform tests from overstating safety: action-aware policy can reduce the consequence of some detector misses, but it cannot compensate for every missed attack.

This limitation is evidence for future architectural work, such as provenance-aware restrictions, capability scoping, multi-signal detection and runtime behavior constraints. It is not to be hidden by changing the expected result.

## Metrics

The system-level harness reports dangerous-action prevention and benign-task completion over these synthetic contract cases. Those numbers describe policy behavior for this declared suite only.

They must remain separate from E01/E03/E04 scientific detector metrics and from any future external red-team evaluation.

## Execution boundary

Every scenario flows through:

`detector evidence -> action-risk classification -> policy -> execution gate`

Only ALLOW may reach the side-effect executor. REVIEW and BLOCK remain non-executing states. Action identity/risk changes after policy evaluation fail closed.

## Versioning

This document governs the synthetic platform-v1 contract suite. Changes to scenario semantics, expected decisions, or metric definitions require an explicit successor version rather than silent mutation.
