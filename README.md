# AgentShield

**AI Agent Security & Runtime Governance**

> Repository note: `demo-repo` is a legacy repository name. The rename is intentionally deferred while controlled AgentShield experiment and evidence branches remain active.

AgentShield is an engineering and research project for constraining AI-agent execution **after a model proposes an action but before a tool is allowed to perform it**.

The system treats prompt-injection detection as only one layer. Authorization, provenance, capability scope, integrity binding and replay resistance are enforced separately so a model cannot gain authority merely by generating a convincing instruction.

## Security model

```text
User / external content
        ↓
Model proposes an action
        ↓
Input & provenance checks
        ↓
Server-owned tool manifest
        ↓
Capability / grant validation
        ↓
Integrity + replay checks
        ↓
Policy decision
   ALLOW | REVIEW | BLOCK
        ↓
Constrained tool execution
```

## Engineering areas

- prompt-injection and adversarial-input handling;
- server-owned tool manifests;
- least-privilege capability grants;
- provenance and trust-boundary checks;
- integrity binding between authorized intent and execution;
- replay resistance and grant lifecycle controls;
- fail-closed policy decisions;
- adversarial scenario harnesses and preserved negative results;
- explicit separation of **detection**, **authorization** and **execution**.

## Controlled implementation

The maintained platform/evidence line currently lives on:

**[`agentshield-platform-v1`](https://github.com/stanleymay20/demo-repo/tree/agentshield-platform-v1)**

Additional research/evaluation branches are intentionally preserved while experiments are active. Their history should not be flattened or rewritten merely to make the repository look cleaner.

## Why this project exists

Agentic systems create a security problem that ordinary prompt filtering does not solve: even if a model understands a request, it still needs an independently enforced answer to questions such as:

- Is this tool available to this actor?
- Was this action actually authorized?
- Is the authorization still valid?
- Has the request been modified since approval?
- Is the model attempting to reuse an old grant?
- Should this action require human review?

AgentShield explores those questions as enforceable runtime controls rather than relying on model self-restraint.

## Evidence discipline

This repository preserves experimental lineage, including failures and negative results. Security claims should be based on the exact branch, test harness and threat model that produced the evidence.

A passing adversarial suite is **not** a universal proof of safety, and the project does not claim that prompt injection can be eliminated by a single classifier or policy rule.

## Portfolio status

AgentShield is a flagship AI-engineering project in this portfolio, focused on **agent security, runtime governance and controlled tool execution**.

Canonical repository naming and default-branch consolidation are deliberately postponed until the active controlled experiment line is frozen and verified.
