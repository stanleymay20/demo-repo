# AgentShield

**AI Agent Security & Runtime Governance**

> Repository note: `demo-repo` is a legacy repository name. Runtime code is now being consolidated onto `main` while historical experiment branches remain preserved as research evidence.

AgentShield constrains AI-agent execution **after a model proposes an action but before a tool is allowed to perform it**.

The system treats prompt-injection detection as only one layer. Authorization, provenance, capability scope, durable grant state, integrity binding, human review and replay resistance are enforced separately so a model cannot gain authority merely by generating a convincing instruction.

## Recruiter quick scan

**Problem:** LLMs can propose actions, but model output must not be treated as authorization.

**What this repository demonstrates:** AI-agent runtime governance, prompt-injection/adversarial handling, provenance checks, least-privilege capability grants, durable atomic replay protection, integrity binding, cryptographically bound human review, explicit ALLOW / REVIEW / BLOCK decisions, tamper-evident audit evidence and preserved negative-test evidence.

**Engineering signal:** probabilistic model reasoning is separated from deterministic execution authority.

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
Capability / durable grant validation
        ↓
Integrity + replay checks
        ↓
Policy decision
   ALLOW | REVIEW | BLOCK
        ↓
If REVIEW: exact signed human approval
        ↓
Atomic grant consumption
        ↓
Constrained tool execution
        ↓
Tamper-evident audit envelope
```

## Runtime implementation

Production-facing primitives live under `agentshield/platform/`.

Key controls include:

- server-owned tool manifests;
- least-privilege authorization scopes;
- in-memory grant authority for deterministic tests;
- PostgreSQL-backed atomic grant authority for multi-worker deployment;
- expiry, revocation and single-use replay resistance;
- action/payload/scope/tool-manifest integrity binding;
- short-lived HMAC review approvals bound to the exact held action;
- fail-closed execution enforcement;
- tamper-evident HMAC audit chaining with key rotation support;
- adversarial contract scenarios and consequence-aware metrics.

## GA quality gates

The GA workflow validates:

- Python 3.11, 3.12, 3.13 and 3.14;
- full platform unit suite;
- live PostgreSQL concurrency semantics;
- wheel build/install smoke test;
- SPDX SBOM generation;
- dependency review;
- CodeQL security analysis;
- tagged-release SHA-256 manifests and build provenance.

See `agentshield/GA_READINESS.md`, `SECURITY.md` and `CONTRIBUTING.md`.

## Research lineage

Detector research remains intentionally separate from the runtime release path. Historical experiment branches and negative results are preserved rather than flattened into production code.

A passing adversarial suite is **not** a universal proof of safety. Detector metrics must stay attached to their exact frozen protocol and data. A production detector-efficacy claim still requires genuinely unseen external validation and independent adversarial reproduction.

## Status

The runtime is in GA hardening. The first GA tag should not be cut until the required repository rules, security checks, license choice and external claim boundaries in `agentshield/GA_READINESS.md` are satisfied.
