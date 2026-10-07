# AgentShield

**AI Agent Security & Runtime Governance**

> Repository note: `demo-repo` is a legacy repository name. Runtime code is being consolidated onto `main` while historical experiment branches remain preserved as research evidence.

AgentShield constrains AI-agent execution **after a model proposes an action but before a tool is allowed to perform it**.

The system treats prompt-injection detection as only one layer. Authorization, provenance, capability scope, durable grant state, decision integrity, human review and replay resistance are enforced separately so a model cannot gain authority merely by generating a convincing instruction.

## Recruiter quick scan

**Problem:** LLMs can propose actions, but model output must not be treated as authorization.

**What this repository demonstrates:** AI-agent runtime governance, prompt-injection/adversarial handling, provenance checks, least-privilege capability grants, exact-effect authorization, durable atomic single-use grants, authenticated detached evaluations, asymmetric human review, explicit ALLOW / REVIEW / BLOCK decisions, execution lifecycle audit evidence and preserved negative-test evidence.

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
Capability / exact-effect / durable grant validation
        ↓
Policy decision
   ALLOW | REVIEW | BLOCK
        ↓
Decision integrity check
(in-process seal or detached Ed25519 signature)
        ↓
If REVIEW: exact Ed25519 human approval
        ↓
Atomic single-use grant consumption
        ↓
Execution-admission audit envelope
        ↓
Constrained tool execution
        ↓
Execution-outcome audit envelope
```

## Runtime implementation

Production-facing primitives live under `agentshield/platform/`.

Key controls include:

- server-owned tool manifests;
- least-privilege authorization scopes;
- mandatory host-approved effects binding exact tool, manifest and complete payload;
- in-memory grant authority for deterministic tests;
- PostgreSQL-backed atomic grant authority for multi-worker deployment;
- single-use executable grants with expiry and revocation enforcement;
- action/payload/scope/tool-manifest integrity binding;
- process-local integrity seals for trusted in-process evaluations;
- optional Ed25519 authentication for detached evaluation objects via `agentshield-runtime[signing]`;
- separate Ed25519 review signing and public-key-only verification roles;
- fail-closed execution enforcement;
- chained execution lifecycle audit events for grant consumption and dispatch success/failure;
- tamper-evident audit envelope chaining with key rotation support;
- adversarial contract scenarios and consequence-aware metrics.

The dependency-free core supports trusted in-process evaluation and execution. If an evaluation or human approval crosses a service/process boundary, install the signing extra and use the public-key verification path. Unsigned detached ALLOW/REVIEW evaluations fail closed.

## GA quality gates

The GA workflow validates:

- Python 3.11, 3.12, 3.13 and 3.14;
- full platform unit suite;
- live PostgreSQL concurrency semantics;
- wheel build/install smoke test;
- SPDX SBOM generation;
- dependency vulnerability audit;
- CodeQL security analysis;
- tagged-release SHA-256 manifests and build provenance.

See `agentshield/GA_READINESS.md`, `SECURITY.md` and `CONTRIBUTING.md`.

Runtime 0.5.0 / policy v7 requires effect-bound, single-use executable grants. Capability-only and legacy reusable grants must be reissued by trusted infrastructure before execution. See `agentshield/EFFECT_AUTHORIZATION_V1.md` for the issuance example, migration and adapter requirements for resource and destination semantics. See `agentshield/DELEGATION_V1.md` for delegation. Review approvals bind the complete evaluation and are verified with public keys only.

## Audit boundary

AgentShield emits and chains execution-admission and execution-outcome evidence without raw prompt, payload, output or exception text. A production host should inject an `AuditTrail` with durable synchronous persistence and periodically anchor the latest envelope hash outside the runtime writer's control. The built-in process trail is a local fallback, not a claim of cross-process durability or protection against tail truncation after process compromise.

## Research lineage

Detector research remains intentionally separate from the runtime release path. Historical experiment branches and negative results are preserved rather than flattened into production code.

A passing adversarial suite is **not** a universal proof of safety. Detector metrics must stay attached to their exact frozen protocol and data. A production detector-efficacy claim still requires genuinely unseen external validation and independent adversarial reproduction.

## Status

The runtime is in GA hardening. The first GA tag should not be cut until the exact-head technical gates are green and the repository-admin gates in `agentshield/GA_READINESS.md` are completed. No synthetic or internal suite establishes a universal security percentage or a 99.999% prevention rate.
