# AgentShield PR #10 — Verifiable Evidence Forensic Audit

Date: 2026-10-07

PR: #10 `AgentShield: verifiable evidence layer v1`

Initial forensic baseline: `55a14ed157600b1de31a0def2a930496e36abcea`

Current exact remediation head: `b045a1ad83e7da09fb7ee5709d39480e756dcedf`

Status: **INTERNAL CODE GATES PASS — KEEP DRAFT / DO NOT MERGE YET**

This audit reviewed and repaired the authority/evidence path without weakening security, scientific-integrity, CI, review, or release gates. `main` remains untouched.

## Exact-head verification

At `b045a1ad83e7da09fb7ee5709d39480e756dcedf`:

- AgentShield GA run `37661044524`: **SUCCESS**
- AgentShield CodeQL run `37661044447`: **SUCCESS**

Earlier milestone heads also earned exact-head green evidence:

- F1/F2 remediation head `78e72cafc34ff980fa72eac1e27a80a33fa7697b`: GA `37657250761` SUCCESS; CodeQL `37657250638` SUCCESS.
- F3 portable-review head `b570f732c62d883346524c8c06ab7a5e21833f63`: GA `37658292575` SUCCESS; CodeQL `37658292635` SUCCESS.

## Findings and disposition

### F1 — Portable record type was not authenticated semantically

Severity: **High**  
Status: **CLOSED**

Before remediation, `EvidenceRecord.record_type` was outside the signed event and verifiers did not re-derive it. A valid signed execution event could therefore be relabelled as a policy decision without forging Ed25519.

Remediation:

- runtime and standalone verifiers derive the expected record type from the signed event schema;
- semantic relabelling fails closed;
- regressions cover in-process and separate-process verification.

### F2 — Receipt did not independently prove authorization-scope material

Severity: **High**  
Status: **CLOSED**

The receipt previously exposed a scope digest plus selected identity fields but not the complete privacy-safe canonical material needed for an outsider to recompute the digest.

Remediation:

- `scope_material()` defines the canonical privacy-safe authority projection;
- signed decision evidence carries that material;
- runtime and standalone verifiers independently recompute the scope digest;
- displayed grant/issuer/principal/tenant and machine-identity fields are cross-checked against the canonical scope material;
- exact effects remain hashes; raw action payloads are not exposed;
- a validly Ed25519-signed but internally inconsistent scope proof is rejected.

### F3 — Human-review approval was referenced only by digest

Severity: **High**  
Status: **CLOSED**

Before remediation, REVIEW execution evidence recorded `review_approval_digest`, but the portable bundle did not carry the original signed approval. An outsider therefore could not independently verify the reviewer signature.

Remediation:

- `ReviewApproval` has an exact portable representation and canonical signed material;
- portable bundles can carry signed review approvals;
- review public keys are supplied independently from audit public keys;
- runtime and standalone verifiers validate the reviewer Ed25519 signature;
- the approval is cross-checked against the signed REVIEW decision's request, action, payload, scope, tool manifest, policy version and evaluation digest;
- execution evidence must reference the same approval digest;
- one admitted grant-consumption event must occur within the approval validity window;
- missing, extra, duplicate, unknown-key and tampered review proofs fail closed.

### F4 — Acting authority did not identify autonomous agent or purpose

Severity: **Medium / product-critical**  
Status: **CLOSED FOR IMMEDIATE DELEGATION; full portable multi-hop history is a future extension**

The old scope identified issuer/principal/tenant but not the autonomous actor or host-controlled purpose.

Remediation introduces a backward-compatible authority model:

- legacy authority remains `agentshield-scope-v3` and is not silently upgraded;
- new machine-bound authority uses `agentshield-scope-v4-agent-purpose`;
- v4 binds `agent_id` and host-controlled `purpose_id`;
- root v4 authority has no delegator and cannot claim a fake parent;
- a delegated v4 child must preserve principal, tenant and purpose;
- the child may change current `agent_id` but must bind both the immediate `delegator_agent_id` and `delegator_grant_id`;
- capabilities and exact effects still attenuate;
- in-memory and PostgreSQL authorities enforce the same lineage semantics;
- signed decision evidence and both receipt verifiers understand v3 and v4;
- REVIEW receipts verify correctly with v4 scope material.

Claim boundary: a v4 receipt independently proves the immediate delegation link committed by the child scope. The receipt does not yet reconstruct an arbitrary multi-hop parent scope chain as a separate portable delegation-proof graph.

### F5 — External anchor publisher did not prove exact statement commitment

Severity: **Medium**  
Status: **CLOSED AT SOFTWARE CONTRACT; real provider remains deployment gate**

The original publisher contract accepted any non-empty external reference, so AgentShield could not prove that the provider had actually committed the exact anchor statement.

Remediation:

- `anchor_statement_digest()` computes a canonical SHA-256 commitment over the full statement;
- the statement binds stream ID, sequence, head-envelope hash, audit key ID and observation time;
- publishers must return `AnchorPublication` containing both an external reference and the committed statement digest;
- AgentShield rejects legacy reference-only publishers and digest mismatches;
- changing the stream identity changes the statement commitment;
- HMAC chains remain ineligible for independent anchoring claims.

Claim boundary: the interface can verify that a provider reports committing the exact canonical statement. Actual provider immutability, independence, retention and operational availability are properties of the concrete external service and are not established by this repository alone.

### F6 — Export timestamp is outer bundle metadata

Severity: **Low**  
Status: **DOCUMENTED BOUNDARY**

`exported_at_utc` is bundle/export metadata rather than signed event evidence. It must not be represented as an authenticated event or external-anchor timestamp.

## Positive security properties at current head

The exact green head now demonstrates:

- deterministic authorization separated from probabilistic model output;
- exact-effect authorization;
- single-use grants and replay resistance;
- authority-owned security clocks;
- principal/tenant binding;
- optional v4 agent/purpose/immediate-parent binding;
- preserved legacy v3 behavior rather than silent semantic migration;
- asymmetric Ed25519 human-review authority;
- signed ALLOW / REVIEW / BLOCK decisions;
- execution lifecycle evidence with policy version;
- semantic receipt verification beyond signature validity;
- independent scope-digest recomputation;
- portable independently verifiable human-review proofs;
- durable serialized PostgreSQL evidence streams;
- public-key-only offline audit verification;
- exact external-anchor statement commitment contract;
- explicit refusal to treat local storage as an independent external anchor.

## Final forensic verdict for PR #10 code

**PASS FOR INTERNAL CODE / SECURITY-GATE CONVERGENCE. DO NOT MERGE YET.**

No known F1–F5 technical blocker from this audit remains open at exact head `b045a1ad83e7da09fb7ee5709d39480e756dcedf`.

The remaining release blockers are external or repository-owner/admin gates:

1. independent human/security review of the final diff;
2. a real independently controlled external anchoring provider and provider-specific operational proof;
3. production signing-key custody, rotation and authenticated public-key distribution;
4. protected canonical `main` with required review/status checks;
5. repository license choice;
6. controlled convergence through the PR #9 lineage before any merge to `main`;
7. detector research remains separate and does not justify universal `100%` or `99.999%` prevention claims.

Keep PR #10 draft and unmerged until those gates are satisfied.
