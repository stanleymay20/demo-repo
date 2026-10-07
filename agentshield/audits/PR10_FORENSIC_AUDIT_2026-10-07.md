# AgentShield PR #10 — Verifiable Evidence Forensic Audit

Date: 2026-10-07

PR: #10 `AgentShield: verifiable evidence layer v1`

Initial forensic baseline: `55a14ed157600b1de31a0def2a930496e36abcea`

Latest exact code head verified before this documentation convergence: `337c26f07298dedd21ab8ff907f9fb2ed780ce6d`

Status: **INTERNAL CODE GATES PASS — KEEP DRAFT / DO NOT MERGE YET**

This audit reviewed and repaired the authority/evidence path without weakening security, scientific-integrity, CI, review, or release gates. `main` remains untouched.

## Exact-head verification

At `337c26f07298dedd21ab8ff907f9fb2ed780ce6d`:

- AgentShield GA run `37676075777`: **SUCCESS**
- AgentShield CodeQL run `37676075749`: **SUCCESS**

Earlier milestone heads also earned exact-head green evidence:

- F1/F2 remediation head `78e72cafc34ff980fa72eac1e27a80a33fa7697b`: GA `37657250761` SUCCESS; CodeQL `37657250638` SUCCESS.
- F3 portable-review head `b570f732c62d883346524c8c06ab7a5e21833f63`: GA `37658292575` SUCCESS; CodeQL `37658292635` SUCCESS.
- F4/F5 implementation head `b045a1ad83e7da09fb7ee5709d39480e756dcedf`: GA `37661044524` SUCCESS; CodeQL `37661044447` SUCCESS.
- Documentation-converged head `8d4a26e249cbd056679b2d09d6e31b8da789f631`: GA `37661600603` SUCCESS; CodeQL `37661600517` SUCCESS.

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

### F7 — Runtime and anchor boundaries accepted unsupported audit-envelope schema versions

Severity: **Medium / protocol-integrity**  
Status: **CLOSED**

The standalone verifier rejected unsupported audit-envelope schema versions, but the in-process HMAC/Ed25519 verifiers authenticated whatever `schema_version` was included in otherwise valid signed material. The external anchor builder also checked Ed25519 algorithm but did not reject an unsupported envelope schema before publication.

This was not a signature-forgery path, but it created inconsistent protocol-version semantics between runtime, portable verification and anchoring.

Remediation:

- runtime audit verification now fails closed with `SCHEMA_MISMATCH` unless the envelope schema exactly matches the supported version;
- HMAC and Ed25519 regressions cover unsupported schemas;
- the anchor boundary rejects unsupported audit-envelope schemas before invoking the external publisher;
- standalone verification already enforced the supported envelope schema.

### F8 — Accepted Ed25519 signature text could make the chain-head hash malleable

Severity: **High for evidence-head canonicalization**  
Status: **CLOSED**

Python's `bytes.fromhex()` accepts alternate textual encodings such as embedded whitespace. Ed25519 verifies signature bytes, while AgentShield's `envelope_hash` commits the signature string itself. On the final envelope, an equivalent signature-byte representation could therefore verify while producing a different accepted head hash. The standalone verifier also previously tolerated unsigned extra envelope fields while its computed head hash included them.

That is especially dangerous at the external-anchoring boundary, where the head hash is the object being committed.

Remediation:

- runtime Ed25519 verification requires the signer-produced canonical representation: exactly 128 lowercase hexadecimal characters;
- the standalone verifier enforces the same canonical Ed25519 representation;
- the standalone verifier requires the exact audit-envelope field set, rejecting unsigned extra envelope fields;
- one-record-head regressions prove that whitespace-reencoded signatures and extra wrapper fields are rejected rather than producing alternate accepted head hashes.

### Protocol-version boundary — future execution-event schemas

The v1 receipt profile recognizes the current policy-decision and execution-event schemas used by this branch. Unknown future execution schemas must not be advertised as understood v1 semantics merely because an audit signature is valid. Future schema support requires an explicit verifier/profile revision and corresponding tests; generic signed audit evidence does not automatically acquire execution-authority meaning.

## Positive security properties at current head

The exact green code head now demonstrates:

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
- fail-closed supported audit-envelope schema handling;
- canonical Ed25519 envelope encoding with stable accepted head hashes;
- exact external-anchor statement commitment contract;
- refusal to anchor unsupported audit-envelope schemas;
- explicit refusal to treat local storage as an independent external anchor.

## Final forensic verdict for PR #10 code

**PASS FOR INTERNAL CODE / SECURITY-GATE CONVERGENCE. DO NOT MERGE YET.**

No known F1–F5, F7 or F8 technical blocker from this audit remains open at exact code head `337c26f07298dedd21ab8ff907f9fb2ed780ce6d`. F6 remains an explicit metadata boundary.

The remaining release blockers are external or repository-owner/admin gates:

1. independent human/security review of the final diff;
2. a real independently controlled external anchoring provider and provider-specific operational proof;
3. production signing-key custody, rotation and authenticated public-key distribution;
4. protected canonical `main` with required review/status checks;
5. repository license choice;
6. controlled convergence through the PR #9 lineage before any merge to `main`;
7. detector research remains separate and does not justify universal `100%` or `99.999%` prevention claims.

Repository evidence checked during this pass confirms that `main` is currently unprotected, no repository ruleset is configured, no license is configured, and neither PR #9 nor PR #10 currently has a submitted human review. Those gates therefore remain genuinely open.

Keep PR #10 draft and unmerged until those gates are satisfied.
