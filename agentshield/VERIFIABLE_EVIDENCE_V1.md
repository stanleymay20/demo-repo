# AgentShield Verifiable Evidence v1

Status: **draft / stacked on the PR #9 remediation branch**. This document describes the current verified code contract, not a production-GA deployment claim.

Verified implementation head before this documentation-only convergence: `b045a1ad83e7da09fb7ee5709d39480e756dcedf`.

- AgentShield GA `37661044524`: SUCCESS
- AgentShield CodeQL `37661044447`: SUCCESS

## Goal

AgentShield proves what authority an AI action was evaluated under, what decision was made, what crossed the execution boundary, and—when human review is required—which independently signed approval authorized the exact held action.

The evidence architecture separates:

- private audit signing authority from public audit verification;
- model proposals from deterministic execution authority;
- policy-decision evidence from execution lifecycle evidence;
- human-review signing authority from execution-side verification;
- durable internal persistence from external trust anchoring;
- legacy authority semantics from newer machine/purpose-bound authority.

## Audit cryptography

Portable audit evidence uses Ed25519 envelopes. The evidence writer holds private keys; auditors and other verifiers need public keys only.

The legacy HMAC `AuditSigner` remains available for dependency-free local/internal integrity. HMAC evidence is not accepted as independently verifiable portable evidence because anyone able to verify the shared secret can also forge records.

Each audit envelope commits:

- envelope schema version;
- algorithm;
- zero-based sequence number;
- previous-envelope hash;
- canonical event hash;
- audit key ID.

The next envelope hashes the complete previous envelope. Full-chain verification checks signatures, event hashes, sequence continuity and previous-hash linkage, and reports the first broken record.

## Deterministic authorization evidence

When evidence mode is configured, `evaluate_request(..., audit_trail=trail)` synchronously records every ALLOW, REVIEW or BLOCK decision before returning it. A durable evidence failure therefore fails the governed flow rather than silently returning an unaudited decision.

No raw prompt, action payload or tool output is added to portable evidence. Authority-relevant values are represented as structured metadata and cryptographic digests.

## Authorization scope versions

### Legacy identity-bound v3

`agentshield-scope-v3` binds:

- grant ID;
- issuer;
- principal;
- tenant;
- normalized allowed capabilities;
- exact-effect SHA-256 commitments.

Existing v3 grants retain their existing semantics. They are not silently reinterpreted as machine-identity grants.

### Agent/purpose-bound v4

`agentshield-scope-v4-agent-purpose` additionally binds:

- current `agent_id`;
- host-controlled `purpose_id`;
- immediate `delegator_agent_id` when delegated;
- immediate `delegator_grant_id` when delegated.

Root v4 authority carries no delegator. Direct issuance fails if a caller attempts to invent a parent.

For a v4 delegation:

- issuer, principal and tenant remain unchanged;
- purpose remains unchanged;
- capabilities and exact effects must attenuate;
- current agent may change to the delegated child agent;
- child must bind the parent agent as `delegator_agent_id`;
- child must bind the parent grant as `delegator_grant_id`.

The same semantics are enforced in memory and by the PostgreSQL authority.

This proves the immediate delegation link committed by the child scope. The v1 portable receipt does not yet package arbitrary multi-hop parent scopes into a standalone delegation-proof graph.

## Self-contained scope proof

Signed decision evidence carries the privacy-safe canonical authorization-scope material plus its digest.

Runtime and standalone verifiers independently:

1. validate the exact v3 or v4 scope schema;
2. normalize/check capabilities and exact-effect digests;
3. recompute the canonical scope digest;
4. compare it to the signed `authorization_scope_digest`;
5. cross-check displayed issuer/principal/tenant/agent/purpose/delegator fields against the canonical material.

This prevents a validly signed event with internally inconsistent authority metadata from being accepted merely because its Ed25519 audit signature is valid.

## Human-review proof

A REVIEW policy decision is not executable by itself.

The trusted review service signs a `ReviewApproval` with Ed25519. The approval commits:

- approval ID;
- request ID;
- action digest;
- payload digest;
- authorization-scope digest;
- authoritative tool-manifest digest;
- policy version;
- evaluation digest;
- reviewer identity;
- validity window;
- review key ID.

Execution gateways hold review public keys only.

When a reviewed action executes, the portable evidence bundle can carry the original signed approval. Verification requires review public-key trust anchors independently from audit public-key trust anchors.

Runtime and standalone receipt verification then checks that:

- the reviewer Ed25519 signature is valid;
- the approval corresponds to exactly one signed REVIEW decision;
- request/action/payload/scope/tool/policy/evaluation bindings agree;
- execution events reference the same approval digest;
- exactly one admitted grant-consumption transition occurred inside the approval validity window.

Missing, tampered, duplicate, unreferenced or unknown-key review proofs fail closed.

## Portable evidence bundle

The current draft profile is:

- `agentshield-evidence-bundle-v1`
- `agentshield-verifiable-action-receipt-v1`

Each evidence record contains the signed event and its audit envelope. Optional human-review proofs are carried separately within the same portable bundle.

Public keys are deliberately not embedded as trusted roots. Verifiers receive expected audit/review public keys through independent authenticated channels.

`record_type` is not trusted as free-form wrapper metadata: both verifiers derive the expected type from the signed event schema and reject semantic relabelling.

The format is AgentShield-native and designed to map cleanly onto emerging agent-action-receipt work. It does not claim conformance to an adopted final IETF standard.

## Standalone verification

`tools/agentshield_verify.py` uses only Python standard library + `cryptography`. It does not import the AgentShield runtime or contact AgentShield services.

Audit-only example:

```bash
python tools/agentshield_verify.py evidence.json \
  --pubkey audit-2026=<64-hex-character-raw-ed25519-public-key>
```

Reviewed-execution example:

```bash
python tools/agentshield_verify.py evidence.json \
  --pubkey audit-2026=<audit-public-key-hex> \
  --review-pubkey reviewer-2026=<review-public-key-hex>
```

A successful verification establishes, relative to the supplied trust anchors, that:

1. signed event hashes match;
2. audit signatures are valid;
3. chain sequence/order/links are intact;
4. record semantics match signed event schemas;
5. authorization-scope commitments are internally reconstructable and consistent;
6. v4 machine/purpose/immediate-parent identity metadata agrees with the committed scope;
7. any reviewed execution has a separately valid reviewer signature and matching authority/evaluation bindings;
8. the chain head can be independently recomputed.

It does not prove that signing services were uncompromised or that the public-key distribution channel itself was trustworthy.

## Durable PostgreSQL evidence

`PostgresAuditTrail` is the multi-worker durable evidence path. It:

- accepts Ed25519 signers only;
- obtains a transaction-scoped advisory lock for the logical stream;
- reads the current head while holding that lock;
- signs the next envelope against that exact head;
- persists event and envelope atomically;
- reloads the complete stream for independent verification;
- exposes the current head hash for external anchoring.

Integration tests exercise concurrent workers and verify one contiguous chain.

`PostgresGrantAuthority` provides atomic single-use grant lifecycle and delegation with database-owned time and root-to-leaf locking. It enforces the same v3/v4 identity and delegation rules as the in-memory authority.

## External anchoring contract

`HeadAnchorStatement` contains:

- statement schema;
- stream ID;
- current sequence;
- current head-envelope hash;
- audit key ID;
- observation time.

`anchor_statement_digest()` produces the canonical SHA-256 commitment over the complete statement.

A provider implementing `HeadAnchorPublisher` must return an `AnchorPublication` containing:

- durable external reference;
- the exact statement digest it committed.

AgentShield rejects:

- legacy reference-only publisher results;
- a provider-reported digest that differs from the locally recomputed canonical statement digest;
- HMAC chains presented as independently anchorable evidence.

Changing stream identity changes the anchor statement commitment.

**Deployment boundary:** the repository does not configure a real independently controlled anchoring service. Provider immutability, retention, independence and availability must be demonstrated by the selected concrete provider and production operations. Therefore do not claim production history is externally anchored until that exists.

## Export timestamp boundary

`exported_at_utc` is outer bundle metadata. It participates in the full bundle digest but is not itself an audit-signed event timestamp or external-anchor timestamp. Treat it as informational export metadata only.

## Demonstration boundary

`examples/agentshield_verifiable_block_demo.py` demonstrates a destructive-action proposal against a production-like resource being BLOCKed and exported as signed evidence. It does not connect to or delete from a real production database.

The test suite also verifies receipt semantics, scope reconstruction, v4 agent/purpose binding, PostgreSQL delegation behavior, review proof portability, and separate-process verification.

## Remaining gates before external GA

The internal F1–F5 forensic findings are closed at the verified code head. The remaining release gates are deliberately outside the current code-only claim:

1. independent human/security review of the final diff;
2. a real independently controlled external anchoring provider with operational evidence;
3. production signing-key custody, rotation and authenticated public-key distribution;
4. protected canonical `main` with required reviews/status checks;
5. repository license choice;
6. controlled convergence through the PR #9 lineage before any merge to `main`;
7. detector research remains separate and cannot justify universal `100%` or `99.999%` prevention claims.

## Safe claim boundary

At the verified internal code head it is reasonable to say:

> AgentShield has a draft deterministic authorization and Ed25519 evidence layer that records ALLOW, REVIEW and BLOCK decisions, independently reconstructs canonical authorization-scope commitments, supports agent/purpose-bound immediate delegation, independently verifies reviewed executions with separate human-review trust anchors, persists one serialized PostgreSQL evidence stream, exports portable hash-chained evidence, and requires external anchor providers to commit the exact canonical chain-head statement.

Do not yet say:

- production history is externally anchored or impossible to truncate;
- arbitrary multi-hop delegation history is fully reconstructed from one receipt;
- every AgentShield deployment produces independent receipts;
- the format is an adopted IETF standard;
- independent human security review is complete;
- production key management is proven;
- AgentShield is 100% secure or has measured five-nines unauthorized-consequence prevention.
