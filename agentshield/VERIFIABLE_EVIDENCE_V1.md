# AgentShield Verifiable Evidence v1

Status: **draft / stacked on the PR #9 remediation branch**. Do not treat this document as a GA release claim.

## Goal

AgentShield should be able to prove what it decided and what crossed the execution boundary without requiring an auditor to trust the AgentShield service or receive a secret signing key.

The v1 evidence path therefore separates:

- **private signing authority** held by the evidence writer;
- **public verification authority** held by auditors, customers, regulators or other systems;
- **signed decision evidence** for ALLOW, REVIEW and BLOCK;
- **execution lifecycle evidence** for admitted actions;
- **portable JSON bundles** that can be taken away and checked offline;
- **durable multi-worker persistence** for one serialized evidence stream;
- **external trust anchors** supplied independently from the bundle and database.

## Cryptographic model

Portable evidence uses Ed25519 audit envelopes. `Ed25519AuditSigner` holds raw private keys. `Ed25519AuditVerifier` holds public keys only and exposes no signing operation.

The older `AuditSigner` HMAC path remains available for dependency-free local integrity and legacy/internal use. **HMAC evidence is not accepted by the portable bundle builder as independently verifiable evidence**, because anyone who can verify an HMAC also possesses the capability to forge one.

Each envelope binds:

- envelope schema version;
- signature algorithm;
- zero-based contiguous sequence number;
- previous-envelope hash;
- canonical event hash;
- key ID.

The next envelope hashes the complete previous envelope, creating an ordered chain. `verify_chain()` identifies the first broken event/link/signature.

## Decision evidence

`evaluate_request(..., audit_trail=trail)` synchronously appends the complete `AuditEvent` before returning the policy result. This covers:

- ALLOW;
- REVIEW;
- BLOCK.

A configured durable sink/trail failure propagates instead of silently returning an unaudited decision. Existing callers that do not opt into an evidence trail retain the legacy API behavior; such calls must not be advertised as producing independent receipts.

No raw prompt, action payload or tool output is added by the evidence layer. The evaluation event carries digests and structured policy metadata.

## Acting-for identity

`AuthorizationScope` now distinguishes:

- `issuer`: authority that minted the grant;
- `principal`: end-user/service on whose behalf the agent acts;
- `tenant`: containing organization/account.

Principal and tenant are part of `agentshield-scope-v3` and therefore part of the authoritative scope digest. They cannot be changed while reusing an issued grant, and delegation must preserve both fields. Signed decision evidence surfaces issuer/principal/tenant together with the scope digest.

**Migration:** grants issued against the older v2 scope digest must be reissued by trusted infrastructure. Failing closed on an old digest is intentional; the runtime must not silently reinterpret old grants as identity-bound authority.

## Portable evidence bundles

`agentshield.platform.receipts` defines the AgentShield-native draft profile:

- `agentshield-evidence-bundle-v1`
- `agentshield-verifiable-action-receipt-v1`

A bundle carries the exact signed event and audit envelope for each record. Public keys are intentionally **not** embedded as trusted keys. The verifier must receive the expected public key through an independent channel.

The profile is designed to map to emerging signed/hash-chained agent-receipt work, but **does not claim conformance to a final IETF standard**.

## Offline verifier

`tools/agentshield_verify.py` uses only the Python standard library and `cryptography`. It does not import the AgentShield runtime and does not contact AgentShield services.

Example:

```bash
python tools/agentshield_verify.py evidence.json \
  --pubkey audit-2026=<64-hex-character-raw-ed25519-public-key>
```

A successful verification establishes that, relative to the supplied public-key trust anchor:

1. every event matches its signed hash;
2. every Ed25519 signature is valid;
3. sequence/order and previous-envelope links are intact;
4. the chain head can be independently recomputed.

It does **not** by itself prove that the signing service was uncompromised, that the public-key distribution channel is trustworthy, or that no valid signed suffix was removed after the latest externally anchored head.

## Durable PostgreSQL evidence stream

`PostgresAuditTrail` is the multi-worker persistence path. It:

- accepts Ed25519 signers only;
- obtains a transaction-scoped advisory lock per table/stream;
- reads the current database head while holding that lock;
- signs the next envelope against that exact head;
- persists event + envelope in one transaction;
- can reload the chain for offline public-key verification;
- exposes the current head hash for external anchoring.

The integration suite races multiple workers against one stream and verifies that one contiguous chain is produced.

## External anchoring boundary

`HeadAnchorPublisher` / `publish_head_anchor()` define the handoff to an independently controlled transparency log, object-lock store, timestamping service or equivalent system. The runtime refuses to describe HMAC chains as independently anchorable evidence.

**The repository does not ship or configure an external anchoring provider.** A fake local anchor would not improve the trust model. Deployment evidence is only externally anchored once a real independently controlled provider accepts the chain-head statement and returns a durable reference.

## End-to-end refusal demonstration

`examples/agentshield_verifiable_block_demo.py` proposes a destructive `delete_data` action against `production.users`, receives a policy BLOCK, exports the signed BLOCK event, and prints the public key needed by the standalone verifier. The demonstration does not connect to or delete from a real database.

The test suite then invokes `tools/agentshield_verify.py` in a separate process and proves that rewriting the decision or signed event is detected.

## Still open before an external GA claim

This branch intentionally does not paper over the remaining work:

1. **Real external head anchoring.** Configure and operationally prove an independently controlled anchor provider; the integration contract alone is not an external anchor.
2. **Independent security review.** Internal and AI-assisted review is not a substitute for an external human/security review of the final diff.
3. **Repository/admin GA gates.** Main-branch protection, required checks/reviews, license choice and canonical-main convergence remain separate release gates.
4. **Production key management.** Private signing keys must be held outside agent control, rotated deliberately, and distributed to verifiers through an authenticated public-key channel.
5. **Detector claims.** Verifiable governance evidence does not establish universal prompt-injection detection or a 99.999% prevention rate.

## Safe claim boundary for this draft

Only after the exact-head test matrix is green, it is reasonable to say:

> AgentShield has a draft Ed25519-signed evidence layer that records ALLOW, REVIEW and BLOCK decisions, cryptographically binds acting principal/tenant identity into authorization, persists one serialized evidence chain across PostgreSQL workers, exports a portable hash-chained JSON bundle, and verifies that bundle offline with public keys only.

Do not yet say:

- every AgentShield deployment produces independent receipts;
- production history is externally anchored or impossible to truncate;
- the format is an adopted IETF standard;
- the implementation has received the required independent human security review;
- AgentShield is 100% secure or has measured five-nines unauthorized-consequence prevention.
