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
- **external trust anchors** supplied independently from the bundle.

## Cryptographic model

Portable evidence uses Ed25519 audit envelopes. `Ed25519AuditSigner` holds raw private keys. `Ed25519AuditVerifier` holds public keys only and exposes no signing operation.

The older `AuditSigner` HMAC path remains available for dependency-free local integrity and legacy/internal use. **HMAC evidence is not accepted by the portable bundle builder as independently verifiable evidence**, because anyone who can verify an HMAC also possesses the capability to forge one.

Each envelope binds:

- envelope schema version;
- signature algorithm;
- sequence number;
- previous-envelope hash;
- canonical event hash;
- key ID.

The next envelope hashes the complete previous envelope, creating an ordered chain.

## Decision evidence

`evaluate_request(..., audit_trail=trail)` synchronously appends the complete `AuditEvent` before returning the policy result. This covers:

- ALLOW;
- REVIEW;
- BLOCK.

A configured durable sink failure propagates instead of silently returning an unaudited decision. Existing callers that do not opt into an evidence trail retain the legacy API behavior; such calls must not be advertised as producing independent receipts.

No raw prompt, action payload or tool output is added by the evidence layer. The existing evaluation event carries digests and structured policy metadata.

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
3. record order and previous-envelope links are intact;
4. the chain head can be independently recomputed.

It does **not** by itself prove that the signing service was uncompromised, that the public-key distribution channel is trustworthy, or that no signed suffix was truncated after the last externally anchored head.

## Still open before an external GA claim

This branch intentionally does not paper over the remaining work:

1. **Principal / tenant binding.** The existing scope has an issuer but not a distinct end-user principal and tenant. These must be added through a versioned authorization-scope migration and preserved through delegation before receipts claim "acting for" identity.
2. **Durable evidence sink.** The `AuditSink` interface exists, but a production PostgreSQL receipt/evidence sink still needs to ship and be tested across workers.
3. **External head anchoring.** A chain can still be tail-truncated by a compromised writer unless recent head hashes are published outside the writer's control (for example object-lock storage or a transparency service).
4. **Independent security review.** Internal and AI-assisted review is not a substitute for an external human/security review of the final diff.
5. **Repository/admin GA gates.** Main-branch protection, required checks/reviews, license choice and canonical-main convergence remain separate release gates.
6. **Detector claims.** Verifiable governance evidence does not establish universal prompt-injection detection or a 99.999% prevention rate.

## Safe claim boundary for this draft

Once the exact-head tests are green, it is reasonable to say:

> AgentShield has a draft Ed25519-signed evidence path that can record ALLOW, REVIEW and BLOCK decisions, export a portable hash-chained JSON bundle, and verify that bundle offline with public keys only.

Do not yet say:

- every AgentShield deployment produces independent receipts;
- receipts prove an end-user/tenant identity;
- the history is externally anchored or impossible to truncate;
- the format is an adopted IETF standard;
- AgentShield is 100% secure or has measured five-nines unauthorized-consequence prevention.
