# AgentShield PR #10 — Verifiable Evidence Forensic Audit

Date: 2026-10-07

PR: #10 `AgentShield: verifiable evidence layer v1`

Audit baseline initially reviewed: `55a14ed157600b1de31a0def2a930496e36abcea`

Current remediation head at the time this audit note was created: `8a043f177872267d8db7aac0fd4a1a650d659e8e`

Status: **BLOCK — do not merge yet**

This is a read/repair forensic pass against the evidence and authority claims of PR #10. It does not weaken security, scientific-integrity, CI, release, or review gates. `main` remains untouched.

## Scope of review

The review follows the authority/evidence path end to end:

1. authorization identity and scope binding;
2. delegation preservation;
3. policy decision evidence;
4. human-review binding;
5. execution lifecycle evidence;
6. portable receipt semantics;
7. standalone offline verification;
8. PostgreSQL durable evidence;
9. external head anchoring.

## Findings

### F1 — Portable record type was not authenticated semantically

Severity: **High**

Status: **Remediated in branch; exact-head CI still required**

The audit envelope signs the event, not the outer `EvidenceRecord.record_type`. Before remediation, a valid signed execution event could be relabelled as `policy_decision` (or vice versa) without changing the signed event or envelope. Both `verify_bundle()` and the standalone verifier ignored the wrapper field and would still accept the cryptographic chain.

This is not an Ed25519 forgery, but it is a dangerous semantic-integrity failure for consumers that dispatch logic based on `record_type`.

Remediation:

- `verify_bundle()` now derives the expected record type from the signed event schema and fails closed on mismatch;
- `tools/agentshield_verify.py` now requires `record_type` and independently derives/compares it;
- in-process and standalone regressions were added for record relabelling.

Remediation commits:

- `a15681f0c63ee8b1b962b9e263cd34620f516466`
- `a4954a188b9a59794d713f1d1c14741a594a9e0b`
- `e1d167fbeb913596087c1fc75ea5c38c176a01a7`
- `8a043f177872267d8db7aac0fd4a1a650d659e8e`

Do not mark closed for release until exact-head GA and CodeQL are green.

### F2 — Receipt does not yet independently prove the authorization-scope material

Severity: **High**

Status: **Open**

`agentshield-scope-v3` correctly binds `grant_id`, issuer, principal, tenant, capabilities and exact-effect digests into `authorization_scope_digest`. The decision event surfaces the scope digest plus selected identity fields.

However, the portable receipt does not carry the complete canonical scope material needed by an independent verifier to recompute that digest. With only the receipt and audit public key, an outsider can prove that AgentShield signed an event asserting a principal/tenant and a scope digest, but cannot independently prove that those displayed identity values were the exact values committed inside that digest.

Required remediation direction:

- define a privacy-safe canonical authorization-scope projection containing only digest-safe authority material;
- include it in signed decision evidence or as a separately signed receipt proof object;
- make both runtime and standalone verifiers recompute `authorization_scope_digest` from that material and fail closed on mismatch;
- add substitution regressions for principal, tenant, capability set, grant id and exact-effect digest set.

Until closed, phrase the claim as signed evidence of AgentShield's authority decision, not as a fully self-contained third-party proof of the underlying authorization scope.

### F3 — Human-review approval is referenced by digest but is not portable proof

Severity: **High**

Status: **Open**

The runtime correctly verifies an Ed25519 `ReviewApproval` bound to request, action, payload, scope, tool manifest, policy version and evaluation digest before executing a REVIEW decision.

Execution evidence stores only `review_approval_digest`. The portable evidence bundle does not include the signed `ReviewApproval` object or enough verifier material to independently validate the human approval from the receipt alone.

Required remediation direction:

- add a receipt proof object for the signed review approval when REVIEW is executed;
- preserve the review signer key id and exact signed approval material;
- allow the offline verifier to receive review public-key trust anchors separately and validate the approval signature;
- cross-check the approval's scope/evaluation/action/payload/tool/policy digests against the signed decision and execution evidence;
- add missing/wrong-reviewer/wrong-key/replayed-approval/tampered-approval regressions.

Until closed, a portable receipt can prove that AgentShield's audit signer recorded a review-approval digest, not independently prove the reviewer signature itself.

### F4 — Current acting identity does not identify the autonomous agent

Severity: **Medium / product-critical**

Status: **Open**

The current scope binds issuer, principal and tenant. It does not bind the concrete autonomous actor (`agent_id`) or a host-defined task/purpose identifier.

This means multiple agents acting for the same principal/tenant are not distinguishable in the authorization scope itself.

Required design work before implementation:

- define whether `agent_id` is immutable or intentionally changes during delegation;
- define explicit delegation lineage when one agent delegates to another;
- define host-controlled `purpose_id` semantics and whether purpose is immutable or attenuable;
- version the scope digest again only after these semantics are frozen;
- ensure in-memory, PostgreSQL, review, execution and receipt evidence all preserve the model.

Do not add these as cosmetic receipt fields. They must be authority-bound.

### F5 — External anchor statement does not cryptographically bind stream identity itself

Severity: **Medium**

Status: **Open / deployment-boundary design**

`HeadAnchorStatement` contains `stream_id`, sequence, head-envelope hash, audit key id and observed time. The referenced head envelope is Ed25519 signed, but `stream_id` and the complete anchor statement are not themselves signed by the audit key. `publish_head_anchor()` also treats any non-empty publisher reference as a successful durable publication.

A real provider adapter may make this trustworthy operationally, but the generic contract alone does not prove that the external reference commits to the exact statement bytes or that the caller-supplied stream label belongs to the signed chain.

Required direction:

- define provider requirements for immutable statement-byte commitment;
- consider signing or hashing the canonical anchor statement and requiring the external receipt to bind that digest;
- define how `stream_id` maps to tenant/agent identity and how a verifier checks that mapping;
- add provider-conformance tests once a real anchor backend is selected.

The existing code is appropriately honest that no real external anchor is configured; retain that boundary.

### F6 — Export timestamp is bundle metadata, not signed event evidence

Severity: **Low**

Status: **Open / documentation hardening**

`exported_at_utc` is included in the outer evidence bundle and bundle digest, but not in the signed audit events/envelopes. The offline verifier validates the chain without authenticating the export timestamp.

This is acceptable if documented as informational export metadata. It must not be presented as an independently authenticated event time or anchor time.

## Positive findings

The review confirms several strong properties at the audited baseline:

- Ed25519 private-sign/public-verify separation for audit evidence;
- contiguous zero-based hash-chain verification with first-invalid-record reporting;
- fail-closed policy decision persistence when an evidence trail is configured;
- principal/tenant binding inside scope v3 and preservation during delegation;
- exact-effect authorization and single-use/replay-resistant grants inherited from PR #9;
- PostgreSQL advisory-lock serialization for one durable multi-worker evidence stream;
- explicit refusal to claim a fake local store as an external trust anchor;
- direct policy version on execution evidence through the execution-event builder default after stale-policy rejection;
- destructive-action BLOCK demonstration that does not execute a real destructive side effect.

## Release verdict

**BLOCK — minor wording changes are not enough.**

F1 is repaired in the branch but must earn a new exact-head green run. F2 and F3 are the principal technical blockers to positioning the current JSON bundle as a self-contained verifiable-authority receipt. F4 is the principal product-identity blocker for a multi-agent gateway. F5 must be addressed when selecting a real external anchoring provider.

Do not merge PR #10 or promote its claim boundary until the new head is green and the open High findings are either fixed or explicitly moved outside the receipt's advertised assurance boundary.
