# AgentShield PR #10 — Independent Forensic Security Audit

Date: 2026-10-07 · Reviewer role: independent adversarial security / protocol / distributed-systems review (AI-assisted; this is **not** the independent *human* review the release gates require).

## B. Audited SHA

| | SHA |
|---|---|
| **Audited PR #10 head** (verified as the live head before work began) | **`e7c64ea5155d8b2717ed8b3cbb3de85010541e7d`** |
| PR #10 base = PR #9 head | `7339e389fa0f05358d2f5bcae48482320f28ac6d` (verified ancestor) |
| Remediated code head pushed by this audit (all CI green) | `f4f1ef0b04b8cf7ed5232ae9c81d3243bbf6a984` |
| Final head | the commit adding this report: one regression test strengthened (no runtime change) plus documentation; its CI runs are recorded on PR #10 |

Scope: the full PR #10 diff against its base (28 files, +3,686/−86) plus inherited PR #9 behaviour it depends on (grants, PostgreSQL grants, policy, pipeline, signing, review, tools, effects, actions). Commits `337c26f..e7c64ea` were confirmed documentation-only.

## A. Executive verdict

**At `e7c64ea`: MAJOR REVISION REQUIRED.**
**At remediated head `f4f1ef0`: PASS WITH CONDITIONS (internal code only).**

The authorization core is strong. Every delegation, substitution, downgrade, replay and race attack attempted against both the in-memory and the PostgreSQL authority failed, with identical semantics in both. The evidence cryptography (Ed25519 envelopes, canonical signatures, exact envelope shape, schema fail-closed) holds for the envelope layer.

The weaknesses were one level up, in what the gateway trusts and what a receipt actually proves:

1. **The gateway trusted caller-supplied object identity.** An approval a reviewer signed for message A executed an unreviewed message B. A `read_data` grant dispatched `funds.transfer` without review. Both need attacker-controlled Python objects inside the gateway's process, which is the exact type-confusion class the gateway already claimed to defend against for `PipelineResult`.
2. **Receipts did not prove authority before execution.** A validly signed receipt could show a REVIEW-held request "executed" under ALLOW, with a different grant, a different effect, or no authorizing decision at all. Both verifiers accepted it.
3. **Durable PostgreSQL evidence could silently become unverifiable.** JSONB rewrites `-0.0` and exponent floats. One detector score of `-0.0` from the shipped pipeline made the entire stream fail verification from record 0.
4. **F2 was not fully closed.** A decision displaying principal/tenant/grant identity with no scope commitment verified as valid.

All four, plus five lower findings, are fixed at `f4f1ef0`, with 20 exploit regressions and 2 over-blocking guards. Every exploit regression was confirmed to fail on an untouched `e7c64ea` worktree; the two guards pass on both heads by design. Conditions for progression are in sections J and K.

## C. Findings

Severity reflects the realistic attacker. "In-process" means the attacker must control Python objects passed into `enforce_and_execute`. A model, remote client or tool output cannot do this.

| ID | Sev. | Component | Exploit / failure mode | Evidence | Status | Remediation |
|---|---|---|---|---|---|---|
| N1 | **Medium** (High where the executor is reachable only through the gateway by semi-trusted in-process callers) | Execution gateway | (a) `ActionDescriptor` subclass answers `docs.read` to every check and `funds.transfer` at dispatch: a `read_data` grant executes a transfer with no review, and evidence records two different action names. (b) `str`-subclass fields in a `ReviewApproval` compare equal to anything while Ed25519 verifies the genuine bytes: an approval for request A authorizes request B. (c) Audit metadata was read before the seal check, so forged digests restored mid-call let an un-evaluated payload execute. (d) A `str`-subclass `grant_id` passed every check, consumed the grant, then crashed. | PoC + `GatewayTypeConfusionTests` (4 exploits; all fail at `e7c64ea`) | **Fixed** `b1fe2f8` | All caller objects (evaluation, action, scope, approval, evaluation signature) are re-materialized from exact built-in types before any check. The seal, every binding check and the dispatch use only those snapshots. |
| N2 | **Medium** | Receipts, both verifiers | Execution records were never linked to policy decisions except through the review path. A signed chain could show a REVIEW or BLOCK request executed as ALLOW, with a substituted grant, effect or action name, or with no decision at all, and still verify. "Authority before execution" therefore rested on the writer's word. | `ExecutionLinkageTests` (6 cases; all fail at `e7c64ea`) | **Fixed** `d5bfc07` | Every execution transition must resolve to exactly one earlier signed decision with the same request, evaluation, decision (ALLOW/REVIEW only), policy, action, grant and effect. The effect must be in the reconstructed scope commitment, and lifecycle order is enforced. |
| N3 | **Low** | Receipts, both verifiers | `startswith("agentshield-execution-audit-event-")` gave execution semantics to `…-v999`. The spec stated this must not happen; the code still did it. Demoting to an opaque record would hide such events from linkage, so neither outcome is safe. | `test_unknown_future_execution_schema…` | **Fixed** `d5bfc07` | Exact schemas only. Unknown `agentshield-*` schemas are `unsupported`: export refuses them and both verifiers fail with `SCHEMA_MISMATCH`. |
| N4 | **Medium** | `PostgresAuditTrail` | JSONB drops `-0.0` and rewrites `1e16` as an integer. The append commits, the reload hashes differently, and the whole stream is unverifiable from that record on. Reachable from the shipped pipeline via a detector score of `-0.0`. | PoC + `test_platform_postgres_evidence_fidelity.py` (fails at `e7c64ea`) | **Fixed** `34d5fe0` | `INSERT … RETURNING event_json` with an in-transaction hash check; lossy events roll back and fail closed. `-0.0` detector scores are normalized at source. |
| N5 | **Low** | Review protocol | Review signatures accepted any `bytes.fromhex` text (uppercase, spaces), so one approval had several accepted digests. Portable proofs accepted re-encoded timestamps: the runtime verifier accepted bytes the reviewer never signed, and the standalone verifier rejected them, so the two disagreed. | `ReviewSignatureCanonicalizationTests`, `ReviewProofEncodingTests` | **Fixed** `75693c4`, `d5bfc07` | Canonical 128-hex lowercase signatures at the gateway and in both verifiers. A proof must equal its exact canonical signed form. |
| N6 | **Low** | Receipts, both verifiers | Unsigned bundle-level and record-level fields (`"verified": true`, `"audited_by": …`) rode along with valid evidence. F8 had fixed this only at envelope level. | `test_unsigned_bundle_and_record_wrapper_fields…` | **Fixed** `d5bfc07` | Exact field sets for bundle, record and envelope. |
| N7 | **Low** | Receipts, both verifiers | A malformed `key_id` (list) crashed the runtime verifier with `AttributeError` and the CLI with a traceback. Fail-closed by accident, outside the API contract. | `test_malformed_envelope_values…` | **Fixed** `d5bfc07` | Exact envelope types; malformed input yields a structured verdict. |
| N8 | **Low** | Execution gateway | `KeyboardInterrupt`/`SystemExit` during dispatch left evidence ending at "admitted" for a dispatch that was attempted. | `InterruptedDispatchEvidenceTests` | **Fixed** `b1fe2f8` | Record `dispatch_completed/failed`, then re-raise. |
| F2-R | **Medium** | Receipts, both verifiers | Decision displaying `authorization_principal/tenant/grant_id` without material or digest skipped scope verification entirely. | `test_displayed_identity_without_scope_commitment…` | **Fixed** `f4f1ef0` | Any `authorization_*` field requires the canonical commitment. |
| N9 | **Medium** (design) | Receipt format | Verification must start at sequence 0, so a receipt for one action carries every earlier record in the stream, including other principals' and tenants' identities, grants and action names. There is no inclusion proof or checkpointed segment verification. | PoC H9 | **Open** | Minimum: one stream per tenant (ideally per principal). Proper fix: signed checkpoints plus Merkle inclusion proofs (a v2 receipt). |
| N10 | **Medium** (claim) | Gateway defaults | Evidence is optional. `evaluate_request` records nothing without `audit_trail`, and `enforce_and_execute` defaults to a process-ephemeral HMAC trail that is lost on exit and is not independently verifiable. "No action without evidence" holds only if the host wires it. | Code reading | **Open** | Add a strict mode that refuses execution without a durable Ed25519 trail and a decision record, or enforce it in the deployment profile. |
| N11 | **Low** | Anchoring | No offline function checks an `AnchorReceipt` against a bundle head. The anchor builder does not verify the head envelope's signature, and the statement's `audit_key_id` is an unverified label. | Code reading | **Open** | Add anchor-receipt verification to the standalone verifier; verify the head before anchoring. |
| N12 | **Low** | PostgreSQL | No `lock_timeout`/`statement_timeout`. A stuck transaction holding a stream's advisory lock blocks every append, and therefore every governed execution, indefinitely (fail-closed availability loss). | Code reading | **Open** | Set per-transaction timeouts; alert on lock waits. |
| N13 | **Low** | CI | CodeQL paths covered only `agentshield/**`, so a change to `tools/agentshield_verify.py` alone was never scanned. | Workflow diff | **Fixed** `120cd0b` | Paths widened. |
| N14 | **Info** | Receipts | `bundle_digest` was documented as "stable … for external anchoring" but covers the unsigned `exported_at_utc`. | Code reading | **Fixed** `d5bfc07` (docstring) | Anchor the chain head, not the bundle digest. |
| N15 | **Medium** (production) | Keys | Verifiers accept any trusted key for any sequence: no key validity windows, revocation or compromise cut-over. `key_id` is a free label. Nothing prevents one Ed25519 key serving the audit, review and evaluation roles (message domain separation limits cross-protocol forgery, but role separation is unenforced). No KMS/HSM boundary or authenticated key distribution. | Code reading | **Open** | See section J. |
| N16 | **Info** | Detached evaluation | `EvaluationSignature` accepts non-canonical hex. It is not persisted as evidence and replay is bounded by the single-use grant. | Code reading | Open (informational) | Canonicalize for consistency. |

## D. Attack-surface map

| Layer | What was attacked | Result at `e7c64ea` | At `f4f1ef0` |
|---|---|---|---|
| Decision | Policy routing, detector influence, unknown capabilities | Sound. Sensitive actions never ALLOW; unknown capabilities route to REVIEW; tool, grant, scope and effect failures BLOCK | Unchanged |
| Authority | Fake parents/delegators, purpose/tenant/principal/issuer substitution, v3↔v4 upgrade/downgrade, capability and effect amplification, sibling races, cycles, depth, replay, revocation, 16-way concurrent consume, 12-way concurrent delegation | **All rejected, identically in memory and PostgreSQL**; exactly 1 winner per race; depth capped at 8 hops | Unchanged |
| Review | Substitution, replay, expiry, unknown key, encoding manipulation, type confusion | Signature, expiry and binding sound for genuine objects. **Bypass via type confusion (N1b)**; encoding malleability (N5) | Fixed |
| Execution | Mutation/substitution of action, payload, scope, grant, tool, policy, decision, detector, evaluation; TOCTOU; double dispatch; exceptions | Payload snapshot, digest binding, single-use consume-before-dispatch and audit-before-dispatch all sound. **Caller-object identity trusted (N1)**; BaseException gap (N8) | Fixed |
| Evidence | Signature malleability, schema confusion, relabelling, wrapper fields, canonical JSON (Unicode, duplicate keys, int/float, NaN, null) | Envelope layer sound: every signed field is in the signature material and signatures are canonical. **Receipt semantics weak (N2, N3, N6, F2-R)** | Fixed. N9 open |
| Database | Forks, lock ordering, rollback, sequence uniqueness, fidelity | No forks (advisory lock plus PK `(stream_id, sequence)` as backstop); 24-way concurrent appends form one valid chain. **JSONB fidelity (N4)**; no timeouts (N12) | N4 fixed; N12 open |
| Anchoring | Statement binding, digest lies, HMAC/unsupported schema | Statement binds stream, sequence, head, key, time; mismatched digests and HMAC are rejected. No offline anchor verification (N11); provider honesty is unprovable in-repo | N11 open |
| Keys | Rotation, revocation, separation, distribution | Development-grade only (N15) | Open |
| CI/release | Path filters, skipped jobs, exact-head evidence | Green and real (section F). CodeQL path gap (N13) | N13 fixed; repository gates open |

Canonical-JSON notes. Duplicate JSON keys collapse on parse before hashing, so they cannot yield a second accepted hash. Integer vs float (`1` vs `1.0`) and NFC vs NFD Unicode produce different bytes and therefore fail the signature rather than creating ambiguity. `allow_nan=False` rejects NaN/Infinity everywhere. Event timestamps are writer-clock strings that are signed but not monotonicity-checked; the security-relevant times (grant validity, review validity) are authority-owned. **Answer to the brief's central question:** after remediation, no two distinct accepted JSON representations of the same signed authority yield different accepted head hashes, review digests or verdicts. Before remediation that was true for envelopes but false for review proofs (N5).

## E. Trust-boundary analysis

| Component | If compromised… | Can forge | Can execute | Still independently detectable |
|---|---|---|---|---|
| Host application | Total: it supplies the executor, scope and registry | Whatever its keys allow | Anything, by calling the executor directly | Only records that were signed; a bypassed gateway leaves no evidence (N10) |
| Policy engine (in-process) | Wrong decisions | Signed decisions via the evaluation/audit keys it can reach | Within live grants | Effect ∈ scope, grant and review linkage (N2 checks) |
| Model | Hostile proposals only | Nothing | Nothing outside grants; sensitive actions require review | Full decision trail |
| Tool registry | Mislabelled capabilities | — | Under-declared tools pass as NORMAL | Manifest digest is in evidence; semantic truth is not |
| Grant authority / PostgreSQL grants | Issue or revive grants | Any scope | Any effect it grants | Scope material in receipts shows what was granted, not whether it should have been |
| PostgreSQL (evidence) | Delete, reorder or truncate rows | Nothing signed | Nothing | Edits and reordering fail verification; **tail truncation only with an external anchor** |
| Audit signer | Rewrite history | Entire chains | — | Only against an earlier external anchor |
| Review signer | Approve anything | Any approval, any `reviewer` string | REVIEW actions within grants | Approvals are attributable to the review key, not to a person (no per-reviewer keys) |
| Evaluation signer | Forge detached ALLOW/REVIEW | Evaluations | Within live single-use grants | Linkage and effect-in-scope checks |
| Executor/tool | Do something other than asked | Its own output | Anything within its own privileges | Evidence proves what was *authorized and dispatched*, not what the tool *did* |
| Anchor provider | Lie about commitment | False inclusion | — | Not detectable in-repo; needs a transparency log with public auditability |
| Public-key distribution | Substitute keys | Everything downstream | — | Nothing. This is the root of trust and is currently out-of-band raw hex |
| Human reviewer | Approves a bad action | — | That one exact action | The approval is bound to exact digests, so the error is attributable and non-transferable |

## F. CI and release-gate audit

- Runs 37676428942 (GA) and 37676428993 (CodeQL) belong to `e7c64ea` exactly (`pull_request`, branch `agentshield-verifiable-evidence-v1`). All 7 GA jobs succeeded with no skipped steps: Python 3.11/3.12/3.13/3.14 units, PostgreSQL integration (`test_platform_postgres_*`, service `postgres:16.15-alpine`), wheel/SBOM, `pip-audit`. CodeQL ran `security-extended` over the whole checkout.
- Job logs are served from Azure blob storage, which this audit environment could not reach. Test execution was therefore **reproduced locally** against PostgreSQL 16.15: 221 platform tests and 26 PostgreSQL tests passed with no skips at `e7c64ea`.
- PR #10's workflow change only adds paths and broadens the PostgreSQL step from one module to all `test_platform_postgres_*`. No weakening was found. Action versions are SHA-pinned. Permissions are `contents: read`, plus `security-events: write` for CodeQL.
- Residual CI notes: CodeQL path gap (N13, fixed). PostgreSQL tests skip silently when the DSN is absent, which is correct for unit jobs, and the dedicated job sets the DSN. Code-scanning results were not readable via API (HTTP 403), so CodeQL "success" means the analysis ran, not that alert counts were inspected.
- Remediated heads: `12ed044` (GA 37681270809, CodeQL 37681270923) and `f4f1ef0` (GA 37681437049, CodeQL 37681437179). All jobs green. Local at the final head: 243 platform and 28 PostgreSQL tests pass.
- Repository gates re-checked via API on 2026-10-07: `main` `protected: false`; 0 rulesets and 0 branch rules; `license: null`; PR #9 and PR #10 each have **0 reviews**; both are draft.

## G. Claim-boundary audit

| Claim | Verdict | Defensible wording today |
|---|---|---|
| "Verifiable Authority for AI Actions" | **Acceptable as a product tagline only with scope** | "…for actions routed through the AgentShield gateway in evidence mode" |
| "Proof before AI acts" | **Not as stated** | "Signed authorization evidence is recorded before an action is dispatched" |
| "Every consequential action can produce independently verifiable evidence" | **No**: "every" is false (bypass, default ephemeral trail, N10) | "Every action executed through the gateway with an Ed25519 trail produces an independently verifiable receipt" |
| "Prevents unauthorized AI actions" | **No, unqualified** | "Blocks actions that lack valid, exact, single-use authority at its execution gateway" |
| "Provides non-repudiation" | **No**: operator-held keys, no external anchor, no per-reviewer keys | "Tamper-evident, writer-signed evidence" |
| "Tamper-proof audit logs" | **No**: signer compromise and tail truncation without anchor | "Tamper-evident, hash-chained, Ed25519-signed" |
| "Five-nines security" | **No**: no measurement basis | Do not use |
| "100% secure" | **No** | Do not use |

Evidence tiers:
- **Proven by code and tests:** exact-effect single-use authority; v3/v4 identity binding and immediate delegation; consume-before-dispatch; audit-before-dispatch; signed decisions and execution transitions; receipt linkage and scope reconstruction; canonical encodings; serialized PostgreSQL streams.
- **Proven only in development:** PostgreSQL behaviour on a single node; concurrency at 16–24 threads.
- **Requires production evidence:** key custody and rotation; external anchoring; durability under failover; performance.
- **Not proven:** non-repudiation; truncation resistance; prevention outside the gateway; detector efficacy; any availability figure.

## H. Independent reproduction of F1–F8

| ID | Prior status | Reproduced attack | Result |
|---|---|---|---|
| F1 relabelling | Closed | Relabel signed execution as `policy_decision` | **Closed.** Adjacent prefix weakness found and fixed as N3 |
| F2 scope proof | Closed | Tamper material/digest/identity; omit material while displaying identity | **Was incomplete** (F2-R): fixed `f4f1ef0` |
| F3 portable review | Closed | Missing, extra, duplicate, tampered, unknown-key proofs | **Closed** for those cases; encoding malleability fixed as N5 |
| F4 machine identity | Closed (immediate) | Section D authority matrix, both backends | **Closed for immediate delegation.** Multi-hop lineage is not in receipts (documented) |
| F5 anchor contract | Closed (software) | Digest mismatch, HMAC, unsupported schema | **Closed at contract level.** No offline anchor verification (N11); provider honesty unprovable in-repo |
| F6 export timestamp | Documented | Edit `exported_at_utc` | **Accurate boundary.** `bundle_digest` doc corrected (N14) |
| F7 envelope schema | Closed | Unsupported envelope schema at runtime and anchoring | **Closed.** Event-schema analogue was open (N3), now fixed |
| F8 head malleability | Closed | Whitespace/uppercase signatures, `sequence: true/1.0`, extra envelope fields | **Closed for envelopes** (every signed field is in signature material). Wrapper analogue (N6) and review analogue (N5) fixed |

## I. New tests

22 tests are in `agentshield/tests/test_platform_forensic_regressions.py` and `test_platform_postgres_evidence_fidelity.py`: 20 exploit regressions, each of which fails on an untouched `e7c64ea` worktree and passes at the remediated head, plus 2 guards (marked) that pass on both heads and exist to catch over-blocking. Evidence tests run both the runtime verifier and the standalone CLI (`python -I`, separate process).

| Test | Exploit prevented |
|---|---|
| `test_action_whose_name_changes_between_check_and_dispatch_is_blocked` | Grant for one tool dispatches another (calibrated to the real dispatch read) |
| `test_review_approval_with_lying_fields_cannot_authorize_another_request` | Reviewer approval for A executes unreviewed B |
| `test_scope_with_lying_grant_id_is_blocked` | Scope type confusion consuming grants then crashing |
| `test_metadata_swapped_back_before_seal_check…` | Check/seal TOCTOU executing an un-evaluated payload |
| `test_genuine_flows_still_execute_after_snapshotting` (guard) | Over-blocking of legitimate executions |
| `test_gateway_rejects_uppercase_review_signature` | Alternate signature encodings yielding multiple approval digests |
| `test_genuine_allow_and_review_receipts_verify` (guard) | Over-rejection of legitimate receipts |
| `test_review_decision_cannot_be_receipted_as_allow_execution` | Held action shown executed without approval |
| `test_block_decision_cannot_be_followed_by_execution` | BLOCKed action shown executed |
| `test_execution_with_substituted_grant_or_effect_is_rejected` | Grant, effect or action substitution in execution evidence |
| `test_execution_without_any_authorizing_decision_is_rejected` | Orphan execution receipts |
| `test_dispatch_without_grant_consumption_or_twice_is_rejected` | Lifecycle-order forgery and double dispatch |
| `test_unknown_future_execution_schema_is_not_given_v1_semantics` | Schema prefix confusion, both promotion and demotion |
| `test_displayed_identity_without_scope_commitment_is_rejected` | Unbound displayed authority identity (F2-R) |
| `test_unsigned_bundle_and_record_wrapper_fields_are_rejected` | Unsigned banners on verifying evidence |
| `test_malformed_envelope_values_yield_a_verdict_not_a_crash` | Verifier crashes on hostile JSON types |
| `test_reencoded_review_proof_rejected_by_both_verifiers` | Accepting unsigned bytes; verifier disagreement |
| `test_receipt_consistently_built_on_noncanonical_review_signature_rejected` | A receipt built end-to-end on an alternate signature encoding, giving one approval a second accepted digest |
| `test_keyboard_interrupt_records_failed_completion_then_propagates` | Evidence ending at "admitted" after a real dispatch |
| `test_negative_zero_score_is_normalized` | Source of JSONB-lossy detector scores |
| `test_lossy_event_is_refused_instead_of_silently_breaking_the_stream` (PostgreSQL) | Silent permanent loss of stream verifiability |
| `test_pipeline_negative_zero_detector_score_keeps_durable_receipt_verifiable` (PostgreSQL) | Same, via the shipped pipeline |

One existing test fixture changed: `test_platform_receipts.py` used a synthetic execution record with no authorizing decision, which is exactly the receipt shape N2 now rejects. It was rebuilt from a real evaluate→execute flow. The record count moved from 2 to 3 because a genuine execution emits one decision and two transitions. No assertion was relaxed and no test was deleted.

## J. Remaining external blockers

1. **Independent human security review** of PR #9, PR #10 and this remediation (currently 0 reviews on each).
2. **Repository controls:** protect `main` (required reviews and required GA + CodeQL checks); add a ruleset; choose a licence.
3. **Key management (N15):** KMS/HSM-held keys per role (audit / review / evaluation) and per tenant; key validity windows enforced by verifiers; revocation and compromise cut-over; authenticated public-key distribution (signed key manifest or transparency log). Raw hex out-of-band is a root of trust, not a mechanism.
4. **External anchoring:** a real independent provider (for example a transparency log or RFC 3161 TSA) behind `HeadAnchorPublisher`, plus offline anchor verification (N11).
5. **Receipt privacy and scale (N9):** per-tenant streams now; checkpoints with inclusion proofs for a v2 receipt.
6. **Evidence-mandatory mode (N10)** before claiming "no action without evidence".
7. **Operational:** PostgreSQL lock and statement timeouts (N12); failover and durability testing.

## K. Final recommendation

**Safe to request independent review.**

Not yet safe to converge into PR #9 or merge toward `main`. Convergence should follow a human review of the PR #9 + PR #10 + remediation diff and the repository controls in J.2. PR #10 remains **draft**. Nothing was merged and `main` was not touched.

## Standards sanity check (adopt only where it adds assurance or interoperability)

- **High value.** Sigstore Rekor or an RFC 3161 TSA as concrete anchor providers. SPIFFE/WIMSE workload identity behind v4 `agent_id`, so agent identity is attested rather than asserted. The IETF WIMSE work on agent authentication/authorization (`draft-klrc-aiagent-auth`, now continued as `draft-ietf-wimse-aims`) builds on WIMSE and OAuth and is the closest standards track to v4's model.
- **Medium value.** DSSE/in-toto envelope wrapping of receipts for ecosystem tooling. OAuth Rich Authorization Requests to carry exact effects from enterprise IdPs. DPoP/mTLS to bind grant use to the gateway key. MCP authorization at the tool-call boundary, mapping MCP calls onto `ActionDescriptor` and the gateway.
- **Low value now.** OPA or Cedar (current policy is deterministic and versioned; adopt only for customer-authored policy). W3C Verifiable Credentials. OpenTelemetry (useful operationally if spans carry envelope hashes, but no assurance gain).
- **Guidance.** NIST NCCoE's software and AI agent identity and authorization project is at concept-paper / comment stage (Feb 2026), not normative. OWASP agentic-AI guidance ("excessive agency") is directly addressed by exact-effect single-use grants. Cite these as alignment, not conformance.

Sources: [NIST NCCoE — Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) · [NIST concept paper announcement (Feb 2026)](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents) · [IETF draft-klrc-aiagent-auth (datatracker)](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)
