# PR #6 Remediation — Independent Verification

**Branch:** `agentshield-pr6-audit-remediation` (draft PR #9 → `agentshield-ga-integration-2026-09-29`)
**Verified head:** `59d0d63` (35 commits on top of audited head `5c4467f`); follow-up fix `633cd0f`
**Date:** 2026-10-07
**Method:** fresh checkout; full suite on Python 3.11, 3.12, 3.13, 3.14 against live PostgreSQL 16; original exploit tests from `ed7727f` re-run unmodified; line review of every changed runtime module; nine-case adversarial battery against the F1 fix.
**Independence:** the remediation was written separately from this verification. This is still AI-assisted review, not the external human security review required as a GA gate.

---

## 1. Verdict

The remediation closes F1–F6 as specified, with one residual bypass in the F1 fix (F1b below), now fixed in `633cd0f`. After that commit no confirmed exploit remains in the reviewed scope.

**PR #6 is still not GA.** Remaining gates: LICENSE, external human review, main integration with branch protection, and the residual architecture items in §5.

| Finding | Fix on branch | Verified |
|---|---|---|
| F1 forged decision | In-process HMAC seal + Ed25519 detached evaluation signing | ✅ 7/7 forgery attacks held — **plus F1b bypass found and fixed** |
| F2 unbounded reuse | All executable grants single-use; legacy `single_use=False` rows → `REUSABLE_UNSUPPORTED` | ✅ |
| F3 caller clock | `now=` removed from all authority methods; injected clock (memory) / `clock_timestamp()` (PostgreSQL) | ✅ no caller-supplied time remains in any public authority method |
| F4 execution audit | Chained `grant_consumed` → `dispatch_completed` (executed/failed) envelopes; dispatch blocked if first audit write fails | ✅ with residuals (§5) |
| F5 review HMAC | `ReviewSigner` (Ed25519 private) / `ReviewVerifier` (public keys only) | ✅ gateway can no longer mint approvals |
| F6 workflows | Notebook workflow deleted; all actions SHA-pinned; every workflow has a `permissions:` block | ✅ |
| F7 hygiene | `tests/__init__.py` added; CI password replaced by `POSTGRES_HOST_AUTH_METHOD: trust` | ✅ — **LICENSE still absent** |

---

## 2. Test evidence

| Run | Result |
|---|---|
| Python 3.11 / 3.12 / 3.13 / 3.14 at `59d0d63`, live PostgreSQL | 165 / 165 each, 0 skipped |
| Same at `633cd0f` | 166 / 166 each, 0 skipped |
| GitHub checks at `59d0d63` | all success: Unit 3.11–3.14, PostgreSQL integration, Wheel/SBOM, dependency audit, CodeQL, GitGuardian |

### Exploit-test continuity

ChatGPT's standard was: *the same exploit tests fail before and pass after.* That standard is met for F1 only. Be precise about this in external evidence:

| Test | Original (`ed7727f`) re-run unmodified at `59d0d63` | Explanation |
|---|---|---|
| F1 | Errors (`issue()` no longer accepts `single_use`) | With only that fixture keyword removed, the **original attack body passes unchanged** |
| F2 | Errors (`single_use` removed) | The attack is now **unexpressible** through the public API; the rewritten test forges a legacy record directly and proves it fails closed |
| F3 | Errors (`now` removed) | Same: the vulnerable parameter no longer exists; the rewritten test proves expiry holds under an injected clock and that `now=` raises `TypeError` |

The honest evidence statement is: *F1 — same attack, now blocked. F2 and F3 — the vulnerable API surface was removed, and the rewritten tests prove the replacement fails closed.* Both are legitimate fixes. They are different kinds of evidence.

---

## 3. Adversarial battery against the F1 fix

| # | Attack | Result |
|---|---|---|
| 1 | Original F1: `replace()` BLOCK → ALLOW (seal copied along) | Held — seal mismatch → treated as unsigned detached |
| 2 | Forged ALLOW carrying a seal transplanted from a different genuine ALLOW | Held |
| 3 | Detached REVIEW validly signed, flipped to ALLOW, signature reused | Held — `mismatch` |
| 4 | Detached ALLOW signed by attacker key relabelled with trusted `key_id` | Held — `invalid_signature` |
| 5 | Valid signed detached ALLOW replayed | First use executes (correct); replay held — grant consumed |
| 6 | Valid signed ALLOW for grant A presented with grant B | Held — grant identity |
| 7 | Sealed ALLOW with audit metadata (effect digest) mutated | Held — effect check |
| 8 | **Stateful `PipelineResult` subclass: forged fields to decision checks, genuine fields to seal check** | **BYPASS at `59d0d63` → BLOCK executed.** Held at `633cd0f` |

### F1b — residual bypass (fixed in `633cd0f`)

**Severity:** LOW–MEDIUM. It needs attacker-defined Python in the process, which the seal's own docstring places out of scope. It is still worth fixing: the payload path already rejects subclasses for exactly this reason, and an external reviewer would flag the inconsistency.

**Cause:** `enforce_and_execute` read `pipeline_result.policy.decision` at the top and compared it with the audit event, then later called `verify_in_process_evaluation`, which re-read the same attributes. A subclass with properties can return different values on each read.

**Fix:** reject anything other than exact `PipelineResult` / `PolicyDecision` / `DetectionResult` / `AuditEvent` (and a plain-`dict` metadata) before reading any field. Frozen dataclasses of exact type are read-stable, so the checks and the seal see the same data.

**Regression:** `test_f1b_stateful_subclass_cannot_split_seal_from_decision`. It locates the seal path by caller frame rather than read count, so it stays valid if the read order changes. It fails at `59d0d63` (`EXECUTED`) and passes at `633cd0f`.

---

## 4. What the F1 seal does and does not prove

The in-process seal authenticates *"produced by `evaluate_request` in this process, unmodified"*. It does **not** authenticate *"produced with the host's configured detector and provenance"*. `detector` and `provenance` are arguments to `evaluate_request`, so any code that can call it can obtain a genuine seal on an evaluation of its choosing.

That is the same trust assumption as before ("the pipeline must stay outside agent control"), but now narrower and explicit. The impact is bounded by the other layers, which held in every test:

- Sensitive actions always resolve to REVIEW and need an Ed25519 human approval the gateway cannot mint.
- Only host-issued, exact-effect, single-use grants can execute.

So the worst case for a compromised evaluation caller is **one execution of one host-approved, normal-tier effect per grant**. That is the containment property the EIC narrative should rest on.

To close it rather than bound it, expose a host-constructed `Evaluator` object that holds the detector, the provenance policy and the signing key, and have the gateway accept only results that carry that evaluator's signature.

---

## 5. Residual items (not exploits; must be stated in GA_READINESS)

1. **The default audit trail is process-local and unbounded.** `_PROCESS_AUDIT_TRAIL` holds every event and envelope in memory for the life of the process, which is a slow memory leak in long-running workers. Each worker also has its own chain (separate sequence 0 and head), so a multi-worker deployment has no single tamper-evident order even though grants are serialized in PostgreSQL. Fix: require an injected `AuditTrail` in production (or fail closed without one), and add a PostgreSQL-backed trail that assigns the sequence under the same transaction discipline as grants.
2. **Audit envelopes are still HMAC.** The audit writer can rewrite history, and tail truncation is undetectable without external head anchoring. The docs say so; it should also be listed as a GA gate, or audit signing should move to Ed25519 like review.
3. **`EXECUTED_AUDIT_FAILED`** correctly reports a side effect whose final audit write failed. Hosts must alert on it. Document the required operator response.
4. **LICENSE** is absent. This is a hard blocker for GA and for any EIC IP statement.
5. **`main`** still carries `tmp-notebook-run.yml` and `agentshield-eval.yml` in their old form. They disappear only when PR #6 merges. Draft PR #2 (`tmp-notebook-run → main`) is still open; close it.
6. **No `.gitignore`.** Local runs leave `__pycache__/` and `*.egg-info/` untracked.

---

## 6. Recommended next steps

1. CI is green on `633cd0f` (all 17 checks). Merge PR #9 into the GA branch.
2. Choose the license.
3. Address §5.1 (the audit trail is the only residual with operational impact).
4. Commission one external human review of the merged GA branch. Give the reviewer the original audit, this verification, and the exploit tests. That review is the TRL and validation evidence the EIC application currently lacks.
5. Keep the claim language from the original audit: architectural containment (§4) as the headline; detector performance reported separately, with confidence intervals and adaptive-attack results. Neither this verification nor the test suite measures a 99.999% rate.
