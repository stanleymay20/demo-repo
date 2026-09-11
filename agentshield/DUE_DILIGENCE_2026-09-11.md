# AgentShield Due Diligence — 2026-09-11

## Scope

This review treats `stanleymay20/demo-repo` as the AgentShield repository and evaluates the current repository presentation, scientific experiment lineage, platform security architecture, CI evidence, and production-readiness gaps. It does not reinterpret running experiments or overwrite the frozen academic baseline.

## Executive assessment

AgentShield is materially more advanced than the repository name and default branch suggest. The project contains a disciplined prompt-injection research programme and an emerging layered agent-security platform that correctly separates detector evidence from authorization and execution control.

The project is **not yet production-ready and should not currently be described as a validated breakthrough**. The strongest preserved high-recall experiment before the running v14 study does not satisfy the declared <=1% audit-FPR gate, the current external evidence is not a pristine untouched final holdout, and the repository lacks a canonical public trunk, branch/ruleset governance, release packaging, and production-grade durable authorization state.

## Repository identity and governance

Observed on review:

- public repository name: `demo-repo`;
- default branch: `main`;
- default `README.md` still identifies the repository only as `Demo`;
- the default branch does not contain the current AgentShield platform or research implementation;
- strategic work is distributed across experiment/platform branches;
- repository description, topics, homepage and license are not configured;
- no repository rulesets were returned by the GitHub API;
- inspected branch metadata showed the active AgentShield branches as unprotected;
- inspected recent commits were unsigned.

This makes the public repository substantially weaker as a product/research artifact than the underlying work deserves.

## Scientific-integrity assessment

### Strengths

The current v14 high-recall protocol explicitly:

- preserves the frozen academic baseline;
- treats >=90% recall as a research target rather than a quota;
- requires observed validation FPR <=1%;
- prohibits threshold loosening after audit results are seen;
- uses validation-only model and threshold selection followed by one-shot internal audit;
- does not access BrowseSafe benchmark/test labels in the experiment;
- removes normalized train/test content overlap using content hashes;
- preserves failed and negative results;
- explicitly states that a strong internal result would still not prove production security or an untouched external breakthrough.

This is a strong scientific posture.

### Preserved experiment evidence

| Experiment | Audit recall | Audit observed FPR | Interpretation |
|---|---:|---:|---|
| E01 sparse high-recall | 57.25% | 1.078% | Genuine improvement, but declared <=1% gate failed. |
| E03 ProtectAI specialist | 5.603% | 0.838% | Valid negative result. |
| E04 Wolf Defender Small v2 | 1.218% | 1.557% | Valid negative result; all declared gates fail. |
| v14 high-recall assessment | running | running | No metric may be promoted until workflow/evidence completes and is verified. |

E04 evidence was independently checked against GitHub Actions artifact `10274950248`; the artifact SHA-256 is `1fdd392c4c40f908d5218c30335f82a27f36ce963219aeb258ffdf122bebb937`.

### Methodological cautions

- `observed FPR <=1%` on an audit split with roughly hundreds of negative cases is not the same as establishing a population FPR <=1%. For a production/security claim, a larger untouched external holdout should be used and the upper confidence bound should be considered.
- Multiple models/hyperparameters/fusions are selected on one validation split. The one-shot audit is a useful control, but repeated historical use of related internal data means it should not become the final external claim set.
- BrowseSafe has historical exposure in the wider project, so future breakthrough claims require a genuinely untouched external corpus or independently curated/red-team holdout.

## Platform-security assessment

The platform branch is structurally sound in its central security idea: prompt-injection detection is a risk signal, not authorization.

Current controls include:

- explicit input provenance;
- versioned detector evidence;
- server-owned tool manifests/registry;
- action-consequence classification;
- least-privilege `AuthorizationScope`;
- server-owned `GrantAuthority` with expiry, revocation and single-use replay resistance;
- cryptographic bindings for action, payload, scope and tool manifest;
- fail-closed ALLOW / REVIEW / BLOCK decisions;
- execution-time mutation checks;
- structured audit events;
- separation of detector metrics from harmful-action/benign-completion system metrics.

The current `GrantAuthority` is deliberately in-memory and documents that a production deployment needs an atomic durable store for race-safe verify/consume across workers. That remains a production blocker, not merely an implementation detail.

## CI defect found and repaired during due diligence

The platform branch had a failing CI state after grant-authority/replay hardening. The core controls themselves were passing, but five scenario-contract tests still constructed `AuthorizationScope` objects without a trusted `GrantAuthority`. The policy correctly returned `REVIEW` instead of the old expected `ALLOW`.

The scenario harness was repaired without weakening the security contract: it now models a trusted host issuing the scenario grant and passes the same server-owned authority through evaluation and execution.

Repair commit: `03307b80c14562b12c8c5db274a2a47f1d1962ec`.

Post-repair GitHub Actions run `34640907666` completed successfully with **71/71 platform tests passing**.

## Major outstanding risks

### P0 — canonical repository/trunk

`main` is not AgentShield's real source of truth. A controlled integration path is needed after the current v14 experiment is frozen. Do not rewrite or mass-move running experiment files while the workflow is still executing.

### P0 — external validation

No production or breakthrough claim should be made without an untouched external holdout or independent red-team reproduction, with confidence intervals and predeclared gates.

### P0 — durable authorization state

Replace the in-memory grant authority with an atomic durable implementation before multi-worker or production deployment.

### P1 — repository governance

Add branch/ruleset protection, required checks, review requirements, release/tag policy, and signed/provenance-aware release practices.

### P1 — reproducibility and supply chain

Move from mostly runtime-captured dependency versions to controlled constraints/lock files. Pin GitHub Actions to reviewed immutable commit SHAs for a hardened release path. Add dependency/update automation, SAST/CodeQL or equivalent, secret scanning controls where available, SBOM/provenance generation and release artifacts.

### P1 — repository identity

After the controlled branches are consolidated, rename/rebrand the repository from `demo-repo` to an AgentShield-specific name and replace the demo README with an evidence-aware project README. Add description, topics, license and contribution/security documentation.

### P2 — source layout

Complete the already-proposed separation into explicit `research/`, `platform/`, `evaluation/`, `docs/` and immutable evidence/release areas while preserving Git history and experiment lineage.

## Recommended promotion path

1. Allow v14 to finish unchanged and verify its uploaded evidence before interpretation.
2. Freeze the v14 result whether positive or negative; do not retune from audit.
3. Keep the platform branch independently green and security-gated.
4. Build a canonical AgentShield integration branch only after the running experiment is frozen.
5. Preserve research lineage rather than merging experiment scripts into production policy.
6. Run an untouched external evaluation and independent adversarial/system test programme.
7. Harden repository governance, dependencies, authorization persistence and release provenance.
8. Only then promote a production/security claim and make the clean integrated branch the repository default.

## Due-diligence verdict

**Research discipline:** strong.

**Security architecture:** promising and conceptually well-separated.

**Current detector evidence:** not yet sufficient for a breakthrough claim.

**Repository presentation/governance:** materially below the quality of the underlying work and a priority to fix.

**Production readiness:** not yet; the project should remain controlled research + security-platform development until the P0 items above are closed.
