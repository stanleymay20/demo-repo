# Exact-effect authorization — runtime 0.2.0 / policy v5

This document describes the v5 effect-binding change. Runtime 0.3.0 / policy v6
supersedes its upgrade instructions; see `DELEGATION_V1.md` before upgrading.

## Why this is required

At runtime 0.1.0, a capability grant permitting `read_data` could authorize both
`{"tenant":"approved-team"}` and `{"tenant":"other-team"}` when a detector
missed an attack. Re-evaluating a changed payload generated fresh integrity hashes
but did not prove that the originating task authorized the new resource.

Every executable grant now includes a finite tuple of `allowed_effects`. An effect
digest binds the complete strict-JSON payload, canonical action identity/capabilities,
and authoritative tool manifest including its version, under `agentshield-effect-v1`.
The scope digest binds the entire sorted/deduplicated allowlist to the issued grant
record, including in PostgreSQL. Appending or replacing effects invalidates the grant.

## Trusted issuance example

```python
from agentshield.platform import AuthorizationScope, ToolManifest, effect_digest

# Loaded from trusted host configuration and an independently approved workflow.
manifest = ToolManifest("records.read", ("read_data",), version="1")
approved_payload = {"tenant": "team-a", "record": "report-1", "destination": "local"}
scope = AuthorizationScope(
    grant_id="unique-host-issued-task-id",
    allowed_capabilities=("read_data",),
    issuer="authenticated-host-principal",
    allowed_effects=(effect_digest(
        action=manifest.descriptor,
        payload=approved_payload,
        manifest=manifest,
    ),),
)
# Issue through the trusted grant authority after independent intent approval.
# authority.issue(scope)   # use PostgresGrantAuthority for concurrent deployments
```

Do not fill `approved_payload` by automatically echoing whatever a model proposes.
Computing a digest is public and does not itself grant authority. The authority
and approval policy must be unreachable from untrusted agent tool/code execution.

## Enforcement and lifecycle

- Evaluation computes the effect from the payload captured before callbacks and
  a verified host manifest. The audit stores its digest and scope-check status.
- An effect outside a nonempty allowlist is BLOCK, even with low detector risk.
- Missing effect authority is REVIEW during evaluation and BLOCK at execution.
  The remedy is trusted reissuance, not a generic human approval over an unbound grant.
- Execution rechecks the effect against the scope and recorded digest before
  grant consumption. Signed review approval cannot override an effect mismatch.
- Default single-use consumption allows one dispatch from the finite set; it does
  not grant one dispatch per allowed effect. Existing explicit reusable grants retain
  their reusable semantics and must be deliberately chosen by trusted infrastructure.
- Tool names must exactly equal their manifest names; whitespace aliases are rejected.
- Policy/audit versions must match the current runtime before execution.

## Migration

This is a deliberate pre-GA breaking security change, signaled by runtime 0.2.0
and policy v5. Existing descriptive scopes can still be constructed, but empty
`allowed_effects` no longer authorizes execution. Reissue approved grants with fresh IDs and
reevaluate pending requests; do not add wildcard digests or silently approve an
agent's proposed payload. Existing stored grants/approvals bind the old scope digest
and must be replaced through trusted issuance. The PostgreSQL schema is unchanged:
the existing scope digest covers the new field. Coordinate workers on policy v5 and
retire v4 workers before relying on the mandatory binding. Mixed-version workers
must not continue executing v4 requests.

## Limits and next controls

This binds exact requests, not generic semantic equivalence. An adapter must resolve
tenant/resource ownership, relative paths/symlinks, redirects, DNS changes, service
defaults and any other external state that could alter an effect. Pin the resolved
identity into the approved payload or enforce it atomically at the tool boundary.
If an adapter cannot establish this, hold or reject the action. Full payload approval
is conservative: even a benign argument change requires a newly approved effect.

Runtime 0.3.0 adds conserved single-use delegation (see `DELEGATION_V1.md`);
child scopes must never be self-issued by agents. General multi-action budgets, temporal
provenance, independent external evaluation, complete mediation, process isolation
and deployment-level secret separation remain separate requirements. Synthetic
tests demonstrate these contracts, not a measured 99.999% prevention probability.

## Verification scope

Regression tests deliberately force detector misses while testing tenant/resource/
destination substitution, added recipients/amounts/paths, tool/version substitution,
forged allowlist expansion, legacy grants with signed human approval, stale policy,
missing audit bindings, finite allowlists and single-use exhaustion. PostgreSQL CI
also verifies that forged effect expansion cannot consume the durable grant.
