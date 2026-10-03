# Conserved delegation — runtime 0.3.0 / policy v6

Runtime 0.4.0 / policy v7 adds mandatory review-evidence binding; see
`REVIEW_EVIDENCE_V1.md` for the current upgrade instructions.

Delegation transfers one execution right from a single-use parent to one child.
It does not mint an additional right. The parent becomes `DELEGATED` and cannot
execute or delegate again. The child can execute once or transfer its right again,
up to eight delegation edges. Reusable parents and fan-out are rejected.

## Trusted host contract

```python
from dataclasses import replace
from datetime import timedelta

# parent_scope has already been independently approved and issued by the host.
child_scope = replace(
    parent_scope,
    grant_id="fresh-host-generated-child-id",
    allowed_capabilities=("read_data",),
    allowed_effects=(parent_scope.allowed_effects[0],),
)
authority.delegate(parent_scope, child_scope, ttl=timedelta(minutes=1))
```

Child capabilities and exact effects must be nonempty subsets of the authentic
parent scope. The originating issuer must remain unchanged; the child ID must be
unused. Expiry is clamped to the parent expiry. Delegation and issuance are trusted
host management operations: never expose them or the database credentials to agent
code. A public digest or a caller-supplied issuer string is not authentication.

Every verification and consumption checks the entire bounded ancestor chain.
Revoked, expired, consumed, missing or invalid ancestry blocks admission; future-dated
grants cannot execute. Revoking any ancestor invalidates its descendants without
rewriting each row. Revocation cannot undo an action already admitted by a committed
consumption transaction. Failed dispatch does not refund an execution right.

## Atomicity

The in-memory authority serializes lifecycle operations with a process-local lock.
Use PostgreSQL for multiple workers. PostgreSQL locks ancestry from root to leaf,
then reads database time and checks validity. Child insertion and parent transfer
commit together; insertion failure rolls back the transfer. Execution, delegation
and ancestor revocation serialize on the relevant rows. Connection factories must
return non-autocommit connections; unsafe connections are rejected. Parent links
are immutable under the authority API. Database administrators remain trusted.

Do not supply `now` in production: it is a trusted deterministic-test override.
Production uses database time after lock acquisition, so a grant that expires while
waiting cannot be admitted using a stale transaction-start timestamp.

## Required coordinated upgrade

This is a breaking pre-GA change, not an online mixed-worker migration:

1. Stop admission and drain/retire all older execution workers.
2. Run `PostgresGrantAuthority.ensure_schema()` using the upgrade role. It adds
   nullable `parent_grant_id` and `delegated_to` columns idempotently and retains rows.
   Apply normal database backup and change controls for your deployment.
3. Upgrade all issuers, evaluators and execution workers to runtime 0.3.0 / policy v6.
4. Reissue independently approved scopes with fresh IDs, then reevaluate requests
   and regenerate approvals before resuming admission.

The scope digest now includes `agentshield-scope-v2`. Legacy stored scope hashes
fail closed, and older workers cannot authenticate new child scopes. Policy/audit
version checks reject stale evaluations. Retained old rows are historical records;
do not rewrite their hashes to bypass reissuance. Rolling back requires stopping
admission and a separately reviewed reissuance plan; old workers do not enforce
ancestor revocation or conserved delegation.

## Verification and limits

Shared memory/PostgreSQL regressions cover attenuation, expiry, revoked ancestry,
depth limits, duplicate-child rollback, competing delegations and execution racing
delegation. PostgreSQL-specific tests cover autocommit rejection, expiry during a
row-lock wait and upgrading the prior schema. Execution tests cover revocation
between evaluation and dispatch and one-time execution through a delegated grant.

This budget is one dispatch, not a general monetary, token or multi-action budget.
Exact-effect binding still depends on trusted adapters resolving resource identity
and destination semantics. Temporal provenance, process isolation, complete mediation
and independent external evaluation remain requirements. These contract tests do
not establish a measured 99.999% unauthorized-consequence prevention rate.
