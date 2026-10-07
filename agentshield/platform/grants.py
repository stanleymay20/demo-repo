"""Authoritative lifecycle for AgentShield capability grants.

AuthorizationScope describes *what* a task may do. GrantAuthority is the server-owned
state that decides whether that scope is genuine, current, revoked, expired or already
consumed. Every executable GA grant is single-use.

The in-memory implementation is appropriate for deterministic tests and a single-process
prototype. Production deployments must replace it with an atomic durable store so
verify/consume is race-safe across workers. Time is owned by the authority: callers cannot
supply a historical timestamp to verification or consumption.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import secrets
from typing import Callable, Protocol
from threading import RLock

from .authorization import AuthorizationScope
from .integrity import scope_digest


class GrantStatus(str, Enum):
    VALID = "valid"
    UNKNOWN = "unknown"
    MISMATCH = "mismatch"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"
    DELEGATED = "delegated"
    ANCESTOR_INVALID = "ancestor_invalid"
    NOT_YET_VALID = "not_yet_valid"
    REUSABLE_UNSUPPORTED = "reusable_unsupported"


@dataclass(frozen=True)
class GrantRecord:
    grant_id: str
    scope_digest: str
    issuer: str
    nonce: str
    issued_at_utc: datetime
    expires_at_utc: datetime
    single_use: bool
    revoked: bool = False
    consumed_at_utc: datetime | None = None
    parent_grant_id: str | None = None
    delegated_to: str | None = None

    def __post_init__(self) -> None:
        if self.issued_at_utc.tzinfo is None or self.expires_at_utc.tzinfo is None:
            raise ValueError("grant timestamps must be timezone-aware")
        if self.expires_at_utc <= self.issued_at_utc:
            raise ValueError("grant expiry must be after issuance")


def grant_record_digest(record: GrantRecord) -> str:
    """Bind the immutable authorization record without logging its nonce in cleartext."""

    material = {
        "grant_id": record.grant_id,
        "scope_digest": record.scope_digest,
        "issuer": record.issuer,
        "nonce": record.nonce,
        "issued_at_utc": record.issued_at_utc.astimezone(timezone.utc).isoformat(),
        "expires_at_utc": record.expires_at_utc.astimezone(timezone.utc).isoformat(),
        "single_use": record.single_use,
        "parent_grant_id": record.parent_grant_id,
        "delegated_to": record.delegated_to,
        "revoked": record.revoked,
        "consumed_at_utc": (
            None
            if record.consumed_at_utc is None
            else record.consumed_at_utc.astimezone(timezone.utc).isoformat()
        ),
    }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class GrantAuthorityProtocol(Protocol):
    """Structural contract shared by in-memory and durable grant authorities."""

    def verify(
        self,
        scope: AuthorizationScope,
    ) -> tuple[GrantStatus, GrantRecord | None]: ...

    def consume(
        self,
        scope: AuthorizationScope,
    ) -> tuple[GrantStatus, GrantRecord | None]: ...


MAX_DELEGATION_DEPTH = 8


def load_grant_chain(get: Callable[[str], GrantRecord | None], grant_id: str) -> tuple[GrantRecord, ...]:
    """Load leaf first, with bounded traversal even if storage is corrupt."""
    chain: list[GrantRecord] = []
    seen: set[str] = set()
    current: str | None = grant_id
    while current is not None and current not in seen and len(chain) <= MAX_DELEGATION_DEPTH:
        seen.add(current)
        record = get(current)
        if record is None:
            break
        chain.append(record)
        current = record.parent_grant_id
    return tuple(chain)


def verify_grant_chain(
    scope: AuthorizationScope, chain: tuple[GrantRecord, ...], now: datetime,
) -> GrantStatus:
    if not chain:
        return GrantStatus.UNKNOWN
    leaf = chain[0]
    if leaf.scope_digest != scope_digest(scope) or leaf.issuer != scope.issuer:
        return GrantStatus.MISMATCH
    if chain[-1].parent_grant_id is not None:
        return GrantStatus.ANCESTOR_INVALID
    # Legacy v3 child scopes never carried the parent grant id. Machine-bound v4 scopes
    # do, so only v4 can be independently checked against the durable lineage record here.
    if scope.machine_identity_bound and scope.delegator_grant_id != leaf.parent_grant_id:
        return GrantStatus.MISMATCH
    for index, record in enumerate(chain):
        if not record.single_use:
            status = GrantStatus.REUSABLE_UNSUPPORTED
        elif record.revoked:
            status = GrantStatus.REVOKED
        elif record.consumed_at_utc is not None:
            status = GrantStatus.CONSUMED
        elif now < record.issued_at_utc:
            status = GrantStatus.NOT_YET_VALID
        elif now >= record.expires_at_utc:
            status = GrantStatus.EXPIRED
        else:
            status = GrantStatus.VALID
        if status is not GrantStatus.VALID:
            return status if index == 0 else GrantStatus.ANCESTOR_INVALID
        if index:
            child = chain[index - 1]
            if (child.parent_grant_id != record.grant_id
                    or record.delegated_to != child.grant_id
                    or child.issuer != record.issuer
                    or child.expires_at_utc > record.expires_at_utc):
                return GrantStatus.ANCESTOR_INVALID
    return GrantStatus.DELEGATED if leaf.delegated_to is not None else GrantStatus.VALID


def delegated_record(
    parent_scope: AuthorizationScope, child_scope: AuthorizationScope,
    chain: tuple[GrantRecord, ...], *, now: datetime, ttl: timedelta,
) -> GrantRecord:
    """Validate attenuation and construct a child; caller must transfer atomically.

    Legacy v3 authority stays legacy during delegation. A machine-bound v4 parent may
    delegate to another agent, but the child must preserve principal, tenant and purpose,
    and must commit the parent's agent id and grant id as the immediate delegation link.
    """
    if verify_grant_chain(parent_scope, chain, now) is not GrantStatus.VALID:
        raise ValueError("parent grant is not valid for delegation")
    parent = chain[0]
    if not parent.single_use:
        raise ValueError("delegation requires a single-use parent")
    if len(chain) > MAX_DELEGATION_DEPTH:
        raise ValueError("maximum delegation depth exceeded")
    if (
        child_scope.grant_id == parent_scope.grant_id
        or child_scope.issuer != parent_scope.issuer
        or child_scope.principal != parent_scope.principal
        or child_scope.tenant != parent_scope.tenant
    ):
        raise ValueError(
            "child needs a fresh id and must preserve originating issuer, principal and tenant"
        )
    if parent_scope.machine_identity_bound:
        if (
            not child_scope.machine_identity_bound
            or child_scope.purpose_id != parent_scope.purpose_id
            or child_scope.delegator_agent_id != parent_scope.agent_id
            or child_scope.delegator_grant_id != parent_scope.grant_id
        ):
            raise ValueError(
                "machine-bound child must preserve purpose and bind the parent agent and grant"
            )
    elif child_scope.machine_identity_bound:
        raise ValueError("legacy authority cannot acquire machine identity during delegation")
    if (not child_scope.allowed_capabilities
            or not set(child_scope.allowed_capabilities).issubset(parent_scope.allowed_capabilities)
            or not child_scope.allowed_effects
            or not set(child_scope.allowed_effects).issubset(parent_scope.allowed_effects)):
        raise ValueError("child capabilities and effects must be nonempty subsets of parent authority")
    if ttl <= timedelta(0):
        raise ValueError("child ttl must be positive")
    return GrantRecord(
        grant_id=child_scope.grant_id, scope_digest=scope_digest(child_scope),
        issuer=child_scope.issuer, nonce=secrets.token_urlsafe(24),
        issued_at_utc=now, expires_at_utc=min(now + ttl, parent.expires_at_utc),
        single_use=True, parent_grant_id=parent.grant_id,
    )


class GrantAuthority:
    """Thread-safe single-process authority; use PostgreSQL across workers.

    Tests that need deterministic time may inject an authority-owned clock at
    construction. Individual security decisions never accept caller-supplied time.
    """

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._records: dict[str, GrantRecord] = {}
        self._lock = RLock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("authority clock must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)

    def issue(
        self, scope: AuthorizationScope, *, ttl: timedelta = timedelta(minutes=5),
    ) -> GrantRecord:
        if ttl <= timedelta(0):
            raise ValueError("grant ttl must be positive")
        if scope.delegator_agent_id is not None or scope.delegator_grant_id is not None:
            raise ValueError("directly issued root authority cannot claim a delegator")
        with self._lock:
            if scope.grant_id in self._records:
                raise ValueError("grant_id already exists")
            issued_at = self._now()
            record = GrantRecord(
                grant_id=scope.grant_id, scope_digest=scope_digest(scope), issuer=scope.issuer,
                nonce=secrets.token_urlsafe(24), issued_at_utc=issued_at,
                expires_at_utc=issued_at + ttl, single_use=True,
            )
            self._records[scope.grant_id] = record
            return record

    def get(self, grant_id: str) -> GrantRecord | None:
        with self._lock:
            return self._records.get(grant_id)

    def verify(self, scope: AuthorizationScope):
        with self._lock:
            chain = load_grant_chain(self._records.get, scope.grant_id)
            return verify_grant_chain(scope, chain, self._now()), chain[0] if chain else None

    def revoke(self, grant_id: str) -> bool:
        with self._lock:
            record = self._records.get(grant_id)
            if record is None:
                return False
            self._records[grant_id] = replace(record, revoked=True)
            return True

    def consume(self, scope: AuthorizationScope):
        with self._lock:
            current = self._now()
            chain = load_grant_chain(self._records.get, scope.grant_id)
            status = verify_grant_chain(scope, chain, current)
            record = chain[0] if chain else None
            if status is not GrantStatus.VALID or record is None:
                return status, record
            consumed = replace(record, consumed_at_utc=current)
            self._records[scope.grant_id] = consumed
            return GrantStatus.VALID, consumed

    def delegate(
        self, parent_scope: AuthorizationScope, child_scope: AuthorizationScope, *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> GrantRecord:
        with self._lock:
            if child_scope.grant_id in self._records:
                raise ValueError("grant_id already exists")
            chain = load_grant_chain(self._records.get, parent_scope.grant_id)
            child = delegated_record(parent_scope, child_scope, chain, now=self._now(), ttl=ttl)
            self._records[parent_scope.grant_id] = replace(chain[0], delegated_to=child.grant_id)
            self._records[child.grant_id] = child
            return child
