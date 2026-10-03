"""Authoritative lifecycle for AgentShield capability grants.

AuthorizationScope describes *what* a task may do. GrantAuthority is the server-owned
state that decides whether that scope is genuine, current, revoked, expired or already
consumed. Single-use grants are the secure default.

The in-memory implementation is appropriate for deterministic tests and a single-process
prototype. Production deployments must replace it with an atomic durable store so
verify/consume is race-safe across workers.
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
        *,
        now: datetime | None = None,
    ) -> tuple[GrantStatus, GrantRecord | None]: ...

    def consume(
        self,
        scope: AuthorizationScope,
        *,
        now: datetime | None = None,
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
    for index, record in enumerate(chain):
        if record.revoked:
            status = GrantStatus.REVOKED
        elif record.single_use and record.consumed_at_utc is not None:
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
                    or record.delegated_to != child.grant_id or not record.single_use
                    or child.issuer != record.issuer
                    or child.expires_at_utc > record.expires_at_utc):
                return GrantStatus.ANCESTOR_INVALID
    return GrantStatus.DELEGATED if leaf.delegated_to is not None else GrantStatus.VALID


def delegated_record(
    parent_scope: AuthorizationScope, child_scope: AuthorizationScope,
    chain: tuple[GrantRecord, ...], *, now: datetime, ttl: timedelta,
) -> GrantRecord:
    """Validate attenuation and construct a child; caller must transfer atomically."""
    if verify_grant_chain(parent_scope, chain, now) is not GrantStatus.VALID:
        raise ValueError("parent grant is not valid for delegation")
    parent = chain[0]
    if not parent.single_use:
        raise ValueError("delegation requires a single-use parent")
    if len(chain) > MAX_DELEGATION_DEPTH:
        raise ValueError("maximum delegation depth exceeded")
    if (child_scope.grant_id == parent_scope.grant_id
            or child_scope.issuer != parent_scope.issuer):
        raise ValueError("child needs a fresh id and the same originating issuer")
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
    """Thread-safe single-process authority; use PostgreSQL across workers."""

    def __init__(self) -> None:
        self._records: dict[str, GrantRecord] = {}
        self._lock = RLock()

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        now = datetime.now(timezone.utc) if value is None else value
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return now.astimezone(timezone.utc)

    def issue(
        self, scope: AuthorizationScope, *, ttl: timedelta = timedelta(minutes=5),
        single_use: bool = True, now: datetime | None = None,
    ) -> GrantRecord:
        if ttl <= timedelta(0):
            raise ValueError("grant ttl must be positive")
        with self._lock:
            if scope.grant_id in self._records:
                raise ValueError("grant_id already exists")
            issued_at = self._now(now)
            record = GrantRecord(
                grant_id=scope.grant_id, scope_digest=scope_digest(scope), issuer=scope.issuer,
                nonce=secrets.token_urlsafe(24), issued_at_utc=issued_at,
                expires_at_utc=issued_at + ttl, single_use=single_use,
            )
            self._records[scope.grant_id] = record
            return record

    def get(self, grant_id: str) -> GrantRecord | None:
        with self._lock:
            return self._records.get(grant_id)

    def verify(self, scope: AuthorizationScope, *, now: datetime | None = None):
        with self._lock:
            chain = load_grant_chain(self._records.get, scope.grant_id)
            return verify_grant_chain(scope, chain, self._now(now)), chain[0] if chain else None

    def revoke(self, grant_id: str) -> bool:
        with self._lock:
            record = self._records.get(grant_id)
            if record is None:
                return False
            self._records[grant_id] = replace(record, revoked=True)
            return True

    def consume(self, scope: AuthorizationScope, *, now: datetime | None = None):
        with self._lock:
            current = self._now(now)
            status, record = self.verify(scope, now=current)
            if status is not GrantStatus.VALID or record is None or not record.single_use:
                return status, record
            consumed = replace(record, consumed_at_utc=current)
            self._records[scope.grant_id] = consumed
            return GrantStatus.VALID, consumed

    def delegate(
        self, parent_scope: AuthorizationScope, child_scope: AuthorizationScope, *,
        ttl: timedelta = timedelta(minutes=5), now: datetime | None = None,
    ) -> GrantRecord:
        with self._lock:
            if child_scope.grant_id in self._records:
                raise ValueError("grant_id already exists")
            chain = load_grant_chain(self._records.get, parent_scope.grant_id)
            child = delegated_record(parent_scope, child_scope, chain, now=self._now(now), ttl=ttl)
            self._records[parent_scope.grant_id] = replace(chain[0], delegated_to=child.grant_id)
            self._records[child.grant_id] = child
            return child
