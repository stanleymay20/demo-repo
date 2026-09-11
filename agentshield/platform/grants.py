"""Authoritative lifecycle for AgentShield capability grants.

AuthorizationScope describes *what* a task may do. GrantAuthority is the server-owned
state that decides whether that scope is genuine, current, revoked, expired or already
consumed. Single-use grants are the secure default.

The in-memory implementation is appropriate for deterministic tests and a single-process
prototype. Production deployments must replace it with an atomic durable store so
verify/consume is race-safe across workers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import secrets

from .authorization import AuthorizationScope
from .integrity import scope_digest


class GrantStatus(str, Enum):
    VALID = "valid"
    UNKNOWN = "unknown"
    MISMATCH = "mismatch"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


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

    def __post_init__(self) -> None:
        if self.issued_at_utc.tzinfo is None or self.expires_at_utc.tzinfo is None:
            raise ValueError("grant timestamps must be timezone-aware")
        if self.expires_at_utc <= self.issued_at_utc:
            raise ValueError("grant expiry must be after issuance")


class GrantAuthority:
    """Server-owned grant lifecycle with expiry, revocation and replay resistance."""

    def __init__(self) -> None:
        self._records: dict[str, GrantRecord] = {}

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        now = datetime.now(timezone.utc) if value is None else value
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return now.astimezone(timezone.utc)

    def issue(
        self,
        scope: AuthorizationScope,
        *,
        ttl: timedelta = timedelta(minutes=5),
        single_use: bool = True,
        now: datetime | None = None,
    ) -> GrantRecord:
        if ttl <= timedelta(0):
            raise ValueError("grant ttl must be positive")
        if scope.grant_id in self._records:
            raise ValueError("grant_id already exists")
        issued_at = self._now(now)
        record = GrantRecord(
            grant_id=scope.grant_id,
            scope_digest=scope_digest(scope),
            issuer=scope.issuer,
            nonce=secrets.token_urlsafe(24),
            issued_at_utc=issued_at,
            expires_at_utc=issued_at + ttl,
            single_use=single_use,
        )
        self._records[scope.grant_id] = record
        return record

    def get(self, grant_id: str) -> GrantRecord | None:
        return self._records.get(grant_id)

    def verify(
        self,
        scope: AuthorizationScope,
        *,
        now: datetime | None = None,
    ) -> tuple[GrantStatus, GrantRecord | None]:
        record = self._records.get(scope.grant_id)
        if record is None:
            return GrantStatus.UNKNOWN, None
        if record.scope_digest != scope_digest(scope) or record.issuer != scope.issuer:
            return GrantStatus.MISMATCH, record
        if record.revoked:
            return GrantStatus.REVOKED, record
        if record.single_use and record.consumed_at_utc is not None:
            return GrantStatus.CONSUMED, record
        if self._now(now) >= record.expires_at_utc:
            return GrantStatus.EXPIRED, record
        return GrantStatus.VALID, record

    def revoke(self, grant_id: str) -> bool:
        record = self._records.get(grant_id)
        if record is None:
            return False
        self._records[grant_id] = GrantRecord(
            grant_id=record.grant_id,
            scope_digest=record.scope_digest,
            issuer=record.issuer,
            nonce=record.nonce,
            issued_at_utc=record.issued_at_utc,
            expires_at_utc=record.expires_at_utc,
            single_use=record.single_use,
            revoked=True,
            consumed_at_utc=record.consumed_at_utc,
        )
        return True

    def consume(
        self,
        scope: AuthorizationScope,
        *,
        now: datetime | None = None,
    ) -> tuple[GrantStatus, GrantRecord | None]:
        """Atomically consume a single-use grant in this authority instance.

        A durable production implementation must provide the equivalent operation with
        a transactional compare-and-set so two workers cannot consume the same grant.
        """

        status, record = self.verify(scope, now=now)
        if status is not GrantStatus.VALID or record is None:
            return status, record
        if not record.single_use:
            return GrantStatus.VALID, record
        consumed_at = self._now(now)
        consumed = GrantRecord(
            grant_id=record.grant_id,
            scope_digest=record.scope_digest,
            issuer=record.issuer,
            nonce=record.nonce,
            issued_at_utc=record.issued_at_utc,
            expires_at_utc=record.expires_at_utc,
            single_use=True,
            revoked=record.revoked,
            consumed_at_utc=consumed_at,
        )
        self._records[scope.grant_id] = consumed
        return GrantStatus.VALID, consumed
