"""Production-grade durable grant authority backed by PostgreSQL.

This adapter preserves the GrantAuthority contract while moving grant lifecycle state
into a transactional shared store. Single-use consumption is an atomic UPDATE so two
workers cannot successfully consume the same grant.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Any, Callable

from .authorization import AuthorizationScope
from .grants import GrantRecord, GrantStatus
from .integrity import scope_digest

_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PostgresGrantAuthority:
    """Atomic, multi-worker grant lifecycle for PostgreSQL/psycopg connections."""

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        *,
        table_name: str = "agentshield_grants",
    ) -> None:
        if not _TABLE_RE.fullmatch(table_name):
            raise ValueError("table_name must be a simple SQL identifier")
        self._connection_factory = connection_factory
        self._table = table_name

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        now = datetime.now(timezone.utc) if value is None else value
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _row_to_record(row: tuple[Any, ...] | None) -> GrantRecord | None:
        if row is None:
            return None
        return GrantRecord(
            grant_id=row[0],
            scope_digest=row[1],
            issuer=row[2],
            nonce=row[3],
            issued_at_utc=row[4],
            expires_at_utc=row[5],
            single_use=bool(row[6]),
            revoked=bool(row[7]),
            consumed_at_utc=row[8],
        )

    @property
    def _columns(self) -> str:
        return (
            "grant_id, scope_digest, issuer, nonce, issued_at_utc, "
            "expires_at_utc, single_use, revoked, consumed_at_utc"
        )

    def ensure_schema(self) -> None:
        ddl = f"""
        CREATE TABLE IF NOT EXISTS {self._table} (
            grant_id TEXT PRIMARY KEY,
            scope_digest TEXT NOT NULL,
            issuer TEXT NOT NULL,
            nonce TEXT NOT NULL,
            issued_at_utc TIMESTAMPTZ NOT NULL,
            expires_at_utc TIMESTAMPTZ NOT NULL,
            single_use BOOLEAN NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            consumed_at_utc TIMESTAMPTZ NULL
        );
        CREATE INDEX IF NOT EXISTS {self._table}_expires_idx
            ON {self._table} (expires_at_utc);
        """
        conn = self._connection_factory()
        try:
            with conn.cursor() as cur:
                cur.execute(ddl)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

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
        sql = f"""
        INSERT INTO {self._table}
            ({self._columns})
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (grant_id) DO NOTHING
        RETURNING {self._columns}
        """
        conn = self._connection_factory()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        record.grant_id,
                        record.scope_digest,
                        record.issuer,
                        record.nonce,
                        record.issued_at_utc,
                        record.expires_at_utc,
                        record.single_use,
                        record.revoked,
                        record.consumed_at_utc,
                    ),
                )
                created = self._row_to_record(cur.fetchone())
            if created is None:
                conn.rollback()
                raise ValueError("grant_id already exists")
            conn.commit()
            return created
        except ValueError:
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get(self, grant_id: str) -> GrantRecord | None:
        conn = self._connection_factory()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {self._columns} FROM {self._table} WHERE grant_id = %s",
                    (grant_id,),
                )
                return self._row_to_record(cur.fetchone())
        finally:
            conn.close()

    def verify(
        self,
        scope: AuthorizationScope,
        *,
        now: datetime | None = None,
    ) -> tuple[GrantStatus, GrantRecord | None]:
        record = self.get(scope.grant_id)
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
        conn = self._connection_factory()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE {self._table}
                    SET revoked = TRUE
                    WHERE grant_id = %s
                    RETURNING grant_id
                    """,
                    (grant_id,),
                )
                row = cur.fetchone()
            conn.commit()
            return row is not None
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def consume(
        self,
        scope: AuthorizationScope,
        *,
        now: datetime | None = None,
    ) -> tuple[GrantStatus, GrantRecord | None]:
        """Atomically consume a valid single-use grant immediately before dispatch."""

        current = self._now(now)
        digest = scope_digest(scope)
        sql = f"""
        UPDATE {self._table}
        SET consumed_at_utc = CASE
            WHEN single_use THEN %s
            ELSE consumed_at_utc
        END
        WHERE grant_id = %s
          AND scope_digest = %s
          AND issuer = %s
          AND revoked = FALSE
          AND expires_at_utc > %s
          AND (single_use = FALSE OR consumed_at_utc IS NULL)
        RETURNING {self._columns}
        """
        conn = self._connection_factory()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    (current, scope.grant_id, digest, scope.issuer, current),
                )
                record = self._row_to_record(cur.fetchone())
            if record is not None:
                conn.commit()
                return GrantStatus.VALID, record
            conn.rollback()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        # The atomic update did not win. Re-read to return the precise fail-closed reason.
        return self.verify(scope, now=current)
