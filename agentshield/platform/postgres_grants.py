"""Durable grants and conserved delegation, serialized by root-to-leaf row locks.

Factories must return non-autocommit psycopg connections. Validity is checked with
PostgreSQL's clock after acquiring locks, including all delegation ancestors.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Any, Callable

from .authorization import AuthorizationScope
from .grants import (
    GrantRecord, GrantStatus, delegated_record, load_grant_chain, verify_grant_chain,
)
from .integrity import scope_digest

_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PostgresGrantAuthority:
    """Atomic grant lifecycle and single-credit delegation across workers."""

    def __init__(self, connection_factory: Callable[[], Any], *, table_name: str = "agentshield_grants"):
        if not _TABLE_RE.fullmatch(table_name):
            raise ValueError("table_name must be a simple SQL identifier")
        self._connection_factory = connection_factory
        self._table = table_name

    @staticmethod
    def _now(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return value.astimezone(timezone.utc)

    @contextmanager
    def _transaction(self):
        conn = self._connection_factory()
        try:
            if conn.autocommit:
                raise ValueError("grant authority requires autocommit=False for row-lock safety")
            with conn.cursor() as cur:
                yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _clock(self, cur, now: datetime | None) -> datetime:
        if now is None:
            cur.execute("SELECT clock_timestamp()")
            now = cur.fetchone()[0]
        return self._now(now)

    @property
    def _columns(self) -> str:
        return (
            "grant_id, scope_digest, issuer, nonce, issued_at_utc, "
            "expires_at_utc, single_use, revoked, consumed_at_utc, parent_grant_id, delegated_to"
        )

    @staticmethod
    def _row_to_record(row) -> GrantRecord | None:
        return None if row is None else GrantRecord(*row)

    def _read(self, cur, grant_id: str, *, lock=False) -> GrantRecord | None:
        cur.execute(
            f"SELECT {self._columns} FROM {self._table} WHERE grant_id = %s"
            + (" FOR UPDATE" if lock else ""), (grant_id,),
        )
        return self._row_to_record(cur.fetchone())

    def _locked_chain(self, cur, grant_id: str) -> tuple[GrantRecord, ...]:
        chain = load_grant_chain(lambda key: self._read(cur, key), grant_id)
        if not chain or chain[-1].parent_grant_id is not None:
            return chain  # missing/cyclic/over-depth ancestry will fail validation
        locked = []
        # Parent links are immutable. Root-first locking gives all operations on
        # one family a consistent order and prevents sibling budget races.
        for original in reversed(chain):
            current = self._read(cur, original.grant_id, lock=True)
            if current is None or current.parent_grant_id != original.parent_grant_id:
                raise ValueError("grant lineage changed while acquiring execution locks")
            locked.append(current)
        return tuple(reversed(locked))

    def _insert(self, cur, record: GrantRecord) -> GrantRecord:
        cur.execute(
            f"INSERT INTO {self._table} ({self._columns}) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            f"ON CONFLICT (grant_id) DO NOTHING RETURNING {self._columns}",
            (record.grant_id, record.scope_digest, record.issuer, record.nonce,
             record.issued_at_utc, record.expires_at_utc, record.single_use,
             record.revoked, record.consumed_at_utc, record.parent_grant_id, record.delegated_to),
        )
        created = self._row_to_record(cur.fetchone())
        if created is None:
            raise ValueError("grant_id already exists")
        return created

    def ensure_schema(self) -> None:
        with self._transaction() as cur:
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {self._table} (
                    grant_id TEXT PRIMARY KEY, scope_digest TEXT NOT NULL,
                    issuer TEXT NOT NULL, nonce TEXT NOT NULL,
                    issued_at_utc TIMESTAMPTZ NOT NULL, expires_at_utc TIMESTAMPTZ NOT NULL,
                    single_use BOOLEAN NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE,
                    consumed_at_utc TIMESTAMPTZ NULL,
                    parent_grant_id TEXT NULL, delegated_to TEXT NULL
                );
                ALTER TABLE {self._table} ADD COLUMN IF NOT EXISTS parent_grant_id TEXT NULL;
                ALTER TABLE {self._table} ADD COLUMN IF NOT EXISTS delegated_to TEXT NULL;
                CREATE INDEX IF NOT EXISTS {self._table}_expires_idx ON {self._table} (expires_at_utc);
            """)

    def issue(
        self, scope: AuthorizationScope, *, ttl: timedelta = timedelta(minutes=5),
        single_use: bool = True, now: datetime | None = None,
    ) -> GrantRecord:
        if ttl <= timedelta(0):
            raise ValueError("grant ttl must be positive")
        with self._transaction() as cur:
            current = self._clock(cur, now)
            return self._insert(cur, GrantRecord(
                grant_id=scope.grant_id, scope_digest=scope_digest(scope), issuer=scope.issuer,
                nonce=secrets.token_urlsafe(24), issued_at_utc=current,
                expires_at_utc=current + ttl, single_use=single_use,
            ))

    def get(self, grant_id: str) -> GrantRecord | None:
        with self._transaction() as cur:
            return self._read(cur, grant_id)

    def verify(self, scope: AuthorizationScope, *, now: datetime | None = None):
        with self._transaction() as cur:
            chain = self._locked_chain(cur, scope.grant_id)
            status = verify_grant_chain(scope, chain, self._clock(cur, now))
            return status, chain[0] if chain else None

    def revoke(self, grant_id: str) -> bool:
        with self._transaction() as cur:
            cur.execute(
                f"UPDATE {self._table} SET revoked = TRUE WHERE grant_id = %s RETURNING grant_id",
                (grant_id,),
            )
            return cur.fetchone() is not None

    def consume(self, scope: AuthorizationScope, *, now: datetime | None = None):
        with self._transaction() as cur:
            chain = self._locked_chain(cur, scope.grant_id)
            current = self._clock(cur, now)
            status = verify_grant_chain(scope, chain, current)
            record = chain[0] if chain else None
            if status is not GrantStatus.VALID or record is None or not record.single_use:
                return status, record
            cur.execute(
                f"UPDATE {self._table} SET consumed_at_utc = %s WHERE grant_id = %s "
                f"RETURNING {self._columns}", (current, scope.grant_id),
            )
            consumed = self._row_to_record(cur.fetchone())
            if consumed is None:
                raise RuntimeError("locked grant disappeared before consumption")
            return GrantStatus.VALID, consumed

    def delegate(
        self, parent_scope: AuthorizationScope, child_scope: AuthorizationScope, *,
        ttl: timedelta = timedelta(minutes=5), now: datetime | None = None,
    ) -> GrantRecord:
        with self._transaction() as cur:
            chain = self._locked_chain(cur, parent_scope.grant_id)
            child = delegated_record(parent_scope, child_scope, chain, now=self._clock(cur, now), ttl=ttl)
            created = self._insert(cur, child)
            cur.execute(
                f"UPDATE {self._table} SET delegated_to = %s WHERE grant_id = %s RETURNING grant_id",
                (created.grant_id, parent_scope.grant_id),
            )
            if cur.fetchone() is None:
                raise RuntimeError("locked parent disappeared before delegation")
            return created
