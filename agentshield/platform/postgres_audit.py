"""Durable PostgreSQL-backed AgentShield audit trail.

Unlike a simple persistence callback, this trail serializes chain construction in the
database. Every worker locks one logical stream, reads its current head, signs the next
envelope against that exact head, and persists envelope + event in the same transaction.
This prevents independent process-local chains from silently diverging.

The class requires an Ed25519 signer so persisted evidence remains independently
verifiable with public keys only. External head anchoring is intentionally separate: a
host should periodically publish ``head_hash`` outside the database writer's control.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import re
from typing import Any, Callable, Mapping

from .audit import (
    AuditEnvelope,
    ED25519_ALGORITHM,
    Ed25519AuditSigner,
    envelope_hash,
)


_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _event_mapping(event: Any) -> dict[str, Any]:
    if hasattr(event, "to_dict"):
        value = event.to_dict()
    elif isinstance(event, Mapping):
        value = dict(event)
    else:
        raise TypeError("audit event must be a mapping or expose to_dict()")
    try:
        # Detach custom objects and reject non-JSON/NaN values before persistence.
        return json.loads(json.dumps(value, allow_nan=False, ensure_ascii=False))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("audit event must be portable strict JSON") from exc


class PostgresAuditTrail:
    """Database-serialized Ed25519 audit chain for one logical evidence stream."""

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        signer: Ed25519AuditSigner,
        *,
        stream_id: str,
        table_name: str = "agentshield_audit_events",
    ) -> None:
        if not _TABLE_RE.fullmatch(table_name):
            raise ValueError("table_name must be a simple SQL identifier")
        if type(stream_id) is not str or not stream_id.strip():
            raise ValueError("stream_id must be a non-empty string")
        if not isinstance(signer, Ed25519AuditSigner):
            raise TypeError("durable independent evidence requires Ed25519AuditSigner")
        self._connection_factory = connection_factory
        self._signer = signer
        self._stream_id = stream_id.strip()
        self._table = table_name

    @contextmanager
    def _transaction(self):
        conn = self._connection_factory()
        try:
            if conn.autocommit:
                raise ValueError("PostgresAuditTrail requires autocommit=False")
            with conn.cursor() as cur:
                yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def ensure_schema(self) -> None:
        with self._transaction() as cur:
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {self._table} (
                    stream_id TEXT NOT NULL,
                    sequence BIGINT NOT NULL,
                    schema_version TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    previous_envelope_hash TEXT NULL,
                    event_hash TEXT NOT NULL,
                    envelope_hash TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    event_json JSONB NOT NULL,
                    persisted_at_utc TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                    PRIMARY KEY (stream_id, sequence),
                    UNIQUE (stream_id, envelope_hash)
                );
                CREATE INDEX IF NOT EXISTS {self._table}_head_idx
                    ON {self._table} (stream_id, sequence DESC);
            """)

    def _lock_stream(self, cur) -> None:
        # The two-argument advisory lock gives this table namespace plus stream identity a
        # transaction-scoped mutex without requiring a pre-existing row for empty streams.
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
            (self._table, self._stream_id),
        )

    def _read_head(self, cur) -> AuditEnvelope | None:
        cur.execute(
            f"SELECT schema_version, sequence, previous_envelope_hash, event_hash, "
            f"key_id, signature, algorithm FROM {self._table} "
            "WHERE stream_id = %s ORDER BY sequence DESC LIMIT 1",
            (self._stream_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return AuditEnvelope(
            schema_version=row[0], sequence=row[1], previous_envelope_hash=row[2],
            event_hash=row[3], key_id=row[4], signature=row[5], algorithm=row[6],
        )

    def append(self, event: Any) -> AuditEnvelope:
        mapped = _event_mapping(event)
        with self._transaction() as cur:
            self._lock_stream(cur)
            previous = self._read_head(cur)
            sequence = 0 if previous is None else previous.sequence + 1
            envelope = self._signer.seal(mapped, sequence=sequence, previous=previous)
            if envelope.algorithm != ED25519_ALGORITHM:
                raise RuntimeError("durable evidence signer did not produce Ed25519")
            digest = envelope_hash(envelope)
            cur.execute(
                f"INSERT INTO {self._table} ("
                "stream_id, sequence, schema_version, algorithm, previous_envelope_hash, "
                "event_hash, envelope_hash, key_id, signature, event_json"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    self._stream_id, envelope.sequence, envelope.schema_version,
                    envelope.algorithm, envelope.previous_envelope_hash,
                    envelope.event_hash, digest, envelope.key_id, envelope.signature,
                    json.dumps(mapped, sort_keys=True, ensure_ascii=False, allow_nan=False),
                ),
            )
            return envelope

    def load(self) -> tuple[tuple[AuditEnvelope, ...], tuple[dict[str, Any], ...]]:
        with self._transaction() as cur:
            cur.execute(
                f"SELECT schema_version, sequence, previous_envelope_hash, event_hash, "
                f"key_id, signature, algorithm, event_json FROM {self._table} "
                "WHERE stream_id = %s ORDER BY sequence ASC",
                (self._stream_id,),
            )
            envelopes: list[AuditEnvelope] = []
            events: list[dict[str, Any]] = []
            for row in cur.fetchall():
                envelopes.append(AuditEnvelope(
                    schema_version=row[0], sequence=row[1], previous_envelope_hash=row[2],
                    event_hash=row[3], key_id=row[4], signature=row[5], algorithm=row[6],
                ))
                raw_event = row[7]
                events.append(raw_event if type(raw_event) is dict else json.loads(raw_event))
            return tuple(envelopes), tuple(events)

    @property
    def envelopes(self) -> tuple[AuditEnvelope, ...]:
        return self.load()[0]

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return self.load()[1]

    @property
    def head(self) -> AuditEnvelope | None:
        with self._transaction() as cur:
            self._lock_stream(cur)
            return self._read_head(cur)

    @property
    def head_hash(self) -> str | None:
        current = self.head
        return None if current is None else envelope_hash(current)
