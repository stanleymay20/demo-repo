"""External anchoring contract for AgentShield evidence-chain heads.

This module intentionally does not pretend local storage is an external trust anchor.
Deployments supply a publisher backed by an independently controlled transparency log,
object-lock store, timestamping service, ledger, or equivalent system.

A publisher must attest the exact canonical anchor-statement digest it committed. This
binds stream identity, sequence, chain-head hash, audit key id and observation time to the
external reference. Whether that reference is truly immutable remains a provider/deployment
property and must be validated by the concrete adapter and operations evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Protocol

from .audit import (
    AUDIT_ENVELOPE_SCHEMA_VERSION,
    AuditEnvelope,
    ED25519_ALGORITHM,
    envelope_hash,
)


ANCHOR_STATEMENT_SCHEMA_VERSION = "agentshield-head-anchor-v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class HeadAnchorStatement:
    schema_version: str
    stream_id: str
    sequence: int
    head_envelope_hash: str
    audit_key_id: str
    observed_at_utc: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AnchorPublication:
    """Provider result proving which canonical statement digest it committed."""

    external_reference: str
    committed_statement_digest: str

    def __post_init__(self) -> None:
        if type(self.external_reference) is not str or not self.external_reference.strip():
            raise ValueError("external_reference must be a non-empty string")
        if (
            type(self.committed_statement_digest) is not str
            or _HEX_64.fullmatch(self.committed_statement_digest) is None
        ):
            raise ValueError("committed_statement_digest must be lowercase SHA-256 hex")
        object.__setattr__(self, "external_reference", self.external_reference.strip())


@dataclass(frozen=True)
class AnchorReceipt:
    statement: HeadAnchorStatement
    statement_digest: str
    external_reference: str


class HeadAnchorPublisher(Protocol):
    """Host-supplied external publication boundary.

    The concrete provider must durably commit the canonical statement and return the exact
    SHA-256 digest it stored. A local/mock implementation is not an independent trust anchor.
    """

    def publish(self, statement: HeadAnchorStatement) -> AnchorPublication: ...


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def anchor_statement_digest(statement: HeadAnchorStatement) -> str:
    """Return the canonical SHA-256 commitment an external provider must persist."""

    if type(statement) is not HeadAnchorStatement:
        raise TypeError("statement must be an exact HeadAnchorStatement")
    return hashlib.sha256(_canonical_bytes(statement.to_dict())).hexdigest()


def build_head_anchor_statement(
    *, stream_id: str, head: AuditEnvelope, observed_at_utc: datetime | None = None,
) -> HeadAnchorStatement:
    if type(stream_id) is not str or not stream_id.strip():
        raise ValueError("stream_id must be a non-empty string")
    if head.schema_version != AUDIT_ENVELOPE_SCHEMA_VERSION:
        raise ValueError("cannot anchor an unsupported audit envelope schema")
    if head.algorithm != ED25519_ALGORITHM:
        raise ValueError("independent head anchoring requires an Ed25519 audit chain")
    moment = observed_at_utc or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("observed_at_utc must be timezone-aware")
    return HeadAnchorStatement(
        schema_version=ANCHOR_STATEMENT_SCHEMA_VERSION,
        stream_id=stream_id.strip(),
        sequence=head.sequence,
        head_envelope_hash=envelope_hash(head),
        audit_key_id=head.key_id,
        observed_at_utc=moment.astimezone(timezone.utc).isoformat(),
    )


def publish_head_anchor(
    *, stream_id: str, head: AuditEnvelope, publisher: HeadAnchorPublisher,
    observed_at_utc: datetime | None = None,
) -> AnchorReceipt:
    """Publish and verify an exact-statement commitment at an external trust boundary."""

    statement = build_head_anchor_statement(
        stream_id=stream_id, head=head, observed_at_utc=observed_at_utc,
    )
    expected_digest = anchor_statement_digest(statement)
    publication = publisher.publish(statement)
    if type(publication) is not AnchorPublication:
        raise RuntimeError(
            "external anchor publisher must return AnchorPublication with statement commitment"
        )
    if publication.committed_statement_digest != expected_digest:
        raise RuntimeError(
            "external anchor publisher committed a different statement digest"
        )
    return AnchorReceipt(
        statement=statement,
        statement_digest=expected_digest,
        external_reference=publication.external_reference,
    )
