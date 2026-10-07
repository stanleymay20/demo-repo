"""External anchoring contract for AgentShield evidence-chain heads.

This module intentionally does not pretend local storage is an external trust anchor.
Deployments supply a publisher backed by an independently controlled transparency log,
object-lock store, timestamping service, ledger, or equivalent system.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Protocol

from .audit import AuditEnvelope, ED25519_ALGORITHM, envelope_hash


ANCHOR_STATEMENT_SCHEMA_VERSION = "agentshield-head-anchor-v1"


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
class AnchorReceipt:
    statement: HeadAnchorStatement
    external_reference: str


class HeadAnchorPublisher(Protocol):
    """Host-supplied external publication boundary."""

    def publish(self, statement: HeadAnchorStatement) -> str: ...


def build_head_anchor_statement(
    *, stream_id: str, head: AuditEnvelope, observed_at_utc: datetime | None = None,
) -> HeadAnchorStatement:
    if type(stream_id) is not str or not stream_id.strip():
        raise ValueError("stream_id must be a non-empty string")
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
    """Publish the signed-chain head through a host-controlled external trust boundary."""

    statement = build_head_anchor_statement(
        stream_id=stream_id, head=head, observed_at_utc=observed_at_utc,
    )
    reference = publisher.publish(statement)
    if type(reference) is not str or not reference.strip():
        raise RuntimeError("external anchor publisher did not return a durable reference")
    return AnchorReceipt(statement=statement, external_reference=reference.strip())
