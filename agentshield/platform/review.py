"""Cryptographically bound human-review approvals for AgentShield.

A REVIEW decision is not executable by itself. A trusted review service signs a
short-lived Ed25519 approval bound to the exact request, action, payload, scope, tool
manifest, policy version and complete evaluation. Execution gateways hold public keys
only, so the ability to verify an approval does not confer the ability to forge one.

Ed25519 support is optional at install time: use ``agentshield-runtime[signing]``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import secrets
from typing import Any, Callable, Mapping


REVIEW_SCHEMA_VERSION = "agentshield-review-v3-ed25519"
_HEX = frozenset("0123456789abcdef")


def canonical_review_signature(value: Any) -> bool:
    """Accept only the signer-produced encoding: 128 lowercase hex characters.

    ``review_approval_digest`` commits the signature text. Accepting alternate encodings
    of the same Ed25519 bytes (uppercase, embedded whitespace) would let one signed
    approval carry several accepted digests in execution evidence.
    """
    return type(value) is str and len(value) == 128 and all(char in _HEX for char in value)


class ReviewStatus(str, Enum):
    VALID = "valid"
    UNKNOWN_KEY = "unknown_key"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    MISMATCH = "mismatch"


@dataclass(frozen=True)
class ReviewApproval:
    approval_id: str
    request_id: str
    action_digest: str
    payload_digest: str
    scope_digest: str
    tool_manifest_digest: str
    policy_version: str
    evaluation_digest: str
    reviewer: str
    issued_at_utc: datetime
    expires_at_utc: datetime
    key_id: str
    signature: str = ""

    def __post_init__(self) -> None:
        if self.issued_at_utc.tzinfo is None or self.expires_at_utc.tzinfo is None:
            raise ValueError("review timestamps must be timezone-aware")
        if self.expires_at_utc <= self.issued_at_utc:
            raise ValueError("review approval expiry must be after issuance")
        if (type(self.evaluation_digest) is not str or len(self.evaluation_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.evaluation_digest)):
            raise ValueError("evaluation_digest must be a SHA-256 hex digest")
        for value, field in (
            (self.approval_id, "approval_id"),
            (self.request_id, "request_id"),
            (self.action_digest, "action_digest"),
            (self.payload_digest, "payload_digest"),
            (self.scope_digest, "scope_digest"),
            (self.tool_manifest_digest, "tool_manifest_digest"),
            (self.policy_version, "policy_version"),
            (self.reviewer, "reviewer"),
            (self.key_id, "key_id"),
        ):
            if not value.strip():
                raise ValueError(f"{field} must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        """Return the exact portable signed approval representation."""
        material = review_approval_material(self)
        material["signature"] = self.signature
        return material


def review_approval_material(approval: ReviewApproval) -> dict[str, Any]:
    """Return the canonical bytes-to-sign material for one human approval."""
    return {
        "review_schema": REVIEW_SCHEMA_VERSION,
        "evaluation_digest": approval.evaluation_digest,
        "approval_id": approval.approval_id,
        "request_id": approval.request_id,
        "action_digest": approval.action_digest,
        "payload_digest": approval.payload_digest,
        "scope_digest": approval.scope_digest,
        "tool_manifest_digest": approval.tool_manifest_digest,
        "policy_version": approval.policy_version,
        "reviewer": approval.reviewer,
        "issued_at_utc": approval.issued_at_utc.astimezone(timezone.utc).isoformat(),
        "expires_at_utc": approval.expires_at_utc.astimezone(timezone.utc).isoformat(),
        "key_id": approval.key_id,
    }


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def review_approval_digest(approval: ReviewApproval) -> str:
    return hashlib.sha256(_canonical_bytes(approval.to_dict())).hexdigest()


def load_review_approval(value: Mapping[str, Any]) -> ReviewApproval:
    """Parse a portable approval without trusting its signature."""
    if type(value) is not dict:
        raise ValueError("review approval proof must be an object")
    expected = {
        "review_schema", "evaluation_digest", "approval_id", "request_id",
        "action_digest", "payload_digest", "scope_digest", "tool_manifest_digest",
        "policy_version", "reviewer", "issued_at_utc", "expires_at_utc", "key_id",
        "signature",
    }
    if set(value) != expected or value.get("review_schema") != REVIEW_SCHEMA_VERSION:
        raise ValueError("unsupported or malformed review approval proof")
    try:
        issued = datetime.fromisoformat(value["issued_at_utc"])
        expires = datetime.fromisoformat(value["expires_at_utc"])
    except (TypeError, ValueError) as exc:
        raise ValueError("review approval timestamps are invalid") from exc
    try:
        approval = ReviewApproval(
            approval_id=value["approval_id"],
            request_id=value["request_id"],
            action_digest=value["action_digest"],
            payload_digest=value["payload_digest"],
            scope_digest=value["scope_digest"],
            tool_manifest_digest=value["tool_manifest_digest"],
            policy_version=value["policy_version"],
            evaluation_digest=value["evaluation_digest"],
            reviewer=value["reviewer"],
            issued_at_utc=issued,
            expires_at_utc=expires,
            key_id=value["key_id"],
            signature=value["signature"],
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("review approval proof fields are invalid") from exc
    # The portable proof must be byte-for-byte the canonical signed representation.
    # Otherwise a relayer can re-encode timestamps (or the signature) so the accepted
    # proof differs from the exact bytes the reviewer signed, and independent verifiers
    # that hash the literal proof disagree with ones that normalize it first.
    if not canonical_review_signature(approval.signature) or approval.to_dict() != value:
        raise ValueError("review approval proof is not in canonical signed form")
    return approval


def _cryptography():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - dependency-free install path
        raise RuntimeError(
            "Ed25519 review approvals require agentshield-runtime[signing]"
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def _normalize_clock(clock: Callable[[], datetime]) -> datetime:
    now = clock()
    if now.tzinfo is None:
        raise ValueError("review authority clock must return a timezone-aware datetime")
    return now.astimezone(timezone.utc)


class ReviewSigner:
    """Review-service-only holder of Ed25519 private signing keys."""

    def __init__(
        self,
        private_keys: Mapping[str, bytes],
        *,
        active_key_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        _, _, PrivateKey, _ = _cryptography()
        clean = dict(private_keys)
        if not clean or active_key_id not in clean:
            raise ValueError("active_key_id must reference a configured review private key")
        self._keys = {}
        for key_id, raw in clean.items():
            if not key_id.strip() or len(raw) != 32:
                raise ValueError("Ed25519 private keys must be 32 raw bytes with a non-empty id")
            self._keys[key_id] = PrivateKey.from_private_bytes(raw)
        self._active_key_id = active_key_id
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def issue(
        self,
        *,
        request_id: str,
        action_digest: str,
        payload_digest: str,
        scope_digest: str,
        tool_manifest_digest: str,
        policy_version: str,
        evaluation_digest: str,
        reviewer: str,
        ttl: timedelta = timedelta(minutes=5),
    ) -> ReviewApproval:
        if ttl <= timedelta(0):
            raise ValueError("review approval ttl must be positive")
        issued_at = _normalize_clock(self._clock)
        approval = ReviewApproval(
            approval_id="review_" + secrets.token_urlsafe(18),
            request_id=request_id,
            action_digest=action_digest,
            payload_digest=payload_digest,
            scope_digest=scope_digest,
            tool_manifest_digest=tool_manifest_digest,
            policy_version=policy_version,
            evaluation_digest=evaluation_digest,
            reviewer=reviewer,
            issued_at_utc=issued_at,
            expires_at_utc=issued_at + ttl,
            key_id=self._active_key_id,
        )
        signature = self._keys[self._active_key_id].sign(
            _canonical_bytes(review_approval_material(approval))
        ).hex()
        return replace(approval, signature=signature)

    def public_keys(self) -> dict[str, bytes]:
        _, serialization, _, _ = _cryptography()
        return {
            key_id: key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            for key_id, key in self._keys.items()
        }


class ReviewVerifier:
    """Execution-side approval verifier containing public keys only."""

    def __init__(
        self,
        public_keys: Mapping[str, bytes],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        _, _, _, PublicKey = _cryptography()
        clean = dict(public_keys)
        if not clean:
            raise ValueError("at least one review public key is required")
        self._keys = {}
        for key_id, raw in clean.items():
            if not key_id.strip() or len(raw) != 32:
                raise ValueError("Ed25519 public keys must be 32 raw bytes with a non-empty id")
            self._keys[key_id] = PublicKey.from_public_bytes(raw)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def verify_signature(self, approval: ReviewApproval) -> ReviewStatus:
        """Verify approval authorship without applying current-time semantics."""
        key = self._keys.get(approval.key_id)
        if key is None:
            return ReviewStatus.UNKNOWN_KEY
        if not canonical_review_signature(approval.signature):
            return ReviewStatus.INVALID_SIGNATURE
        signature = bytes.fromhex(approval.signature)
        InvalidSignature, _, _, _ = _cryptography()
        try:
            key.verify(signature, _canonical_bytes(review_approval_material(approval)))
        except InvalidSignature:
            return ReviewStatus.INVALID_SIGNATURE
        return ReviewStatus.VALID

    def verify(
        self,
        approval: ReviewApproval,
        *,
        request_id: str,
        action_digest: str,
        payload_digest: str,
        scope_digest: str,
        tool_manifest_digest: str,
        policy_version: str,
        evaluation_digest: str,
    ) -> ReviewStatus:
        signature_status = self.verify_signature(approval)
        if signature_status is not ReviewStatus.VALID:
            return signature_status
        current = _normalize_clock(self._clock)
        if current < approval.issued_at_utc:
            return ReviewStatus.NOT_YET_VALID
        if current >= approval.expires_at_utc:
            return ReviewStatus.EXPIRED
        expected = (
            request_id,
            action_digest,
            payload_digest,
            scope_digest,
            tool_manifest_digest,
            policy_version,
            evaluation_digest,
        )
        observed = (
            approval.request_id,
            approval.action_digest,
            approval.payload_digest,
            approval.scope_digest,
            approval.tool_manifest_digest,
            approval.policy_version,
            approval.evaluation_digest,
        )
        if observed != expected:
            return ReviewStatus.MISMATCH
        return ReviewStatus.VALID
