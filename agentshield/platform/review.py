"""Cryptographically bound human-review approvals for AgentShield.

A REVIEW decision is not executable by itself. A trusted review service can issue a
short-lived HMAC approval that is bound to the exact request, action, payload, scope,
tool manifest, policy version and complete evaluation that were reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import secrets
from typing import Any, Mapping


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


def _material(approval: ReviewApproval) -> dict[str, Any]:
    return {
        "review_schema": "agentshield-review-v2",
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
    material = _material(approval)
    material["signature"] = approval.signature
    return hashlib.sha256(_canonical_bytes(material)).hexdigest()


class ReviewAuthority:
    """Issue and verify short-lived approvals with explicit signing-key rotation."""

    def __init__(self, keys: Mapping[str, bytes], *, active_key_id: str) -> None:
        clean = dict(keys)
        if active_key_id not in clean:
            raise ValueError("active_key_id is not present in keys")
        if not clean:
            raise ValueError("at least one review key is required")
        for key_id, key in clean.items():
            if not key_id.strip():
                raise ValueError("review key ids must be non-empty")
            if len(key) < 32:
                raise ValueError("review keys must contain at least 32 bytes")
        self._keys = clean
        self._active_key_id = active_key_id

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        now = datetime.now(timezone.utc) if value is None else value
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return now.astimezone(timezone.utc)

    def _signature(self, approval: ReviewApproval, key: bytes) -> str:
        return hmac.new(key, _canonical_bytes(_material(approval)), hashlib.sha256).hexdigest()

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
        now: datetime | None = None,
    ) -> ReviewApproval:
        if ttl <= timedelta(0):
            raise ValueError("review approval ttl must be positive")
        issued_at = self._now(now)
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
        return replace(
            approval,
            signature=self._signature(approval, self._keys[self._active_key_id]),
        )

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
        now: datetime | None = None,
    ) -> ReviewStatus:
        key = self._keys.get(approval.key_id)
        if key is None:
            return ReviewStatus.UNKNOWN_KEY
        expected_signature = self._signature(replace(approval, signature=""), key)
        if not hmac.compare_digest(expected_signature, approval.signature):
            return ReviewStatus.INVALID_SIGNATURE
        current = self._now(now)
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
