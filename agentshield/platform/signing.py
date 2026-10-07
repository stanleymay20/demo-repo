"""Optional Ed25519 authentication for detached AgentShield evaluations.

The core runtime remains dependency-free. Install ``agentshield-runtime[signing]`` when
evaluation objects cross a process or service boundary. Private signing keys belong only
in the evaluation service; execution gateways should receive public verification keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Mapping

from .pipeline import PipelineResult, pipeline_result_digest


_EVALUATION_SIGNATURE_SCHEMA = "agentshield-evaluation-signature-v1"


class EvaluationSignatureStatus(str, Enum):
    VALID = "valid"
    UNKNOWN_KEY = "unknown_key"
    INVALID_SIGNATURE = "invalid_signature"
    MISMATCH = "mismatch"


@dataclass(frozen=True)
class EvaluationSignature:
    key_id: str
    evaluation_digest: str
    signature: str

    def __post_init__(self) -> None:
        if not self.key_id.strip():
            raise ValueError("key_id must be non-empty")
        if (
            len(self.evaluation_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.evaluation_digest)
        ):
            raise ValueError("evaluation_digest must be a SHA-256 hex digest")
        if not self.signature.strip():
            raise ValueError("signature must be non-empty")


def _cryptography():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - exercised in dependency-free installs
        raise RuntimeError(
            "Ed25519 signing requires agentshield-runtime[signing]"
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def _message(*, key_id: str, evaluation_digest: str) -> bytes:
    return json.dumps(
        {
            "schema": _EVALUATION_SIGNATURE_SCHEMA,
            "key_id": key_id,
            "evaluation_digest": evaluation_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class EvaluationSigner:
    """Evaluation-service-only holder of Ed25519 private keys."""

    def __init__(self, private_keys: Mapping[str, bytes], *, active_key_id: str) -> None:
        _, _, PrivateKey, _ = _cryptography()
        clean = dict(private_keys)
        if not clean or active_key_id not in clean:
            raise ValueError("active_key_id must reference a configured private key")
        self._keys = {}
        for key_id, raw in clean.items():
            if not key_id.strip() or len(raw) != 32:
                raise ValueError("Ed25519 private keys must be 32 raw bytes with a non-empty id")
            self._keys[key_id] = PrivateKey.from_private_bytes(raw)
        self._active_key_id = active_key_id

    def sign(self, result: PipelineResult) -> EvaluationSignature:
        digest = pipeline_result_digest(result)
        key_id = self._active_key_id
        signature = self._keys[key_id].sign(
            _message(key_id=key_id, evaluation_digest=digest)
        ).hex()
        return EvaluationSignature(
            key_id=key_id,
            evaluation_digest=digest,
            signature=signature,
        )

    def public_keys(self) -> dict[str, bytes]:
        """Export raw public keys for distribution to execution gateways."""

        _, serialization, _, _ = _cryptography()
        return {
            key_id: key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            for key_id, key in self._keys.items()
        }


class EvaluationVerifier:
    """Execution-side verifier containing public keys only."""

    def __init__(self, public_keys: Mapping[str, bytes]) -> None:
        _, _, _, PublicKey = _cryptography()
        clean = dict(public_keys)
        if not clean:
            raise ValueError("at least one evaluation public key is required")
        self._keys = {}
        for key_id, raw in clean.items():
            if not key_id.strip() or len(raw) != 32:
                raise ValueError("Ed25519 public keys must be 32 raw bytes with a non-empty id")
            self._keys[key_id] = PublicKey.from_public_bytes(raw)

    def verify(
        self,
        result: PipelineResult,
        signature: EvaluationSignature,
    ) -> EvaluationSignatureStatus:
        key = self._keys.get(signature.key_id)
        if key is None:
            return EvaluationSignatureStatus.UNKNOWN_KEY
        digest = pipeline_result_digest(result)
        if signature.evaluation_digest != digest:
            return EvaluationSignatureStatus.MISMATCH
        InvalidSignature, _, _, _ = _cryptography()
        try:
            encoded_signature = bytes.fromhex(signature.signature)
        except ValueError:
            return EvaluationSignatureStatus.INVALID_SIGNATURE
        try:
            key.verify(
                encoded_signature,
                _message(key_id=signature.key_id, evaluation_digest=digest),
            )
        except InvalidSignature:
            return EvaluationSignatureStatus.INVALID_SIGNATURE
        return EvaluationSignatureStatus.VALID
