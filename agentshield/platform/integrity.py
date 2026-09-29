"""Canonical integrity binding for AgentShield authorization inputs.

Only hashes are stored in audit metadata; raw payload values and full grants are not
persisted here. Inputs must be JSON-compatible so authorization and execution can
reproduce the same canonical representation deterministically.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .actions import ActionDescriptor, normalize_capabilities
from .authorization import AuthorizationScope
from .tools import ToolManifest


def _canonical_json(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("authorization input must be JSON-compatible") from exc
    return text.encode("utf-8")


def payload_digest(payload: Mapping[str, Any] | None) -> str:
    data = {} if payload is None else dict(payload)
    return hashlib.sha256(_canonical_json(data)).hexdigest()


def action_digest(action: ActionDescriptor) -> str:
    material = {
        "name": action.name.strip(),
        "capabilities": list(normalize_capabilities(action.capabilities)),
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def scope_digest(scope: AuthorizationScope) -> str:
    material = {
        "grant_id": scope.grant_id,
        "issuer": scope.issuer,
        "allowed_capabilities": list(scope.allowed_capabilities),
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def tool_manifest_digest(manifest: ToolManifest) -> str:
    material = {
        "name": manifest.name,
        "version": manifest.version,
        "capabilities": list(manifest.capabilities),
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()
