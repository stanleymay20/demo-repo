"""Canonical integrity binding for AgentShield authorization inputs.

Only hashes are stored in audit metadata; raw payload values and full grants are not
persisted here. Inputs must be JSON-compatible so authorization and execution can
reproduce the same canonical representation deterministically.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping

from .actions import ActionDescriptor, normalize_capabilities
from .authorization import AuthorizationScope
from .tools import ToolManifest

MAX_PAYLOAD_DEPTH = 64


def snapshot_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Detach a strict JSON object from caller-owned state.

    Non-string keys, tuples and custom container/scalar subclasses are rejected:
    their JSON representation can alias a different Python value or run callbacks.
    The snapshot is taken before calling detectors or authority adapters and is the
    only payload handed to the trusted executor. Depth and cycles fail closed.
    """

    data = {} if payload is None else payload
    if type(data) is not dict:
        raise ValueError("action payload must be a plain JSON object")
    active: set[int] = set()

    def copy_value(value: Any, depth: int) -> Any:
        if depth > MAX_PAYLOAD_DEPTH:
            raise ValueError("action payload exceeds maximum JSON nesting depth")
        kind = type(value)
        if value is None or kind in (str, int, bool):
            return value
        if kind is float:
            if not math.isfinite(value):
                raise ValueError("action payload numbers must be finite")
            return value
        if kind not in (dict, list):
            raise ValueError("action payload must contain plain JSON values")
        identity = id(value)
        if identity in active:
            raise ValueError("action payload must not contain cycles")
        active.add(identity)
        try:
            if kind is list:
                return [copy_value(item, depth + 1) for item in value]
            result: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("action payload object keys must be strings")
                result[key] = copy_value(item, depth + 1)
            return result
        finally:
            active.remove(identity)

    try:
        return copy_value(data, 0)
    except (RuntimeError, RecursionError) as exc:
        raise ValueError("action payload could not be safely snapshotted") from exc


def _canonical_json(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("authorization input must be JSON-compatible") from exc


def payload_digest(payload: Mapping[str, Any] | None) -> str:
    data = snapshot_payload(payload)
    return hashlib.sha256(_canonical_json(data)).hexdigest()


def action_digest(action: ActionDescriptor) -> str:
    material = {
        "name": action.name.strip(),
        "capabilities": list(normalize_capabilities(action.capabilities)),
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def scope_digest(scope: AuthorizationScope) -> str:
    material = {
        "scope_schema": "agentshield-scope-v2",
        "grant_id": scope.grant_id,
        "issuer": scope.issuer,
        "allowed_capabilities": list(scope.allowed_capabilities),
        "allowed_effects": list(scope.allowed_effects),
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def tool_manifest_digest(manifest: ToolManifest) -> str:
    material = {
        "name": manifest.name,
        "version": manifest.version,
        "capabilities": list(manifest.capabilities),
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()
