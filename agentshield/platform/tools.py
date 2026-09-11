"""Server-owned tool capability manifests for AgentShield.

Agent-provided action metadata is not authoritative. The registry is the trusted source
for what a tool can actually do, preventing capability under-declaration from weakening
policy decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .actions import ActionDescriptor, normalize_capabilities


@dataclass(frozen=True)
class ToolManifest:
    name: str
    capabilities: tuple[str, ...]
    version: str = "1"

    def __post_init__(self) -> None:
        name = self.name.strip()
        version = self.version.strip()
        if not name:
            raise ValueError("tool name must be non-empty")
        if not version:
            raise ValueError("tool version must be non-empty")
        capabilities = normalize_capabilities(self.capabilities)
        if not capabilities:
            raise ValueError("tool capabilities must be non-empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "capabilities", capabilities)

    @property
    def descriptor(self) -> ActionDescriptor:
        return ActionDescriptor(self.name, self.capabilities)


class ToolRegistry:
    """Immutable registry of authoritative tool manifests."""

    def __init__(self, manifests: tuple[ToolManifest, ...]):
        index: dict[str, ToolManifest] = {}
        for manifest in manifests:
            if manifest.name in index:
                raise ValueError(f"duplicate tool manifest: {manifest.name}")
            index[manifest.name] = manifest
        self._index = index

    def resolve(self, name: str) -> ToolManifest | None:
        return self._index.get(name.strip())


class ToolVerificationStatus(str, Enum):
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    UNREGISTERED = "unregistered"
    UNKNOWN = "unknown"


def verify_action_descriptor(
    action: ActionDescriptor,
    registry: ToolRegistry | None,
) -> tuple[ToolVerificationStatus, ToolManifest | None]:
    """Compare an agent-proposed descriptor with the server-owned manifest."""

    if registry is None:
        return ToolVerificationStatus.UNKNOWN, None

    manifest = registry.resolve(action.name)
    if manifest is None:
        return ToolVerificationStatus.UNREGISTERED, None

    declared = normalize_capabilities(action.capabilities)
    if declared != manifest.capabilities:
        return ToolVerificationStatus.MISMATCH, manifest

    return ToolVerificationStatus.VERIFIED, manifest
