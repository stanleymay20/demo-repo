"""AgentShield layered agent-security platform primitives."""

from .audit import (
    AuditEnvelope,
    AuditSigner,
    AuditTrail,
    AuditVerificationStatus,
    ChainVerificationResult,
    Ed25519AuditSigner,
    Ed25519AuditVerifier,
    verify_chain,
)
from .authorization import AuthorizationScope, ScopeStatus, check_action_scope
from .events import ExecutionAuditEvent, evaluation_digest
from .effects import effect_digest, check_effect_scope
from .pipeline import pipeline_result_digest, verify_in_process_evaluation
from .policy import ActionRisk, ContentRisk, Decision, PolicyInput, decide
from .postgres_grants import PostgresGrantAuthority
from .provenance import InputProvenance, TrustLevel
from .receipts import (
    EvidenceBundle,
    EvidenceRecord,
    build_bundle,
    bundle_digest,
    load_bundle,
    verify_bundle,
)
from .review import ReviewApproval, ReviewSigner, ReviewVerifier, ReviewStatus
from .signing import (
    EvaluationSignature,
    EvaluationSignatureStatus,
    EvaluationSigner,
    EvaluationVerifier,
)
from .tools import ToolManifest, ToolRegistry, ToolVerificationStatus

__all__ = [
    "ActionRisk",
    "AuditEnvelope",
    "AuditSigner",
    "AuditTrail",
    "AuditVerificationStatus",
    "AuthorizationScope",
    "ChainVerificationResult",
    "ContentRisk",
    "Decision",
    "Ed25519AuditSigner",
    "Ed25519AuditVerifier",
    "EvaluationSignature",
    "EvaluationSignatureStatus",
    "EvaluationSigner",
    "EvaluationVerifier",
    "EvidenceBundle",
    "EvidenceRecord",
    "ExecutionAuditEvent",
    "InputProvenance",
    "PolicyInput",
    "PostgresGrantAuthority",
    "ReviewApproval",
    "ReviewSigner",
    "ReviewVerifier",
    "ReviewStatus",
    "ScopeStatus",
    "ToolManifest",
    "ToolRegistry",
    "ToolVerificationStatus",
    "TrustLevel",
    "build_bundle",
    "bundle_digest",
    "check_action_scope",
    "check_effect_scope",
    "effect_digest",
    "evaluation_digest",
    "load_bundle",
    "pipeline_result_digest",
    "verify_bundle",
    "verify_chain",
    "verify_in_process_evaluation",
    "decide",
]
