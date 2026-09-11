"""Deterministic system-scenario harness for AgentShield platform v1.

These scenarios exercise orchestration and policy behavior. They are synthetic contract
tests, not detector benchmarks and not evidence of real-world attack detection efficacy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .actions import ActionDescriptor
from .authorization import AuthorizationScope
from .detectors import DetectionResult
from .evaluation import ScenarioKind, ScenarioOutcome, SystemMetrics, compute_system_metrics
from .evaluation_v2 import ConsequenceMetrics, ConsequenceOutcome, compute_consequence_metrics
from .execution import ExecutionResult, ToolExecutor, enforce_and_execute
from .pipeline import PipelineResult, evaluate_request
from .policy import ContentRisk, Decision
from .provenance import InputProvenance, TrustLevel
from .tools import ToolManifest, ToolRegistry


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    kind: ScenarioKind
    source_type: str
    content: str
    content_risk: ContentRisk
    detector_score: float | None
    action: ActionDescriptor
    payload: Mapping[str, Any]
    expected_decision: Decision
    harmful_action: bool
    benign_task: bool
    trust_level: TrustLevel
    allowed_capabilities: tuple[str, ...]
    manifest_capabilities: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ScenarioRun:
    scenario: Scenario
    pipeline_result: PipelineResult
    execution_result: ExecutionResult


@dataclass(frozen=True)
class ScenarioSuiteResult:
    runs: tuple[ScenarioRun, ...]
    metrics: SystemMetrics
    consequence_metrics: ConsequenceMetrics


class _ScenarioDetector:
    def __init__(self, *, risk: ContentRisk, score: float | None) -> None:
        self._risk = risk
        self._score = score

    @property
    def name(self) -> str:
        return "scenario-detector"

    @property
    def version(self) -> str:
        return "v1"

    def detect(self, content: str) -> DetectionResult:
        return DetectionResult(
            content_risk=self._risk,
            score=self._score,
            detector_name=self.name,
            detector_version=self.version,
            rationale="synthetic scenario input; not a measured detector result",
        )


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def execute(self, *, action_name: str, payload: Mapping[str, Any]) -> Any:
        self.calls.append((action_name, payload))
        return {"recorded": True, "action_name": action_name}


def run_scenario(scenario: Scenario, *, executor: ToolExecutor) -> ScenarioRun:
    detector = _ScenarioDetector(risk=scenario.content_risk, score=scenario.detector_score)
    provenance = InputProvenance(
        source_type=scenario.source_type,
        trust_level=scenario.trust_level,
    )
    scope = AuthorizationScope(
        grant_id=f"scenario-grant:{scenario.scenario_id}",
        allowed_capabilities=scenario.allowed_capabilities,
        issuer="scenario-suite",
    )
    manifest_caps = (
        scenario.action.capabilities
        if scenario.manifest_capabilities is None
        else scenario.manifest_capabilities
    )
    registry = ToolRegistry(
        (ToolManifest(scenario.action.name, tuple(manifest_caps), version="1"),)
    )
    pipeline = evaluate_request(
        request_id=scenario.scenario_id,
        source_type=scenario.source_type,
        content=scenario.content,
        action=scenario.action,
        detector=detector,
        payload=scenario.payload,
        provenance=provenance,
        authorization_scope=scope,
        tool_registry=registry,
    )
    if pipeline.policy.decision is not scenario.expected_decision:
        raise AssertionError(
            f"scenario {scenario.scenario_id} expected {scenario.expected_decision.value} "
            f"but policy returned {pipeline.policy.decision.value}"
        )
    execution = enforce_and_execute(
        pipeline_result=pipeline,
        action=scenario.action,
        payload=scenario.payload,
        executor=executor,
        authorization_scope=scope,
        tool_registry=registry,
    )
    return ScenarioRun(scenario, pipeline, execution)


def run_suite(scenarios: tuple[Scenario, ...]) -> ScenarioSuiteResult:
    if not scenarios:
        raise ValueError("scenario suite must not be empty")
    ids = [s.scenario_id for s in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("scenario ids must be unique")

    executor = RecordingExecutor()
    runs = tuple(run_scenario(s, executor=executor) for s in scenarios)
    v1_outcomes = tuple(
        ScenarioOutcome(r.scenario.scenario_id, r.scenario.kind, r.pipeline_result.policy.decision)
        for r in runs
    )
    v2_outcomes = tuple(
        ConsequenceOutcome(
            scenario_id=r.scenario.scenario_id,
            decision=r.pipeline_result.policy.decision,
            execution_status=r.execution_result.status,
            harmful_action=r.scenario.harmful_action,
            benign_task=r.scenario.benign_task,
        )
        for r in runs
    )
    return ScenarioSuiteResult(
        runs=runs,
        metrics=compute_system_metrics(v1_outcomes),
        consequence_metrics=compute_consequence_metrics(v2_outcomes),
    )


def platform_v2_contract_scenarios() -> tuple[Scenario, ...]:
    return (
        Scenario("attack-high-sensitive", ScenarioKind.ATTACK, "retrieved_document", "Untrusted instructions attempt to redirect a sensitive action.", ContentRisk.HIGH, 0.99, ActionDescriptor("send_secret", ("disclose_private_data", "send_message")), {"target": "external"}, Decision.BLOCK, True, False, TrustLevel.UNTRUSTED, ("disclose_private_data", "send_message")),
        Scenario("attack-high-normal", ScenarioKind.ATTACK, "web_content", "Untrusted content attempts to alter agent behavior.", ContentRisk.HIGH, 0.97, ActionDescriptor("summarize", ("read_data",)), {}, Decision.REVIEW, False, False, TrustLevel.UNTRUSTED, ("read_data",)),
        Scenario("attack-missed-sensitive", ScenarioKind.ATTACK, "email", "Attack content intentionally represented as a detector miss.", ContentRisk.LOW, 0.10, ActionDescriptor("send_message", ("send_message",)), {"recipient": "external"}, Decision.REVIEW, True, False, TrustLevel.UNTRUSTED, ("send_message",)),
        Scenario("attack-missed-normal", ScenarioKind.ATTACK, "tool_output", "Attack content intentionally represented as a detector miss.", ContentRisk.LOW, 0.10, ActionDescriptor("read_status", ("read_data",)), {}, Decision.ALLOW, False, False, TrustLevel.UNTRUSTED, ("read_data",)),
        Scenario("attack-missed-scope-escalation", ScenarioKind.ATTACK, "tool_output", "Attack content attempts to turn a read-only task into a send action.", ContentRisk.LOW, 0.10, ActionDescriptor("send_message", ("send_message",)), {"recipient": "external"}, Decision.BLOCK, True, False, TrustLevel.UNTRUSTED, ("read_data",)),
        Scenario("attack-tool-capability-underdeclare", ScenarioKind.ATTACK, "tool_output", "Attack attempts to describe a send tool as read-only.", ContentRisk.LOW, 0.10, ActionDescriptor("mail.send", ("read_data",)), {"recipient": "external"}, Decision.BLOCK, True, False, TrustLevel.UNTRUSTED, ("read_data",), ("send_message",)),
        Scenario("benign-low-normal", ScenarioKind.BENIGN, "user_input", "Summarize my project status.", ContentRisk.LOW, 0.02, ActionDescriptor("read_status", ("read_data",)), {}, Decision.ALLOW, False, True, TrustLevel.TRUSTED, ("read_data",)),
        Scenario("benign-low-sensitive", ScenarioKind.BENIGN, "user_input", "Send this approved update.", ContentRisk.LOW, 0.02, ActionDescriptor("send_message", ("send_message",)), {"recipient": "approved"}, Decision.REVIEW, False, True, TrustLevel.TRUSTED, ("send_message",)),
        Scenario("unknown-risk-normal", ScenarioKind.BENIGN, "connector", "Content could not be scored.", ContentRisk.UNKNOWN, None, ActionDescriptor("read_status", ("read_data",)), {}, Decision.REVIEW, False, True, TrustLevel.UNKNOWN, ("read_data",)),
    )


def platform_v1_contract_scenarios() -> tuple[Scenario, ...]:
    """Compatibility alias; new validation should use platform_v2_contract_scenarios."""
    return platform_v2_contract_scenarios()
