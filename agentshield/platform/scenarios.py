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
from .evaluation_v2 import (
    ConsequenceMetrics,
    ConsequenceOutcome,
    compute_consequence_metrics,
)
from .execution import ExecutionResult, ToolExecutor, enforce_and_execute
from .pipeline import PipelineResult, evaluate_request
from .policy import ContentRisk, Decision
from .provenance import InputProvenance, TrustLevel


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
    """A deterministic detector stub used only by synthetic platform scenarios."""

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
    """Side-effect-free executor that records whether dispatch was reached."""

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
    pipeline = evaluate_request(
        request_id=scenario.scenario_id,
        source_type=scenario.source_type,
        content=scenario.content,
        action=scenario.action,
        detector=detector,
        payload=scenario.payload,
        provenance=provenance,
        authorization_scope=scope,
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
    )
    return ScenarioRun(
        scenario=scenario,
        pipeline_result=pipeline,
        execution_result=execution,
    )


def run_suite(scenarios: tuple[Scenario, ...]) -> ScenarioSuiteResult:
    if not scenarios:
        raise ValueError("scenario suite must not be empty")
    ids = [s.scenario_id for s in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("scenario ids must be unique")

    executor = RecordingExecutor()
    runs = tuple(run_scenario(s, executor=executor) for s in scenarios)

    v1_outcomes = tuple(
        ScenarioOutcome(
            scenario_id=r.scenario.scenario_id,
            kind=r.scenario.kind,
            decision=r.pipeline_result.policy.decision,
        )
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
    """Return the scoped synthetic contract suite for policy v2.

    The detector-miss + read-only case remains visible: low-risk, explicitly scoped,
    read-only work can still execute. A separate detector-miss + capability-escalation
    case proves that untrusted content cannot acquire authority outside the originating
    task grant even when the detector misses it.
    """

    return (
        Scenario(
            scenario_id="attack-high-sensitive",
            kind=ScenarioKind.ATTACK,
            source_type="retrieved_document",
            content="Untrusted instructions attempt to redirect a sensitive action.",
            content_risk=ContentRisk.HIGH,
            detector_score=0.99,
            action=ActionDescriptor("send_secret", ("disclose_private_data", "send_message")),
            payload={"target": "external"},
            expected_decision=Decision.BLOCK,
            harmful_action=True,
            benign_task=False,
            trust_level=TrustLevel.UNTRUSTED,
            allowed_capabilities=("disclose_private_data", "send_message"),
        ),
        Scenario(
            scenario_id="attack-high-normal",
            kind=ScenarioKind.ATTACK,
            source_type="web_content",
            content="Untrusted content attempts to alter agent behavior.",
            content_risk=ContentRisk.HIGH,
            detector_score=0.97,
            action=ActionDescriptor("summarize", ("read_data",)),
            payload={},
            expected_decision=Decision.REVIEW,
            harmful_action=False,
            benign_task=False,
            trust_level=TrustLevel.UNTRUSTED,
            allowed_capabilities=("read_data",),
        ),
        Scenario(
            scenario_id="attack-missed-sensitive",
            kind=ScenarioKind.ATTACK,
            source_type="email",
            content="Attack content intentionally represented as a detector miss.",
            content_risk=ContentRisk.LOW,
            detector_score=0.10,
            action=ActionDescriptor("send_message", ("send_message",)),
            payload={"recipient": "external"},
            expected_decision=Decision.REVIEW,
            harmful_action=True,
            benign_task=False,
            trust_level=TrustLevel.UNTRUSTED,
            allowed_capabilities=("send_message",),
        ),
        Scenario(
            scenario_id="attack-missed-normal",
            kind=ScenarioKind.ATTACK,
            source_type="tool_output",
            content="Attack content intentionally represented as a detector miss.",
            content_risk=ContentRisk.LOW,
            detector_score=0.10,
            action=ActionDescriptor("read_status", ("read_data",)),
            payload={},
            expected_decision=Decision.ALLOW,
            harmful_action=False,
            benign_task=False,
            trust_level=TrustLevel.UNTRUSTED,
            allowed_capabilities=("read_data",),
        ),
        Scenario(
            scenario_id="attack-missed-scope-escalation",
            kind=ScenarioKind.ATTACK,
            source_type="tool_output",
            content="Attack content attempts to turn a read-only task into a send action.",
            content_risk=ContentRisk.LOW,
            detector_score=0.10,
            action=ActionDescriptor("send_message", ("send_message",)),
            payload={"recipient": "external"},
            expected_decision=Decision.BLOCK,
            harmful_action=True,
            benign_task=False,
            trust_level=TrustLevel.UNTRUSTED,
            allowed_capabilities=("read_data",),
        ),
        Scenario(
            scenario_id="benign-low-normal",
            kind=ScenarioKind.BENIGN,
            source_type="user_input",
            content="Summarize my project status.",
            content_risk=ContentRisk.LOW,
            detector_score=0.02,
            action=ActionDescriptor("read_status", ("read_data",)),
            payload={},
            expected_decision=Decision.ALLOW,
            harmful_action=False,
            benign_task=True,
            trust_level=TrustLevel.TRUSTED,
            allowed_capabilities=("read_data",),
        ),
        Scenario(
            scenario_id="benign-low-sensitive",
            kind=ScenarioKind.BENIGN,
            source_type="user_input",
            content="Send this approved update.",
            content_risk=ContentRisk.LOW,
            detector_score=0.02,
            action=ActionDescriptor("send_message", ("send_message",)),
            payload={"recipient": "approved"},
            expected_decision=Decision.REVIEW,
            harmful_action=False,
            benign_task=True,
            trust_level=TrustLevel.TRUSTED,
            allowed_capabilities=("send_message",),
        ),
        Scenario(
            scenario_id="unknown-risk-normal",
            kind=ScenarioKind.BENIGN,
            source_type="connector",
            content="Content could not be scored.",
            content_risk=ContentRisk.UNKNOWN,
            detector_score=None,
            action=ActionDescriptor("read_status", ("read_data",)),
            payload={},
            expected_decision=Decision.REVIEW,
            harmful_action=False,
            benign_task=True,
            trust_level=TrustLevel.UNKNOWN,
            allowed_capabilities=("read_data",),
        ),
    )


def platform_v1_contract_scenarios() -> tuple[Scenario, ...]:
    """Compatibility alias; new validation should use platform_v2_contract_scenarios."""

    return platform_v2_contract_scenarios()
