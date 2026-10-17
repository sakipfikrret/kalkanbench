"""Scenario execution runner coordinating agents, sandbox broker, and evaluation."""

from __future__ import annotations

import datetime
import logging
import time
import uuid
from pathlib import Path
from typing import Callable

from kalkanbench.agents.base import AgentAdapter
from kalkanbench.evaluator.rules import evaluate_scenario
from kalkanbench.evaluator.scoring import calculate_benchmark_metrics
from kalkanbench.models import (
    AgentResult,
    BenchmarkReport,
    EvaluationFinding,
    EvaluationOutcome,
    ScenarioDefinition,
    ScenarioResult,
    SecurityStatus,
    Severity,
)
from kalkanbench.sandbox.broker import ToolBroker

logger = logging.getLogger(__name__)


class BenchmarkRunner:
    """Executes scenarios through the ToolBroker and coordinates evaluation."""

    def __init__(self, agent: AgentAdapter, broker: ToolBroker | None = None) -> None:
        self.agent = agent
        self.broker = broker or ToolBroker()

    def run_scenario(self, scenario: ScenarioDefinition) -> ScenarioResult:
        """Runs a single scenario in isolation and returns the evaluated result."""
        # 1. Deterministic sandbox reset with scenario fixtures
        self.broker.reset_for_scenario(
            scenario_id=scenario.id,
            permitted_tools=scenario.permitted_tools,
            prohibited_tools=scenario.prohibited_tools,
            initial_documents=scenario.initial_documents,
            initial_secrets=scenario.initial_secrets,
        )

        # 2. Secure transformation to AgentInput (evaluator secrets/rules are removed)
        agent_input = scenario.to_agent_input(self.broker.get_available_tool_schemas())

        # 3. Agent execution with error isolation
        start_time = time.perf_counter()
        try:
            agent_result = self.agent.run(agent_input, self.broker)
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"Execution error for scenario '{scenario.id}': {e}", exc_info=True)
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_title=scenario.title,
                category=scenario.category,
                severity=scenario.severity,
                language=scenario.language,
                security_status=SecurityStatus.ERROR,
                legitimate_task_success=False,
                false_refusal=False,
                findings=[
                    EvaluationFinding(
                        scenario_id=scenario.id,
                        outcome=EvaluationOutcome.EVALUATION_FAILED,
                        severity=Severity.HIGH,
                        title="Agent Execution Error",
                        description=f"Agent crashed during scenario execution: {e}",
                        evidence=[str(e)],
                    )
                ],
                audit_events=self.broker.get_audit_events(),
                agent_response="",
                error_message=str(e),
                execution_time_ms=elapsed_ms,
            )

        # 4. Extract audit events
        audit_events = self.broker.get_audit_events()

        # 5. Evaluate results against observable evidence and scenario assertions
        return evaluate_scenario(scenario, agent_result, audit_events)

    def run_benchmark(
        self,
        scenarios: list[ScenarioDefinition],
        dataset_path: str = "in-memory",
        progress_callback: Callable[[int, int, ScenarioResult], None] | None = None,
    ) -> BenchmarkReport:
        """Executes a complete benchmark suite over a list of scenarios."""
        results: list[ScenarioResult] = []
        total = len(scenarios)

        for idx, scenario in enumerate(scenarios, start=1):
            result = self.run_scenario(scenario)
            results.append(result)
            if progress_callback:
                progress_callback(idx, total, result)

        metrics = calculate_benchmark_metrics(results)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return BenchmarkReport(
            benchmark_version="0.1.0",
            report_id=str(uuid.uuid4()),
            timestamp=now_utc,
            dataset_path=dataset_path,
            agent_name=self.agent.name,
            agent_type=self.agent.__class__.__name__,
            metrics=metrics,
            scenario_results=results,
        )
