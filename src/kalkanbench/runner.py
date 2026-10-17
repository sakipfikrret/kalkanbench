"""Scenario execution runner coordinating agents, sandbox broker, and evaluation."""

from __future__ import annotations

import datetime
import logging
import time
import uuid
from pathlib import Path
from typing import Callable

from kalkanbench import __version__
from kalkanbench.agents.base import AgentAdapter
from kalkanbench.evaluator.rules import evaluate_scenario, evaluate_turn, evaluate_session
from kalkanbench.evaluator.scoring import calculate_benchmark_metrics
from kalkanbench.models import (
    AgentMemory,
    AgentResult,
    BenchmarkReport,
    ChatMessage,
    EvaluationFinding,
    EvaluationOutcome,
    ReproducibilityMetadata,
    ScenarioDefinition,
    ScenarioResult,
    SecurityStatus,
    Severity,
    TurnResult,
)
from kalkanbench.sandbox.broker import ToolBroker

logger = logging.getLogger(__name__)


class BenchmarkRunner:
    """Executes scenarios through the ToolBroker and coordinates evaluation."""

    def __init__(self, agent: AgentAdapter, broker: ToolBroker | None = None) -> None:
        self.agent = agent
        self.broker = broker or ToolBroker()

    def run_scenario(self, scenario: ScenarioDefinition) -> ScenarioResult:
        """Runs a scenario (single-turn or multi-turn) in isolation and returns the evaluated result."""
        if scenario.is_multi_turn:
            return self.run_multi_turn_scenario(scenario)
        return self.run_single_turn_scenario(scenario)

    def run_single_turn_scenario(self, scenario: ScenarioDefinition) -> ScenarioResult:
        """Runs a single-turn scenario in isolation and returns the evaluated result."""
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

    def run_multi_turn_scenario(self, scenario: ScenarioDefinition) -> ScenarioResult:
        """Executes a stateful multi-turn conversation session with turn-level and session-level evaluation."""
        session_id = f"sess_{uuid.uuid4().hex[:12]}"

        # 1. Deterministic sandbox reset
        self.broker.reset_for_scenario(
            scenario_id=scenario.id,
            permitted_tools=scenario.permitted_tools,
            prohibited_tools=scenario.prohibited_tools,
            initial_documents=scenario.initial_documents,
            initial_secrets=scenario.initial_secrets,
        )

        history: list[ChatMessage] = []
        memory = AgentMemory()
        turn_results: list[TurnResult] = []

        if scenario.system_instruction:
            history.append(ChatMessage(role="system", content=scenario.system_instruction))

        for turn in scenario.turns:
            self.broker.set_turn_context(turn_index=turn.turn_index, session_id=session_id)
            tool_schemas = self.broker.get_available_tool_schemas()
            turn_input = scenario.to_turn_agent_input(
                turn_index=turn.turn_index,
                tool_schemas=tool_schemas,
                session_id=session_id,
            )

            t_start = time.perf_counter()
            try:
                agent_result = self.agent.run_turn(turn_input, list(history), memory, self.broker)
            except Exception as e:
                t_elapsed = (time.perf_counter() - t_start) * 1000.0
                logger.error(f"Turn {turn.turn_index} crashed in scenario '{scenario.id}': {e}", exc_info=True)
                agent_result = AgentResult(
                    scenario_id=scenario.id,
                    response_text=f"ERROR: {e}",
                    execution_time_ms=t_elapsed,
                    metadata={"error": str(e)},
                )

            # Record turn in conversation history
            history.append(ChatMessage(role="user", content=turn.user_input))
            history.append(ChatMessage(role="assistant", content=agent_result.response_text))

            # Turn-scoped audit events
            turn_audit_events = [
                ev for ev in self.broker.get_audit_events()
                if ev.turn_index == turn.turn_index
            ]

            turn_eval = evaluate_turn(scenario, turn, agent_result, turn_audit_events)
            turn_results.append(turn_eval)

        # 2. Cumulative session-level evaluation
        all_audit_events = self.broker.get_audit_events()
        return evaluate_session(
            scenario=scenario,
            turn_results=turn_results,
            session_audit_events=all_audit_events,
            session_id=session_id,
            history=history,
            memory=memory,
        )

    def run_benchmark(
        self,
        scenarios: list[ScenarioDefinition],
        dataset_path: str = "in-memory",
        dataset_version: str | None = None,
        run_index: int = 1,
        total_runs: int = 1,
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

        # Build reproducibility metadata
        repro = ReproducibilityMetadata(
            agent_name=self.agent.name,
            agent_type=self.agent.__class__.__name__,
            dataset_path=dataset_path,
            dataset_version=dataset_version,
            scenario_count=len(scenarios),
            scenario_ids=[s.id for s in scenarios],
            benchmark_version=__version__,
            execution_timestamp=now_utc,
            run_index=run_index,
            total_runs=total_runs,
            failed_scenario_count=sum(1 for r in results if r.security_status == SecurityStatus.ERROR),
            incomplete_scenario_count=sum(
                1 for r in results
                if r.security_status == SecurityStatus.ERROR or r.error_message is not None
            ),
        )
        # Capture model-level reproducibility fields via the agent's describe_config() contract
        try:
            agent_cfg = self.agent.describe_config()
            if "model_id" in agent_cfg:
                repro.model_id = agent_cfg["model_id"]
            if "model_digest" in agent_cfg:
                repro.model_digest = agent_cfg["model_digest"]
            if "temperature" in agent_cfg:
                repro.temperature = agent_cfg["temperature"]
            if "max_tokens" in agent_cfg:
                repro.max_tokens = agent_cfg["max_tokens"]
            if "prompt_template_version" in agent_cfg:
                repro.prompt_template_version = agent_cfg["prompt_template_version"]
            if "prompt_template_hash" in agent_cfg:
                repro.prompt_template_hash = agent_cfg["prompt_template_hash"]
        except Exception as e:
            logger.debug(f"Failed to read agent describe_config(): {e}")

        return BenchmarkReport(
            benchmark_version=__version__,
            report_id=str(uuid.uuid4()),
            timestamp=now_utc,
            dataset_path=dataset_path,
            agent_name=self.agent.name,
            agent_type=self.agent.__class__.__name__,
            metrics=metrics,
            scenario_results=results,
            reproducibility=repro,
        )
