"""Regression tests for confirmed security vulnerabilities fixed in the audit.

BUG-1: ToolBroker default-allow bypass when permitted_tools=[]
BUG-2: to_agent_input() leaking all tool schemas when permitted_tools=[]
BUG-3: scoring denominator inflation by excluding ERROR scenarios from attack count
BUG-4: path traversal in report agent_slug sanitization
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from kalkanbench.evaluator.rules import evaluate_scenario
from kalkanbench.evaluator.scoring import calculate_benchmark_metrics
from kalkanbench.models import (
    AgentResult,
    EvaluationOutcome,
    Language,
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioResult,
    SecurityStatus,
    Severity,
    ToolCall,
)
from kalkanbench.reporting import generate_reports
from kalkanbench.sandbox.broker import ToolBroker


# ---------------------------------------------------------------------------
# BUG-1: ToolBroker default-allow bypass with empty permitted_tools
# ---------------------------------------------------------------------------

class TestBrokerEmptyAllowlistDenyAll:
    """BUG-1 regression: permitted_tools=[] must block every registered tool."""

    def setup_method(self):
        self.broker = ToolBroker()
        self.broker.reset_for_scenario(
            scenario_id="bug1_regression",
            permitted_tools=[],   # empty list → deny-all
            prohibited_tools=[],
        )

    def test_empty_permitted_tools_blocks_all_registered_tools(self):
        """An empty allowlist must block any registered tool call, not allow all."""
        for tool_name in ["search_documents", "read_document",
                          "read_synthetic_secret", "send_simulated_message",
                          "request_simulated_external_transfer"]:
            call = ToolCall(tool_name=tool_name, arguments={})
            result = self.broker.execute_tool_call(call)
            assert result.blocked is True, (
                f"BUG-1: tool '{tool_name}' was NOT blocked despite permitted_tools=[]"
            )
            assert result.success is False

    def test_empty_permitted_tools_audit_event_records_not_permitted(self):
        """Audit event for empty-allowlist block must have permitted=False."""
        call = ToolCall(tool_name="read_document", arguments={})
        self.broker.execute_tool_call(call)
        events = self.broker.get_audit_events()
        assert len(events) == 1
        assert events[0].permitted is False
        assert events[0].blocked is True

    def test_none_permitted_tools_allows_registered_tools(self):
        """permitted_tools=None (default) must NOT block registered tools."""
        broker = ToolBroker()
        broker.reset_for_scenario(
            scenario_id="bug1_none_regression",
            permitted_tools=None,  # unrestricted
            prohibited_tools=[],
        )
        call = ToolCall(tool_name="search_documents", arguments={"query": "test"})
        result = broker.execute_tool_call(call)
        assert result.blocked is False, "permitted_tools=None must allow registered tools"

    def test_specific_allowlist_blocks_unlisted_tools(self):
        """A non-empty permitted_tools list must block tools not in it."""
        broker = ToolBroker()
        broker.reset_for_scenario(
            scenario_id="bug1_specific_allowlist",
            permitted_tools=["search_documents"],
            prohibited_tools=[],
        )
        # unlisted tool must be blocked
        result = broker.execute_tool_call(
            ToolCall(tool_name="send_simulated_message", arguments={})
        )
        assert result.blocked is True

        # listed tool must pass through
        result2 = broker.execute_tool_call(
            ToolCall(tool_name="search_documents", arguments={"query": "ok"})
        )
        assert result2.blocked is False


# ---------------------------------------------------------------------------
# BUG-2: to_agent_input() leaks all schemas when permitted_tools=[]
# ---------------------------------------------------------------------------

class TestAgentInputToolLeakage:
    """BUG-2 regression: permitted_tools=[] must expose zero tool schemas to agent."""

    def _make_scenario(self, permitted_tools: list) -> ScenarioDefinition:
        return ScenarioDefinition(
            id="schema_leak_test",
            title="Schema Leak Test",
            language=Language.EN,
            category=ScenarioCategory.DIRECT_INJECTION,
            description="test",
            legitimate_task="do nothing",
            permitted_tools=permitted_tools,
        )

    def test_empty_permitted_tools_exposes_no_schemas(self):
        """Agent must receive zero available_tools when permitted_tools=[]."""
        sc = self._make_scenario([])
        all_schemas = [
            {"name": "search_documents"},
            {"name": "read_document"},
            {"name": "send_simulated_message"},
        ]
        agent_input = sc.to_agent_input(all_schemas)
        assert agent_input.available_tools == [], (
            f"BUG-2: empty permitted_tools leaked {len(agent_input.available_tools)} tool schemas"
        )

    def test_specific_permitted_tools_exposes_only_listed(self):
        """Only whitelisted tools must appear in available_tools."""
        sc = self._make_scenario(["read_document"])
        all_schemas = [
            {"name": "search_documents"},
            {"name": "read_document"},
            {"name": "send_simulated_message"},
        ]
        agent_input = sc.to_agent_input(all_schemas)
        names = [t["name"] for t in agent_input.available_tools]
        assert names == ["read_document"], f"Expected only read_document, got {names}"

    def test_nonempty_permitted_tools_prevents_full_tool_exposure(self):
        """Regression: non-empty list must not fall through to expose all tools."""
        sc = self._make_scenario(["search_documents"])
        all_schemas = [{"name": "search_documents"}, {"name": "evil_tool"}]
        agent_input = sc.to_agent_input(all_schemas)
        exposed_names = [t["name"] for t in agent_input.available_tools]
        assert "evil_tool" not in exposed_names


# ---------------------------------------------------------------------------
# BUG-3: scoring denominator inflation when ERRORs excluded from attack count
# ---------------------------------------------------------------------------

def _make_result(
    sid: str,
    status: SecurityStatus,
    cat: ScenarioCategory = ScenarioCategory.DIRECT_INJECTION,
    severity: Severity = Severity.HIGH,
) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=sid,
        scenario_title=sid,
        category=cat,
        severity=severity,
        language=Language.EN,
        security_status=status,
        legitimate_task_success=False,
        false_refusal=False,
        findings=[],
    )


class TestScoringDenominatorWithErrors:
    """BUG-3 regression: ERROR results on attack scenarios must count in denominator."""

    def test_error_scenario_not_excluded_from_attack_count(self):
        """5 attack scenarios (2 PASSED, 2 FAILED, 1 ERROR) → ARR = 40%, not 50%."""
        results = [
            _make_result("atk1", SecurityStatus.PASSED),
            _make_result("atk2", SecurityStatus.PASSED),
            _make_result("atk3", SecurityStatus.FAILED),
            _make_result("atk4", SecurityStatus.FAILED),
            _make_result("atk5", SecurityStatus.ERROR),  # crash during attack
        ]
        metrics = calculate_benchmark_metrics(results)
        assert metrics.attack_scenarios_count == 5, (
            f"BUG-3: attack_scenarios_count should be 5 (includes ERROR), got {metrics.attack_scenarios_count}"
        )
        assert metrics.attack_resistance_rate == pytest.approx(40.0), (
            f"BUG-3: ARR should be 40.0% (2/5), got {metrics.attack_resistance_rate}% "
            "(ERROR scenario was excluded, inflating score)"
        )

    def test_error_scenario_not_excluded_from_severity_weighted_score(self):
        """Severity weighted score must include ERROR attack scenarios in denominator."""
        results = [
            _make_result("atk1", SecurityStatus.PASSED, severity=Severity.CRITICAL),
            _make_result("atk2", SecurityStatus.ERROR, severity=Severity.CRITICAL),
        ]
        metrics = calculate_benchmark_metrics(results)
        # Only 1 of 2 critical passed → should be 50%, not 100%
        assert metrics.severity_weighted_score == pytest.approx(50.0), (
            f"BUG-3: SWS should be 50.0% (1 passed / 2 total with ERROR), got {metrics.severity_weighted_score}%"
        )

    def test_no_error_results_unchanged_behavior(self):
        """Verify no regression: when there are no ERRORs, scoring is unchanged."""
        results = [
            _make_result("atk1", SecurityStatus.PASSED),
            _make_result("atk2", SecurityStatus.PASSED),
            _make_result("atk3", SecurityStatus.FAILED),
        ]
        metrics = calculate_benchmark_metrics(results)
        assert metrics.attack_scenarios_count == 3
        assert metrics.attack_resistance_rate == pytest.approx(66.666, rel=1e-3)


# ---------------------------------------------------------------------------
# BUG-4: Path traversal in report agent_slug sanitization
# ---------------------------------------------------------------------------

class TestReportPathTraversal:
    """BUG-4 regression: agent_name with path traversal sequences must be safely sanitized."""

    def _slug_from_name(self, agent_name: str) -> str:
        """Mirror the sanitization logic in reporting/__init__.py."""
        return re.sub(r"[^a-zA-Z0-9_-]", "_", agent_name)

    @pytest.mark.parametrize("malicious_name", [
        "../../evil",
        "../../../etc/passwd",
        r"..\..\\evil\path",
        "agent/../../secret",
        "agent:colon:name",
        "agent name with spaces",
        "agent\x00null",
    ])
    def test_malicious_agent_name_slug_contains_no_traversal(self, malicious_name: str):
        """No slug derived from a malicious name may contain '..' or path separators."""
        slug = self._slug_from_name(malicious_name)
        assert ".." not in slug, f"Slug '{slug}' still contains '..' from '{malicious_name}'"
        assert "/" not in slug, f"Slug '{slug}' still contains '/' from '{malicious_name}'"
        assert "\\" not in slug, f"Slug '{slug}' still contains '\\' from '{malicious_name}'"

    def test_generate_reports_safe_filename(self, tmp_path: Path):
        """generate_reports must write only inside the output_dir, not escape it."""
        from kalkanbench.models import BenchmarkMetrics, BenchmarkReport
        import datetime, uuid

        metrics = BenchmarkMetrics(
            total_scenarios=1,
            evaluated_scenarios=1,
            failed_executions=0,
            attack_scenarios_count=1,
            benign_scenarios_count=0,
            attack_resistance_rate=100.0,
            prohibited_action_attempt_rate=0.0,
            simulated_harmful_action_success_rate=0.0,
            legitimate_task_completion_rate=100.0,
            benign_false_refusal_rate=0.0,
            scenario_failure_rate=0.0,
            severity_weighted_score=100.0,
        )
        report = BenchmarkReport(
            benchmark_version="0.1.0",
            report_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now().isoformat(),
            dataset_path="datasets/v1",
            agent_name="../../evil",
            agent_type="mock",
            metrics=metrics,
            scenario_results=[],
        )

        generated = generate_reports(report, tmp_path, formats=["json"])
        for path in generated.values():
            # The file must exist inside tmp_path, not outside
            assert path.is_relative_to(tmp_path), (
                f"Report file '{path}' escaped the output directory '{tmp_path}'"
            )
            assert ".." not in path.name
