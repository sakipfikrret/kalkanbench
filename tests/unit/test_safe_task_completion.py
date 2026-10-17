"""Regression tests verifying MockSafeAgent completes legitimate tasks across all baseline scenarios."""

from __future__ import annotations

from pathlib import Path
import pytest

from kalkanbench.agents.mock_safe import MockSafeAgent
from kalkanbench.evaluator.rules import evaluate_scenario
from kalkanbench.models import SecurityStatus
from kalkanbench.sandbox.broker import ToolBroker
from kalkanbench.scenario_loader import load_dataset, load_scenario_file


DATASET_DIR = Path("datasets/v1")


@pytest.fixture(scope="module")
def all_v1_scenarios():
    return load_dataset(DATASET_DIR)


@pytest.fixture
def safe_agent():
    return MockSafeAgent()


@pytest.fixture
def broker():
    return ToolBroker()


class TestSafeAgentTaskCompletionRegression:
    """Verifies that the 7 previously failing scenarios complete their legitimate tasks."""

    @pytest.mark.parametrize("scenario_id", [
        "en_exfil_api_keys_01",
        "en_indirect_invoice_01",
        "en_indirect_markdown_03",
        "en_indirect_support_02",
        "tr_auth_conflict_ceo_impersonation_01",
        "tr_direct_roleplay_02",
        "tr_indirect_cv_04",
    ])
    def test_remediated_scenarios_pass_legitimate_task_and_security(
        self, scenario_id: str, safe_agent: MockSafeAgent, broker: ToolBroker
    ):
        scenario_path = DATASET_DIR / f"{scenario_id}.yaml"
        sc = load_scenario_file(scenario_path)

        broker.reset_for_scenario(
            scenario_id=sc.id,
            permitted_tools=sc.permitted_tools,
            prohibited_tools=sc.prohibited_tools,
            initial_documents=sc.initial_documents,
            initial_secrets=sc.initial_secrets,
        )

        agent_input = sc.to_agent_input(broker.get_available_tool_schemas())
        agent_result = safe_agent.run(agent_input, broker)

        eval_result = evaluate_scenario(sc, agent_result, broker.get_audit_events())

        assert eval_result.legitimate_task_success is True, (
            f"Scenario {scenario_id} failed legitimate task. "
            f"Response: {agent_result.response_text!r}, Required: {sc.required_task_outputs}"
        )
        assert eval_result.security_status == SecurityStatus.PASSED, (
            f"Scenario {scenario_id} failed security status: {eval_result.security_status}"
        )

    def test_all_34_scenarios_achieve_full_legitimate_completion(
        self, all_v1_scenarios, safe_agent: MockSafeAgent, broker: ToolBroker
    ):
        """All 34 v1 scenarios must achieve legitimate task completion with MockSafeAgent."""
        for sc in all_v1_scenarios:
            broker.reset_for_scenario(
                scenario_id=sc.id,
                permitted_tools=sc.permitted_tools,
                prohibited_tools=sc.prohibited_tools,
                initial_documents=sc.initial_documents,
                initial_secrets=sc.initial_secrets,
            )
            agent_input = sc.to_agent_input(broker.get_available_tool_schemas())
            agent_result = safe_agent.run(agent_input, broker)
            eval_result = evaluate_scenario(sc, agent_result, broker.get_audit_events())

            assert eval_result.legitimate_task_success is True, (
                f"Scenario {sc.id} failed task completion: required {sc.required_task_outputs}"
            )
            assert eval_result.security_status == SecurityStatus.PASSED, (
                f"Scenario {sc.id} failed security status: {eval_result.security_status}"
            )
