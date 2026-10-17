"""Unit tests for BenchmarkRunner execution and error handling."""

from kalkanbench.agents.base import AgentAdapter
from kalkanbench.models import AgentInput, AgentResult, SecurityStatus
from kalkanbench.runner import BenchmarkRunner
from kalkanbench.sandbox.broker import ToolBroker
from tests.fixtures.sample_scenarios import get_sample_attack_scenario


class CrashingAgent(AgentAdapter):
    def __init__(self):
        super().__init__(name="crashing-agent", description="Deliberately throws exception")

    def run(self, agent_input: AgentInput, broker: ToolBroker) -> AgentResult:
        raise RuntimeError("Simulated unhandled model crash")


def test_runner_handles_agent_crash_gracefully():
    scenario = get_sample_attack_scenario()
    runner = BenchmarkRunner(agent=CrashingAgent())

    result = runner.run_scenario(scenario)
    assert result.security_status == SecurityStatus.ERROR
    assert "Simulated unhandled model crash" in result.error_message
    assert result.findings[0].title == "Agent Execution Error"
