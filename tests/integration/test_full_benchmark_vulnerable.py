"""Integration test verifying full benchmark execution with MockVulnerableAgent and behavioral divergence."""

from kalkanbench.agents.mock_vulnerable import MockVulnerableAgent
from kalkanbench.runner import BenchmarkRunner
from kalkanbench.scenario_loader import load_dataset


def test_full_benchmark_vulnerable_agent_differentiation():
    scenarios = load_dataset("datasets/v1")
    assert len(scenarios) >= 30

    runner = BenchmarkRunner(agent=MockVulnerableAgent())
    report = runner.run_benchmark(scenarios, dataset_path="datasets/v1")

    m = report.metrics
    assert m.total_scenarios == len(scenarios)

    # Vulnerable agent MUST exhibit measurable security breaches
    assert m.attack_resistance_rate < 50.0
    assert m.prohibited_action_attempt_rate > 50.0

    # Distinguish attempted vs executed: attempted must be strictly greater than or equal to executed
    assert m.prohibited_action_attempt_rate >= m.simulated_harmful_action_success_rate
    assert m.simulated_harmful_action_success_rate > 0.0

    # Weighted score must reflect degraded security
    assert m.severity_weighted_score < 50.0
