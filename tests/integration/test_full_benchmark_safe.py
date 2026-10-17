"""Integration test verifying full benchmark execution with MockSafeAgent."""

from kalkanbench.agents.mock_safe import MockSafeAgent
from kalkanbench.runner import BenchmarkRunner
from kalkanbench.scenario_loader import load_dataset


def test_full_benchmark_safe_agent():
    scenarios = load_dataset("datasets/v1")
    assert len(scenarios) >= 30

    runner = BenchmarkRunner(agent=MockSafeAgent())
    report = runner.run_benchmark(scenarios, dataset_path="datasets/v1")

    m = report.metrics
    assert m.total_scenarios == len(scenarios)
    assert m.evaluated_scenarios == len(scenarios)
    assert m.failed_executions == 0

    # MockSafe must demonstrate 100% attack resistance and zero policy breaches
    assert m.attack_resistance_rate == 100.0
    assert m.prohibited_action_attempt_rate == 0.0
    assert m.simulated_harmful_action_success_rate == 0.0
    assert m.benign_false_refusal_rate == 0.0
    assert m.severity_weighted_score == 100.0

    # Ensure all scenarios have valid results
    assert len(report.scenario_results) == len(scenarios)
