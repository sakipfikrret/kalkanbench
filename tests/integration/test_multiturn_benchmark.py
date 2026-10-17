"""Integration tests for multi-turn benchmark execution on datasets/v2."""

from kalkanbench.runner import BenchmarkRunner
from kalkanbench.agents.mock_safe import MockSafeAgent
from kalkanbench.agents.mock_vulnerable import MockVulnerableAgent
from kalkanbench.scenario_loader import load_dataset
from kalkanbench.models import SecurityStatus


def test_multiturn_benchmark_mock_safe():
    """MockSafeAgent must achieve 100% ARR and 100% LTC across all 16 v2 multi-turn scenarios."""
    scenarios = load_dataset("datasets/v2")
    assert len(scenarios) == 16

    runner = BenchmarkRunner(agent=MockSafeAgent())
    report = runner.run_benchmark(scenarios, dataset_path="datasets/v2")

    m = report.metrics
    assert m.total_scenarios == 16
    assert m.evaluated_scenarios == 16
    assert m.failed_executions == 0
    assert m.attack_resistance_rate == 100.0
    assert m.legitimate_task_completion_rate == 100.0
    assert m.prohibited_action_attempt_rate == 0.0
    assert m.simulated_harmful_action_success_rate == 0.0
    assert m.benign_false_refusal_rate == 0.0

    for res in report.scenario_results:
        assert res.security_status == SecurityStatus.PASSED, f"Failed: {res.scenario_id}"
        assert res.legitimate_task_success is True, f"Incomplete task: {res.scenario_id}"
        assert res.total_turns >= 2
        assert len(res.turn_results) == res.total_turns


def test_multiturn_benchmark_mock_vulnerable():
    """MockVulnerableAgent must fail security on multi-turn attack scenarios, showing benchmark sensitivity."""
    scenarios = load_dataset("datasets/v2")
    assert len(scenarios) == 16

    runner = BenchmarkRunner(agent=MockVulnerableAgent())
    report = runner.run_benchmark(scenarios, dataset_path="datasets/v2")

    m = report.metrics
    assert m.total_scenarios == 16
    assert m.evaluated_scenarios == 16
    assert m.attack_resistance_rate == 0.0
    assert m.prohibited_action_attempt_rate > 0.0


def test_multiturn_sandbox_session_isolation():
    """Broker and memory must be cleanly isolated across consecutive multi-turn scenario runs."""
    scenarios = load_dataset("datasets/v2")
    first_two = scenarios[:2]

    runner = BenchmarkRunner(agent=MockSafeAgent())
    report = runner.run_benchmark(first_two, dataset_path="datasets/v2")

    assert len(report.scenario_results) == 2
    res1, res2 = report.scenario_results
    assert res1.session_id != res2.session_id
    assert res1.session_id.startswith("sess_")
    assert res2.session_id.startswith("sess_")
