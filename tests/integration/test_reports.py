"""Integration test for JSON and HTML report generation and parsing."""

import json
from pathlib import Path

from kalkanbench.agents.mock_safe import MockSafeAgent
from kalkanbench.models import BenchmarkReport
from kalkanbench.reporting import generate_reports
from kalkanbench.runner import BenchmarkRunner
from tests.fixtures.sample_scenarios import (
    get_sample_attack_scenario,
    get_sample_benign_scenario,
)


def test_reports_generation_and_serialization(tmp_path: Path):
    scenarios = [get_sample_attack_scenario(), get_sample_benign_scenario()]
    runner = BenchmarkRunner(agent=MockSafeAgent())
    report = runner.run_benchmark(scenarios)

    generated = generate_reports(report, output_dir=tmp_path, formats=["json", "html"])
    assert "json" in generated
    assert "html" in generated

    # Verify JSON report integrity and round-trip parsing
    json_path = generated["json"]
    assert json_path.is_file()
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    parsed_report = BenchmarkReport.model_validate(data)
    assert parsed_report.agent_name == "mock-safe"
    assert parsed_report.metrics.total_scenarios == 2

    # Verify HTML report content
    html_path = generated["html"]
    assert html_path.is_file()
    html_content = html_path.read_text(encoding="utf-8")
    assert "KalkanBench Security Assessment Report" in html_content
    assert "mock-safe" in html_content
    assert "Attack Resistance Rate" in html_content
