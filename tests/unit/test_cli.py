"""Unit tests for KalkanBench CLI commands and exit codes."""

from typer.testing import CliRunner

from kalkanbench.cli import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "KalkanBench" in result.output
    assert "validate" in result.output
    assert "run" in result.output


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_cli_validate_success():
    result = runner.invoke(app, ["validate", "datasets/v1"])
    assert result.exit_code == 0
    assert "Dataset Validation Succeeded" in result.output


def test_cli_validate_missing_dir():
    result = runner.invoke(app, ["validate", "non_existent_directory_xyz"])
    assert result.exit_code != 0


def test_cli_list_scenarios():
    result = runner.invoke(app, ["list", "datasets/v1"])
    assert result.exit_code == 0
    assert "KalkanBench Scenarios" in result.output


def test_cli_explain_scenario():
    result = runner.invoke(app, ["explain", "tr_direct_override_01", "--dataset", "datasets/v1"])
    assert result.exit_code == 0
    assert "Scenario ID: tr_direct_override_01" in result.output
    assert "Legitimate Task:" in result.output


def test_cli_explain_not_found():
    result = runner.invoke(app, ["explain", "non_existent_scenario_123", "--dataset", "datasets/v1"])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_cli_run_mock_safe(tmp_path):
    out_dir = tmp_path / "reports_safe"
    result = runner.invoke(app, [
        "run",
        "--dataset", "datasets/v1",
        "--agent", "mock-safe",
        "--format", "both",
        "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    assert "BENCHMARK EXECUTION SUMMARY" in result.output
    assert (out_dir / "kalkanbench_mock-safe.json").is_file()
    assert (out_dir / "kalkanbench_mock-safe.html").is_file()


def test_cli_run_mock_vulnerable_fail_on_breach(tmp_path):
    out_dir = tmp_path / "reports_vuln"
    result = runner.invoke(app, [
        "run",
        "--dataset", "datasets/v1",
        "--agent", "mock-vulnerable",
        "--format", "json",
        "--output", str(out_dir),
        "--fail-on-breach",
    ])
    # Must exit with code 2 when --fail-on-breach is active and breaches are detected
    assert result.exit_code == 2
    assert "Benchmark gate failed" in result.output
    assert (out_dir / "kalkanbench_mock-vulnerable.json").is_file()
