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
    assert "0.3.0" in result.output


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


def test_cli_check_ollama():
    from unittest.mock import patch
    with patch("kalkanbench.agents.ollama.check_ollama_service") as mock_srv:
        mock_srv.return_value = {"available": True, "version": "0.1.32"}
        result = runner.invoke(app, ["check-ollama"])
        assert result.exit_code == 0
        assert "Ollama service is available" in result.output


def test_cli_check_ollama_unavailable():
    from unittest.mock import patch
    with patch("kalkanbench.agents.ollama.check_ollama_service") as mock_srv:
        mock_srv.return_value = {"available": False, "error": "Connection refused"}
        result = runner.invoke(app, ["check-ollama"])
        assert result.exit_code == 1
        assert "Service unavailable" in result.output


def test_cli_compare(tmp_path):
    out_dir = tmp_path / "comp_out"
    # Run two small benchmarks to generate reports
    rep_dir_a = tmp_path / "rep_a"
    rep_dir_b = tmp_path / "rep_b"
    runner.invoke(app, ["run", "--dataset", "datasets/v1", "--agent", "mock-safe", "--output", str(rep_dir_a)])
    runner.invoke(app, ["run", "--dataset", "datasets/v1", "--agent", "mock-vulnerable", "--output", str(rep_dir_b)])

    rep_a = rep_dir_a / "kalkanbench_mock-safe.json"
    rep_b = rep_dir_b / "kalkanbench_mock-vulnerable.json"

    result = runner.invoke(app, [
        "compare",
        str(rep_a),
        str(rep_b),
        "--output", str(out_dir),
        "--label1", "Safe",
        "--label2", "Vuln",
    ])
    assert result.exit_code == 0
    assert "KalkanBench Model Comparison" in result.output
    assert "Metrics Differential" in result.output
    assert (out_dir / "comparison.json").is_file()
    assert (out_dir / "comparison.html").is_file()


def test_cli_repeated_runs(tmp_path):
    out_dir = tmp_path / "rep_variance"
    result = runner.invoke(app, [
        "run",
        "--dataset", "datasets/heldout",
        "--agent", "mock-safe",
        "--runs", "2",
        "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    assert "Multi-Run Variance" in result.output
    assert "Run 1/2" in result.output
    assert "Run 2/2" in result.output

