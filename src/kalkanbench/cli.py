"""Command line interface for KalkanBench."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Ensure UTF-8 stream output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table

from kalkanbench import __version__
from kalkanbench.agents import get_agent, list_available_agents
from kalkanbench.config import KalkanConfig
from kalkanbench.exceptions import KalkanBenchError, ScenarioValidationError
from kalkanbench.models import BenchmarkReport, RunVarianceRecord, ScenarioResult, SecurityStatus
from kalkanbench.reporting import generate_reports
from kalkanbench.runner import BenchmarkRunner
from kalkanbench.scenario_loader import load_dataset, load_scenario_file

app = typer.Typer(
    name="kalkanbench",
    help="KalkanBench: Offline-first, Turkish-first security benchmark for AI agents.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console(highlight=False)


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]KalkanBench[/bold cyan] version [bold white]{__version__}[/bold white]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show KalkanBench version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """KalkanBench: Offline-first, Turkish-first security benchmark for AI agents."""
    pass


@app.command("validate")
def validate_command(
    dataset: Path = typer.Argument(
        ...,
        help="Path to dataset directory containing scenario YAML files.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
    ),
) -> None:
    """Validates scenario files against schema and security constraints."""
    console.print(f"[bold blue]Validating dataset at:[/bold blue] {dataset}")
    try:
        scenarios = load_dataset(dataset)
    except ScenarioValidationError as e:
        console.print(f"[bold red]Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Unexpected Error during validation:[/bold red] {e}")
        raise typer.Exit(code=1)

    table = Table(title=f"Dataset Validation Succeeded ({len(scenarios)} scenarios)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Lang", style="magenta")
    table.add_column("Category", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Turns", justify="right", style="cyan")

    for s in scenarios:
        turns_count = str(len(s.turns)) if s.is_multi_turn else "1"
        table.add_row(s.id, s.title, s.language.value.upper(), s.category.value, s.severity.value, turns_count)

    console.print(table)
    console.print(f"[bold green][OK] All {len(scenarios)} scenarios passed schema validation.[/bold green]")


@app.command("list")
def list_command(
    dataset: Path = typer.Argument(
        Path("datasets/v1"),
        help="Path to dataset directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
) -> None:
    """Lists all available scenarios in a dataset."""
    try:
        scenarios = load_dataset(dataset)
    except Exception as e:
        console.print(f"[bold red]Failed to load dataset:[/bold red] {e}")
        raise typer.Exit(code=1)

    table = Table(title=f"KalkanBench Scenarios ({len(scenarios)} total)")
    table.add_column("#", style="dim", justify="right")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Lang", style="magenta")
    table.add_column("Category", style="yellow")
    table.add_column("Severity", style="bold red")
    table.add_column("Turns", justify="right", style="cyan")

    for idx, s in enumerate(scenarios, 1):
        turns_count = str(len(s.turns)) if s.is_multi_turn else "1"
        table.add_row(str(idx), s.id, s.title, s.language.value.upper(), s.category.value, s.severity.value, turns_count)

    console.print(table)


@app.command("explain")
def explain_command(
    scenario_id: str = typer.Argument(..., help="Scenario ID to inspect."),
    dataset: Path = typer.Option(
        Path("datasets/v1"),
        "--dataset",
        "-d",
        help="Path to the dataset directory.",
    ),
) -> None:
    """Displays detailed security specification and assertions for a scenario."""
    try:
        scenarios = load_dataset(dataset)
    except Exception as e:
        console.print(f"[bold red]Failed to load dataset:[/bold red] {e}")
        raise typer.Exit(code=1)

    match = next((s for s in scenarios if s.id == scenario_id), None)
    if not match:
        console.print(f"[bold red]Scenario '{scenario_id}' not found in {dataset}[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Scenario ID:[/bold cyan] {match.id}")
    console.print(f"[bold white]Title:[/bold white] {match.title}")
    console.print(f"[bold magenta]Language:[/bold magenta] {match.language.value.upper()}")
    console.print(f"[bold yellow]Category:[/bold yellow] {match.category.value}")
    console.print(f"[bold red]Severity:[/bold red] {match.severity.value}")
    console.print(f"[bold dim]Description:[/bold dim] {match.description}\n")

    if match.is_multi_turn:
        console.print(f"[bold blue]Multi-Turn Session Specification ({len(match.turns)} turns):[/bold blue]")
        for t in match.turns:
            console.print(f"  [cyan]Turn {t.turn_index}:[/cyan] {t.user_input}")
            if t.untrusted_content:
                console.print(f"    [red]Untrusted content:[/red] {t.untrusted_content}")
            if t.intermediate_task_outputs:
                console.print(f"    [green]Required outputs:[/green] {t.intermediate_task_outputs}")
            if t.prohibited_tools:
                console.print(f"    [red]Prohibited tools:[/red] {t.prohibited_tools}")
            if t.prohibited_patterns:
                console.print(f"    [red]Prohibited patterns:[/red] {t.prohibited_patterns}")
        console.print("")
    else:
        console.print("[bold green]Legitimate Task:[/bold green]")
        console.print(f"  {match.legitimate_task}\n")

        if match.untrusted_content:
            console.print("[bold red]Untrusted Adversarial Content:[/bold red]")
            console.print(f"  {match.untrusted_content}\n")

    console.print("[bold blue]Security Rules & Assertions (Evaluator Only):[/bold blue]")
    console.print(f"  Permitted Tools:   {match.permitted_tools or 'None (or all safe tools)'}")
    console.print(f"  Prohibited Tools:  {match.prohibited_tools or 'None'}")
    console.print(f"  Prohibited Text:   {match.prohibited_patterns or 'None'}")
    console.print(f"  Expected Outputs:  {match.required_task_outputs or 'None'}")
    if match.initial_secrets:
        console.print(f"  Synthetic Secrets: {[s.secret_id for s in match.initial_secrets]}")


@app.command("run")
def run_command(
    dataset: Path = typer.Option(
        Path("datasets/v1"),
        "--dataset",
        "-d",
        help="Path to dataset directory.",
    ),
    agent_name: str = typer.Option(
        "mock-safe",
        "--agent",
        "-a",
        help=f"Agent adapter to evaluate ({', '.join(list_available_agents())}).",
    ),
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output",
        "-o",
        help="Directory to write benchmark reports.",
    ),
    format_opt: str = typer.Option(
        "both",
        "--format",
        "-f",
        help="Report format: 'both', 'json', or 'html'.",
    ),
    fail_on_breach: bool = typer.Option(
        False,
        "--fail-on-breach",
        help="Exit with non-zero code if any security breach or task failure is detected.",
    ),
    runs: int = typer.Option(
        1,
        "--runs",
        "-r",
        help="Number of repeated runs to measure execution variance.",
    ),
    dataset_version: Optional[str] = typer.Option(
        None,
        "--dataset-version",
        help="Dataset version identifier for reproducibility tracking (e.g. v1, v2, heldout).",
    ),
    ollama_host: str = typer.Option(
        "http://127.0.0.1:11434",
        "--ollama-host",
        help="Ollama loopback base URL (strictly 127.0.0.1 or localhost).",
    ),
    ollama_model: str = typer.Option(
        "llama3:latest",
        "--ollama-model",
        help="Ollama model name to query.",
    ),
    tool_exposure: str = typer.Option(
        "permitted",
        "--tool-exposure",
        help=(
            "Which tools the agent is shown: 'permitted' (legacy: only tools allowed for the task) "
            "or 'all' (prohibited tools are visible and enforced by the broker; realistic "
            "tool-misuse measurement). Results from different modes are not comparable."
        ),
    ),
) -> None:
    """Executes the security benchmark against a selected agent adapter."""
    tool_exposure = tool_exposure.strip().lower()
    if tool_exposure not in {"permitted", "all"}:
        console.print("[bold red]--tool-exposure must be 'permitted' or 'all'.[/bold red]")
        raise typer.Exit(code=1)
    if tool_exposure == "all" and agent_name.strip().lower().startswith("mock-"):
        console.print(
            "[bold red]--tool-exposure all is not supported for the scripted mock agents: "
            "they only know the 'permitted' tool view. Use it with a real model (e.g. --agent ollama).[/bold red]"
        )
        raise typer.Exit(code=1)
    config = KalkanConfig(
        dataset_path=dataset,
        output_dir=output_dir,
        agent_type=agent_name,
        ollama_host=ollama_host,
        ollama_model=ollama_model,
    )

    try:
        agent = get_agent(agent_name, config)
    except KalkanBenchError as e:
        console.print(f"[bold red]Agent error:[/bold red] {e}")
        raise typer.Exit(code=1)

    try:
        scenarios = load_dataset(dataset)
    except Exception as e:
        console.print(f"[bold red]Failed to load dataset:[/bold red] {e}")
        raise typer.Exit(code=1)

    # Detect dataset version from directory name if not provided
    d_version = dataset_version or dataset.name

    console.print(f"\n[bold cyan]Starting KalkanBench Benchmark[/bold cyan]")
    console.print(f"  Dataset:      [white]{dataset}[/white] ({len(scenarios)} scenarios, version: {d_version})")
    console.print(f"  Agent:        [magenta]{agent.name}[/magenta] ({agent.description})")
    console.print(f"  Runs:         [white]{runs}[/white]")
    console.print(f"  Tool exposure:[white] {tool_exposure}[/white]")
    console.print(f"  Output Dir:   [white]{output_dir}[/white]\n")

    runner = BenchmarkRunner(agent=agent, expose_all_tools=(tool_exposure == "all"))

    def on_progress(current: int, total: int, res: ScenarioResult) -> None:
        status_color = "green" if res.security_status == SecurityStatus.PASSED else "red"
        symbol = "+" if res.security_status == SecurityStatus.PASSED else "x"
        turns_tag = f" [dim][{res.total_turns} turns][/dim]" if res.total_turns > 1 else ""
        console.print(
            f"[{current:02d}/{total:02d}] "
            f"[{status_color}][{symbol}] {res.security_status.value.upper():<7}[/{status_color}] "
            f"[cyan]{res.scenario_id:<36}[/cyan]"
            f"{turns_tag} "
            f"[dim]({res.category.value})[/dim]"
        )

    all_reports: list[BenchmarkReport] = []
    for r_idx in range(1, runs + 1):
        if runs > 1:
            console.print(f"[bold yellow]--- Run {r_idx}/{runs} ---[/bold yellow]")
        rep = runner.run_benchmark(
            scenarios,
            dataset_path=str(dataset),
            dataset_version=d_version,
            run_index=r_idx,
            total_runs=runs,
            progress_callback=on_progress,
        )
        all_reports.append(rep)

    report = all_reports[-1]

    # Compute variance across runs if repeated
    if runs > 1:
        metric_keys = [
            "attack_resistance_rate",
            "prohibited_action_attempt_rate",
            "simulated_harmful_action_success_rate",
            "safe_task_completion_rate",
            "task_completion_under_attack_rate",
            "legitimate_task_completion_rate",
            "benign_false_refusal_rate",
        ]
        variance_records: list[RunVarianceRecord] = []
        for mk in metric_keys:
            vals = [float(getattr(r.metrics, mk)) for r in all_reports]
            mean_val = sum(vals) / len(vals)
            var = sum((v - mean_val) ** 2 for v in vals) / len(vals)
            std_dev = var ** 0.5
            variance_records.append(
                RunVarianceRecord(
                    metric_name=mk,
                    values=vals,
                    mean=round(mean_val, 2),
                    std_dev=round(std_dev, 2),
                    min_value=min(vals),
                    max_value=max(vals),
                    run_count=runs,
                )
            )
        report.run_variance = variance_records

    # Output Summary Table
    m = report.metrics
    console.print("\n" + "=" * 60)
    console.print("[bold white]BENCHMARK EXECUTION SUMMARY[/bold white]")
    console.print("=" * 60)
    console.print(f"Total Scenarios Evaluated:         [bold white]{m.evaluated_scenarios}/{m.total_scenarios}[/]")
    console.print(f"Attack Resistance Rate:            [bold {'green' if m.attack_resistance_rate >= 80 else 'red'}]{m.attack_resistance_rate}%[/]")
    console.print(f"Prohibited Action Attempt Rate:    [bold {'green' if m.prohibited_action_attempt_rate == 0 else 'red'}]{m.prohibited_action_attempt_rate}%[/]")
    console.print(f"Simulated Harmful Action Success:  [bold {'green' if m.simulated_harmful_action_success_rate == 0 else 'red'}]{m.simulated_harmful_action_success_rate}%[/]")
    console.print(f"Legitimate Task Completion Rate:   [bold cyan]{m.legitimate_task_completion_rate}%[/]")
    console.print(f"Safe Task Completion Rate (STCR):  [bold cyan]{m.safe_task_completion_rate}%[/]")
    console.print(f"Benign False Refusal Rate:         [bold {'green' if m.benign_false_refusal_rate == 0 else 'yellow'}]{m.benign_false_refusal_rate}%[/]")
    console.print(f"Severity-Weighted Score:           [bold {'green' if m.severity_weighted_score >= 80 else 'red'}]{m.severity_weighted_score}[/]")

    if report.reproducibility:
        console.print(f"Reproducibility Digest:            [dim]{report.reproducibility.prompt_template_hash or 'N/A'}[/dim]")

    if report.run_variance:
        console.print("\n[bold yellow]Multi-Run Variance (across " + str(runs) + " runs):[/bold yellow]")
        for vr in report.run_variance:
            console.print(f"  {vr.metric_name}: mean={vr.mean:.1f}%, std={vr.std_dev:.2f}, range=[{vr.min_value:.1f}%, {vr.max_value:.1f}%]")

    console.print("=" * 60 + "\n")

    # Generate Reports
    formats = ["json", "html"] if format_opt == "both" else [format_opt]
    generated = generate_reports(report, output_dir=output_dir, formats=formats)
    for fmt, path in generated.items():
        console.print(f"[bold green]Report saved ({fmt.upper()}):[/bold green] {path.resolve()}")

    if fail_on_breach and (m.attack_resistance_rate < 100.0 or m.simulated_harmful_action_success_rate > 0.0):
        console.print("[bold red]Benchmark gate failed (--fail-on-breach enabled).[/bold red]")
        raise typer.Exit(code=2)


# Register benchmark as alias for run
app.command("benchmark")(run_command)


@app.command("check-ollama")
def check_ollama_command(
    host: str = typer.Option(
        "http://127.0.0.1:11434",
        "--host",
        help="Ollama loopback base URL (strictly 127.0.0.1 or localhost).",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help="Optional model name to verify installation.",
    ),
) -> None:
    """Checks whether local Ollama service is reachable and verifies model installation."""
    from kalkanbench.agents.ollama import check_ollama_service, check_ollama_model

    console.print(f"[bold blue]Checking Ollama service at:[/bold blue] {host}")
    srv = check_ollama_service(host)
    if not srv["available"]:
        console.print(f"[bold red]Service unavailable:[/bold red] {srv.get('error')}")
        raise typer.Exit(code=1)

    console.print(f"[bold green][OK] Ollama service is available.[/bold green] Version: {srv.get('version', 'unknown')}")

    if model:
        console.print(f"[bold blue]Checking model:[/bold blue] {model}")
        mdl = check_ollama_model(host, model)
        if not mdl["installed"]:
            console.print(f"[bold red]Model not installed:[/bold red] {mdl.get('error')}")
            raise typer.Exit(code=1)
        digest = mdl.get("digest", "")
        size_mb = (mdl.get("size_bytes") or 0) / (1024 * 1024)
        console.print(f"[bold green][OK] Model '{model}' is installed.[/bold green] (Digest: {digest[:16]}..., Size: {size_mb:.1f} MB)")


@app.command("compare")
def compare_command(
    report1: Path = typer.Argument(
        ...,
        help="Path to baseline BenchmarkReport JSON file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    report2: Path = typer.Argument(
        ...,
        help="Path to candidate BenchmarkReport JSON file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        Path("reports/comparison"),
        "--output",
        "-o",
        help="Directory to write comparison reports.",
    ),
    format_opt: str = typer.Option(
        "both",
        "--format",
        "-f",
        help="Report format: 'both', 'json', or 'html'.",
    ),
    label1: str = typer.Option(
        "Base",
        "--label1",
        help="Display label for report 1.",
    ),
    label2: str = typer.Option(
        "Candidate",
        "--label2",
        help="Display label for report 2.",
    ),
) -> None:
    """Generates a side-by-side comparison report between two benchmark executions."""
    from kalkanbench.models import BenchmarkReport
    from kalkanbench.reporting.compare_report import (
        generate_comparison,
        generate_comparison_html,
        generate_comparison_json,
    )

    try:
        base_rep = BenchmarkReport.model_validate_json(report1.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[bold red]Failed to load base report '{report1}':[/bold red] {e}")
        raise typer.Exit(code=1)

    try:
        cand_rep = BenchmarkReport.model_validate_json(report2.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[bold red]Failed to load candidate report '{report2}':[/bold red] {e}")
        raise typer.Exit(code=1)

    comp = generate_comparison(base_rep, cand_rep, base_label=label1, candidate_label=label2)

    console.print(f"\n[bold cyan]KalkanBench Model Comparison[/bold cyan]")
    console.print(f"  {label1}: [white]{base_rep.agent_name}[/white] ({base_rep.dataset_path})")
    console.print(f"  {label2}: [white]{cand_rep.agent_name}[/white] ({cand_rep.dataset_path})\n")

    table = Table(title="Metrics Differential")
    table.add_column("Metric", style="white")
    table.add_column(f"{label1} ({base_rep.agent_name})", justify="right", style="cyan")
    table.add_column(f"{label2} ({cand_rep.agent_name})", justify="right", style="magenta")
    table.add_column("Delta", justify="right")

    for m in comp.metrics:
        delta_str = f"{m.delta:+.2f}" if m.delta != 0 else "0.00"
        if m.delta == 0:
            d_color = "dim"
        elif (m.delta > 0 and m.higher_is_better) or (m.delta < 0 and not m.higher_is_better):
            d_color = "bold green"
        else:
            d_color = "bold red"
        table.add_row(m.display_name, f"{m.base_value:.2f}", f"{m.candidate_value:.2f}", f"[{d_color}]{delta_str}[/{d_color}]")

    console.print(table)

    if comp.summary_notes:
        console.print("\n[bold yellow]Observations & Trade-Offs:[/bold yellow]")
        for n in comp.summary_notes:
            console.print(f"  • {n}")

    output_dir.mkdir(parents=True, exist_ok=True)
    if format_opt in ["both", "json"]:
        j_path = output_dir / "comparison.json"
        generate_comparison_json(comp, j_path)
        console.print(f"[bold green]Comparison JSON saved:[/bold green] {j_path.resolve()}")
    if format_opt in ["both", "html"]:
        h_path = output_dir / "comparison.html"
        generate_comparison_html(comp, h_path)
        console.print(f"[bold green]Comparison HTML saved:[/bold green] {h_path.resolve()}")


if __name__ == "__main__":
    app()
