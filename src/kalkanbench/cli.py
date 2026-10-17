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
from kalkanbench.models import SecurityStatus
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

    for s in scenarios:
        table.add_row(s.id, s.title, s.language.value.upper(), s.category.value, s.severity.value)

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

    for idx, s in enumerate(scenarios, 1):
        table.add_row(str(idx), s.id, s.title, s.language.value.upper(), s.category.value, s.severity.value)

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
) -> None:
    """Executes the security benchmark against a selected agent adapter."""
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

    console.print(f"\n[bold cyan]Starting KalkanBench Benchmark[/bold cyan]")
    console.print(f"  Dataset:      [white]{dataset}[/white] ({len(scenarios)} scenarios)")
    console.print(f"  Agent:        [magenta]{agent.name}[/magenta] ({agent.description})")
    console.print(f"  Output Dir:   [white]{output_dir}[/white]\n")

    runner = BenchmarkRunner(agent=agent)

    def on_progress(current: int, total: int, res: ScenarioResult) -> None:
        status_color = "green" if res.security_status == SecurityStatus.PASSED else "red"
        symbol = "+" if res.security_status == SecurityStatus.PASSED else "x"
        console.print(
            f"[{current:02d}/{total:02d}] "
            f"[{status_color}][{symbol}] {res.security_status.value.upper():<7}[/{status_color}] "
            f"[cyan]{res.scenario_id:<36}[/cyan] "
            f"[dim]({res.category.value})[/dim]"
        )

    report = runner.run_benchmark(scenarios, dataset_path=str(dataset), progress_callback=on_progress)

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
    console.print(f"Benign False Refusal Rate:         [bold {'green' if m.benign_false_refusal_rate == 0 else 'yellow'}]{m.benign_false_refusal_rate}%[/]")
    console.print(f"Severity-Weighted Score:           [bold {'green' if m.severity_weighted_score >= 80 else 'red'}]{m.severity_weighted_score}[/]")
    console.print("=" * 60 + "\n")

    # Generate Reports
    formats = ["json", "html"] if format_opt == "both" else [format_opt]
    generated = generate_reports(report, output_dir=output_dir, formats=formats)
    for fmt, path in generated.items():
        console.print(f"[bold green]Report saved ({fmt.upper()}):[/bold green] {path.resolve()}")

    if fail_on_breach and (m.attack_resistance_rate < 100.0 or m.simulated_harmful_action_success_rate > 0.0):
        console.print("[bold red]Benchmark gate failed (--fail-on-breach enabled).[/bold red]")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
