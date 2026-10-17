"""JSON report generation for KalkanBench."""

from __future__ import annotations

from pathlib import Path

from kalkanbench.models import BenchmarkReport


def generate_json_report(report: BenchmarkReport, output_path: Path | str) -> Path:
    """Serializes the BenchmarkReport to a formatted JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    json_str = report.model_dump_json(indent=2)
    path.write_text(json_str, encoding="utf-8")
    return path
