"""Reporting module for KalkanBench."""

from __future__ import annotations

import re
from pathlib import Path

from kalkanbench.models import BenchmarkReport
from kalkanbench.reporting.compare_report import (
    ModelComparisonReport,
    generate_comparison,
    generate_comparison_html,
    generate_comparison_json,
)
from kalkanbench.reporting.html_report import generate_html_report
from kalkanbench.reporting.json_report import generate_json_report


def generate_reports(
    report: BenchmarkReport,
    output_dir: Path | str,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Generates benchmark reports in the requested formats (json, html)."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = formats or ["json", "html"]
    generated: dict[str, Path] = {}

    # Strict allowlist: only alphanumerics, underscores, and hyphens.
    # Prevents path traversal (e.g. "../../evil") regardless of OS path separator.
    agent_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", report.agent_name)
    base_name = f"kalkanbench_{agent_slug}"

    if "json" in formats:
        json_path = out_dir / f"{base_name}.json"
        generate_json_report(report, json_path)
        generated["json"] = json_path

    if "html" in formats:
        html_path = out_dir / f"{base_name}.html"
        generate_html_report(report, html_path)
        generated["html"] = html_path

    return generated


__all__ = [
    "generate_json_report",
    "generate_html_report",
    "generate_reports",
    "generate_comparison",
    "generate_comparison_json",
    "generate_comparison_html",
    "ModelComparisonReport",
]
