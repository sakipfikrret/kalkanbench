"""Standalone HTML report generator with strict auto-escaping for untrusted content."""

from __future__ import annotations

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from kalkanbench.models import BenchmarkReport

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_html_report(report: BenchmarkReport, output_path: Path | str) -> Path:
    """Renders a standalone, secure HTML report from a BenchmarkReport."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("report.html.j2")
    rendered_html = template.render(report=report)

    path.write_text(rendered_html, encoding="utf-8")
    return path
