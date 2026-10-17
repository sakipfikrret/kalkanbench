"""Model comparison report generator for KalkanBench v0.3.

Produces side-by-side comparative analysis between two benchmark runs:
- Attack resistance and dual-goal security/utility trade-offs.
- Prohibited action attempt vs simulated harm rates.
- Category and language breakdowns.
- Per-scenario status differential.
- Variance/preliminary notice if sample count is small.
- Exports to formatted JSON and standalone styled HTML.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

from kalkanbench.models import BenchmarkReport


class MetricComparisonItem(BaseModel):
    metric_name: str
    display_name: str
    base_value: float
    candidate_value: float
    delta: float
    higher_is_better: bool = True
    denominator_info: str = ""


class CategoryComparisonItem(BaseModel):
    category: str
    base_pass_rate: float
    candidate_pass_rate: float
    delta: float
    base_total: int
    candidate_total: int


class LanguageComparisonItem(BaseModel):
    language: str
    base_pass_rate: float
    candidate_pass_rate: float
    delta: float
    base_total: int
    candidate_total: int


class ScenarioDiffItem(BaseModel):
    scenario_id: str
    category: str
    base_status: str
    candidate_status: str
    base_task_success: bool
    candidate_task_success: bool
    status_changed: bool


class ModelComparisonReport(BaseModel):
    report_schema_version: str = "2.0"
    base_label: str
    candidate_label: str
    base_agent: str
    candidate_agent: str
    base_report_id: str
    candidate_report_id: str
    base_dataset_path: str
    candidate_dataset_path: str
    base_total_scenarios: int
    candidate_total_scenarios: int
    is_preliminary: bool = False
    metrics: list[MetricComparisonItem] = Field(default_factory=list)
    categories: list[CategoryComparisonItem] = Field(default_factory=list)
    languages: list[LanguageComparisonItem] = Field(default_factory=list)
    scenario_diffs: list[ScenarioDiffItem] = Field(default_factory=list)
    summary_notes: list[str] = Field(default_factory=list)


def generate_comparison(
    base: BenchmarkReport,
    candidate: BenchmarkReport,
    base_label: str = "Base",
    candidate_label: str = "Candidate",
) -> ModelComparisonReport:
    """Computes differential comparison between two executed benchmark runs."""
    bm = base.metrics
    cm = candidate.metrics

    # Define tracked metrics with directionality and denominators
    metric_specs = [
        ("attack_resistance_rate", "Attack Resistance Rate (%)", bm.attack_resistance_rate, cm.attack_resistance_rate, True, f"Base N={bm.attack_scenarios_count}, Cand N={cm.attack_scenarios_count}"),
        ("prohibited_action_attempt_rate", "Prohibited Action Attempt Rate (%)", bm.prohibited_action_attempt_rate, cm.prohibited_action_attempt_rate, False, f"Base N={bm.attack_scenarios_count}, Cand N={cm.attack_scenarios_count}"),
        ("simulated_harmful_action_success_rate", "Simulated Harm Success Rate (%)", bm.simulated_harmful_action_success_rate, cm.simulated_harmful_action_success_rate, False, f"Base N={bm.attack_scenarios_count}, Cand N={cm.attack_scenarios_count}"),
        ("safe_task_completion_rate", "Safe Task Completion Rate / STCR (%)", bm.safe_task_completion_rate, cm.safe_task_completion_rate, True, f"All scenarios Base N={bm.total_scenarios}, Cand N={cm.total_scenarios}"),
        ("task_completion_under_attack_rate", "Task Completion Under Attack / TCUA (%)", bm.task_completion_under_attack_rate, cm.task_completion_under_attack_rate, True, f"Attack scenarios Base N={bm.attack_scenarios_count}, Cand N={cm.attack_scenarios_count}"),
        ("legitimate_task_completion_rate", "Legitimate Task Completion Rate (%)", bm.legitimate_task_completion_rate, cm.legitimate_task_completion_rate, True, f"All scenarios Base N={bm.total_scenarios}, Cand N={cm.total_scenarios}"),
        ("benign_false_refusal_rate", "Benign False Refusal Rate (%)", bm.benign_false_refusal_rate, cm.benign_false_refusal_rate, False, f"Benign scenarios Base N={bm.benign_scenarios_count}, Cand N={cm.benign_scenarios_count}"),
        ("scenario_failure_rate", "Execution / Evaluator Failure Rate (%)", bm.scenario_failure_rate, cm.scenario_failure_rate, False, f"All scenarios Base N={bm.total_scenarios}, Cand N={cm.total_scenarios}"),
        ("severity_weighted_score", "Severity-Weighted Score", bm.severity_weighted_score, cm.severity_weighted_score, True, "Weighted by scenario severity (Critical: 4x, High: 3x, Medium: 2x, Low: 1x)"),
    ]

    metric_items: list[MetricComparisonItem] = []
    for m_name, d_name, b_val, c_val, higher_better, denom in metric_specs:
        metric_items.append(
            MetricComparisonItem(
                metric_name=m_name,
                display_name=d_name,
                base_value=round(b_val, 2),
                candidate_value=round(c_val, 2),
                delta=round(c_val - b_val, 2),
                higher_is_better=higher_better,
                denominator_info=denom,
            )
        )

    # Categories breakdown comparison
    cat_keys = sorted(set(bm.category_metrics.keys()) | set(cm.category_metrics.keys()))
    category_items: list[CategoryComparisonItem] = []
    for cat in cat_keys:
        b_info = bm.category_metrics.get(cat, {})
        c_info = cm.category_metrics.get(cat, {})
        b_pr = float(b_info.get("pass_rate", 0.0))
        c_pr = float(c_info.get("pass_rate", 0.0))
        category_items.append(
            CategoryComparisonItem(
                category=cat,
                base_pass_rate=round(b_pr, 2),
                candidate_pass_rate=round(c_pr, 2),
                delta=round(c_pr - b_pr, 2),
                base_total=int(b_info.get("total", 0)),
                candidate_total=int(c_info.get("total", 0)),
            )
        )

    # Languages breakdown comparison
    lang_keys = sorted(set(bm.language_metrics.keys()) | set(cm.language_metrics.keys()))
    language_items: list[LanguageComparisonItem] = []
    for lang in lang_keys:
        b_info = bm.language_metrics.get(lang, {})
        c_info = cm.language_metrics.get(lang, {})
        b_pr = float(b_info.get("pass_rate", 0.0))
        c_pr = float(c_info.get("pass_rate", 0.0))
        language_items.append(
            LanguageComparisonItem(
                language=lang.upper(),
                base_pass_rate=round(b_pr, 2),
                candidate_pass_rate=round(c_pr, 2),
                delta=round(c_pr - b_pr, 2),
                base_total=int(b_info.get("total", 0)),
                candidate_total=int(c_info.get("total", 0)),
            )
        )

    # Scenario differential
    base_map = {r.scenario_id: r for r in base.scenario_results}
    cand_map = {r.scenario_id: r for r in candidate.scenario_results}
    all_scenarios = sorted(set(base_map.keys()) | set(cand_map.keys()))

    diffs: list[ScenarioDiffItem] = []
    for sc_id in all_scenarios:
        b_res = base_map.get(sc_id)
        c_res = cand_map.get(sc_id)
        b_st = b_res.security_status.value if b_res else "N/A"
        c_st = c_res.security_status.value if c_res else "N/A"
        b_ts = b_res.legitimate_task_success if b_res else False
        c_ts = c_res.legitimate_task_success if c_res else False
        cat_name = (b_res.category.value if b_res else (c_res.category.value if c_res else "unknown"))
        diffs.append(
            ScenarioDiffItem(
                scenario_id=sc_id,
                category=cat_name,
                base_status=b_st,
                candidate_status=c_st,
                base_task_success=b_ts,
                candidate_task_success=c_ts,
                status_changed=(b_st != c_st or b_ts != c_ts),
            )
        )

    # Summary notes & preliminary flags
    notes: list[str] = []
    min_obs = min(bm.total_scenarios, cm.total_scenarios)
    is_prelim = min_obs < 10
    if is_prelim:
        notes.append(f"PRELIMINARY: Comparison is based on only {min_obs} scenarios. Results should not be considered statistically conclusive.")

    ar_delta = cm.attack_resistance_rate - bm.attack_resistance_rate
    stcr_delta = cm.safe_task_completion_rate - bm.safe_task_completion_rate
    if ar_delta > 0 and stcr_delta < 0:
        notes.append(f"Trade-off: {candidate_label} has higher attack resistance (+{ar_delta:.1f}%) but lower task completion under safety constraints ({stcr_delta:.1f}%).")
    elif ar_delta < 0 and stcr_delta > 0:
        notes.append(f"Trade-off: {candidate_label} completed more tasks (+{stcr_delta:.1f}%) but has lower attack resistance ({ar_delta:.1f}%).")
    elif ar_delta > 0 and stcr_delta >= 0:
        notes.append(f"{candidate_label} demonstrates strict improvement: higher attack resistance (+{ar_delta:.1f}%) and equal or higher task completion.")
    elif ar_delta < 0 and stcr_delta < 0:
        notes.append(f"{candidate_label} exhibits lower performance across both security ({ar_delta:.1f}%) and task completion ({stcr_delta:.1f}%).")

    return ModelComparisonReport(
        base_label=base_label,
        candidate_label=candidate_label,
        base_agent=base.agent_name,
        candidate_agent=candidate.agent_name,
        base_report_id=base.report_id,
        candidate_report_id=candidate.report_id,
        base_dataset_path=base.dataset_path,
        candidate_dataset_path=candidate.dataset_path,
        base_total_scenarios=bm.total_scenarios,
        candidate_total_scenarios=cm.total_scenarios,
        is_preliminary=is_prelim,
        metrics=metric_items,
        categories=category_items,
        languages=language_items,
        scenario_diffs=diffs,
        summary_notes=notes,
    )


def generate_comparison_json(comparison: ModelComparisonReport, output_path: Path | str) -> Path:
    """Exports model comparison to formatted JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(comparison.model_dump_json(indent=2), encoding="utf-8")
    return path


def generate_comparison_html(comparison: ModelComparisonReport, output_path: Path | str) -> Path:
    """Generates standalone HTML comparison report with styled deltas and escaping."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    b_label = html.escape(comparison.base_label)
    c_label = html.escape(comparison.candidate_label)
    b_agent = html.escape(comparison.base_agent)
    c_agent = html.escape(comparison.candidate_agent)

    # Build metric rows
    metric_rows = []
    for m in comparison.metrics:
        # Determine delta color
        delta_str = f"{m.delta:+.2f}" if m.delta != 0 else "0.00"
        if m.delta == 0:
            badge_class = "delta-neutral"
        elif (m.delta > 0 and m.higher_is_better) or (m.delta < 0 and not m.higher_is_better):
            badge_class = "delta-pos"
        else:
            badge_class = "delta-neg"

        metric_rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(m.display_name)}</strong><br><small class='text-muted'>{html.escape(m.denominator_info)}</small></td>"
            f"<td>{m.base_value:.2f}</td>"
            f"<td>{m.candidate_value:.2f}</td>"
            f"<td><span class='badge {badge_class}'>{delta_str}</span></td>"
            f"</tr>"
        )

    # Build category rows
    cat_rows = []
    for c in comparison.categories:
        delta_str = f"{c.delta:+.2f}%" if c.delta != 0 else "0.00%"
        badge_class = "delta-pos" if c.delta > 0 else ("delta-neg" if c.delta < 0 else "delta-neutral")
        cat_rows.append(
            f"<tr>"
            f"<td><code>{html.escape(c.category)}</code></td>"
            f"<td>{c.base_pass_rate:.1f}% <small class='text-muted'>(N={c.base_total})</small></td>"
            f"<td>{c.candidate_pass_rate:.1f}% <small class='text-muted'>(N={c.candidate_total})</small></td>"
            f"<td><span class='badge {badge_class}'>{delta_str}</span></td>"
            f"</tr>"
        )

    # Build language rows
    lang_rows = []
    for l in comparison.languages:
        delta_str = f"{l.delta:+.2f}%" if l.delta != 0 else "0.00%"
        badge_class = "delta-pos" if l.delta > 0 else ("delta-neg" if l.delta < 0 else "delta-neutral")
        lang_rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(l.language)}</strong></td>"
            f"<td>{l.base_pass_rate:.1f}% <small class='text-muted'>(N={l.base_total})</small></td>"
            f"<td>{l.candidate_pass_rate:.1f}% <small class='text-muted'>(N={l.candidate_total})</small></td>"
            f"<td><span class='badge {badge_class}'>{delta_str}</span></td>"
            f"</tr>"
        )

    # Preliminary banner
    prelim_banner = ""
    if comparison.is_preliminary:
        prelim_banner = """
        <div class="alert alert-warning">
            ⚠️ <strong>PRELIMINARY RESULTS:</strong> This comparison is based on fewer than 10 scenarios.
            Statistical confidence is limited and numbers should be considered indicative only.
        </div>
        """

    # Notes
    notes_html = "".join(f"<li>{html.escape(n)}</li>" for n in comparison.summary_notes)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KalkanBench Model Comparison</title>
<style>
:root {{
    --bg-color: #0f172a;
    --card-bg: #1e293b;
    --text-color: #e2e8f0;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --pos: #4ade80;
    --neg: #f87171;
    --neutral: #94a3b8;
    --border: #334155;
}}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-color);
    color: var(--text-color);
    margin: 0;
    padding: 24px;
}}
.container {{
    max-width: 1100px;
    margin: 0 auto;
}}
.header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px;
    margin-bottom: 24px;
}}
h1 {{ margin: 0 0 8px 0; color: #fff; font-size: 1.8rem; }}
.card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}
th, td {{
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
}}
th {{ background: #0b1329; color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; }}
.text-muted {{ color: var(--text-muted); font-size: 0.85rem; }}
.badge {{
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.85rem;
    font-weight: bold;
}}
.delta-pos {{ background: rgba(74, 222, 128, 0.2); color: var(--pos); }}
.delta-neg {{ background: rgba(248, 113, 113, 0.2); color: var(--neg); }}
.delta-neutral {{ background: rgba(148, 163, 184, 0.2); color: var(--neutral); }}
.alert {{
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 20px;
}}
.alert-warning {{
    background: #451a03;
    border: 1px solid #b45309;
    color: #fde68a;
}}
code {{
    background: #0b1329;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.88rem;
}}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ KalkanBench Model Comparison</h1>
        <p class="text-muted">Comparing <strong>{b_label}</strong> ({b_agent}) vs <strong>{c_label}</strong> ({c_agent})</p>
    </div>

    {prelim_banner}

    <div class="card">
        <h2>Benchmark Metrics Differential</h2>
        <table>
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>{b_label} ({b_agent})</th>
                    <th>{c_label} ({c_agent})</th>
                    <th>Delta</th>
                </tr>
            </thead>
            <tbody>
                {''.join(metric_rows)}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Breakdown by Attack Category</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>{b_label} Pass Rate</th>
                    <th>{c_label} Pass Rate</th>
                    <th>Delta</th>
                </tr>
            </thead>
            <tbody>
                {''.join(cat_rows)}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Breakdown by Language</h2>
        <table>
            <thead>
                <tr>
                    <th>Language</th>
                    <th>{b_label} Pass Rate</th>
                    <th>{c_label} Pass Rate</th>
                    <th>Delta</th>
                </tr>
            </thead>
            <tbody>
                {''.join(lang_rows)}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Evaluation Findings & Trade-Off Notes</h2>
        <ul>
            {notes_html}
        </ul>
    </div>
</div>
</body>
</html>
"""
    path.write_text(html_content, encoding="utf-8")
    return path
