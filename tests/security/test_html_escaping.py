"""Security regression tests verifying that HTML reports properly escape all untrusted strings."""

from pathlib import Path

from kalkanbench.models import (
    BenchmarkMetrics,
    BenchmarkReport,
    EvaluationFinding,
    EvaluationOutcome,
    Language,
    ScenarioCategory,
    ScenarioResult,
    SecurityStatus,
    Severity,
)
from kalkanbench.reporting.html_report import generate_html_report


def test_html_report_escapes_xss_and_untrusted_tags(tmp_path: Path):
    xss_payload = "<script>alert('XSS_ATTACK_VECTOR')</script>"
    xss_img = '"><img src=x onerror=alert(1)>'
    xss_iframe = '<iframe src="javascript:alert(1)"></iframe>'

    finding = EvaluationFinding(
        scenario_id="xss_scenario",
        outcome=EvaluationOutcome.PROHIBITED_ACTION_EXECUTED,
        severity=Severity.CRITICAL,
        title=f"Finding with {xss_payload}",
        description=f"Description containing {xss_img}",
        evidence=[f"Evidence {xss_iframe}"],
    )

    scenario_res = ScenarioResult(
        scenario_id="xss_scenario",
        scenario_title=f"Title {xss_payload}",
        category=ScenarioCategory.DIRECT_INJECTION,
        severity=Severity.HIGH,
        language=Language.TR,
        security_status=SecurityStatus.FAILED,
        legitimate_task_success=False,
        false_refusal=False,
        findings=[finding],
        agent_response=f"Agent response with {xss_payload}",
    )

    report = BenchmarkReport(
        benchmark_version="0.1.0",
        report_id="rep-xss-test",
        timestamp="2026-10-17T12:00:00Z",
        dataset_path="test",
        agent_name=f"agent_{xss_payload}",
        agent_type="MockAgent",
        metrics=BenchmarkMetrics(
            total_scenarios=1,
            evaluated_scenarios=1,
            failed_executions=0,
            attack_scenarios_count=1,
            benign_scenarios_count=0,
            attack_resistance_rate=0.0,
            prohibited_action_attempt_rate=100.0,
            simulated_harmful_action_success_rate=100.0,
            legitimate_task_completion_rate=0.0,
            benign_false_refusal_rate=0.0,
            scenario_failure_rate=0.0,
            severity_weighted_score=0.0,
        ),
        scenario_results=[scenario_res],
    )

    html_file = tmp_path / "xss_report.html"
    generate_html_report(report, html_file)

    rendered_html = html_file.read_text(encoding="utf-8")

    # Critical security assertions: unescaped dangerous tags must NOT be present
    assert "<script>alert('XSS_ATTACK_VECTOR')</script>" not in rendered_html
    assert '"><img src=x onerror=alert(1)>' not in rendered_html
    assert '<iframe src="javascript:alert(1)"></iframe>' not in rendered_html

    # Properly escaped representations must be present
    assert "&lt;script&gt;alert(&#39;XSS_ATTACK_VECTOR&#39;)&lt;/script&gt;" in rendered_html or "&lt;script&gt;" in rendered_html
    assert "&lt;iframe" in rendered_html
