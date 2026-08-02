"""Tests for the report renderers.

The HTML report is the deliverable, so the properties worth pinning down are the
ones that make it usable as one: it must be self-contained, it must not execute
data from a client tenant, and it must contain all five sections.
"""

from __future__ import annotations

import re

import pytest

from src.audit import CHECK_NAMES, main, run_checks
from src.checks.base import TenantContext
from src.demo_client import DemoClient
from src.report import build_roadmap, build_verdict, render_html, write_csv
from src.scoring import CRITICAL, LOW, Finding, count_by_severity


@pytest.fixture
def audit_result():
    context = TenantContext(DemoClient(), demo=True)
    findings, inventory = run_checks(context, CHECK_NAMES, threshold=0.5)
    return findings, inventory


@pytest.fixture
def rendered(tmp_path, audit_result):
    findings, inventory = audit_result
    path = render_html(
        findings=findings,
        inventory=inventory,
        output_path=tmp_path / "report.html",
        org_name="Test Org",
        org_url="https://dev-00000000.okta.com",
        demo=True,
    )
    return path.read_text()


def test_report_contains_all_five_sections(rendered):
    for section in [
        "Executive summary",
        "Non-human identity inventory",
        "Findings",
        "Remediation roadmap",
        "Methodology, scope and limitations",
    ]:
        assert section in rendered


def test_report_is_self_contained(rendered):
    """No CDN, no remote font, no external image.

    A report that needs the internet to render is a report that looks broken
    when a client opens the attachment on a plane.
    """
    remote = re.findall(r'(?:src|href)="https?://', rendered)
    assert not remote, f"external references found: {remote}"
    assert "@import" not in rendered
    assert "<style>" in rendered


def flat(text: str) -> str:
    """Collapse whitespace so assertions survive HTML line wrapping."""
    return re.sub(r"\s+", " ", text)


def test_report_states_read_only_access(rendered):
    assert "Read-only" in rendered
    assert "no create, update or delete operation exists" in flat(rendered)


def test_demo_report_is_labelled_as_demo(rendered):
    assert "Demonstration report" in rendered
    assert "No real Okta tenant was contacted" in flat(rendered)


def test_report_declares_heuristic_limitations(rendered):
    assert "probabilistic" in rendered
    assert "false positives" in rendered


def test_report_names_the_next_engagement_scope(rendered):
    assert "CI/CD" in rendered
    assert "cloud IAM" in rendered.lower() or "Cloud IAM" in rendered


def test_tenant_data_is_escaped_not_executed(tmp_path):
    """An app label from a client tenant is untrusted input."""
    hostile = Finding(
        nhi_type="oauth_service_app",
        identity="<script>alert('xss')</script>",
        severity=LOW,
        finding="test",
        evidence="<img src=x onerror=alert(1)>",
        risk="r",
        remediation="m",
    )
    html = render_html(
        findings=[hostile],
        inventory=[],
        output_path=tmp_path / "r.html",
        org_name="<b>Org</b>",
        org_url="https://x.okta.com",
    ).read_text()

    # The payloads appear as visible text, not as live markup: every angle
    # bracket that came from tenant data is entity-encoded, so the browser
    # renders "<img src=x onerror=...>" rather than parsing an img tag.
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<b>Org</b>" not in html


def test_verdict_leads_with_the_worst_finding(audit_result):
    findings, inventory = audit_result
    verdict = build_verdict(findings, inventory, count_by_severity(findings))
    assert verdict
    assert "24 hours" in verdict[0]


def test_roadmap_is_ordered_by_urgency(audit_result):
    findings, _ = audit_result
    roadmap = build_roadmap(findings)
    assert roadmap[0]["severity"] == CRITICAL
    assert "24 hours" in roadmap[0]["timeframe"]
    assert all(phase["actions"] for phase in roadmap)


def test_csv_has_one_row_per_finding(tmp_path, audit_result):
    findings, _ = audit_result
    path = write_csv(findings, tmp_path / "findings.csv")
    lines = path.read_text().strip().splitlines()
    assert lines[0].startswith("severity,nhi_type,identity")
    # Fields contain embedded newlines, so count rows via csv rather than lines.
    import csv

    with path.open() as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(findings)


# ------------------------------------------------------------------------ CLI


def test_cli_demo_end_to_end_writes_html(tmp_path, capsys):
    exit_code = main(
        ["--demo", "--format", "html", "--output", str(tmp_path / "out")]
    )
    assert exit_code == 0
    assert (tmp_path / "out.html").exists()


def test_cli_fail_on_critical_returns_nonzero(tmp_path):
    code = main(
        ["--demo", "--format", "csv", "--fail-on", "critical",
         "--output", str(tmp_path / "out")]
    )
    assert code == 2


def test_cli_rejects_unknown_check():
    with pytest.raises(SystemExit):
        main(["--demo", "--checks", "not_a_check"])


def test_cli_rejects_out_of_range_threshold():
    with pytest.raises(SystemExit):
        main(["--demo", "--threshold", "5"])


def test_cli_subset_of_checks_runs_only_those(tmp_path):
    code = main(
        ["--demo", "--checks", "api_tokens", "--format", "csv",
         "--output", str(tmp_path / "sub")]
    )
    assert code == 0
    text = (tmp_path / "sub.csv").read_text()
    assert "api_token" in text
    assert "scim" not in text
