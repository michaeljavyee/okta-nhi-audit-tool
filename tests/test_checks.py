"""Tests for the checks, the scoring model, and the read-only guarantee.

The checks run against DemoClient, which serves the same fixtures `--demo` uses.
That means these tests exercise the exact code path an interviewer runs, rather
than a parallel test-only implementation that can drift.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.checks import (
    admin_roles,
    api_tokens,
    hooks,
    oauth_service_apps,
    scim_connections,
    service_accounts,
)
from src.checks.base import TenantContext
from src.demo_client import DemoClient
from src.scoring import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    SEVERITY_ORDER,
    Finding,
    count_by_severity,
    days_since,
    score_service_account,
    sort_findings,
)

SRC = Path(__file__).resolve().parent.parent / "src"


@pytest.fixture
def context():
    return TenantContext(DemoClient(), demo=True)


# --------------------------------------------------------- read-only guarantee


def test_no_write_verbs_anywhere_in_src():
    """The central design claim of this tool, asserted mechanically.

    If someone later adds a 'remediate' feature, this test fails and forces the
    conversation rather than letting the claim in the README quietly become
    false.
    """
    forbidden = re.compile(
        r"(session|requests)\s*\.\s*(post|put|patch|delete)\s*\(", re.IGNORECASE
    )
    offenders = []
    for path in SRC.rglob("*.py"):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if forbidden.search(line):
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert not offenders, "Write operations found in src/:\n" + "\n".join(offenders)


def test_client_only_exposes_get():
    from src.okta_client import OktaClient

    public = {name for name in dir(OktaClient) if not name.startswith("_")}
    assert not public & {"post", "put", "patch", "delete", "create", "update"}


# ------------------------------------------------------------------ API tokens


def test_orphaned_token_is_critical(context):
    findings, _ = api_tokens.run(context)
    orphaned = [f for f in findings if f.severity == CRITICAL]
    assert len(orphaned) == 1
    assert orphaned[0].identity == "terraform-okta-provider"
    assert "DEPROVISIONED" in orphaned[0].evidence


def test_orphaned_token_finding_explains_inherited_privilege(context):
    findings, _ = api_tokens.run(context)
    critical = next(f for f in findings if f.severity == CRITICAL)
    assert "privileges its creator held" in critical.risk
    assert "Security -> API -> Tokens" in critical.remediation


def test_continuously_used_token_flagged_as_never_expiring(context):
    findings, _ = api_tokens.run(context)
    immortal = [f for f in findings if "expiry never takes effect" in f.finding]
    assert len(immortal) == 1
    assert immortal[0].identity == "nightly-user-sync"


def test_idle_token_flagged_low_as_availability_risk(context):
    findings, _ = api_tokens.run(context)
    idle = [f for f in findings if "expire silently" in f.finding]
    assert len(idle) == 1
    assert idle[0].severity == LOW


def test_every_token_appears_in_inventory(context):
    _, inventory = api_tokens.run(context)
    assert len(inventory) == 4
    assert all(item.owner for item in inventory)


# ------------------------------------------------------------ service accounts


def test_known_service_accounts_are_detected(context):
    _, _, scores = service_accounts.run(context, threshold=0.5)
    detected = {s.login for s in scores if s.is_suspected}
    assert "svc-jira@example.com" in detected
    assert "automation@example.com" in detected
    assert "bot-builds@example.com" in detected


def test_ordinary_humans_are_not_flagged(context):
    _, _, scores = service_accounts.run(context, threshold=0.5)
    detected = {s.login for s in scores if s.is_suspected}
    assert not any(login.startswith("amara.") for login in detected)
    assert not any(login.startswith("ben.") for login in detected)


def test_well_managed_service_account_scores_lower_than_the_bad_one(context):
    """The control case. A tool that flags everything equally is useless."""
    _, _, scores = service_accounts.run(context, threshold=0.5)
    by_login = {s.login: s for s in scores}
    assert by_login["svc-backup@example.com"].score < by_login["svc-jira@example.com"].score


def test_well_managed_service_account_is_only_low_severity(context):
    findings, _, _ = service_accounts.run(context, threshold=0.5)
    backup = [f for f in findings if f.identity == "svc-backup@example.com"]
    assert backup and backup[0].severity == LOW


def test_threshold_is_tunable(context):
    _, _, strict = service_accounts.run(context, threshold=0.95)
    fresh = TenantContext(DemoClient(), demo=True)
    _, _, loose = service_accounts.run(fresh, threshold=0.3)
    assert sum(s.is_suspected for s in strict) <= sum(s.is_suspected for s in loose)


def test_score_reasons_are_always_populated_when_flagged(context):
    _, _, scores = service_accounts.run(context, threshold=0.5)
    for score in scores:
        if score.is_suspected:
            assert score.reasons, f"{score.login} flagged with no stated reason"


def test_scoring_is_pure_and_weights_sum_to_one():
    from src.scoring import HEURISTIC_WEIGHTS

    assert abs(sum(HEURISTIC_WEIGHTS.values()) - 1.0) < 1e-9

    user = {"id": "x", "profile": {"login": "svc-thing@example.com"}}
    perfect = score_service_account(
        user, has_mfa=False, had_interactive_login=False, api_event_count=5
    )
    assert perfect.score == 1.0

    human = {"id": "y", "profile": {"login": "jane.doe@example.com"}}
    none = score_service_account(
        human, has_mfa=True, had_interactive_login=True, api_event_count=0
    )
    assert none.score == 0.0


# --------------------------------------------------------------- admin roles


def test_super_admin_on_service_account_is_critical(context):
    _, _, scores = service_accounts.run(context, threshold=0.5)
    findings, _ = admin_roles.run(context, scores)
    critical = [f for f in findings if f.severity == CRITICAL]
    assert len(critical) == 1
    assert critical[0].identity == "svc-jira@example.com"
    assert "Super Administrator" in critical[0].finding


def test_lesser_admin_role_on_service_account_is_high(context):
    _, _, scores = service_accounts.run(context, threshold=0.5)
    findings, _ = admin_roles.run(context, scores)
    org_admin = [f for f in findings if f.identity == "automation@example.com"]
    assert org_admin and org_admin[0].severity == HIGH


def test_human_admins_are_not_reported(context):
    _, _, scores = service_accounts.run(context, threshold=0.5)
    findings, _ = admin_roles.run(context, scores)
    assert not any("amara" in f.identity for f in findings)


# ---------------------------------------------------------- oauth service apps


def test_overscoped_oauth_app_is_high(context):
    findings, _ = oauth_service_apps.run(context)
    high = [f for f in findings if f.severity == HIGH]
    assert len(high) == 1
    assert high[0].identity == "Internal Provisioning Service"
    assert "okta.users.manage" in high[0].evidence
    assert "okta.users.read" in high[0].evidence


def test_correctly_scoped_oauth_app_is_low_not_high(context):
    findings, _ = oauth_service_apps.run(context)
    reporting = [f for f in findings if f.identity == "Security Reporting Exporter"]
    assert reporting and reporting[0].severity == LOW


def test_saml_apps_are_not_treated_as_service_integrations(context):
    _, inventory = oauth_service_apps.run(context)
    labels = {item.identity for item in inventory}
    assert "Slack" not in labels
    assert "Notion" not in labels


# ---------------------------------------------------------------------- hooks


def test_plaintext_hook_destination_is_high(context):
    findings, _ = hooks.run(context)
    plaintext = [f for f in findings if "plaintext HTTP" in f.finding]
    assert len(plaintext) == 1
    assert plaintext[0].severity == HIGH


def test_hook_without_auth_header_is_flagged(context):
    findings, _ = hooks.run(context)
    assert any("no authentication header" in f.finding for f in findings)


def test_inline_hook_flagged_as_in_the_auth_path(context):
    findings, _ = hooks.run(context)
    inline = [f for f in findings if "synchronously" in f.finding]
    assert len(inline) == 1
    assert "token-claim-enrichment" == inline[0].identity


def test_hook_destinations_are_never_contacted(context):
    """No probing of client third-party endpoints. Read-only means their whole
    environment, not just their Okta tenant."""
    source = (SRC / "checks" / "hooks.py").read_text()
    assert "requests." not in source
    assert "urlopen" not in source


# ----------------------------------------------------------------------- SCIM


def test_provisioning_on_inactive_app_is_high(context):
    findings, _ = scim_connections.run(context)
    stale = [f for f in findings if f.severity == HIGH]
    assert len(stale) == 1
    assert "Zoom" in stale[0].identity


def test_create_without_deactivate_is_medium(context):
    findings, _ = scim_connections.run(context)
    github = [f for f in findings if "GitHub" in f.identity]
    assert github and github[0].severity == MEDIUM
    assert "offboard" in github[0].risk.lower() or "Offboarding" in github[0].risk


def test_apps_without_provisioning_are_skipped(context):
    _, inventory = scim_connections.run(context)
    assert "Notion" not in {item.identity for item in inventory}


# -------------------------------------------------------- deliverable quality


def test_every_finding_has_business_language_risk_and_remediation(context):
    from src.audit import CHECK_NAMES, run_checks

    findings, _ = run_checks(context, CHECK_NAMES, threshold=0.5)
    assert findings
    for finding in findings:
        assert len(finding.risk) > 120, f"{finding.identity}: risk too thin"
        assert len(finding.remediation) > 60, f"{finding.identity}: remediation too thin"
        assert finding.evidence, f"{finding.identity}: no evidence"
        assert finding.identity


def test_demo_run_produces_at_least_one_critical(context):
    from src.audit import CHECK_NAMES, run_checks

    findings, inventory = run_checks(context, CHECK_NAMES, threshold=0.5)
    counts = count_by_severity(findings)
    assert counts[CRITICAL] >= 1
    assert len(inventory) >= 10


def test_findings_sort_most_severe_first():
    findings = [
        Finding("api_token", "b", LOW, "f", "e", "r", "x"),
        Finding("api_token", "a", CRITICAL, "f", "e", "r", "x"),
        Finding("api_token", "c", MEDIUM, "f", "e", "r", "x"),
    ]
    assert [f.severity for f in sort_findings(findings)] == [CRITICAL, MEDIUM, LOW]


def test_invalid_severity_is_rejected_at_construction():
    with pytest.raises(ValueError):
        Finding("api_token", "x", "catastrophic", "f", "e", "r", "x")


def test_invalid_nhi_type_is_rejected_at_construction():
    with pytest.raises(ValueError):
        Finding("smoke_signal", "x", LOW, "f", "e", "r", "x")


# ---------------------------------------------------------------- date helpers


def test_days_since_handles_z_suffix_and_none():
    assert days_since(None) is None
    assert days_since("not a date") is None
    assert days_since("2020-01-01T00:00:00.000Z") > 1000


# ---------------------------------------------------------------- demo client


def test_demo_client_404s_endpoints_the_fixtures_do_not_model():
    client = DemoClient()
    assert client.get_optional("/api/v1/apps/0oaSAMLNOTION0EXAMPLE/features") is None
    assert list(client.paginate_optional("/api/v1/nothing/here")) == []


def test_demo_and_real_clients_share_the_same_interface():
    from src.okta_client import OktaClient

    required = {"get", "get_optional", "paginate", "paginate_optional",
                "verify_connection", "close"}
    assert required <= set(dir(DemoClient))
    assert required <= set(dir(OktaClient))
