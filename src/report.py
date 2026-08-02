"""Output renderers: HTML deliverable, CSV, and terminal table.

The HTML report is the product. The terminal output is for you while you work;
the CSV is for a client who wants to track remediation in a spreadsheet. Only
the HTML is designed to be handed to someone.
"""

from __future__ import annotations

import csv
import html
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .scoring import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    NHI_TYPE_LABELS,
    SEVERITY_DEFINITIONS,
    SEVERITY_ORDER,
    SEVERITY_TIMEFRAME,
    Finding,
    InventoryItem,
    count_by_severity,
)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

SCOPE_COVERED = [
    "Org API tokens: owner, creation date, last use, expiry posture",
    "API service integrations using the OAuth client_credentials grant, and their granted scopes",
    "User objects assessed as probable service accounts",
    "Administrative role assignments held by those accounts",
    "Event hooks and inline hooks, including destination and authentication configuration",
    "SCIM provisioning connections and their downstream lifecycle capabilities",
]

SCOPE_EXCLUDED = [
    "Human user hygiene: stale accounts, MFA coverage, password policy",
    "Credentials held in CI/CD systems (GitHub Actions, CircleCI, Jenkins)",
    "Cloud IAM roles, access keys and workload identities (AWS, GCP, Azure)",
    "Secrets committed to source control repositories",
    "API keys created directly inside downstream SaaS applications",
    "Okta Workflows connections and their stored credentials",
    "Penetration testing or exploitation of any kind",
]


def render_html(
    findings: List[Finding],
    inventory: List[InventoryItem],
    output_path: Path,
    org_name: str,
    org_url: str,
    demo: bool = False,
    threshold: float = 0.5,
    scope_limitations: List[str] | None = None,
) -> Path:
    """Render the self-contained HTML assessment report.

    autoescape is on: findings carry data straight out of a client tenant, and
    an app label containing a `<script>` tag should render as text, not execute.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")

    counts = count_by_severity(findings)

    inventory_by_type: "OrderedDict[str, List[InventoryItem]]" = OrderedDict()
    for nhi_type in NHI_TYPE_LABELS:
        items = [item for item in inventory if item.nhi_type == nhi_type]
        if items:
            inventory_by_type[nhi_type] = items

    rendered = template.render(
        org_name=org_name,
        org_url=org_url,
        generated_at=datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC"),
        demo=demo,
        threshold=f"{threshold:.2f}",
        findings=findings,
        inventory=inventory,
        inventory_by_type=inventory_by_type,
        type_labels=NHI_TYPE_LABELS,
        counts=counts,
        verdict=build_verdict(findings, inventory, counts),
        roadmap=build_roadmap(findings),
        severity_definitions=SEVERITY_DEFINITIONS,
        scope_covered=SCOPE_COVERED,
        scope_excluded=SCOPE_EXCLUDED,
        scope_limitations=scope_limitations or [],
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    return output_path


def build_verdict(
    findings: List[Finding],
    inventory: List[InventoryItem],
    counts: Dict[str, int],
) -> List[str]:
    """The one-paragraph judgement a reader takes away if they read nothing else.

    Deliberately written as prose rather than statistics. A client executive
    reads this paragraph and the severity counts, and nothing else.
    """
    total = len(inventory)
    critical = counts[CRITICAL]
    high = counts[HIGH]

    paragraphs: List[str] = []

    if critical:
        headline = (
            f"This assessment identified {total} non-human identities in the "
            f"Okta tenant and {critical} finding{'s' if critical != 1 else ''} "
            "requiring action within 24 hours. "
        )
    elif high:
        headline = (
            f"This assessment identified {total} non-human identities in the "
            f"Okta tenant. No issue rises to the level of immediate exposure, "
            f"but {high} finding{'s' if high != 1 else ''} represent "
            "meaningful standing risk. "
        )
    else:
        headline = (
            f"This assessment identified {total} non-human identities in the "
            "Okta tenant and found no critical or high-severity issues. "
        )

    if critical:
        worst = next(f for f in findings if f.severity == CRITICAL)
        headline += (
            f"The most significant is {worst.identity}: "
            f"{_decapitalise(worst.finding)}"
        )
    paragraphs.append(headline.strip())

    paragraphs.append(
        "The pattern across these findings is ownership rather than "
        "configuration. Individually, most of the issues below are the result of "
        "a reasonable decision made quickly — a token issued to unblock a "
        "deployment, an admin role granted to fix a failing sync, a scope set to "
        "manage because it was simpler than working out which read scopes were "
        "needed. What makes them risk rather than debt is that no person or team "
        "currently owns any of these identities, so nothing causes them to be "
        "revisited. Okta provides no owner field for tokens, hooks or service "
        "integrations, which means ownership has to be maintained deliberately "
        "or not at all."
    )

    if total:
        paragraphs.append(
            f"The inventory in section 2 lists all {total} identities. For most "
            "organisations this list has never previously been assembled, and it "
            "is worth reviewing on its own terms — before considering the "
            "findings — simply to establish whether every entry is recognised."
        )

    return paragraphs


def build_roadmap(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Group findings into sequenced remediation phases.

    Sequencing by severity rather than effort is a deliberate choice, stated in
    the report: the point of the roadmap is to answer "what do we do Monday",
    not "what is cheapest".
    """
    phase_titles = {
        CRITICAL: "Immediate containment",
        HIGH: "Reduce standing privilege",
        MEDIUM: "Tighten scope and lifecycle",
        LOW: "Hygiene and inventory",
    }

    roadmap: List[Dict[str, Any]] = []
    for severity in [CRITICAL, HIGH, MEDIUM, LOW]:
        matching = [f for f in findings if f.severity == severity]
        if not matching:
            continue
        roadmap.append(
            {
                "severity": severity,
                "title": phase_titles[severity],
                "timeframe": SEVERITY_TIMEFRAME[severity],
                "actions": [
                    {
                        "summary": f"{finding.identity} — {finding.finding}",
                        "detail": _first_sentence(finding.remediation),
                    }
                    for finding in matching
                ],
            }
        )
    return roadmap


def _decapitalise(text: str) -> str:
    """Lowercase the first letter so a sentence reads on from a colon.

    Leaves acronyms alone: "API token is owned by..." must not become "aPI".
    The test is whether the first two characters are both uppercase, which
    catches API, SCIM, OAuth and MFA without needing a word list.
    """
    if len(text) >= 2 and text[0].isupper() and text[1].isupper():
        return text
    return text[0].lower() + text[1:] if text else text


def _first_sentence(text: str) -> str:
    for delimiter in (". ", "? "):
        if delimiter in text:
            candidate = text.split(delimiter)[0] + delimiter.strip()
            if len(candidate) > 25:
                return candidate
    return text


# ------------------------------------------------------------------------ CSV


CSV_COLUMNS = [
    "severity",
    "nhi_type",
    "identity",
    "identity_id",
    "check",
    "finding",
    "evidence",
    "risk",
    "remediation",
]


def write_csv(findings: List[Finding], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for finding in findings:
            row = finding.to_dict()
            writer.writerow({column: row.get(column, "") for column in CSV_COLUMNS})
    return output_path


def write_inventory_csv(inventory: List[InventoryItem], output_path: Path) -> Path:
    columns = [
        "nhi_type",
        "identity",
        "identity_id",
        "owner",
        "created",
        "last_used",
        "privilege",
        "notes",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for item in inventory:
            writer.writerow(item.to_dict())
    return output_path


# ------------------------------------------------------------------- terminal

SEVERITY_STYLES = {
    CRITICAL: "bold white on red",
    HIGH: "bold dark_orange",
    MEDIUM: "yellow",
    LOW: "green",
    "info": "blue",
}


def print_terminal(
    findings: List[Finding],
    inventory: List[InventoryItem],
    org_name: str,
    demo: bool = False,
) -> None:
    """Rich terminal summary. Falls back to plain text if rich isn't installed."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:  # pragma: no cover
        _print_plain(findings, inventory, org_name)
        return

    console = Console()
    counts = count_by_severity(findings)

    subtitle = "DEMO — bundled fixture data" if demo else "read-only assessment"
    console.print()
    console.print(
        Panel(
            f"[bold]Non-Human Identity Assessment[/bold]\n{org_name}",
            subtitle=subtitle,
            expand=False,
        )
    )

    summary = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    summary.add_column("Severity")
    summary.add_column("Count", justify="right")
    for severity in [CRITICAL, HIGH, MEDIUM, LOW]:
        summary.add_row(
            f"[{SEVERITY_STYLES[severity]}] {severity.upper()} [/]",
            str(counts[severity]),
        )
    summary.add_row("[dim]NHIs inventoried[/dim]", str(len(inventory)))
    console.print()
    console.print(summary)

    if not findings:
        console.print("\n[green]No findings.[/green]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold",
        title="\nFindings",
        title_justify="left",
        expand=True,
    )
    table.add_column("Sev", width=9, no_wrap=True)
    table.add_column("Type", width=16)
    table.add_column("Identity", width=30, overflow="fold")
    table.add_column("Finding", overflow="fold")

    for finding in findings:
        table.add_row(
            f"[{SEVERITY_STYLES[finding.severity]}] {finding.severity.upper()} [/]",
            finding.nhi_type,
            finding.identity,
            finding.finding,
        )
    console.print(table)

    critical = [f for f in findings if f.severity == CRITICAL]
    if critical:
        console.print()
        for finding in critical:
            console.print(
                Panel(
                    f"[bold]{finding.finding}[/bold]\n\n"
                    f"[dim]Evidence:[/dim] {finding.evidence}\n\n"
                    f"[dim]Remediation:[/dim] {_first_sentence(finding.remediation)}",
                    title=f"[bold white on red] CRITICAL [/] {finding.identity}",
                    border_style="red",
                )
            )
    console.print()


def _print_plain(
    findings: List[Finding], inventory: List[InventoryItem], org_name: str
) -> None:  # pragma: no cover
    counts = count_by_severity(findings)
    print(f"\nNon-Human Identity Assessment — {org_name}")
    print("-" * 70)
    for severity in SEVERITY_ORDER:
        if counts[severity]:
            print(f"  {severity.upper():>9}: {counts[severity]}")
    print(f"  {'inventory':>9}: {len(inventory)}")
    print("-" * 70)
    for finding in findings:
        print(f"[{finding.severity.upper():>8}] {finding.identity}: {finding.finding}")
    print()
