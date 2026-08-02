"""CLI entry point: orchestrates the checks and writes the outputs.

    python -m src.audit --demo --format html

READ-ONLY GUARANTEE. Every network call in this program goes through
OktaClient._get, which is hardcoded to HTTP GET. There is no POST, PUT, PATCH or
DELETE anywhere in src/. That is verifiable in one grep, and the CI pipeline
runs exactly that grep on every commit.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, List, Tuple

from .checks import (
    admin_roles,
    api_tokens,
    hooks,
    oauth_service_apps,
    scim_connections,
    service_accounts,
)
from .checks.base import TenantContext
from .report import (
    print_terminal,
    render_html,
    write_csv,
    write_inventory_csv,
)
from .scoring import CRITICAL, HIGH, Finding, InventoryItem, sort_findings

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

CHECK_NAMES = [
    "api_tokens",
    "service_accounts",
    "admin_roles",
    "oauth_service_apps",
    "hooks",
    "scim_connections",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.audit",
        description=(
            "Inventory and risk-score the non-human identities in an Okta "
            "tenant. Read-only: this tool issues GET requests exclusively."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m src.audit --demo --format html\n"
            "  python -m src.audit --format all --output reports/acme\n"
            "  python -m src.audit --checks api_tokens,admin_roles\n"
        ),
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help=(
            "run against bundled fixture data instead of a live tenant. "
            "No Okta account or network access required."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "html", "csv", "all"],
        default="terminal",
        help="output format (default: terminal). 'all' writes html + csv too.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "output path stem for html/csv "
            "(default: reports/audit_demo or reports/audit_<timestamp>)"
        ),
    )
    parser.add_argument(
        "--checks",
        default="all",
        help=f"comma-separated subset of: {', '.join(CHECK_NAMES)} (default: all)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=(
            "service-account heuristic threshold, 0.0-1.0 (default: 0.5, or "
            "NHI_SERVICE_ACCOUNT_THRESHOLD from the environment). Lower = more "
            "sensitive = more false positives."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=["never", "critical", "high"],
        default="never",
        help=(
            "exit non-zero when findings at or above this severity exist. "
            "Useful in CI. Default: never."
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def build_client(demo: bool) -> Tuple[Any, str, str]:
    """Return (client, org_name, org_url).

    Duck typing at work: DemoClient and OktaClient share the four methods the
    checks call, so nothing downstream branches on which one it got.
    """
    if demo:
        from .demo_client import DemoClient

        client = DemoClient()
        org = client.verify_connection()
        return client, org.get("companyName", "Demo Organisation"), client.org_url

    from .okta_client import OktaClient, OktaError

    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:  # pragma: no cover
        pass

    org_url = os.environ.get("OKTA_ORG_URL", "").strip()
    token = os.environ.get("OKTA_API_TOKEN", "").strip()

    if not org_url or not token:
        sys.exit(
            "Missing configuration.\n"
            "  Set OKTA_ORG_URL and OKTA_API_TOKEN — copy .env.example to .env "
            "and fill them in.\n"
            "  Or run without a tenant at all:  python -m src.audit --demo "
            "--format html"
        )

    client = OktaClient(org_url, token)
    try:
        org = client.verify_connection()
    except OktaError as exc:
        sys.exit(f"\nCould not connect to Okta.\n\n{exc}\n")

    return client, org.get("companyName", org_url), org_url


def run_checks(
    context: TenantContext,
    selected: List[str],
    threshold: float,
) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    scores: List[Any] = []

    if "api_tokens" in selected:
        logging.info("Check: org API tokens")
        found, items = api_tokens.run(context)
        findings.extend(found)
        inventory.extend(items)

    # service_accounts must run before admin_roles: the latter cross-references
    # the scored accounts the former produces. Ordering is a real dependency,
    # not a preference.
    if "service_accounts" in selected or "admin_roles" in selected:
        logging.info("Check: suspected service accounts")
        found, items, scores = service_accounts.run(context, threshold=threshold)
        if "service_accounts" in selected:
            findings.extend(found)
            inventory.extend(items)

    if "admin_roles" in selected:
        logging.info("Check: admin roles held by non-humans")
        found, items = admin_roles.run(context, scores)
        findings.extend(found)
        inventory.extend(items)

    if "oauth_service_apps" in selected:
        logging.info("Check: OAuth service integrations")
        found, items = oauth_service_apps.run(context)
        findings.extend(found)
        inventory.extend(items)

    if "hooks" in selected:
        logging.info("Check: event and inline hooks")
        found, items = hooks.run(context)
        findings.extend(found)
        inventory.extend(items)

    if "scim_connections" in selected:
        logging.info("Check: SCIM provisioning connections")
        found, items = scim_connections.run(context)
        findings.extend(found)
        inventory.extend(items)

    return sort_findings(findings), inventory


def resolve_threshold(argument: float | None) -> float:
    if argument is not None:
        value = argument
    else:
        try:
            value = float(os.environ.get("NHI_SERVICE_ACCOUNT_THRESHOLD", "0.5"))
        except ValueError:
            value = 0.5
    if not 0.0 <= value <= 1.0:
        sys.exit(f"--threshold must be between 0.0 and 1.0 (got {value})")
    return value


def resolve_checks(argument: str) -> List[str]:
    if argument.strip().lower() == "all":
        return list(CHECK_NAMES)
    selected = [name.strip() for name in argument.split(",") if name.strip()]
    unknown = [name for name in selected if name not in CHECK_NAMES]
    if unknown:
        sys.exit(
            f"Unknown check(s): {', '.join(unknown)}\n"
            f"  Available: {', '.join(CHECK_NAMES)}"
        )
    return selected


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    threshold = resolve_threshold(args.threshold)
    selected = resolve_checks(args.checks)

    client, org_name, org_url = build_client(args.demo)
    context = TenantContext(client, demo=args.demo)

    try:
        findings, inventory = run_checks(context, selected, threshold)
    finally:
        client.close()

    if args.format in ("terminal", "all"):
        print_terminal(findings, inventory, org_name, demo=args.demo)

    stem = args.output or (
        REPORTS_DIR / ("audit_demo" if args.demo else "audit_report")
    )
    stem = Path(stem)

    written: List[Path] = []

    if args.format in ("html", "all"):
        path = render_html(
            findings=findings,
            inventory=inventory,
            output_path=stem.with_suffix(".html"),
            org_name=org_name,
            org_url=org_url,
            demo=args.demo,
            threshold=threshold,
            scope_limitations=context.scope_limitations,
        )
        written.append(path)

    if args.format in ("csv", "all"):
        written.append(write_csv(findings, stem.with_suffix(".csv")))
        written.append(
            write_inventory_csv(
                inventory, stem.with_name(stem.name + "_inventory").with_suffix(".csv")
            )
        )

    for path in written:
        print(f"wrote {path}")

    if args.fail_on == "critical" and any(f.severity == CRITICAL for f in findings):
        return 2
    if args.fail_on == "high" and any(
        f.severity in (CRITICAL, HIGH) for f in findings
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
