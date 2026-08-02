#!/usr/bin/env python3
"""Seed an Okta Developer Edition tenant with a deliberately messy NHI estate.

    python scripts/seed_tenant.py --dry-run     # show what it would do
    python scripts/seed_tenant.py --confirm     # actually do it

WHY THIS EXISTS: an audit tool that returns "no findings" demonstrates nothing.
This builds a tenant resembling a 40-person startup that grew fast — the kind
that has an orphaned Terraform token and a Super Admin service account — so the
audit has real things to find, and so results are reproducible by anyone.

READ THIS BEFORE RUNNING IT
---------------------------
This script WRITES. It is the only file in the repository that does, which is
why it lives in scripts/ and not in src/, and why nothing under src/ imports it.
CI enforces both of those boundaries.

Run it against a throwaway Okta Developer Edition tenant and nothing else. It
will refuse to run against an org URL that doesn't look like a dev org unless
you pass --i-know-what-im-doing.

WHAT IT CANNOT DO
-----------------
Some of the scenario has to be built by hand, because the Okta API does not
expose it:

  - Org API tokens cannot be created through the API. That is deliberate on
    Okta's part, and it is a good design decision. You create them in the admin
    console (Security -> API -> Tokens), and the orphaned-token scenario is
    built by creating a token as a user you then deactivate.
  - SCIM provisioning configuration is per-connector and largely console-driven.

The script prints step-by-step instructions for those parts at the end.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any, Dict, List, Optional

import requests

# Users
HUMANS = [
    ("Amara", "Okonkwo"), ("Ben", "Sorensen"), ("Chen", "Wei"),
    ("Dara", "Fitzgerald"), ("Elena", "Vasquez"), ("Femi", "Adeyemi"),
    ("Grace", "Lindqvist"), ("Hassan", "Karimi"), ("Ingrid", "Bauer"),
    ("Jonas", "Meyer"), ("Kavita", "Rao"), ("Liam", "ODonnell"),
    ("Mei", "Tanaka"), ("Nadia", "Haddad"), ("Oscar", "Delgado"),
    ("Priya", "Nair"), ("Quentin", "Boucher"), ("Rosa", "Marchetti"),
    ("Samir", "Patel"), ("Tessa", "Nguyen"), ("Ulrich", "Schmitt"),
    ("Vera", "Kowalski"), ("Xiomara", "Reyes"), ("Yusuf", "Demir"),
]

# The user who will be deactivated after creating an API token, producing the
# orphaned-token finding.
DEPARTING_USER = ("Wes", "Brennan")

SERVICE_ACCOUNTS = [
    ("svc", "jira", "svc-jira@example.com", "Jira Integration Service Account"),
    ("Automation", "Account", "automation@example.com", "Automation"),
    ("integration", "hubspot", "integration-hubspot@example.com", "HubSpot Integration"),
    ("build", "bot", "bot-builds@example.com", "CI Build Bot"),
    # The control case: named like a service account, configured correctly.
    ("svc", "backup", "svc-backup@example.com", "Backup Service Account (managed)"),
]

EVENT_HOOK = {
    "name": "legacy-audit-forwarder",
    "events": {"type": "EVENT_TYPE", "items": ["user.session.start"]},
    "channel": {
        "type": "HTTP",
        "version": "1.0.0",
        "config": {
            # Plaintext, third-party, no auth header — three findings in one.
            "uri": "http://audit-collector.thirdparty-vendor.example.net/ingest"
        },
    },
}


class Seeder:
    def __init__(self, org_url: str, token: str, dry_run: bool = True) -> None:
        self.org_url = org_url.rstrip("/")
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"SSWS {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self.created: List[str] = []

    def _request(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        url = f"{self.org_url}{path}"
        if self.dry_run:
            print(f"  [dry-run] {method} {path}")
            return None

        response = self.session.request(method, url, json=payload, timeout=30)

        if response.status_code == 429:
            reset = response.headers.get("X-Rate-Limit-Reset")
            wait = max(1, int(float(reset)) - int(time.time()) + 1) if reset else 10
            print(f"  rate limited, sleeping {wait}s")
            time.sleep(min(wait, 120))
            response = self.session.request(method, url, json=payload, timeout=30)

        if not response.ok:
            print(f"  ! {method} {path} -> {response.status_code}: {response.text[:200]}")
            return None

        return response.json() if response.text else {}

    # -------------------------------------------------------------- operations

    def create_user(
        self,
        first: str,
        last: str,
        login: str,
        display: Optional[str] = None,
        activate: bool = True,
    ) -> Optional[str]:
        payload = {
            "profile": {
                "firstName": first,
                "lastName": last,
                "email": login,
                "login": login,
            },
            "credentials": {
                "password": {"value": _throwaway_password(login)}
            },
        }
        if display:
            payload["profile"]["displayName"] = display

        result = self._request(
            "POST", f"/api/v1/users?activate={str(activate).lower()}", payload
        )
        if result:
            self.created.append(f"user {login}")
            return result.get("id")
        return None

    def deactivate_user(self, user_id: str, login: str) -> None:
        print(f"  deactivating {login} (creates the orphaned-token scenario)")
        self._request("POST", f"/api/v1/users/{user_id}/lifecycle/deactivate")

    def assign_super_admin(self, user_id: str, login: str) -> None:
        print(f"  assigning SUPER_ADMIN to {login}  <- the headline finding")
        self._request("POST", f"/api/v1/users/{user_id}/roles", {"type": "SUPER_ADMIN"})

    def assign_org_admin(self, user_id: str, login: str) -> None:
        print(f"  assigning ORG_ADMIN to {login}")
        self._request("POST", f"/api/v1/users/{user_id}/roles", {"type": "ORG_ADMIN"})

    def create_service_app(self, label: str, scopes: List[str]) -> Optional[str]:
        payload = {
            "name": "oidc_client",
            "label": label,
            "signOnMode": "OPENID_CONNECT",
            "credentials": {
                "oauthClient": {"token_endpoint_auth_method": "client_secret_post"}
            },
            "settings": {
                "oauthClient": {
                    "application_type": "service",
                    "grant_types": ["client_credentials"],
                    "response_types": ["token"],
                }
            },
        }
        result = self._request("POST", "/api/v1/apps", payload)
        if not result:
            return None

        app_id = result.get("id")
        self.created.append(f"app {label}")
        print(f"  created service app '{label}' ({app_id})")

        for scope in scopes:
            print(f"    granting scope {scope}")
            self._request(
                "POST",
                f"/api/v1/apps/{app_id}/grants",
                {"scopeId": scope, "issuer": self.org_url},
            )
        return app_id

    def create_event_hook(self) -> None:
        print("  creating event hook with a plaintext HTTP destination")
        result = self._request("POST", "/api/v1/eventHooks", EVENT_HOOK)
        if result:
            self.created.append("event hook legacy-audit-forwarder")

    # ------------------------------------------------------------------ driver

    def run(self) -> None:
        print("\n1. Creating human users")
        for first, last in HUMANS:
            login = f"{first.lower()}.{last.lower()}@example.com"
            self.create_user(first, last, login)

        print("\n2. Creating the user who will later depart")
        first, last = DEPARTING_USER
        departing_login = f"{first.lower()}.{last.lower()}@example.com"
        departing_id = self.create_user(first, last, departing_login)

        print("\n3. Creating service accounts shaped as users")
        service_ids: Dict[str, Optional[str]] = {}
        for first, last, login, display in SERVICE_ACCOUNTS:
            service_ids[login] = self.create_user(first, last, login, display)

        print("\n4. Granting admin roles to service accounts")
        jira_id = service_ids.get("svc-jira@example.com")
        if jira_id:
            self.assign_super_admin(jira_id, "svc-jira@example.com")
        automation_id = service_ids.get("automation@example.com")
        if automation_id:
            self.assign_org_admin(automation_id, "automation@example.com")

        print("\n5. Creating OAuth service integrations")
        self.create_service_app(
            "Internal Provisioning Service",
            ["okta.users.manage", "okta.groups.manage", "okta.apps.read"],
        )
        self.create_service_app(
            "Security Reporting Exporter",
            ["okta.logs.read", "okta.users.read"],
        )

        print("\n6. Creating an event hook")
        self.create_event_hook()

        self._print_manual_steps(departing_login, departing_id)

    def _print_manual_steps(
        self, departing_login: str, departing_id: Optional[str]
    ) -> None:
        print("\n" + "=" * 72)
        print("MANUAL STEPS — the API cannot do these")
        print("=" * 72)
        print(
            f"""
A. Create the orphaned API token (your flagship finding)

   Org API tokens cannot be created through the API — by design, and it's a
   good design. Do this in the console:

   1. Sign in as {departing_login} (or grant that account admin, then sign in).
   2. Security -> API -> Tokens -> Create Token.
      Name it: terraform-okta-provider
   3. Copy the token somewhere temporary. You need it to exist, not to use it.
   4. Come back as your own admin account and deactivate {departing_login}:
      Directory -> People -> {departing_login} -> More Actions -> Deactivate
      {"(user id: " + departing_id + ")" if departing_id else ""}

   The token now outlives its creator. That is the finding your report leads
   with, and it is exactly what happens in a real company at offboarding.

B. Create two more org API tokens as your own admin user

   - nightly-user-sync        (use it once a week so it never expires)
   - adhoc-reporting-script   (leave it idle so it approaches expiry)

C. Enable SCIM provisioning on two apps

   Applications -> Browse App Catalog -> add Slack and GitHub (SAML).
   For each: Provisioning -> Configure API Integration -> enable.
   Then, on GitHub only, leave "Deactivate Users" DISABLED while enabling
   "Create Users". That produces the create-without-deactivate finding, which
   is the most common real provisioning misconfiguration there is.

D. Do NOT enrol MFA for the service accounts

   Leaving them without factors is the point. Enrol a factor on
   svc-backup@example.com only — it is the control case that proves your tool
   can tell a well-run service account from a badly-run one.

Then run the audit against the tenant:

   python -m src.audit --format all
"""
        )
        if self.created:
            print(f"Created {len(self.created)} objects.")


def _throwaway_password(login: str) -> str:
    """Deterministic throwaway password for a disposable dev tenant.

    Not a secret and not pretending to be one — these accounts exist in a
    developer org that should contain nothing real. Never reuse this pattern
    anywhere that matters.
    """
    import hashlib

    digest = hashlib.sha256(f"seed::{login}".encode()).hexdigest()[:16]
    return f"Seed!{digest}Aa1"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Seed a THROWAWAY Okta Developer Edition tenant with a messy "
            "non-human identity estate. This script performs write operations."
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--dry-run", action="store_true", help="print operations without executing"
    )
    group.add_argument(
        "--confirm", action="store_true", help="actually create objects in the tenant"
    )
    parser.add_argument(
        "--i-know-what-im-doing",
        action="store_true",
        help="permit running against an org URL that is not a dev-* org",
    )
    args = parser.parse_args()

    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    org_url = os.environ.get("OKTA_ORG_URL", "").strip()
    token = os.environ.get("OKTA_API_TOKEN", "").strip()

    if not org_url or not token:
        print(
            "Missing OKTA_ORG_URL / OKTA_API_TOKEN. Copy .env.example to .env "
            "and fill them in.",
            file=sys.stderr,
        )
        return 1

    is_dev_org = "dev-" in org_url or "oktapreview.com" in org_url
    if not is_dev_org and not args.i_know_what_im_doing:
        print(
            f"\nRefusing to seed {org_url}.\n"
            "  This does not look like an Okta Developer Edition org, and this "
            "script creates users, grants Super Admin, and registers hooks.\n"
            "  If you are certain, re-run with --i-know-what-im-doing.\n",
            file=sys.stderr,
        )
        return 1

    if args.confirm:
        print(f"\nAbout to CREATE OBJECTS in: {org_url}")
        print("This includes granting Super Administrator to a service account.")
        answer = input("Type the org URL to confirm: ").strip()
        if answer != org_url:
            print("Mismatch — aborting.", file=sys.stderr)
            return 1

    mode = "DRY RUN" if args.dry_run else "LIVE"
    print(f"\nSeeding {org_url}  [{mode}]")

    Seeder(org_url, token, dry_run=args.dry_run).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
