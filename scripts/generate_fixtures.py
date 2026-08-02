#!/usr/bin/env python3
"""Generate the demo fixture set: a fake 40-person startup that grew too fast.

Run this to regenerate src/fixtures/*.json. The output is committed, so `--demo`
works on a fresh clone with no setup. Regenerating is only necessary if you want
to change the scenario.

    python scripts/generate_fixtures.py

Every domain here is example.com. Every ID is obviously fake. Nothing in this
file touches a real Okta tenant — it writes JSON to disk and nothing else.

The scenario is deliberately designed so the tool has real things to find,
including exactly one finding that should come out CRITICAL, and one service
account that is correctly configured so the tool can demonstrate it does not
simply flag everything.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "src" / "fixtures"

# A fixed reference date makes the fixtures deterministic. "Days since last use"
# is computed relative to NOW at audit time, so the demo tenant is generated
# relative to a fixed anchor and the report notes it as simulated data.
NOW = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

random.seed(1337)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ago(**kwargs) -> str:
    return iso(NOW - timedelta(**kwargs))


HUMANS = [
    ("Amara", "Okonkwo", "ACTIVE"),
    ("Ben", "Sorensen", "ACTIVE"),
    ("Chen", "Wei", "ACTIVE"),
    ("Dara", "Fitzgerald", "ACTIVE"),
    ("Elena", "Vasquez", "ACTIVE"),
    ("Femi", "Adeyemi", "ACTIVE"),
    ("Grace", "Lindqvist", "ACTIVE"),
    ("Hassan", "Karimi", "ACTIVE"),
    ("Ingrid", "Bauer", "ACTIVE"),
    ("Jonas", "Meyer", "ACTIVE"),
    ("Kavita", "Rao", "ACTIVE"),
    ("Liam", "O'Donnell", "ACTIVE"),
    ("Mei", "Tanaka", "ACTIVE"),
    ("Nadia", "Haddad", "ACTIVE"),
    ("Oscar", "Delgado", "ACTIVE"),
    ("Priya", "Nair", "ACTIVE"),
    ("Quentin", "Boucher", "ACTIVE"),
    ("Rosa", "Marchetti", "ACTIVE"),
    ("Samir", "Patel", "ACTIVE"),
    ("Tessa", "Nguyen", "ACTIVE"),
    ("Ulrich", "Schmitt", "ACTIVE"),
    ("Vera", "Kowalski", "ACTIVE"),
    ("Wes", "Brennan", "DEPROVISIONED"),  # left the company — created a token
    ("Xiomara", "Reyes", "ACTIVE"),
    ("Yusuf", "Demir", "ACTIVE"),
]


def build_users() -> list:
    users = []

    for index, (first, last, status) in enumerate(HUMANS):
        login = f"{first.lower()}.{last.lower().replace(chr(39), '')}@example.com"
        users.append(
            {
                "id": f"00uHUMAN{index:04d}EXAMPLE",
                "status": status,
                "created": ago(days=random.randint(200, 900)),
                "lastLogin": None if status == "DEPROVISIONED" else ago(days=random.randint(0, 9)),
                "lastUpdated": ago(days=random.randint(1, 120)),
                "statusChanged": ago(days=41) if status == "DEPROVISIONED" else ago(days=200),
                "profile": {
                    "firstName": first,
                    "lastName": last,
                    "email": login,
                    "login": login,
                    "displayName": f"{first} {last}",
                },
                "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
            }
        )

    # ---- Non-human identities wearing user costumes -------------------------

    # 1. Jira automation. No MFA, no interactive login, and — the headline —
    #    holds Super Admin because someone granted it "just to unblock a sync".
    users.append(
        {
            "id": "00uSVCJIRA0000EXAMPLE",
            "status": "ACTIVE",
            "created": ago(days=612),
            "lastLogin": None,
            "lastUpdated": ago(days=400),
            "profile": {
                "firstName": "svc",
                "lastName": "jira",
                "email": "svc-jira@example.com",
                "login": "svc-jira@example.com",
                "displayName": "Jira Integration Service Account",
            },
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        }
    )

    # 2. Generic automation account. No MFA, no login, org-wide app assignments.
    users.append(
        {
            "id": "00uAUTOMATION0EXAMPLE",
            "status": "ACTIVE",
            "created": ago(days=488),
            "lastLogin": None,
            "lastUpdated": ago(days=310),
            "profile": {
                "firstName": "Automation",
                "lastName": "Account",
                "email": "automation@example.com",
                "login": "automation@example.com",
                "displayName": "Automation",
            },
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        }
    )

    # 3. HubSpot integration account, held by a contractor who has left.
    users.append(
        {
            "id": "00uINTHUBSPOT0EXAMPLE",
            "status": "ACTIVE",
            "created": ago(days=395),
            "lastLogin": ago(days=380),  # one interactive login, at setup
            "lastUpdated": ago(days=380),
            "profile": {
                "firstName": "integration",
                "lastName": "hubspot",
                "email": "integration-hubspot@example.com",
                "login": "integration-hubspot@example.com",
                "displayName": "HubSpot Integration",
            },
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        }
    )

    # 4. Build bot. No MFA, no login, no admin role — medium risk, not critical.
    users.append(
        {
            "id": "00uBOTBUILD000EXAMPLE",
            "status": "ACTIVE",
            "created": ago(days=250),
            "lastLogin": None,
            "lastUpdated": ago(days=250),
            "profile": {
                "firstName": "build",
                "lastName": "bot",
                "email": "bot-builds@example.com",
                "login": "bot-builds@example.com",
                "displayName": "CI Build Bot",
            },
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        }
    )

    # 5. THE CONTROL CASE. Named like a service account, but done properly:
    #    MFA enrolled, no admin role, scoped to one app. The tool must NOT
    #    flag this as high risk, or the whole report loses credibility.
    users.append(
        {
            "id": "00uSVCBACKUP00EXAMPLE",
            "status": "ACTIVE",
            "created": ago(days=180),
            "lastLogin": None,
            "lastUpdated": ago(days=30),
            "profile": {
                "firstName": "svc",
                "lastName": "backup",
                "email": "svc-backup@example.com",
                "login": "svc-backup@example.com",
                "displayName": "Backup Service Account (managed)",
            },
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        }
    )

    return users


def build_api_tokens() -> list:
    return [
        # THE FLAGSHIP FINDING. Created by Wes Brennan, who is DEPROVISIONED.
        # Still in daily use by a nightly job, so it will never expire.
        {
            "id": "00Torphaned000000EXAMPLE",
            "name": "terraform-okta-provider",
            "userId": "00uHUMAN0022EXAMPLE",
            "username": "wes.brennan@example.com",
            "created": ago(days=430),
            "lastUpdated": ago(days=430),
            "expiresAt": iso(NOW + timedelta(days=29)),
            "tokenWindow": "PT720H",
        },
        # Active, used constantly, so the 30-day clock keeps resetting. This is
        # the "silently immortal token" case.
        {
            "id": "00Tnightlyjob0000EXAMPLE",
            "name": "nightly-user-sync",
            "userId": "00uHUMAN0000EXAMPLE",
            "username": "amara.okonkwo@example.com",
            "created": ago(days=740),
            "lastUpdated": ago(hours=9),
            "expiresAt": iso(NOW + timedelta(days=30)),
            "tokenWindow": "PT720H",
        },
        # Idle for 26 days — about to silently die and break whatever uses it.
        {
            "id": "00Tstaletoken0000EXAMPLE",
            "name": "adhoc-reporting-script",
            "userId": "00uHUMAN0010EXAMPLE",
            "username": "kavita.rao@example.com",
            "created": ago(days=190),
            "lastUpdated": ago(days=26),
            "expiresAt": iso(NOW + timedelta(days=4)),
            "tokenWindow": "PT720H",
        },
        # Never used since creation, 8 months ago. Nobody knows what it was for.
        {
            "id": "00Tneverused00000EXAMPLE",
            "name": "token-2",
            "userId": "00uHUMAN0018EXAMPLE",
            "username": "samir.patel@example.com",
            "created": ago(days=243),
            "lastUpdated": ago(days=243),
            "expiresAt": iso(NOW - timedelta(days=213)),
            "tokenWindow": "PT720H",
        },
    ]


def build_apps() -> list:
    return [
        {
            "id": "0oaAPISVCPROV0EXAMPLE",
            "name": "oidc_client",
            "label": "Internal Provisioning Service",
            "status": "ACTIVE",
            "created": ago(days=300),
            "lastUpdated": ago(days=90),
            "signOnMode": "OPENID_CONNECT",
            "credentials": {"oauthClient": {"client_id": "0oaAPISVCPROV0EXAMPLE"}},
            "settings": {
                "oauthClient": {
                    "grant_types": ["client_credentials"],
                    "application_type": "service",
                    "response_types": ["token"],
                }
            },
        },
        {
            "id": "0oaAPISVCRPT00EXAMPLE",
            "name": "oidc_client",
            "label": "Security Reporting Exporter",
            "status": "ACTIVE",
            "created": ago(days=120),
            "lastUpdated": ago(days=60),
            "signOnMode": "OPENID_CONNECT",
            "credentials": {"oauthClient": {"client_id": "0oaAPISVCRPT00EXAMPLE"}},
            "settings": {
                "oauthClient": {
                    "grant_types": ["client_credentials"],
                    "application_type": "service",
                    "response_types": ["token"],
                }
            },
        },
        {
            "id": "0oaSCIMSLACK00EXAMPLE",
            "name": "slack",
            "label": "Slack",
            "status": "ACTIVE",
            "created": ago(days=700),
            "lastUpdated": ago(days=210),
            "signOnMode": "SAML_2_0",
            "settings": {"app": {}},
        },
        {
            "id": "0oaSCIMGITHUB0EXAMPLE",
            "name": "github",
            "label": "GitHub Enterprise Cloud",
            "status": "ACTIVE",
            "created": ago(days=640),
            "lastUpdated": ago(days=430),
            "signOnMode": "SAML_2_0",
            "settings": {"app": {}},
        },
        {
            "id": "0oaSCIMZOOM000EXAMPLE",
            "name": "zoom",
            "label": "Zoom (legacy - migrated off 2025)",
            "status": "INACTIVE",
            "created": ago(days=800),
            "lastUpdated": ago(days=520),
            "signOnMode": "SAML_2_0",
            "settings": {"app": {}},
        },
        {
            "id": "0oaSAMLNOTION0EXAMPLE",
            "name": "notion",
            "label": "Notion",
            "status": "ACTIVE",
            "created": ago(days=410),
            "lastUpdated": ago(days=200),
            "signOnMode": "SAML_2_0",
            "settings": {"app": {}},
        },
    ]


def build_grants() -> dict:
    """OAuth scope grants, keyed by app id.

    The Provisioning Service holds okta.users.manage and okta.groups.manage.
    Its actual traffic (see logs) is all reads — the classic over-scope.
    """
    return {
        "0oaAPISVCPROV0EXAMPLE": [
            {
                "id": "oag001EXAMPLE",
                "scopeId": "okta.users.manage",
                "issuer": "https://dev-00000000.okta.com",
                "status": "ACTIVE",
                "created": ago(days=300),
            },
            {
                "id": "oag002EXAMPLE",
                "scopeId": "okta.groups.manage",
                "issuer": "https://dev-00000000.okta.com",
                "status": "ACTIVE",
                "created": ago(days=300),
            },
            {
                "id": "oag003EXAMPLE",
                "scopeId": "okta.apps.read",
                "issuer": "https://dev-00000000.okta.com",
                "status": "ACTIVE",
                "created": ago(days=300),
            },
        ],
        # Correctly scoped: read-only exporter with read-only scopes.
        "0oaAPISVCRPT00EXAMPLE": [
            {
                "id": "oag004EXAMPLE",
                "scopeId": "okta.logs.read",
                "issuer": "https://dev-00000000.okta.com",
                "status": "ACTIVE",
                "created": ago(days=120),
            },
            {
                "id": "oag005EXAMPLE",
                "scopeId": "okta.users.read",
                "issuer": "https://dev-00000000.okta.com",
                "status": "ACTIVE",
                "created": ago(days=120),
            },
        ],
    }


def build_app_features() -> dict:
    """SCIM provisioning features, keyed by app id.

    Okta returns 404 for this endpoint on apps that don't support provisioning,
    which the client handles via get_optional.
    """
    return {
        "0oaSCIMSLACK00EXAMPLE": [
            {
                "name": "USER_PROVISIONING",
                "status": "ENABLED",
                "description": "User provisioning",
                "capabilities": {
                    "create": {"lifecycleCreate": {"status": "ENABLED"}},
                    "update": {
                        "profile": {"status": "ENABLED"},
                        "lifecycleDeactivate": {"status": "ENABLED"},
                        "password": {"status": "DISABLED"},
                    },
                },
            }
        ],
        "0oaSCIMGITHUB0EXAMPLE": [
            {
                "name": "USER_PROVISIONING",
                "status": "ENABLED",
                "description": "User provisioning",
                "capabilities": {
                    "create": {"lifecycleCreate": {"status": "ENABLED"}},
                    "update": {
                        "profile": {"status": "ENABLED"},
                        # Deactivation is OFF: users are created downstream but
                        # never removed. This is a real, common, quiet failure.
                        "lifecycleDeactivate": {"status": "DISABLED"},
                        "password": {"status": "DISABLED"},
                    },
                },
            }
        ],
        "0oaSCIMZOOM000EXAMPLE": [
            {
                "name": "USER_PROVISIONING",
                "status": "ENABLED",
                "description": "User provisioning",
                "capabilities": {
                    "create": {"lifecycleCreate": {"status": "ENABLED"}},
                    "update": {
                        "profile": {"status": "ENABLED"},
                        "lifecycleDeactivate": {"status": "ENABLED"},
                        "password": {"status": "DISABLED"},
                    },
                },
            }
        ],
    }


def build_event_hooks() -> list:
    return [
        {
            "id": "who001EXAMPLE",
            "name": "user-lifecycle-to-internal-tools",
            "status": "ACTIVE",
            "verificationStatus": "VERIFIED",
            "created": ago(days=260),
            "lastUpdated": ago(days=260),
            "events": {
                "type": "EVENT_TYPE",
                "items": ["user.lifecycle.create", "user.lifecycle.deactivate"],
            },
            "channel": {
                "type": "HTTP",
                "version": "1.0.0",
                "config": {
                    "uri": "https://hooks.internal-tools.example.com/okta/lifecycle",
                    "headers": [],
                    "authScheme": {"type": "HEADER", "key": "Authorization"},
                },
            },
        },
        {
            "id": "who002EXAMPLE",
            "name": "legacy-audit-forwarder",
            "status": "ACTIVE",
            "verificationStatus": "UNVERIFIED",
            "created": ago(days=520),
            "lastUpdated": ago(days=520),
            "events": {"type": "EVENT_TYPE", "items": ["user.session.start"]},
            "channel": {
                "type": "HTTP",
                "version": "1.0.0",
                "config": {
                    # Plaintext HTTP, third-party domain, no auth header.
                    "uri": "http://audit-collector.thirdparty-vendor.example.net/ingest",
                    "headers": [],
                },
            },
        },
    ]


def build_inline_hooks() -> list:
    return [
        {
            "id": "cal001EXAMPLE",
            "name": "token-claim-enrichment",
            "type": "com.okta.oauth2.tokens.transform",
            "status": "ACTIVE",
            "created": ago(days=170),
            "lastUpdated": ago(days=170),
            "channel": {
                "type": "HTTP",
                "version": "1.0.0",
                "config": {
                    "uri": "https://claims.internal-tools.example.com/enrich",
                    "authScheme": {"type": "HEADER", "key": "Authorization"},
                },
            },
        }
    ]


def build_roles() -> dict:
    """Admin role assignments, keyed by user id."""
    return {
        # THE CRITICAL FINDING: a service account with Super Admin.
        "00uSVCJIRA0000EXAMPLE": [
            {
                "id": "ra001EXAMPLE",
                "label": "Super Administrator",
                "type": "SUPER_ADMIN",
                "status": "ACTIVE",
                "created": ago(days=610),
                "assignmentType": "USER",
            }
        ],
        # High: broad user-management admin on an unattended account.
        "00uAUTOMATION0EXAMPLE": [
            {
                "id": "ra002EXAMPLE",
                "label": "Organization Administrator",
                "type": "ORG_ADMIN",
                "status": "ACTIVE",
                "created": ago(days=480),
                "assignmentType": "USER",
            }
        ],
        # A legitimate human admin — should not be flagged as an NHI.
        "00uHUMAN0000EXAMPLE": [
            {
                "id": "ra003EXAMPLE",
                "label": "Super Administrator",
                "type": "SUPER_ADMIN",
                "status": "ACTIVE",
                "created": ago(days=880),
                "assignmentType": "USER",
            }
        ],
        # Read-only admin held by a human. Fine.
        "00uHUMAN0003EXAMPLE": [
            {
                "id": "ra004EXAMPLE",
                "label": "Read Only Administrator",
                "type": "READ_ONLY_ADMIN",
                "status": "ACTIVE",
                "created": ago(days=300),
                "assignmentType": "USER",
            }
        ],
    }


def build_factors() -> dict:
    """Enrolled MFA factors, keyed by user id.

    Every human has at least one. The service accounts have none — except the
    control case, svc-backup, which is enrolled and therefore should score lower.
    """
    factors = {}
    for index, (_first, _last, status) in enumerate(HUMANS):
        if status == "DEPROVISIONED":
            factors[f"00uHUMAN{index:04d}EXAMPLE"] = []
            continue
        factors[f"00uHUMAN{index:04d}EXAMPLE"] = [
            {
                "id": f"ostf{index:04d}EXAMPLE",
                "factorType": "push",
                "provider": "OKTA",
                "status": "ACTIVE",
            }
        ]

    factors["00uSVCJIRA0000EXAMPLE"] = []
    factors["00uAUTOMATION0EXAMPLE"] = []
    factors["00uINTHUBSPOT0EXAMPLE"] = []
    factors["00uBOTBUILD000EXAMPLE"] = []
    # The control case is properly enrolled.
    factors["00uSVCBACKUP00EXAMPLE"] = [
        {
            "id": "ostfBACKUPEXAMPLE",
            "factorType": "token:software:totp",
            "provider": "OKTA",
            "status": "ACTIVE",
        }
    ]
    return factors


def build_logs() -> list:
    """A slice of the System Log.

    Two things are read out of this:
      - API activity per actor (proves an account is in active machine use)
      - interactive sign-ins (proves a human is behind it)
    """
    events = []

    # Machine traffic from the service accounts: API calls, no interactive auth.
    machine_actors = [
        ("00uSVCJIRA0000EXAMPLE", "svc-jira@example.com", 480),
        ("00uAUTOMATION0EXAMPLE", "automation@example.com", 260),
        ("00uINTHUBSPOT0EXAMPLE", "integration-hubspot@example.com", 95),
        ("00uBOTBUILD000EXAMPLE", "bot-builds@example.com", 140),
        ("00uSVCBACKUP00EXAMPLE", "svc-backup@example.com", 31),
    ]
    for actor_id, actor_name, count in machine_actors:
        for n in range(min(count, 12)):  # keep the fixture file readable
            events.append(
                {
                    "uuid": f"evt-{actor_id[-12:]}-{n}",
                    "published": ago(hours=n * 2 + 1),
                    "eventType": "system.api_token.access",
                    "displayMessage": "API token access",
                    "outcome": {"result": "SUCCESS"},
                    "actor": {
                        "id": actor_id,
                        "type": "User",
                        "alternateId": actor_name,
                        "displayName": actor_name,
                    },
                    "client": {"userAgent": {"rawUserAgent": "python-requests/2.31.0"}},
                    "_apiEventCount": count,
                }
            )

    # Interactive human sign-ins.
    for index, (first, last, status) in enumerate(HUMANS[:8]):
        if status == "DEPROVISIONED":
            continue
        login = f"{first.lower()}.{last.lower().replace(chr(39), '')}@example.com"
        events.append(
            {
                "uuid": f"evt-login-{index}",
                "published": ago(days=index % 5, hours=index),
                "eventType": "user.session.start",
                "displayMessage": "User login to Okta",
                "outcome": {"result": "SUCCESS"},
                "actor": {
                    "id": f"00uHUMAN{index:04d}EXAMPLE",
                    "type": "User",
                    "alternateId": login,
                    "displayName": f"{first} {last}",
                },
                "client": {
                    "userAgent": {
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
                    }
                },
            }
        )

    # The HubSpot integration account did sign in interactively — once, at setup,
    # over a year ago. Enough to reduce, but not eliminate, its NHI score.
    events.append(
        {
            "uuid": "evt-login-hubspot-setup",
            "published": ago(days=380),
            "eventType": "user.session.start",
            "displayMessage": "User login to Okta",
            "outcome": {"result": "SUCCESS"},
            "actor": {
                "id": "00uINTHUBSPOT0EXAMPLE",
                "type": "User",
                "alternateId": "integration-hubspot@example.com",
                "displayName": "HubSpot Integration",
            },
            "client": {
                "userAgent": {"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            },
        }
    )

    return events


def build_org() -> dict:
    return {
        "id": "00oEXAMPLEORG000000",
        "subdomain": "dev-00000000",
        "companyName": "Northwind Robotics (DEMO FIXTURE — not a real tenant)",
        "status": "ACTIVE",
        "created": ago(days=900),
        "website": "https://example.com",
    }


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    payloads = {
        "org.json": build_org(),
        "users.json": build_users(),
        "api_tokens.json": build_api_tokens(),
        "apps.json": build_apps(),
        "grants.json": build_grants(),
        "app_features.json": build_app_features(),
        "event_hooks.json": build_event_hooks(),
        "inline_hooks.json": build_inline_hooks(),
        "roles.json": build_roles(),
        "factors.json": build_factors(),
        "logs.json": build_logs(),
    }

    for filename, payload in payloads.items():
        path = FIXTURE_DIR / filename
        path.write_text(json.dumps(payload, indent=2) + "\n")
        count = len(payload) if isinstance(payload, (list, dict)) else 1
        print(f"wrote {path.relative_to(FIXTURE_DIR.parent.parent)} ({count} entries)")


if __name__ == "__main__":
    main()
