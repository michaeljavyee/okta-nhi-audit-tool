"""Check 4 — API Service Integrations (OAuth apps using client_credentials).

These are the *right* way to build a machine integration in Okta — scoped,
revocable, no user context. Which is exactly why the finding here is not "you
used OAuth" but "you scoped it badly".

The audit position is strong because it argues from the vendor's own guidance:
Okta's documentation tells you to grant the narrowest scope that works. An app
holding `okta.users.manage` whose observed traffic is entirely reads is
over-scoped by Okta's own standard, not by ours.

Scope naming in Okta is conveniently regular: `okta.<resource>.<read|manage>`.
`manage` implies read, so a `.manage` grant is always at least as broad as the
`.read` equivalent.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..scoring import (
    HIGH,
    LOW,
    MEDIUM,
    NHI_OAUTH_SERVICE_APP,
    Finding,
    InventoryItem,
    format_date,
)
from .base import TenantContext

CHECK_NAME = "oauth_service_apps"

CLIENT_CREDENTIALS = "client_credentials"

# Scopes whose compromise is a tenant-level event, not a data-exposure event.
TENANT_CONTROL_SCOPES = {
    "okta.users.manage",
    "okta.groups.manage",
    "okta.apps.manage",
    "okta.roles.manage",
    "okta.policies.manage",
    "okta.authorizationServers.manage",
    "okta.factors.manage",
    "okta.sessions.manage",
    "okta.idps.manage",
    "okta.trustedOrigins.manage",
}

SCOPE_MEANING = {
    "okta.users.manage": (
        "create, modify, deactivate and reset credentials for any user in the org"
    ),
    "okta.groups.manage": (
        "create and modify groups and their membership — and therefore change who "
        "has access to what"
    ),
    "okta.apps.manage": "create and modify applications and their assignments",
    "okta.roles.manage": "grant and revoke administrative roles",
    "okta.policies.manage": "modify authentication and MFA policy",
    "okta.authorizationServers.manage": "modify the OAuth machinery itself",
    "okta.factors.manage": "enrol and reset MFA factors for users",
    "okta.sessions.manage": "terminate or impersonate sessions",
}


def run(context: TenantContext) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []

    service_apps = [app for app in context.apps if _is_service_app(app)]

    if not service_apps:
        return findings, inventory

    for app in service_apps:
        app_id = app.get("id", "")
        label = app.get("label") or app.get("name") or app_id
        status = app.get("status", "UNKNOWN")

        grants = list(
            context.client.paginate_optional(f"/api/v1/apps/{app_id}/grants")
        )
        scopes = sorted(
            {grant.get("scopeId", "") for grant in grants if grant.get("scopeId")}
        )

        manage_scopes = [s for s in scopes if s.endswith(".manage")]
        control_scopes = [s for s in scopes if s in TENANT_CONTROL_SCOPES]

        inventory.append(
            InventoryItem(
                nhi_type=NHI_OAUTH_SERVICE_APP,
                identity=label,
                identity_id=app_id,
                owner="unassigned — Okta records no owner on an app object",
                created=format_date(app.get("created")),
                last_used="",
                privilege=", ".join(scopes) if scopes else "no scopes granted",
                notes=(
                    f"client_credentials grant, status {status}"
                    + (f", {len(manage_scopes)} write scope(s)" if manage_scopes else "")
                ),
            )
        )

        if not scopes:
            findings.append(
                Finding(
                    nhi_type=NHI_OAUTH_SERVICE_APP,
                    identity=label,
                    identity_id=app_id,
                    check=CHECK_NAME,
                    severity=LOW,
                    finding=(
                        "API service integration exists with no scopes granted."
                    ),
                    evidence=(
                        f"'{label}' ({app_id}) uses the client_credentials grant "
                        "but has no Okta API scopes assigned."
                    ),
                    risk=(
                        "The integration cannot currently do anything, so there "
                        "is no direct exposure. It matters as inventory: an "
                        "unused client_credentials app is a credential that "
                        "exists, was issued to someone, and is one scope-grant "
                        "away from being live. Nobody is reviewing it because it "
                        "appears to do nothing."
                    ),
                    remediation=(
                        "Deactivate and delete it if the integration was never "
                        "completed. Admin console -> Applications -> select the "
                        "app -> Deactivate."
                    ),
                    metadata={"scopes": scopes},
                )
            )
            continue

        if control_scopes:
            findings.append(
                Finding(
                    nhi_type=NHI_OAUTH_SERVICE_APP,
                    identity=label,
                    identity_id=app_id,
                    check=CHECK_NAME,
                    severity=HIGH,
                    finding=(
                        "API service integration holds tenant-control scopes that "
                        "are broader than a read-only workload requires."
                    ),
                    evidence=(
                        f"'{label}' ({app_id}) is granted: {', '.join(scopes)}. "
                        f"Of these, {', '.join(control_scopes)} permit write "
                        "operations against core identity objects. "
                        "Read-only equivalents exist for each "
                        f"({', '.join(_read_equivalent(s) for s in control_scopes)})."
                    ),
                    risk=_scope_risk(label, control_scopes),
                    remediation=(
                        "Establish what write operations this integration "
                        "actually performs — filter the System Log on this "
                        f"client_id ({app_id}) and look for anything beyond "
                        "reads. If the traffic is read-only, replace each "
                        ".manage scope with its .read equivalent: Admin console "
                        "-> Applications -> "
                        f"{label} -> Okta API Scopes -> revoke the .manage grant "
                        "and grant .read. If some writes are genuinely needed, "
                        "grant only the specific scopes covering them and record "
                        "why in a comment or ticket, so the next reviewer does "
                        "not have to rediscover it. Okta's guidance on scoping "
                        "API service integrations is to grant the narrowest "
                        "scope that permits the workload to function."
                    ),
                    metadata={"scopes": scopes, "control_scopes": control_scopes},
                )
            )
        elif manage_scopes:
            findings.append(
                Finding(
                    nhi_type=NHI_OAUTH_SERVICE_APP,
                    identity=label,
                    identity_id=app_id,
                    check=CHECK_NAME,
                    severity=MEDIUM,
                    finding=(
                        "API service integration holds write scopes that may "
                        "exceed its requirements."
                    ),
                    evidence=(
                        f"'{label}' ({app_id}) is granted: {', '.join(scopes)}, "
                        f"including {', '.join(manage_scopes)}."
                    ),
                    risk=(
                        "Write scopes on a machine integration mean that a leaked "
                        "client secret does not just expose data, it allows "
                        "modification. The practical difference during an "
                        "incident is between 'an attacker read some records' and "
                        "'we cannot trust the current state of the configuration'."
                    ),
                    remediation=(
                        "Confirm the integration writes at all. If it does not, "
                        "downgrade each .manage scope to .read in the app's Okta "
                        "API Scopes tab."
                    ),
                    metadata={"scopes": scopes, "manage_scopes": manage_scopes},
                )
            )
        else:
            findings.append(
                Finding(
                    nhi_type=NHI_OAUTH_SERVICE_APP,
                    identity=label,
                    identity_id=app_id,
                    check=CHECK_NAME,
                    severity=LOW,
                    finding=(
                        "API service integration is scoped read-only. No "
                        "over-privilege identified."
                    ),
                    evidence=(
                        f"'{label}' ({app_id}) holds only read scopes: "
                        f"{', '.join(scopes)}."
                    ),
                    risk=(
                        "Low. This integration is configured the way the others "
                        "should be: OAuth client_credentials rather than a static "
                        "API token, and read-only scopes. The residual risk is "
                        "the client secret itself, which is a bearer credential "
                        "and should be rotated on a schedule and stored in a "
                        "secrets manager rather than a config file."
                    ),
                    remediation=(
                        "No scope change required. Confirm the client secret is "
                        "held in a secrets manager, record an owning team, and "
                        "include it in the quarterly credential rotation cycle. "
                        "Use this integration as the reference pattern when "
                        "migrating the static API tokens identified elsewhere in "
                        "this report."
                    ),
                    metadata={"scopes": scopes},
                )
            )

    return findings, inventory


def _is_service_app(app: Dict[str, Any]) -> bool:
    """True if the app uses the client_credentials grant.

    That grant is the definition of machine-to-machine in OAuth: there is no
    user in the flow at all, only an app authenticating as itself. Any app using
    it is by definition a non-human identity.
    """
    oauth_client = ((app.get("settings") or {}).get("oauthClient")) or {}
    grant_types = oauth_client.get("grant_types") or []
    return CLIENT_CREDENTIALS in grant_types


def _read_equivalent(scope: str) -> str:
    return scope.replace(".manage", ".read") if scope.endswith(".manage") else scope


def _scope_risk(label: str, control_scopes: List[str]) -> str:
    meanings = [
        f"{scope} allows it to {SCOPE_MEANING.get(scope, 'modify core identity objects')}"
        for scope in control_scopes
    ]
    return (
        f"'{label}' authenticates with a client ID and secret and no human is "
        "involved in the flow, so its access is entirely determined by the scopes "
        "granted to it. Those scopes currently include write access to core "
        "identity objects: "
        + "; ".join(meanings)
        + ". If the client secret leaks — from a CI log, an environment variable "
        "dump, a compromised laptop, or a repository — an attacker obtains that "
        "same write access, and it looks like normal integration traffic in the "
        "log. The narrower point is governance: nobody can currently state what "
        "this integration writes, which means nobody can state what an attacker "
        "holding its secret could change. Okta's own guidance is to grant the "
        "least-privileged scope that lets the workload function, so this is "
        "measured against the vendor's stated standard rather than an "
        "external one."
    )
