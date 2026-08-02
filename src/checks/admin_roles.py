"""Check 3 — administrative roles held by non-human identities.

This is the headline check. Cross-referencing the suspected service accounts from
check 2 against Okta's role assignments produces the finding that leads a client
report: an unattended account, with no MFA, whose password lives in a CI variable,
holding Super Administrator.

The severity ladder is deliberate. Super Admin on an NHI is critical without
qualification — it is full tenant control held by a credential with no owner and
no second factor. Other admin roles are high, because the blast radius is smaller
but the underlying problem is identical.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from ..scoring import (
    CRITICAL,
    HIGH,
    MEDIUM,
    NHI_SERVICE_ACCOUNT,
    Finding,
    InventoryItem,
    ServiceAccountScore,
    format_date,
)
from .base import TenantContext

CHECK_NAME = "admin_roles"

# Full tenant control. Nothing else is in this tier.
SUPER_ADMIN_TYPES = {"SUPER_ADMIN"}

# Broad, destructive, or credential-adjacent roles.
HIGH_PRIVILEGE_TYPES = {
    "ORG_ADMIN",
    "APP_ADMIN",
    "USER_ADMIN",
    "GROUP_MEMBERSHIP_ADMIN",
    "MOBILE_ADMIN",
    "API_ACCESS_MANAGEMENT_ADMIN",
}

ROLE_BLAST_RADIUS = {
    "SUPER_ADMIN": (
        "complete administrative control of the tenant, including the ability to "
        "create further admins, disable MFA policies, modify authentication "
        "rules, and access every application"
    ),
    "ORG_ADMIN": (
        "the ability to create, modify and deactivate users and groups across "
        "the organisation, and to reset credentials"
    ),
    "APP_ADMIN": (
        "the ability to modify application assignments and sign-on policies, "
        "which means granting access to any connected SaaS application"
    ),
    "USER_ADMIN": (
        "the ability to manage users in its assigned groups, including "
        "credential resets"
    ),
    "API_ACCESS_MANAGEMENT_ADMIN": (
        "control over authorisation servers, scopes and OAuth policies — the "
        "machinery that governs every other machine identity in the tenant"
    ),
    "READ_ONLY_ADMIN": "read access to all administrative configuration",
    "HELP_DESK_ADMIN": "the ability to reset credentials for assigned users",
    "GROUP_MEMBERSHIP_ADMIN": "control of group membership, and therefore of access",
    "REPORT_ADMIN": "read access to reports and the System Log",
}


def run(
    context: TenantContext,
    suspected: List[ServiceAccountScore],
) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []

    suspected_by_id: Dict[str, ServiceAccountScore] = {
        score.user_id: score for score in suspected if score.is_suspected
    }

    for user_id, score in suspected_by_id.items():
        roles = context.roles_for(user_id)
        if not roles:
            continue

        login = context.user_login(user_id)
        has_mfa = context.has_mfa(user_id)

        for role in roles:
            role_type = role.get("type", "")
            label = role.get("label") or role_type or "unknown role"
            blast = ROLE_BLAST_RADIUS.get(
                role_type, "administrative access to part of the tenant"
            )

            inventory.append(
                InventoryItem(
                    nhi_type=NHI_SERVICE_ACCOUNT,
                    identity=f"{login} — {label}",
                    identity_id=user_id,
                    owner="unassigned",
                    created=format_date(role.get("created")),
                    last_used="",
                    privilege=label,
                    notes=f"admin role held by a suspected non-human identity",
                )
            )

            if role_type in SUPER_ADMIN_TYPES:
                severity = CRITICAL
            elif role_type in HIGH_PRIVILEGE_TYPES:
                severity = HIGH
            else:
                severity = MEDIUM

            findings.append(
                Finding(
                    nhi_type=NHI_SERVICE_ACCOUNT,
                    identity=login,
                    identity_id=user_id,
                    check=CHECK_NAME,
                    severity=severity,
                    finding=(
                        f"Suspected service account holds the {label} "
                        "administrative role."
                    ),
                    evidence=(
                        f"{login} was assessed as a non-human identity "
                        f"(heuristic score {score.score:.2f}: {score.explain()}) "
                        f"and holds {label}, assigned "
                        f"{format_date(role.get('created'))}. "
                        f"MFA enrolled: {'yes' if has_mfa else 'no'}."
                    ),
                    risk=_risk_language(login, label, blast, has_mfa, severity),
                    remediation=_remediation(login, label, severity),
                    metadata={
                        "role_type": role_type,
                        "role_label": label,
                        "score": score.score,
                        "has_mfa": has_mfa,
                    },
                )
            )

    return findings, inventory


def _risk_language(
    login: str, label: str, blast: str, has_mfa: bool, severity: str
) -> str:
    text = (
        f"{login} holds {label}, which grants {blast}. This account shows the "
        "behaviour of software rather than a person: it does not sign in "
        "interactively, and its credential is therefore stored somewhere — a CI "
        "secret, a configuration file, a script, a password manager entry shared "
        "across a team."
    )
    if not has_mfa:
        text += (
            " Because no MFA factor is enrolled, that stored credential is the "
            "only thing standing between an attacker and this level of access. "
            "There is no second factor to fail closed."
        )
    if severity == CRITICAL:
        text += (
            " In practical terms, anyone who obtains this credential owns the "
            "identity provider — and therefore owns every application behind it. "
            "They can create themselves a persistent admin account, weaken MFA "
            "policy, and read or grant access to any connected SaaS system. "
            "Identity provider compromise is the standard opening move in "
            "recent SaaS breaches precisely because it collapses every other "
            "control at once. There is also no accountable owner: if this "
            "credential were used maliciously tomorrow, the audit trail would "
            "name a service account, and nobody could say who was responsible "
            "for it."
        )
    else:
        text += (
            " The privilege is narrower than full tenant control, but the "
            "governance gap is the same — an unowned credential with standing "
            "administrative access that no access review will ever surface."
        )
    return text


def _remediation(login: str, label: str, severity: str) -> str:
    if severity == CRITICAL:
        return (
            f"Treat as urgent. 1) Determine what {login} actually does by "
            "filtering the System Log on this actor over the last 90 days. "
            "2) Identify the minimum role that covers those operations — in "
            "nearly all cases a scoped custom admin role, or no admin role at "
            "all, is sufficient. 3) Replace the Super Administrator assignment "
            f"with that scoped role: Admin console -> Security -> Administrators "
            "-> select the account -> edit assignments. 4) Migrate the workload "
            "to an API Service Integration with explicit scopes, so access is "
            "granted to a workload rather than inherited from a user object. "
            "5) Record a named owning team on the account. Do not simply delete "
            "the role before step 1 — you will break something and not know what."
        )
    return (
        f"Review whether {login} needs {label} at all. Replace it with a custom "
        "admin role scoped to the specific resources and operations the workload "
        "performs, assign a named owning team, and add the account to your "
        "quarterly access review. Where the workload is API-driven, migrate it "
        "to an API Service Integration with least-privilege scopes."
    )
