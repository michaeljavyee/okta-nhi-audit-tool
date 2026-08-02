"""Check 2 — service accounts hiding among regular users.

There is no `isServiceAccount` field in Okta. A service account is just a user
object that happens to be driven by a script. So this check scores every user
against four weak signals and reports the ones that cross a threshold.

Being explicit that this is probabilistic is a strength, not a hedge. A client
who is told "these 4 are definitely service accounts" will find the one that
isn't and stop trusting the report. A client who is told "these 4 scored above
0.5 on these specific signals, here is the breakdown, here is where the method
fails" can engage with it.

The scoring itself lives in src/scoring.py so the weights and threshold are
tunable in one place. See docs/false-positives.md.
"""

from __future__ import annotations

from typing import List, Tuple

from ..scoring import (
    HIGH,
    LOW,
    MEDIUM,
    NHI_SERVICE_ACCOUNT,
    Finding,
    InventoryItem,
    ServiceAccountScore,
    format_date,
    score_service_account,
)
from .base import TenantContext

CHECK_NAME = "service_accounts"

# Only worth spending per-user API calls (factors, roles) on users that already
# match on name or have no recent interactive login. Scoring all 5,000 users in
# a large tenant would mean 10,000 extra requests.
PRESCREEN_SIGNALS_REQUIRED = 1


def run(
    context: TenantContext,
    threshold: float = 0.5,
) -> Tuple[List[Finding], List[InventoryItem], List[ServiceAccountScore]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    scores: List[ServiceAccountScore] = []

    for user in context.users:
        user_id = user.get("id", "")
        if not user_id:
            continue

        # Deactivated users can't be active NHIs; their leftover credentials are
        # covered by the api_tokens and admin_roles checks instead.
        if user.get("status") in {"DEPROVISIONED", "STAGED"}:
            continue

        api_events = context.api_event_count(user_id)
        had_login = context.had_interactive_login(user_id)

        # Cheap prescreen before spending the per-user factor call.
        cheap = score_service_account(
            user, has_mfa=True, had_interactive_login=had_login, api_event_count=api_events
        )
        if cheap.score < threshold - 0.25:
            continue

        has_mfa = context.has_mfa(user_id)
        score = score_service_account(
            user,
            has_mfa=has_mfa,
            had_interactive_login=had_login,
            api_event_count=api_events,
        )
        scores.append(score)

        if score.score < threshold:
            continue

        profile = user.get("profile") or {}
        login = profile.get("login") or profile.get("email") or user_id
        roles = context.roles_for(user_id)
        role_labels = [r.get("label") or r.get("type", "") for r in roles]

        inventory.append(
            InventoryItem(
                nhi_type=NHI_SERVICE_ACCOUNT,
                identity=login,
                identity_id=user_id,
                owner="unassigned — no owning team recorded on the user profile",
                created=format_date(user.get("created")),
                last_used=(
                    f"{api_events} API events in the log window"
                    if api_events
                    else "no API activity observed"
                ),
                privilege=", ".join(role_labels) if role_labels else "no admin role",
                notes=f"heuristic score {score.score:.2f}: {score.explain()}",
            )
        )

        # Severity depends on what the account can actually do. An unattended
        # account with no MFA and no privileges is a hygiene issue; the same
        # account with an admin role is a different conversation, and the
        # admin_roles check raises that one separately at critical/high.
        if not has_mfa and not roles:
            severity = MEDIUM
        elif not has_mfa:
            severity = HIGH
        else:
            severity = LOW

        findings.append(
            Finding(
                nhi_type=NHI_SERVICE_ACCOUNT,
                identity=login,
                identity_id=user_id,
                check=CHECK_NAME,
                severity=severity,
                finding=(
                    "User account appears to be a non-human identity operating "
                    "as a standard user"
                    + ("" if has_mfa else ", with no MFA enrolled.")
                ),
                evidence=(
                    f"{login} scored {score.score:.2f} against a {threshold:.2f} "
                    f"threshold. Signals: {score.explain()}. "
                    f"Created {format_date(user.get('created'))}. "
                    + (
                        f"Admin roles held: {', '.join(role_labels)}."
                        if role_labels
                        else "No admin roles held."
                    )
                ),
                risk=_risk_language(login, has_mfa, bool(role_labels)),
                remediation=(
                    "Confirm with the owning team what this account does. If it "
                    "is a machine identity: assign a named human or team owner "
                    "in the user profile, enrol MFA if any interactive access is "
                    "still required, remove any admin role it does not "
                    "demonstrably need, and plan migration of its workload to an "
                    "API Service Integration so the credential is scoped and "
                    "auditable rather than a password on a user object. If it is "
                    "a shared human account, that is its own finding — split it "
                    "into individual accounts."
                ),
                metadata={
                    "score": score.score,
                    "signals": score.signals,
                    "has_mfa": has_mfa,
                    "roles": role_labels,
                    "api_events": api_events,
                },
            )
        )

    return findings, inventory, scores


def _risk_language(login: str, has_mfa: bool, has_roles: bool) -> str:
    base = (
        f"{login} is being used by software rather than a person, but it exists "
        "in Okta as an ordinary user. That means it is governed by the controls "
        "you designed for humans and not by the ones you would design for a "
        "machine: it will not appear in an access review as an integration, no "
        "one will be asked to re-certify it, and it survives offboarding because "
        "there is no person to offboard."
    )
    if not has_mfa:
        base += (
            " It has no MFA factor enrolled, so its access rests entirely on a "
            "password — one that is almost certainly stored in a script, a CI "
            "variable, or a config file, and has probably never been rotated."
        )
    if has_roles:
        base += (
            " It also holds an administrative role, which means a compromise of "
            "that stored password is an administrative compromise of the tenant."
        )
    return base
