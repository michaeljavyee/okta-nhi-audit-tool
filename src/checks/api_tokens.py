"""Check 1 — org API tokens.

Two facts about Okta API tokens drive everything here, and both are worth
stating in a client report because most people don't know them:

  1. A token inherits the privileges of the human who created it, at the moment
     of creation. If that person's role is later reduced, or they leave the
     company, the token's blast radius is now decoupled from any current human's
     access. Nothing in the Okta UI surfaces this.

  2. Tokens expire 30 days after creation OR last use, whichever is later. The
     clock resets on every call. So a token used by a nightly job never expires
     — indefinitely, silently. Meanwhile a token used monthly dies without
     warning and takes an integration down with it.

Together those produce the two findings this check leads with: orphaned tokens
(critical) and effectively-immortal tokens (medium).
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..scoring import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    NHI_API_TOKEN,
    Finding,
    InventoryItem,
    days_since,
    days_until,
    format_date,
)
from .base import TenantContext

CHECK_NAME = "api_tokens"

# Okta's token lifetime: 30 days from creation or last use.
TOKEN_LIFETIME_DAYS = 30

# A token used at least this often effectively never expires.
ACTIVE_USE_DAYS = 7

# A token idle this long is close to silently expiring.
NEAR_EXPIRY_DAYS = 25


def run(context: TenantContext) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []

    tokens = list(context.client.paginate_optional("/api/v1/api-tokens"))

    if not tokens:
        context.note_limitation(
            "No org API tokens were returned. Either none exist, or the token "
            "used for this audit lacks the Super Admin role required to list "
            "them (the /api/v1/api-tokens endpoint is Super Admin only)."
        )
        return findings, inventory

    for token in tokens:
        token_id = token.get("id", "")
        name = token.get("name") or token_id or "(unnamed token)"
        creator_id = token.get("userId", "")
        creator_login = token.get("username") or context.user_login(creator_id)
        creator_status = context.user_status(creator_id)

        idle_days = days_since(token.get("lastUpdated"))
        created_days = days_since(token.get("created"))
        expiry_days = days_until(token.get("expiresAt"))

        inventory.append(
            InventoryItem(
                nhi_type=NHI_API_TOKEN,
                identity=name,
                identity_id=token_id,
                owner=f"{creator_login} ({creator_status})",
                created=format_date(token.get("created")),
                last_used=_describe_idle(idle_days),
                privilege="Inherits creator's admin privileges at time of creation",
                notes=_describe_expiry(expiry_days),
            )
        )

        # --- Finding: orphaned token (the flagship) -------------------------
        if creator_id and context.is_deactivated(creator_id):
            findings.append(
                Finding(
                    nhi_type=NHI_API_TOKEN,
                    identity=name,
                    identity_id=token_id,
                    check=CHECK_NAME,
                    severity=CRITICAL,
                    finding=(
                        "API token is owned by a user account that is no longer "
                        f"active ({creator_status})."
                    ),
                    evidence=(
                        f"Token '{name}' (id {token_id}) was created on "
                        f"{format_date(token.get('created'))} by {creator_login}, "
                        f"whose Okta account is currently {creator_status}. "
                        f"The token was last used {_describe_idle(idle_days)}."
                    ),
                    risk=(
                        "An Okta API token carries the administrative privileges "
                        "its creator held at the moment it was issued, and those "
                        "privileges do not change when the creator's account is "
                        "deactivated. This credential still has whatever access "
                        f"{creator_login} had, but there is no longer a person "
                        "accountable for it, no one who knows what uses it, and "
                        "no one who would notice if it were stolen. Offboarding "
                        "removed the human and left the credential behind. "
                        "Because the 30-day expiry clock resets on every use, an "
                        "automated job keeps this token alive indefinitely."
                    ),
                    remediation=(
                        "Revoke immediately: Admin console -> Security -> API -> "
                        "Tokens -> revoke this token. Before revoking, identify "
                        "what uses it by filtering the System Log on this token "
                        "and coordinating a replacement. Reissue as an API "
                        "Service Integration with only the scopes the workload "
                        "actually needs, owned by a team rather than a person. "
                        "Add 'revoke API tokens created by this user' to the "
                        "offboarding checklist."
                    ),
                    metadata={
                        "creator": creator_login,
                        "creator_status": creator_status,
                        "idle_days": idle_days,
                    },
                )
            )
            continue

        # --- Finding: never used since creation -----------------------------
        if idle_days is not None and created_days is not None and idle_days == created_days and idle_days > TOKEN_LIFETIME_DAYS:
            findings.append(
                Finding(
                    nhi_type=NHI_API_TOKEN,
                    identity=name,
                    identity_id=token_id,
                    check=CHECK_NAME,
                    severity=MEDIUM,
                    finding="API token has never been used since it was created.",
                    evidence=(
                        f"Token '{name}' was created {created_days} days ago by "
                        f"{creator_login} and shows no use since. Its 30-day "
                        "window has already lapsed."
                    ),
                    risk=(
                        "A credential nobody uses is a credential nobody is "
                        "watching. It represents an unexplained decision — "
                        "someone needed admin API access and either never "
                        "shipped the thing, or shipped it somewhere else. "
                        "Either way the record is now noise that makes real "
                        "tokens harder to review. Generic names like this one "
                        "are a sign the token inventory has no ownership model."
                    ),
                    remediation=(
                        "Confirm with the creator that it is unused, then revoke "
                        "it. Introduce a naming convention that records purpose "
                        "and owning team, e.g. 'terraform-prod-platformteam', so "
                        "the next review does not require archaeology."
                    ),
                    metadata={"creator": creator_login, "idle_days": idle_days},
                )
            )
            continue

        # --- Finding: effectively immortal ----------------------------------
        if idle_days is not None and idle_days <= ACTIVE_USE_DAYS:
            findings.append(
                Finding(
                    nhi_type=NHI_API_TOKEN,
                    identity=name,
                    identity_id=token_id,
                    check=CHECK_NAME,
                    severity=MEDIUM,
                    finding=(
                        "Long-lived static API token in continuous use — its "
                        "expiry never takes effect."
                    ),
                    evidence=(
                        f"Token '{name}' was created "
                        f"{format_date(token.get('created'))} "
                        f"({created_days} days ago) and last used "
                        f"{_describe_idle(idle_days)}. Okta's 30-day expiry runs "
                        "from last use, so continuous use keeps resetting it."
                    ),
                    risk=(
                        "This credential has been valid for "
                        f"{created_days} days and, at the current usage rate, "
                        "will remain valid forever without anyone re-approving "
                        "it. It is a static bearer token: whoever holds the "
                        "string has its full access, there is no MFA, no device "
                        "binding, and no way to tell a legitimate call from a "
                        "stolen one. Okta's own guidance is to prefer scoped "
                        "OAuth 2.0 service integrations over static API tokens "
                        "for exactly this reason."
                    ),
                    remediation=(
                        "Migrate this workload to an API Service Integration "
                        "using the client_credentials grant with only the scopes "
                        "it needs, so access is scoped and short-lived rather "
                        "than unlimited and permanent. Until then, set a "
                        "calendar reminder to rotate this token on a fixed "
                        "schedule and record its owning team."
                    ),
                    metadata={"creator": creator_login, "age_days": created_days},
                )
            )
            continue

        # --- Finding: about to silently expire ------------------------------
        if idle_days is not None and NEAR_EXPIRY_DAYS <= idle_days <= TOKEN_LIFETIME_DAYS:
            findings.append(
                Finding(
                    nhi_type=NHI_API_TOKEN,
                    identity=name,
                    identity_id=token_id,
                    check=CHECK_NAME,
                    severity=LOW,
                    finding=(
                        f"API token has been idle {idle_days} days and will "
                        "expire silently within days."
                    ),
                    evidence=(
                        f"Token '{name}' was last used {idle_days} days ago. "
                        "Okta expires tokens 30 days after last use, so this one "
                        f"lapses in roughly {TOKEN_LIFETIME_DAYS - idle_days} days."
                    ),
                    risk=(
                        "This is an availability risk rather than a security "
                        "one. When the token expires, whatever depends on it "
                        "starts failing with 401s and no advance warning is "
                        "sent. Infrequently-run jobs — quarterly reports, "
                        "disaster-recovery scripts — are the usual casualties, "
                        "and they fail at the moment you need them."
                    ),
                    remediation=(
                        "Decide whether the token is still needed. If it is, "
                        "move the workload to an API Service Integration, which "
                        "does not expire on this basis. If it is not, revoke it."
                    ),
                    metadata={"creator": creator_login, "idle_days": idle_days},
                )
            )
            continue

    return findings, inventory


def _describe_idle(idle_days: Any) -> str:
    if idle_days is None:
        return "unknown"
    if idle_days == 0:
        return "today"
    if idle_days == 1:
        return "1 day ago"
    return f"{idle_days} days ago"


def _describe_expiry(expiry_days: Any) -> str:
    if expiry_days is None:
        return ""
    if expiry_days < 0:
        return f"expired {abs(expiry_days)} days ago"
    return f"expires in {expiry_days} days (resets on each use)"
