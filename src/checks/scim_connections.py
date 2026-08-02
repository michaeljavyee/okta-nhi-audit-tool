"""Check 6 — SCIM provisioning connections.

Every app with provisioning enabled holds a standing credential *into* a
downstream SaaS system. That credential is invisible in Okta's UI — you see a
green "Provisioning enabled" toggle, not "Okta holds an admin API token for your
GitHub organisation".

Two things get flagged:

  1. Provisioning enabled on an INACTIVE app. The app was switched off; the
     downstream credential almost certainly was not revoked. This is the SaaS
     equivalent of an orphaned token.

  2. Create enabled but deactivate disabled. Users flow in and never flow out.
     Six months later the downstream system has active accounts for people who
     left the company, and Okta reports the integration as healthy. This is the
     single most common provisioning misconfiguration and it silently breaks the
     offboarding story a company tells its auditors.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..scoring import (
    HIGH,
    INFO,
    LOW,
    MEDIUM,
    NHI_SCIM,
    Finding,
    InventoryItem,
    format_date,
)
from .base import TenantContext

CHECK_NAME = "scim_connections"

PROVISIONING_FEATURES = {"USER_PROVISIONING", "INBOUND_PROVISIONING", "IMPORT_NEW_USERS"}


def run(context: TenantContext) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []

    for app in context.apps:
        app_id = app.get("id", "")
        label = app.get("label") or app.get("name") or app_id
        status = app.get("status", "UNKNOWN")

        # Okta 404s this endpoint for apps that don't support provisioning, which
        # is the common case. get_optional turns that into an empty result rather
        # than an exception.
        features = context.client.get_optional(
            f"/api/v1/apps/{app_id}/features", default=[]
        ) or []

        enabled = [
            feature
            for feature in features
            if feature.get("name") in PROVISIONING_FEATURES
            and feature.get("status") == "ENABLED"
        ]
        if not enabled:
            continue

        capabilities = _merge_capabilities(enabled)
        can_create = capabilities.get("create", False)
        can_deactivate = capabilities.get("deactivate", False)
        can_update_profile = capabilities.get("update_profile", False)

        capability_text = ", ".join(
            name
            for name, present in (
                ("create users", can_create),
                ("update profiles", can_update_profile),
                ("deactivate users", can_deactivate),
            )
            if present
        ) or "read only"

        inventory.append(
            InventoryItem(
                nhi_type=NHI_SCIM,
                identity=label,
                identity_id=app_id,
                owner="unassigned — the downstream credential has no Okta owner",
                created=format_date(app.get("created")),
                last_used="",
                privilege=f"downstream: {capability_text}",
                notes=f"app status {status}",
            )
        )

        # --- Provisioning still live on a disabled app ----------------------
        if status != "ACTIVE":
            findings.append(
                Finding(
                    nhi_type=NHI_SCIM,
                    identity=label,
                    identity_id=app_id,
                    check=CHECK_NAME,
                    severity=HIGH,
                    finding=(
                        "SCIM provisioning remains configured on an application "
                        f"that is {status}."
                    ),
                    evidence=(
                        f"'{label}' ({app_id}) has status {status} but "
                        "USER_PROVISIONING is still ENABLED with capabilities: "
                        f"{capability_text}."
                    ),
                    risk=(
                        f"When {label} was switched off in Okta, the API "
                        "credential Okta holds for the downstream system was "
                        "almost certainly not revoked on the other side. That "
                        "credential typically has administrative rights in the "
                        "downstream product — it has to, in order to create and "
                        "delete accounts. So there is now a live, privileged, "
                        "unmonitored credential for a system nobody considers "
                        "part of the environment any more. Decommissioning that "
                        "stops at 'we turned it off in Okta' leaves exactly this "
                        "behind, and it will not appear in any inventory because "
                        "the app looks inactive."
                    ),
                    remediation=(
                        "Retrieve the provisioning credential's identity from "
                        f"the {label} admin console and revoke it there — "
                        "deactivating the Okta app does not revoke it. Then "
                        "remove the provisioning configuration from the Okta app "
                        "and delete the app. Add 'revoke downstream provisioning "
                        "credentials' to your SaaS decommissioning checklist."
                    ),
                    metadata={"app_status": status, "capabilities": capabilities},
                )
            )
            continue

        # --- Create without deactivate --------------------------------------
        if can_create and not can_deactivate:
            findings.append(
                Finding(
                    nhi_type=NHI_SCIM,
                    identity=label,
                    identity_id=app_id,
                    check=CHECK_NAME,
                    severity=MEDIUM,
                    finding=(
                        "SCIM provisioning creates downstream users but is not "
                        "configured to deactivate them."
                    ),
                    evidence=(
                        f"'{label}' ({app_id}) has lifecycleCreate ENABLED and "
                        "lifecycleDeactivate DISABLED."
                    ),
                    risk=(
                        "Offboarding is one-directional. When someone leaves, "
                        f"Okta removes their access to {label} at the front door "
                        "but their account inside the downstream system stays "
                        "active. If that system supports any authentication path "
                        "other than SSO — a local password, a personal access "
                        "token, an API key they created — the former employee "
                        "still has access, and nothing in Okta will show it. "
                        "This is also the finding a SOC 2 auditor is looking for "
                        "when they ask you to demonstrate timely access removal: "
                        "the control exists on paper, and does not fully execute."
                    ),
                    remediation=(
                        f"Enable Deactivate Users: Admin console -> Applications "
                        f"-> {label} -> Provisioning -> To App -> edit -> enable "
                        "Deactivate Users. Before enabling, reconcile the "
                        "existing downstream account list against current Okta "
                        "users — there is likely a backlog of accounts belonging "
                        "to people who have already left."
                    ),
                    metadata={"capabilities": capabilities},
                )
            )
            continue

        # --- Correctly configured, but still inventory-worthy ---------------
        findings.append(
            Finding(
                nhi_type=NHI_SCIM,
                identity=label,
                identity_id=app_id,
                check=CHECK_NAME,
                severity=LOW,
                finding=(
                    "SCIM provisioning connection holds a standing privileged "
                    "credential into a downstream system."
                ),
                evidence=(
                    f"'{label}' ({app_id}) is ACTIVE with provisioning "
                    f"capabilities: {capability_text}. Lifecycle create and "
                    "deactivate are both enabled, which is the correct "
                    "configuration."
                ),
                risk=(
                    "No misconfiguration identified — this connection is set up "
                    f"the way it should be. It appears here because the {label} "
                    "provisioning credential is itself a non-human identity that "
                    "few organisations have inventoried. It holds administrative "
                    "rights in a downstream SaaS product, it is stored inside "
                    "Okta, it does not rotate on its own, and it is not covered "
                    "by any access review that looks at humans."
                ),
                remediation=(
                    "No urgent action. Record the connection and its downstream "
                    "privilege level in your integration inventory, assign an "
                    "owning team, and add the provisioning credential to your "
                    "rotation schedule."
                ),
                metadata={"capabilities": capabilities},
            )
        )

    return findings, inventory


def _merge_capabilities(features: List[Dict[str, Any]]) -> Dict[str, bool]:
    """Flatten Okta's nested capability structure into simple booleans.

    The API shape is capabilities.create.lifecycleCreate.status == "ENABLED",
    which is unpleasant to read at every call site.
    """
    result = {"create": False, "deactivate": False, "update_profile": False}

    for feature in features:
        capabilities = feature.get("capabilities") or {}

        create = (capabilities.get("create") or {}).get("lifecycleCreate") or {}
        if create.get("status") == "ENABLED":
            result["create"] = True

        update = capabilities.get("update") or {}
        deactivate = update.get("lifecycleDeactivate") or {}
        if deactivate.get("status") == "ENABLED":
            result["deactivate"] = True

        profile = update.get("profile") or {}
        if profile.get("status") == "ENABLED":
            result["update_profile"] = True

    return result
