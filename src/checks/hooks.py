"""Check 5 — event hooks and inline hooks.

Hooks are the NHI category people forget entirely, because they don't look like
an identity. But an event hook is a standing arrangement in which your identity
provider sends data about your users to a third-party URL, authenticating with a
header you configured once and have not looked at since.

Two properties make them worth auditing:

  - Event hooks are outbound. They carry identity data to somewhere you do not
    control, and the destination is only as trustworthy as whoever owns that
    domain today.
  - Inline hooks are worse, because they are *synchronous and in the path*. A
    token-transform inline hook can modify the claims in an access token before
    it is issued. Whoever controls that endpoint influences authorisation
    decisions.

Note the deliberate omission: this check does NOT probe the destination URLs.
Sending traffic to a client's third-party endpoints during an audit is a side
effect, and the read-only guarantee covers the client's environment as a whole,
not just their Okta tenant.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from ..scoring import (
    HIGH,
    LOW,
    MEDIUM,
    NHI_HOOK,
    Finding,
    InventoryItem,
    format_date,
)
from .base import TenantContext

CHECK_NAME = "hooks"


def run(context: TenantContext) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []

    event_hooks = list(context.client.paginate_optional("/api/v1/eventHooks"))
    inline_hooks = list(context.client.paginate_optional("/api/v1/inlineHooks"))

    for hook in event_hooks:
        findings_for, item = _assess(context, hook, kind="event")
        inventory.append(item)
        findings.extend(findings_for)

    for hook in inline_hooks:
        findings_for, item = _assess(context, hook, kind="inline")
        inventory.append(item)
        findings.extend(findings_for)

    return findings, inventory


def _assess(
    context: TenantContext, hook: Dict[str, Any], kind: str
) -> Tuple[List[Finding], InventoryItem]:
    findings: List[Finding] = []

    hook_id = hook.get("id", "")
    name = hook.get("name") or hook_id
    status = hook.get("status", "UNKNOWN")
    verification = hook.get("verificationStatus", "")
    config = ((hook.get("channel") or {}).get("config")) or {}
    uri = config.get("uri", "")
    auth_scheme = (config.get("authScheme") or {}).get("type", "")
    parsed = urlparse(uri)
    host = parsed.netloc or "unknown"
    is_plaintext = parsed.scheme == "http"
    has_auth = bool(auth_scheme)

    events = ((hook.get("events") or {}).get("items")) or []
    hook_type = hook.get("type", "")

    item = InventoryItem(
        nhi_type=NHI_HOOK,
        identity=f"{name} ({kind} hook)",
        identity_id=hook_id,
        owner="unassigned — Okta records no owner on a hook",
        created=format_date(hook.get("created")),
        last_used="",
        privilege=(
            ", ".join(events)
            if events
            else (hook_type or "inline hook in the authentication path")
        ),
        notes=f"destination {host or 'unknown'}, status {status}"
        + ("" if has_auth else ", NO auth header configured"),
    )

    if status != "ACTIVE":
        return findings, item

    # --- Plaintext destination -------------------------------------------
    if is_plaintext:
        findings.append(
            Finding(
                nhi_type=NHI_HOOK,
                identity=name,
                identity_id=hook_id,
                check=CHECK_NAME,
                severity=HIGH,
                finding=(
                    f"Active {kind} hook delivers identity data over plaintext "
                    "HTTP."
                ),
                evidence=(
                    f"Hook '{name}' ({hook_id}) is ACTIVE and posts to {uri}. "
                    f"The scheme is http, not https. Events sent: "
                    f"{', '.join(events) if events else hook_type}. "
                    f"Auth scheme configured: {auth_scheme or 'none'}. "
                    f"Verification status: {verification or 'unknown'}."
                ),
                risk=(
                    "Every time this hook fires, your identity provider sends "
                    "user data — logins, names, session events — across the "
                    "network unencrypted. Anyone positioned between Okta and "
                    f"{host} can read it, and if an auth header were configured "
                    "they would read that credential too, in the clear, on every "
                    "request. The destination is a third-party domain, so the "
                    "traffic leaves your control entirely. This is the kind of "
                    "finding that appears in a SOC 2 report as an encryption-in-"
                    "transit exception."
                ),
                remediation=(
                    "Move the endpoint to HTTPS with a valid certificate and "
                    "update the hook: Admin console -> Workflow -> Event Hooks "
                    f"-> {name}. If the destination cannot support TLS, the "
                    "integration should be retired rather than fixed. Confirm "
                    "who owns "
                    f"{host} and whether this integration is still required at "
                    "all — hooks pointing at long-forgotten vendors are common."
                ),
                metadata={"uri": uri, "host": host, "kind": kind},
            )
        )

    # --- No auth on the outbound call -------------------------------------
    if not has_auth:
        findings.append(
            Finding(
                nhi_type=NHI_HOOK,
                identity=name,
                identity_id=hook_id,
                check=CHECK_NAME,
                severity=MEDIUM,
                finding=(
                    f"Active {kind} hook posts to an external endpoint with no "
                    "authentication header configured."
                ),
                evidence=(
                    f"Hook '{name}' ({hook_id}) posts to {uri} with no "
                    "authScheme set on the channel configuration."
                ),
                risk=(
                    "Without a shared secret in the request, the receiving "
                    "endpoint has no way to verify that a given payload actually "
                    "came from your Okta tenant. Anyone who learns the URL can "
                    "post forged identity events to it. Whatever that endpoint "
                    "does in response — provision an account, page an on-call "
                    "engineer, write to a database — can be triggered by a "
                    "stranger."
                ),
                remediation=(
                    "Configure an authentication header on the hook and validate "
                    "it at the receiving endpoint. Rotate the secret on the same "
                    "schedule as your other credentials."
                ),
                metadata={"uri": uri, "kind": kind},
            )
        )

    # --- Unverified event hook --------------------------------------------
    if kind == "event" and verification and verification != "VERIFIED":
        findings.append(
            Finding(
                nhi_type=NHI_HOOK,
                identity=name,
                identity_id=hook_id,
                check=CHECK_NAME,
                severity=LOW,
                finding=(
                    "Event hook is ACTIVE but has never completed Okta's "
                    "one-time verification handshake."
                ),
                evidence=(
                    f"Hook '{name}' ({hook_id}) has verificationStatus "
                    f"{verification}, created {format_date(hook.get('created'))}."
                ),
                risk=(
                    "An unverified hook is one that has probably never "
                    "successfully delivered. It is most likely an abandoned "
                    "integration — which matters because it is still configured "
                    "to receive user data if the endpoint ever comes back, and "
                    "because the domain it points at could be re-registered by "
                    "someone else."
                ),
                remediation=(
                    "Verify it if the integration is still wanted, delete it if "
                    "not. Confirm the destination domain is still registered to "
                    "the intended party before verifying."
                ),
                metadata={"verification": verification, "kind": kind},
            )
        )

    # --- Inline hooks are in the auth path ---------------------------------
    if kind == "inline":
        findings.append(
            Finding(
                nhi_type=NHI_HOOK,
                identity=name,
                identity_id=hook_id,
                check=CHECK_NAME,
                severity=MEDIUM,
                finding=(
                    "Inline hook executes synchronously inside the "
                    "authentication or token-issuance path."
                ),
                evidence=(
                    f"Inline hook '{name}' ({hook_id}) of type '{hook_type}' is "
                    f"ACTIVE and calls {uri} during request processing."
                ),
                risk=(
                    "Unlike an event hook, which is fired and forgotten, an "
                    "inline hook is called while Okta is deciding something. A "
                    "token-transform hook can alter the claims placed in an "
                    "access token; a registration or password-import hook can "
                    "influence whether a request is allowed. Whoever controls "
                    f"{host} therefore has influence over authorisation "
                    "decisions in your tenant. There is also an availability "
                    "consequence: if that endpoint is slow or down, "
                    "authentication is affected for real users."
                ),
                remediation=(
                    "Confirm the endpoint is owned by your organisation, not a "
                    "vendor. Restrict who can deploy to it with the same rigour "
                    "you apply to identity infrastructure, because that is what "
                    "it is. Verify the auth header is validated on the receiving "
                    "side, and monitor its latency and error rate."
                ),
                metadata={"uri": uri, "hook_type": hook_type},
            )
        )

    return findings, item
