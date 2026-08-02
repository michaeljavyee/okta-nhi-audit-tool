"""Shared tenant data, fetched once and reused by every check.

Several checks need the same expensive things — the full user list, the System
Log slice, per-user MFA factors. Without a shared context, adding a check would
add another full pagination pass over /api/v1/users, and a tenant with 5,000
users would get audited five times over.

TenantContext loads each piece on first request and caches it. The pattern is
lazy loading, and it's why the checks can be written as independent functions
without any of them worrying about who fetched what.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# How far back to read the System Log. Okta retains 90 days on most plans;
# asking for more silently returns less, which would quietly weaken the
# "no interactive login" signal without saying so. The report states this
# window explicitly as a scope limitation.
SYSTEM_LOG_WINDOW = "90d"

# Cap on System Log events pulled. An audit shouldn't page through a million
# events; we need presence/absence of sign-ins, not a complete record.
SYSTEM_LOG_MAX_EVENTS = 5000

INTERACTIVE_LOGIN_EVENTS = {
    "user.session.start",
    "user.authentication.sso",
    "user.authentication.auth_via_mfa",
}

API_ACTIVITY_EVENTS = {
    "system.api_token.access",
    "app.oauth2.as.token.grant",
    "app.oauth2.client_credentials.grant_type_used",
}


class TenantContext:
    """Lazily-loaded, cached view of the tenant.

    Every property here performs its API calls at most once per run.
    """

    def __init__(self, client: Any, demo: bool = False) -> None:
        self.client = client
        self.demo = demo
        self.scope_limitations: List[str] = []

        self._users: Optional[List[Dict[str, Any]]] = None
        self._apps: Optional[List[Dict[str, Any]]] = None
        self._logs: Optional[List[Dict[str, Any]]] = None
        self._factors: Dict[str, List[Dict[str, Any]]] = {}
        self._roles: Dict[str, List[Dict[str, Any]]] = {}
        self._interactive_logins: Optional[set] = None
        self._api_event_counts: Optional[Counter] = None

    # ------------------------------------------------------------------ users

    @property
    def users(self) -> List[Dict[str, Any]]:
        if self._users is None:
            logger.info("Fetching users")
            # search=... would let Okta filter server-side, but we want
            # DEPROVISIONED users too — they are exactly the ones whose orphaned
            # tokens matter. The default /api/v1/users listing omits them, so we
            # ask for every status explicitly.
            self._users = list(
                self.client.paginate(
                    "/api/v1/users",
                    params={"limit": 200, "filter": 'status pr'},
                )
            )
        return self._users

    @property
    def users_by_id(self) -> Dict[str, Dict[str, Any]]:
        return {user["id"]: user for user in self.users if user.get("id")}

    def user_login(self, user_id: str) -> str:
        user = self.users_by_id.get(user_id)
        if not user:
            return user_id
        profile = user.get("profile") or {}
        return profile.get("login") or profile.get("email") or user_id

    def user_status(self, user_id: str) -> str:
        user = self.users_by_id.get(user_id)
        return (user or {}).get("status", "UNKNOWN")

    def is_deactivated(self, user_id: str) -> bool:
        return self.user_status(user_id) in {
            "DEPROVISIONED",
            "SUSPENDED",
            "LOCKED_OUT",
            "UNKNOWN",
        }

    # ------------------------------------------------------------------- apps

    @property
    def apps(self) -> List[Dict[str, Any]]:
        if self._apps is None:
            logger.info("Fetching applications")
            self._apps = list(
                self.client.paginate("/api/v1/apps", params={"limit": 200})
            )
        return self._apps

    # ---------------------------------------------------------------- factors

    def factors_for(self, user_id: str) -> List[Dict[str, Any]]:
        """MFA factors enrolled by one user.

        This is per-user — Okta has no bulk factor endpoint — so it is only
        called for users that already look like NHI candidates, not for the
        whole directory.
        """
        if user_id not in self._factors:
            self._factors[user_id] = list(
                self.client.paginate_optional(f"/api/v1/users/{user_id}/factors")
            )
        return self._factors[user_id]

    def has_mfa(self, user_id: str) -> bool:
        return any(
            factor.get("status") == "ACTIVE" for factor in self.factors_for(user_id)
        )

    # ------------------------------------------------------------------ roles

    def roles_for(self, user_id: str) -> List[Dict[str, Any]]:
        if user_id not in self._roles:
            self._roles[user_id] = list(
                self.client.paginate_optional(f"/api/v1/users/{user_id}/roles")
            )
        return self._roles[user_id]

    # -------------------------------------------------------------- system log

    @property
    def logs(self) -> List[Dict[str, Any]]:
        if self._logs is None:
            logger.info("Fetching System Log (last %s)", SYSTEM_LOG_WINDOW)
            events: List[Dict[str, Any]] = []
            try:
                for event in self.client.paginate_optional(
                    "/api/v1/logs",
                    params={"since": f"-{SYSTEM_LOG_WINDOW}", "limit": 1000},
                ):
                    events.append(event)
                    if len(events) >= SYSTEM_LOG_MAX_EVENTS:
                        self.scope_limitations.append(
                            f"System Log sampling capped at {SYSTEM_LOG_MAX_EVENTS} "
                            "events; activity signals are based on a sample, not "
                            "the complete log."
                        )
                        break
            except Exception as exc:  # noqa: BLE001 - log access is optional
                logger.warning("System Log unavailable: %s", exc)
                self.scope_limitations.append(
                    "System Log could not be read (the API token may lack the "
                    "required admin role). Interactive-login and API-activity "
                    "signals were unavailable, which lowers confidence in "
                    "service-account detection."
                )
            self._logs = events
        return self._logs

    @property
    def interactive_login_actors(self) -> set:
        """Set of user IDs seen signing in through a browser.

        Absence from this set is the strongest single signal that an account is
        a machine identity — and also the signal most likely to be wrong, since
        it only covers the log retention window.
        """
        if self._interactive_logins is None:
            actors = set()
            for event in self.logs:
                if event.get("eventType") not in INTERACTIVE_LOGIN_EVENTS:
                    continue
                if (event.get("outcome") or {}).get("result") != "SUCCESS":
                    continue
                user_agent = (
                    ((event.get("client") or {}).get("userAgent") or {}).get(
                        "rawUserAgent"
                    )
                    or ""
                )
                # A "login" from python-requests is a script, not a person.
                if _looks_like_a_script(user_agent):
                    continue
                actor_id = (event.get("actor") or {}).get("id")
                if actor_id:
                    actors.add(actor_id)
            self._interactive_logins = actors
        return self._interactive_logins

    @property
    def api_event_counts(self) -> Counter:
        """Count of API-token events per actor ID."""
        if self._api_event_counts is None:
            counts: Counter = Counter()
            for event in self.logs:
                if event.get("eventType") not in API_ACTIVITY_EVENTS:
                    continue
                actor_id = (event.get("actor") or {}).get("id")
                if not actor_id:
                    continue
                # The demo fixtures carry the true count so a readable fixture
                # file can still represent a busy account. Live tenants won't
                # have this key and fall through to counting events.
                true_count = event.get("_apiEventCount")
                if true_count:
                    counts[actor_id] = max(counts[actor_id], int(true_count))
                else:
                    counts[actor_id] += 1
            self._api_event_counts = counts
        return self._api_event_counts

    def had_interactive_login(self, user_id: str) -> bool:
        return user_id in self.interactive_login_actors

    def api_event_count(self, user_id: str) -> int:
        return self.api_event_counts.get(user_id, 0)

    def note_limitation(self, text: str) -> None:
        if text not in self.scope_limitations:
            self.scope_limitations.append(text)


def _looks_like_a_script(user_agent: str) -> bool:
    ua = user_agent.lower()
    return any(
        marker in ua
        for marker in ("python-requests", "curl/", "okhttp", "go-http-client", "axios")
    )
