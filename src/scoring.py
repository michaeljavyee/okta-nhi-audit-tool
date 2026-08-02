"""The Finding model, severity definitions, and the service-account heuristic.

Everything a check produces flows through here. Keeping the vocabulary in one
module means adding a seventh check requires no changes to the report, the CSV
writer, or the terminal output.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------- severity

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

# Sort key: lower number = more severe = appears first.
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

SEVERITY_DEFINITIONS = {
    CRITICAL: (
        "Exploitable now, with org-wide blast radius. A credential that grants "
        "administrative control and is not tied to an accountable human. "
        "Remediate within 24 hours."
    ),
    HIGH: (
        "Meaningful privilege held by an identity with weak or absent controls, "
        "or a credential whose owner cannot be established. "
        "Remediate within 30 days."
    ),
    MEDIUM: (
        "A control gap or over-provisioning that does not by itself grant "
        "escalation, but widens the blast radius if the identity is compromised. "
        "Remediate this quarter."
    ),
    LOW: (
        "Hygiene and operational risk: unused credentials, missing ownership "
        "metadata, configuration that will cause an outage rather than a breach."
    ),
    INFO: (
        "Inventory context with no finding attached. Included because most "
        "organisations have never seen this list."
    ),
}

# Timeframe used to build the remediation roadmap in the report.
SEVERITY_TIMEFRAME = {
    CRITICAL: "Immediate (24 hours)",
    HIGH: "This month (30 days)",
    MEDIUM: "This quarter (90 days)",
    LOW: "Backlog / next review cycle",
    INFO: "No action required",
}

# ---------------------------------------------------------------- NHI types

NHI_API_TOKEN = "api_token"
NHI_OAUTH_SERVICE_APP = "oauth_service_app"
NHI_SERVICE_ACCOUNT = "service_account"
NHI_HOOK = "hook"
NHI_SCIM = "scim"

NHI_TYPE_LABELS = {
    NHI_API_TOKEN: "Org API token",
    NHI_OAUTH_SERVICE_APP: "API service integration (OAuth)",
    NHI_SERVICE_ACCOUNT: "Service account (user object)",
    NHI_HOOK: "Event / inline hook",
    NHI_SCIM: "SCIM provisioning connection",
}


@dataclass
class Finding:
    """One audit result.

    WHY A DATACLASS: `@dataclass` writes __init__, __repr__ and __eq__ from the
    field annotations below. Without it this class would be thirty lines of
    boilerplate assigning self.x = x. More importantly it makes the shape of a
    finding explicit and enforced — every check produces exactly these fields,
    which is what lets the report template loop over findings without knowing
    which check produced them.

    The last four fields are what separate a deliverable from a log dump:

      finding     — what is wrong (one line, factual)
      evidence    — the specific data that proves it
      risk        — why a client should care, in business language, no jargon
      remediation — the exact action, naming the console path where possible

    "3 orphaned API tokens" is data. The risk/remediation pair is what someone
    pays for.
    """

    nhi_type: str
    identity: str
    severity: str
    finding: str
    evidence: str
    risk: str
    remediation: str
    identity_id: str = ""
    check: str = ""
    # Free-form extras used by the inventory table (last used, owner, etc).
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(
                f"Unknown severity {self.severity!r} for finding on "
                f"{self.identity!r}. Use one of: {', '.join(SEVERITY_ORDER)}"
            )
        if self.nhi_type not in NHI_TYPE_LABELS:
            raise ValueError(
                f"Unknown nhi_type {self.nhi_type!r}. Use one of: "
                f"{', '.join(NHI_TYPE_LABELS)}"
            )

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    @property
    def nhi_type_label(self) -> str:
        return NHI_TYPE_LABELS[self.nhi_type]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryItem:
    """One non-human identity, findings aside.

    The inventory is the part of the report most clients have never seen. It
    exists whether or not anything is wrong with the entry.
    """

    nhi_type: str
    identity: str
    identity_id: str
    owner: str = "unknown"
    created: str = ""
    last_used: str = ""
    privilege: str = ""
    notes: str = ""

    @property
    def nhi_type_label(self) -> str:
        return NHI_TYPE_LABELS.get(self.nhi_type, self.nhi_type)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Most severe first, then grouped by NHI type, then alphabetical."""
    return sorted(findings, key=lambda f: (f.rank, f.nhi_type, f.identity))


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


# ------------------------------------------------- service-account heuristic

# Substrings that suggest a login belongs to a machine rather than a person.
# Deliberately conservative — "admin" is not here, because plenty of humans have
# admin in their login and false positives cost credibility in a client report.
SERVICE_ACCOUNT_NAME_PATTERNS = [
    "svc-",
    "svc_",
    "service-",
    "service_",
    "api-",
    "api_",
    "automation",
    "integration",
    "bot-",
    "bot_",
    "-bot",
    "noreply",
    "no-reply",
    "donotreply",
    "sync-",
    "connector",
    "webhook",
    "daemon",
    "robot",
    "system-",
]

# Weights sum to 1.0. Each signal is independently weak; the combination is what
# carries information. Naming is intentionally NOT the heaviest signal — a
# well-run org names service accounts clearly, so naming alone would over-flag
# the orgs doing it right and miss the ones doing it badly.
HEURISTIC_WEIGHTS = {
    "naming_pattern": 0.30,
    "no_mfa_enrolled": 0.25,
    "no_interactive_login": 0.30,
    "has_api_activity": 0.15,
}

DEFAULT_THRESHOLD = 0.5


@dataclass
class ServiceAccountScore:
    """The result of scoring one user, with the reasoning kept attached.

    Carrying the signal breakdown rather than just the number is what lets the
    report say *why* something was flagged. A client can then disagree with a
    specific signal instead of dismissing the whole method.
    """

    user_id: str
    login: str
    score: float
    signals: Dict[str, bool]
    reasons: List[str]

    @property
    def is_suspected(self) -> bool:
        return self.score >= DEFAULT_THRESHOLD

    def explain(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "no service-account signals"


def score_service_account(
    user: Dict[str, Any],
    has_mfa: bool,
    had_interactive_login: bool,
    api_event_count: int,
) -> ServiceAccountScore:
    """Score how likely a user object is actually a machine identity.

    This is a HEURISTIC and is presented as one. It will produce false positives
    (a shared team mailbox scores like a service account) and false negatives (an
    NHI named `data-pipeline-prod@` with a stray browser login does not). See
    docs/false-positives.md.

    Args:
        user: the Okta user object.
        has_mfa: whether any MFA factor is enrolled.
        had_interactive_login: whether the System Log shows a browser sign-in.
        api_event_count: number of API-token events attributed to this actor.
    """
    profile = user.get("profile") or {}
    login = (profile.get("login") or profile.get("email") or "").lower()
    display = (profile.get("displayName") or "").lower()

    matched_patterns = [
        pattern
        for pattern in SERVICE_ACCOUNT_NAME_PATTERNS
        if pattern in login or pattern in display
    ]

    signals = {
        "naming_pattern": bool(matched_patterns),
        "no_mfa_enrolled": not has_mfa,
        "no_interactive_login": not had_interactive_login,
        "has_api_activity": api_event_count > 0,
    }

    score = sum(
        HEURISTIC_WEIGHTS[name] for name, present in signals.items() if present
    )

    reasons = []
    if signals["naming_pattern"]:
        reasons.append(
            f"login matches service-account naming convention "
            f"({', '.join(matched_patterns[:2])})"
        )
    if signals["no_mfa_enrolled"]:
        reasons.append("no MFA factor enrolled")
    if signals["no_interactive_login"]:
        reasons.append("no interactive browser sign-in in the System Log window")
    if signals["has_api_activity"]:
        reasons.append(f"{api_event_count} API events attributed to this actor")

    return ServiceAccountScore(
        user_id=user.get("id", ""),
        login=profile.get("login") or profile.get("email") or user.get("id", ""),
        score=round(score, 3),
        signals=signals,
        reasons=reasons,
    )


# ---------------------------------------------------------------- date utils


def parse_okta_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an Okta timestamp into a timezone-aware datetime.

    Okta returns ISO-8601 ending in "Z". Python's fromisoformat did not accept
    "Z" before 3.11, so we swap it for the explicit UTC offset — harmless on
    newer versions, necessary on older ones.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def days_since(value: Optional[str], now: Optional[datetime] = None) -> Optional[int]:
    parsed = parse_okta_datetime(value)
    if parsed is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return (reference - parsed).days


def days_until(value: Optional[str], now: Optional[datetime] = None) -> Optional[int]:
    parsed = parse_okta_datetime(value)
    if parsed is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return (parsed - reference).days


def format_date(value: Optional[str]) -> str:
    parsed = parse_okta_datetime(value)
    return parsed.strftime("%Y-%m-%d") if parsed else "unknown"
