"""Read-only HTTP client for the Okta Management API.

DESIGN CONSTRAINT: this module issues GET requests only. There is no method here
that can POST, PUT, PATCH or DELETE, and `_get` hardcodes the verb. An audit tool
that can modify the environment it audits is a liability during an engagement —
if a client asks "could this change anything?", the answer needs to be provably
no, not "it shouldn't".

The three things this handles that beginners usually get wrong:

  1. Pagination. Okta does not use ?page=2. It returns a `Link` header containing
     the full URL of the next page. You follow the URL Okta hands you.
  2. Rate limits. On 429, Okta tells you exactly when the window resets in the
     `X-Rate-Limit-Reset` header (a Unix timestamp). Sleep until then, not a
     blind sleep(60).
  3. Errors. A 401 should tell you what to do about it, not raise a bare
     HTTPError with a status code in it.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterator, Optional

import requests

logger = logging.getLogger(__name__)

# How many times we retry a single request that keeps coming back 429.
MAX_RETRIES = 5

# If Okta sends a 429 without a usable X-Rate-Limit-Reset header, fall back to
# this many seconds rather than spinning.
DEFAULT_BACKOFF_SECONDS = 10

# Never sleep longer than this on a single retry, even if the header says to.
# A malformed or far-future header shouldn't hang an audit for an hour.
MAX_SLEEP_SECONDS = 120

DEFAULT_TIMEOUT = 30


class OktaError(Exception):
    """Base class for every error this client raises.

    Callers can `except OktaError` and catch anything we deliberately raise,
    without also swallowing unrelated bugs like a TypeError in our own code.
    """


class OktaAuthError(OktaError):
    """401/403 — the token is wrong, expired, or lacks the required admin role."""


class OktaNotFoundError(OktaError):
    """404 — the endpoint or object doesn't exist in this org.

    Common and non-fatal: several NHI endpoints only exist if a feature is
    enabled for the org, so checks treat this as "nothing to report" rather
    than a failure.
    """


class OktaRateLimitError(OktaError):
    """429 that survived every retry."""


class OktaAPIError(OktaError):
    """Any other non-2xx response."""


class OktaClient:
    """A thin, read-only wrapper around the Okta Management API.

    Args:
        org_url: e.g. "https://dev-12345678.okta.com" (trailing slash is fine).
        api_token: the SSWS token. Never log this, never put it in an exception.
        timeout: per-request timeout in seconds.

    Usage::

        client = OktaClient(org_url, token)
        for user in client.paginate("/api/v1/users"):
            print(user["profile"]["login"])
    """

    def __init__(
        self,
        org_url: str,
        api_token: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not org_url:
            raise ValueError("org_url is required (e.g. https://dev-12345678.okta.com)")
        if not api_token:
            raise ValueError(
                "api_token is required. Set OKTA_API_TOKEN in your .env file — "
                "see .env.example. Never pass a token as a command-line argument; "
                "it ends up in your shell history."
            )

        self.org_url = org_url.rstrip("/")
        self.timeout = timeout

        # WHY A SESSION rather than calling requests.get() every time:
        #
        #   1. Headers are set once, here, instead of being repeated at every
        #      call site — which is how tokens end up accidentally omitted.
        #   2. The underlying TCP connection is reused across requests
        #      (connection pooling). An audit makes dozens of calls to the same
        #      host; without a Session each one redoes the TLS handshake.
        #
        # requests.get() actually creates a throwaway Session internally every
        # single time. Using one explicitly is the same thing, kept alive.
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"SSWS {api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "okta-nhi-audit-tool/1.0 (read-only)",
            }
        )

    # ---------------------------------------------------------------- internals

    def _url(self, path_or_url: str) -> str:
        """Accept either a bare path ("/api/v1/users") or a full URL.

        Pagination hands us back absolute URLs, so both forms have to work.
        """
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return f"{self.org_url}/{path_or_url.lstrip('/')}"

    @staticmethod
    def _sleep_seconds_from_headers(response: requests.Response) -> float:
        """Work out how long to wait after a 429.

        Okta sends `X-Rate-Limit-Reset`: the Unix timestamp when the current
        rate-limit window resets. The correct wait is (reset - now), plus a
        one-second cushion so we don't retry on the exact boundary.
        """
        reset_raw = response.headers.get("X-Rate-Limit-Reset")
        if reset_raw:
            try:
                reset_at = float(reset_raw)
                wait = reset_at - time.time() + 1
                if wait > 0:
                    return min(wait, MAX_SLEEP_SECONDS)
                # A reset time in the past means the window has already rolled
                # over; retry almost immediately.
                return 1.0
            except (TypeError, ValueError):
                logger.debug("Unparseable X-Rate-Limit-Reset: %r", reset_raw)

        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), MAX_SLEEP_SECONDS)
            except (TypeError, ValueError):
                pass

        return DEFAULT_BACKOFF_SECONDS

    def _raise_for_status(self, response: requests.Response) -> None:
        """Turn a bad status code into an exception that says what to do.

        Every message here names the fix. Being on the receiving end of
        "HTTPError: 401 Client Error" at 2am is what this is reacting to.
        """
        if response.ok:
            return

        # Okta returns a structured error body; surface it when present.
        detail = ""
        try:
            body = response.json()
            summary = body.get("errorSummary")
            causes = body.get("errorCauses") or []
            if summary:
                detail = f" Okta says: {summary}"
            if causes:
                cause_text = "; ".join(
                    c.get("errorSummary", "") for c in causes if isinstance(c, dict)
                )
                if cause_text:
                    detail += f" ({cause_text})"
        except ValueError:
            detail = f" Response body: {response.text[:200]}"

        url = response.url

        if response.status_code == 401:
            raise OktaAuthError(
                "401 Unauthorized — the API token was rejected.\n"
                "  Most likely cause: Okta API tokens expire 30 days after "
                "creation or last use, whichever is later. If this token sat "
                "unused for a month, it is gone.\n"
                "  Fix: Admin console -> Security -> API -> Tokens -> Create "
                "Token, then update OKTA_API_TOKEN in your .env.\n"
                f"  Also check OKTA_ORG_URL is the right org: {self.org_url}"
                f"{detail}"
            )

        if response.status_code == 403:
            raise OktaAuthError(
                "403 Forbidden — the token is valid but lacks permission for "
                f"{url}.\n"
                "  An Okta API token inherits the privileges of the human who "
                "created it. If your account is not an admin — or your role was "
                "reduced since the token was made — read calls like this fail.\n"
                "  Fix: create the token from an account with Read-Only Admin "
                "or Super Admin. Read-Only Admin is sufficient for this tool and "
                "is the right choice for a client engagement."
                f"{detail}"
            )

        if response.status_code == 404:
            raise OktaNotFoundError(
                f"404 Not Found — {url}\n"
                "  This often means the feature isn't enabled for this org "
                "rather than that you got the path wrong (Okta hides some "
                "endpoints entirely when the feature is off)."
                f"{detail}"
            )

        if response.status_code == 429:
            raise OktaRateLimitError(
                f"429 Too Many Requests — gave up after {MAX_RETRIES} retries on "
                f"{url}.\n"
                "  Developer orgs allow roughly 1,000 requests/minute, and each "
                "API token is capped at 50% of the org limit (~500/min).\n"
                "  Fix: rerun with fewer checks, or wait a minute."
                f"{detail}"
            )

        raise OktaAPIError(
            f"{response.status_code} from {url}.{detail}"
        )

    def _get(
        self,
        path_or_url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Issue one GET, retrying on 429 until the retry budget is spent.

        This is the only place in the codebase that performs a network request,
        and it is hardcoded to GET. That is the read-only guarantee, enforced in
        one line rather than by convention.
        """
        url = self._url(path_or_url)
        last_response: Optional[requests.Response] = None

        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.get(url, params=params, timeout=self.timeout)
            except requests.exceptions.Timeout as exc:
                raise OktaAPIError(
                    f"Request to {url} timed out after {self.timeout}s. "
                    "Okta may be slow, or the org URL may point somewhere that "
                    "isn't answering. Check OKTA_ORG_URL."
                ) from exc
            except requests.exceptions.ConnectionError as exc:
                raise OktaAPIError(
                    f"Could not connect to {url}. Check OKTA_ORG_URL and your "
                    "network — is the host name right?"
                ) from exc

            if response.status_code != 429:
                self._raise_for_status(response)
                return response

            last_response = response
            sleep_for = self._sleep_seconds_from_headers(response)
            logger.warning(
                "Rate limited on %s (attempt %d/%d). Sleeping %.1fs until the "
                "window resets.",
                url,
                attempt + 1,
                MAX_RETRIES,
                sleep_for,
            )
            time.sleep(sleep_for)

        # Out of retries. last_response is the final 429.
        assert last_response is not None
        self._raise_for_status(last_response)
        raise OktaRateLimitError(f"Exhausted retries on {url}")  # pragma: no cover

    # ------------------------------------------------------------------- public

    def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """GET a single (non-paginated) resource and return the decoded JSON."""
        return self._get(path, params=params).json()

    def paginate(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield every item across every page of a collection endpoint.

        PAGINATION, THE PART PEOPLE GET WRONG:

        Okta does not paginate with ?page=2&per_page=50. It returns an RFC 8288
        `Link` header containing the *complete URL* of the next page, including
        an opaque cursor:

            Link: <https://org.okta.com/api/v1/users?after=00u5&limit=200>; rel="next"

        You must follow that URL verbatim. You cannot construct it yourself,
        because the `after` cursor is Okta's internal position marker. requests
        parses the header for you into `response.links`.

        WHY THIS IS A GENERATOR (`yield` instead of building a list):

        `yield from` hands each item to the caller as it arrives. The caller can
        start processing page 1 while page 2 is still un-fetched, and if they
        `break` early we never request the remaining pages at all. For a tenant
        with 10,000 users that is the difference between holding 10,000 dicts in
        memory and holding 200.

        The consequence to remember: calling this function does *nothing*. It
        returns a generator object. No HTTP request happens until you iterate.
        So this is a no-op::

            client.paginate("/api/v1/users")          # no request made

        and this is what you want::

            list(client.paginate("/api/v1/users"))    # fetches every page
        """
        url: Optional[str] = path

        while url:
            response = self._get(url, params=params)
            payload = response.json()

            # Collection endpoints return a JSON array. If we somehow get an
            # object back, treat it as a single-item result rather than
            # iterating over its keys — which is what a bare `yield from` on a
            # dict would silently do.
            if isinstance(payload, list):
                yield from payload
            else:
                yield payload

            next_link = response.links.get("next", {})
            url = next_link.get("url")

            # The next URL already carries the full query string, cursor and
            # all. Re-sending params here would either duplicate them or, worse,
            # overwrite the cursor and loop on page 1 forever.
            params = None

    def get_optional(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        default: Any = None,
    ) -> Any:
        """GET a resource, returning `default` if the endpoint 404s or is denied.

        Several NHI endpoints only exist when a feature is enabled for the org,
        and some require an admin role the token may not hold. For an audit,
        "this org doesn't have hooks" is a legitimate result, not a crash — but
        we log it so it can be reported as a scope limitation.
        """
        try:
            return self.get(path, params=params)
        except (OktaNotFoundError, OktaAuthError) as exc:
            logger.info("Skipping %s: %s", path, str(exc).splitlines()[0])
            return default

    def paginate_optional(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Like `paginate`, but yields nothing if the endpoint is unavailable.

        Note the shape: we can't just wrap the loop in try/except and return,
        because the exception surfaces during iteration (generators are lazy),
        not at call time.
        """
        try:
            for item in self.paginate(path, params=params):
                yield item
        except (OktaNotFoundError, OktaAuthError) as exc:
            logger.info("Skipping %s: %s", path, str(exc).splitlines()[0])
            return

    def verify_connection(self) -> Dict[str, Any]:
        """Make one cheap authenticated call to fail fast on a bad token.

        Better to blow up here, before the progress bars start, than three
        checks into an audit.
        """
        return self.get("/api/v1/org")

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "OktaClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
