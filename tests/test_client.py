"""Tests for the client layer, against mocked HTTP responses.

Nothing here touches a network. The `responses` library intercepts requests at
the adapter level and returns whatever we register — including headers, which
is what lets us test pagination and 429 handling properly.

The three things worth testing here are exactly the three things that are easy
to get wrong: Link-header pagination, 429 backoff, and error messages.
"""

from __future__ import annotations

import time

import pytest
import requests
import responses

from src.okta_client import (
    OktaAPIError,
    OktaAuthError,
    OktaClient,
    OktaNotFoundError,
    OktaRateLimitError,
)

ORG = "https://dev-00000000.okta.com"
TOKEN = "00FAKETOKENFORTESTSONLY"


@pytest.fixture
def client():
    return OktaClient(ORG, TOKEN)


# ------------------------------------------------------------------ auth setup


def test_token_is_sent_as_ssws_header(client):
    assert client.session.headers["Authorization"] == f"SSWS {TOKEN}"


def test_missing_token_raises_with_actionable_message():
    with pytest.raises(ValueError) as exc:
        OktaClient(ORG, "")
    assert "OKTA_API_TOKEN" in str(exc.value)


def test_trailing_slash_on_org_url_is_normalised():
    assert OktaClient(ORG + "/", TOKEN).org_url == ORG


def test_relative_and_absolute_paths_both_resolve(client):
    assert client._url("/api/v1/users") == f"{ORG}/api/v1/users"
    assert client._url("api/v1/users") == f"{ORG}/api/v1/users"
    other = "https://other.okta.com/api/v1/users?after=abc"
    assert client._url(other) == other


# ------------------------------------------------------------------ pagination


@responses.activate
def test_paginate_follows_link_header_across_pages(client):
    page2 = f"{ORG}/api/v1/users?after=CURSOR2&limit=2"
    page3 = f"{ORG}/api/v1/users?after=CURSOR3&limit=2"

    responses.get(
        f"{ORG}/api/v1/users",
        json=[{"id": "1"}, {"id": "2"}],
        headers={"Link": f'<{page2}>; rel="next"'},
    )
    responses.get(page2, json=[{"id": "3"}, {"id": "4"}],
                  headers={"Link": f'<{page3}>; rel="next"'})
    responses.get(page3, json=[{"id": "5"}])

    ids = [user["id"] for user in client.paginate("/api/v1/users")]
    assert ids == ["1", "2", "3", "4", "5"]


@responses.activate
def test_paginate_stops_when_no_next_link(client):
    responses.get(f"{ORG}/api/v1/users", json=[{"id": "1"}])
    assert len(list(client.paginate("/api/v1/users"))) == 1
    assert len(responses.calls) == 1


@responses.activate
def test_paginate_ignores_self_and_prev_links(client):
    """A `rel="self"` link must not be mistaken for a next page.

    Okta sends self and prev links alongside next. Following the wrong one is an
    infinite loop, which is the specific bug this guards against.
    """
    responses.get(
        f"{ORG}/api/v1/users",
        json=[{"id": "1"}],
        headers={
            "Link": (
                f'<{ORG}/api/v1/users>; rel="self", '
                f'<{ORG}/api/v1/users?before=X>; rel="prev"'
            )
        },
    )
    assert [u["id"] for u in client.paginate("/api/v1/users")] == ["1"]
    assert len(responses.calls) == 1


@responses.activate
def test_paginate_does_not_resend_params_to_the_next_url(client):
    """The next URL already carries the cursor.

    Re-sending the original params would overwrite `after` and loop on page 1
    forever. This asserts the second request goes out exactly as Okta specified.
    """
    page2 = f"{ORG}/api/v1/users?after=CURSOR&limit=200"
    responses.get(
        f"{ORG}/api/v1/users",
        json=[{"id": "1"}],
        headers={"Link": f'<{page2}>; rel="next"'},
    )
    responses.get(page2, json=[{"id": "2"}])

    list(client.paginate("/api/v1/users", params={"limit": 200, "filter": "x"}))

    second = responses.calls[1].request
    assert "after=CURSOR" in second.url
    assert "filter=x" not in second.url


@responses.activate
def test_paginate_is_lazy_until_iterated(client):
    """Calling paginate() makes no request — it returns a generator.

    Worth pinning down: it's the most surprising property of generators for
    someone new to them.
    """
    responses.get(f"{ORG}/api/v1/users", json=[{"id": "1"}])
    generator = client.paginate("/api/v1/users")
    assert len(responses.calls) == 0
    next(generator)
    assert len(responses.calls) == 1


@responses.activate
def test_paginate_handles_object_response_without_iterating_keys(client):
    responses.get(f"{ORG}/api/v1/org", json={"id": "org1"})
    assert list(client.paginate("/api/v1/org")) == [{"id": "org1"}]


# ----------------------------------------------------------------- rate limits


@responses.activate
def test_429_sleeps_until_reset_then_retries(client, monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda seconds: slept.append(seconds))

    reset_at = time.time() + 8
    responses.get(
        f"{ORG}/api/v1/users",
        json={"errorSummary": "rate limit"},
        status=429,
        headers={"X-Rate-Limit-Reset": str(int(reset_at))},
    )
    responses.get(f"{ORG}/api/v1/users", json=[{"id": "1"}])

    assert list(client.paginate("/api/v1/users")) == [{"id": "1"}]
    assert len(slept) == 1
    # Roughly (reset - now) + 1s cushion, not a blind 60.
    assert 7 <= slept[0] <= 10


@responses.activate
def test_429_falls_back_to_retry_after_header(client, monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda seconds: slept.append(seconds))

    responses.get(
        f"{ORG}/api/v1/users", json={}, status=429, headers={"Retry-After": "3"}
    )
    responses.get(f"{ORG}/api/v1/users", json=[])

    list(client.paginate("/api/v1/users"))
    assert slept == [3.0]


@responses.activate
def test_429_with_past_reset_retries_almost_immediately(client, monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda seconds: slept.append(seconds))

    responses.get(
        f"{ORG}/api/v1/users",
        json={},
        status=429,
        headers={"X-Rate-Limit-Reset": str(int(time.time() - 30))},
    )
    responses.get(f"{ORG}/api/v1/users", json=[])

    list(client.paginate("/api/v1/users"))
    assert slept == [1.0]


@responses.activate
def test_sleep_is_capped_even_if_header_is_absurd(client, monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda seconds: slept.append(seconds))

    responses.get(
        f"{ORG}/api/v1/users",
        json={},
        status=429,
        headers={"X-Rate-Limit-Reset": str(int(time.time() + 99999))},
    )
    responses.get(f"{ORG}/api/v1/users", json=[])

    list(client.paginate("/api/v1/users"))
    assert slept[0] <= 120


@responses.activate
def test_persistent_429_eventually_raises(client, monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    for _ in range(6):
        responses.get(f"{ORG}/api/v1/users", json={}, status=429)

    with pytest.raises(OktaRateLimitError) as exc:
        list(client.paginate("/api/v1/users"))
    assert "429" in str(exc.value)


# --------------------------------------------------------------------- errors


@responses.activate
def test_401_explains_the_30_day_expiry(client):
    responses.get(
        f"{ORG}/api/v1/users",
        json={"errorSummary": "Invalid session"},
        status=401,
    )
    with pytest.raises(OktaAuthError) as exc:
        client.get("/api/v1/users")

    message = str(exc.value)
    assert "30 days" in message
    assert "Create Token" in message


@responses.activate
def test_403_explains_inherited_privileges(client):
    responses.get(f"{ORG}/api/v1/api-tokens", json={}, status=403)
    with pytest.raises(OktaAuthError) as exc:
        client.get("/api/v1/api-tokens")
    assert "privileges of the human who created it" in str(exc.value)


@responses.activate
def test_404_raises_not_found(client):
    responses.get(f"{ORG}/api/v1/eventHooks", json={}, status=404)
    with pytest.raises(OktaNotFoundError):
        client.get("/api/v1/eventHooks")


@responses.activate
def test_500_raises_generic_api_error(client):
    responses.get(f"{ORG}/api/v1/users", json={}, status=500)
    with pytest.raises(OktaAPIError):
        client.get("/api/v1/users")


@responses.activate
def test_error_message_never_contains_the_token(client):
    """Regression guard: a token leaked into a stack trace is a token in a log."""
    responses.get(f"{ORG}/api/v1/users", json={}, status=401)
    with pytest.raises(OktaAuthError) as exc:
        client.get("/api/v1/users")
    assert TOKEN not in str(exc.value)


@responses.activate
def test_get_optional_swallows_404_and_403(client):
    responses.get(f"{ORG}/api/v1/eventHooks", json={}, status=404)
    assert client.get_optional("/api/v1/eventHooks", default=[]) == []


@responses.activate
def test_paginate_optional_yields_nothing_on_404(client):
    responses.get(f"{ORG}/api/v1/inlineHooks", json={}, status=404)
    assert list(client.paginate_optional("/api/v1/inlineHooks")) == []


@responses.activate
def test_timeout_message_names_the_setting(client):
    responses.get(f"{ORG}/api/v1/users", body=requests.exceptions.Timeout())
    with pytest.raises(OktaAPIError) as exc:
        client.get("/api/v1/users")
    assert "OKTA_ORG_URL" in str(exc.value)
