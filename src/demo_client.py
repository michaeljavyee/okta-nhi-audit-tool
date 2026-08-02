"""A stand-in for OktaClient that serves bundled JSON fixtures.

WHY THIS EXISTS: an interviewer will clone the repo and run one command. They
will not create an Okta tenant. `--demo` has to produce the full report with
zero setup, which means every check must be able to run against fixture data.

WHY IT'S SHAPED LIKE THE REAL CLIENT: DemoClient exposes the same four methods
as OktaClient — get, paginate, get_optional, paginate_optional — so the checks
have no idea which one they were handed. That's duck typing: Python doesn't care
what class an object is, only that it has the methods being called. The payoff is
that there is exactly one code path through the checks, so `--demo` exercises the
real logic rather than a parallel implementation that can drift out of sync.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


class DemoClient:
    """Serves fixture JSON in response to Okta API paths."""

    def __init__(self, fixture_dir: Optional[Path] = None) -> None:
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR
        if not self.fixture_dir.exists():
            raise FileNotFoundError(
                f"Fixture directory not found: {self.fixture_dir}\n"
                "  Regenerate it with: python scripts/generate_fixtures.py"
            )
        self.org_url = "https://dev-00000000.okta.com"
        self._cache: Dict[str, Any] = {}

    # ---------------------------------------------------------------- internals

    def _load(self, name: str) -> Any:
        if name not in self._cache:
            path = self.fixture_dir / f"{name}.json"
            if not path.exists():
                raise FileNotFoundError(f"Missing fixture: {path}")
            self._cache[name] = json.loads(path.read_text())
        return self._cache[name]

    def _resolve(self, path: str) -> Any:
        """Map an Okta API path to fixture data.

        Returns the sentinel object `_MISSING` when the path isn't something the
        fixtures model, so get_optional can behave like a real 404.
        """
        path = path.split("?")[0].rstrip("/")

        simple = {
            "/api/v1/org": "org",
            "/api/v1/users": "users",
            "/api/v1/api-tokens": "api_tokens",
            "/api/v1/apps": "apps",
            "/api/v1/eventHooks": "event_hooks",
            "/api/v1/inlineHooks": "inline_hooks",
            "/api/v1/logs": "logs",
        }
        if path in simple:
            return self._load(simple[path])

        match = re.fullmatch(r"/api/v1/users/([^/]+)/roles", path)
        if match:
            return self._load("roles").get(match.group(1), [])

        match = re.fullmatch(r"/api/v1/users/([^/]+)/factors", path)
        if match:
            return self._load("factors").get(match.group(1), [])

        match = re.fullmatch(r"/api/v1/apps/([^/]+)/grants", path)
        if match:
            return self._load("grants").get(match.group(1), [])

        match = re.fullmatch(r"/api/v1/apps/([^/]+)/features", path)
        if match:
            features = self._load("app_features").get(match.group(1))
            # Okta genuinely 404s this endpoint for apps without provisioning,
            # so the demo does too — otherwise the 404 handling in the checks
            # would never be exercised in demo mode.
            return features if features is not None else _MISSING

        return _MISSING

    # ------------------------------------------------------------------- public

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        result = self._resolve(path)
        if result is _MISSING:
            raise FileNotFoundError(f"No demo fixture models {path}")
        return result

    def get_optional(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        default: Any = None,
    ) -> Any:
        result = self._resolve(path)
        return default if result is _MISSING else result

    def paginate(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        result = self.get(path, params=params)
        yield from _as_list(result)

    def paginate_optional(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        result = self._resolve(path)
        if result is _MISSING:
            return
        yield from _as_list(result)

    def verify_connection(self) -> Dict[str, Any]:
        return self._load("org")

    def close(self) -> None:  # parity with OktaClient
        pass

    def __enter__(self) -> "DemoClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class _Missing:
    """Sentinel for 'this path doesn't exist', distinct from a legitimate None.

    `None` is a valid fixture value, so we can't use it to mean "not found".
    A unique object solves that — this is the same trick the standard library
    uses for optional arguments that have no sensible default.
    """

    def __repr__(self) -> str:  # pragma: no cover
        return "<MISSING>"


_MISSING = _Missing()


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]
