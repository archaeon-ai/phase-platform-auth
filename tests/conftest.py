"""Shared fixtures for the §2.6.1 conformance suite.

The fixtures here are also exposed via ``phase_platform_auth.testing``
helpers so downstream tools can run the same conformance suite against
their own integrations.
"""

from __future__ import annotations

from typing import Any

import pytest

from phase_platform_auth import Auth0Validator
from phase_platform_auth.jwks import reset_cache_for_tests
from phase_platform_auth.testing import gen_rsa_key, public_jwk

DOMAIN = "auth.example.com"
AUDIENCE = "https://api.example.com"
IDENTITY_CLAIM_URI = "https://example.com/claims/identity"
JWKS_URL = f"https://{DOMAIN}/.well-known/jwks.json"
EXPECTED_ISSUER = f"https://{DOMAIN}/"


# Mock only the validator's JWKS endpoint; stray httpx calls (if any future
# code path makes them) pass through unmocked.
pytestmark = pytest.mark.httpx_mock(
    should_mock=lambda request: request.url.host == DOMAIN,
)


@pytest.fixture(autouse=True)
def _clear_jwks_cache() -> Any:
    reset_cache_for_tests()
    yield
    reset_cache_for_tests()


@pytest.fixture
def signing_key() -> Any:
    return gen_rsa_key()


@pytest.fixture
def jwks(signing_key: Any) -> dict[str, Any]:
    return {"keys": [public_jwk(signing_key, kid="kid-1")]}


@pytest.fixture
def mock_jwks_ok(httpx_mock: Any, jwks: dict[str, Any]) -> Any:
    httpx_mock.add_response(url=JWKS_URL, json=jwks)
    return httpx_mock


@pytest.fixture
def validator() -> Auth0Validator:
    return Auth0Validator(
        domain=DOMAIN,
        audience=AUDIENCE,
        identity_claim_uri=IDENTITY_CLAIM_URI,
    )
