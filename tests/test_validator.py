"""§2.6.1 conformance suite for ``Auth0Validator``.

Each test maps to a §2.6.1 contract item or one of the four Round 1 Codex
findings recorded in the m2020-phase ``HARNESS_LEARNINGS.md``
(``O-FROM-SHERLOC-003``):

- F1 — route-authz wiring: out of scope for the validator (lives in tools).
- F2 — ``sub`` required: ``test_missing_sub_rejected``.
- F3 — ``aud`` array shape: ``test_scalar_aud_rejected``.
- F4 — WWW-Authenticate realm: see ``test_headers.py``.
- F5 — failure logging negatives: tested in tools (the validator raises
       ``AuthError`` with no token contents; what the framework logs is
       framework-scope).

The fixtures (``signing_key``, ``mock_jwks_ok``, ``validator``) live in
``conftest.py`` and double as the ``phase_platform_auth.testing``
demonstration.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from phase_platform_auth import (
    Auth0Validator,
    AuthError,
    JWKSUnavailableError,
    TokenClaims,
)
from phase_platform_auth.testing import (
    gen_rsa_key,
    mint_token,
    public_jwk,
)

from .conftest import (
    AUDIENCE,
    DOMAIN,
    EXPECTED_ISSUER,
    IDENTITY_CLAIM_URI,
    JWKS_URL,
)

# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_token_returns_token_claims(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        sub="user-123",
        email="alice@example.com",
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=["team-member"],
    )

    claims = validator.validate(token)

    assert isinstance(claims, TokenClaims)
    assert claims.sub == "user-123"
    assert claims.email == "alice@example.com"
    assert claims.roles == ["team-member"]
    assert claims.expires_at > datetime.now(UTC)


def test_empty_identity_claim_is_valid(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """§2.6.1: identity claim 'array, may be empty' — empty array is valid."""
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    claims = validator.validate(token)
    assert claims.roles == []


# ---------------------------------------------------------------------------
# §2.6.1: empty / missing token
# ---------------------------------------------------------------------------


def test_empty_token_rejected(validator: Auth0Validator) -> None:
    with pytest.raises(AuthError, match="Missing JWT"):
        validator.validate("")


# ---------------------------------------------------------------------------
# §2.6.1: iss / aud
# ---------------------------------------------------------------------------


def test_wrong_issuer_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer="https://other-issuer.example.com/",
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError):
        validator.validate(token)


def test_wrong_audience_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=["https://other.example.com/api"],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError):
        validator.validate(token)


def test_scalar_aud_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """§2.6.1 F3: aud must be an array. Scalar aud is non-conforming."""
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=AUDIENCE,  # scalar, not [AUDIENCE]
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError, match="aud must be an array"):
        validator.validate(token)


def test_iss_trailing_slash_required(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """Auth0 issuer convention: trailing slash is part of the literal match."""
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=f"https://{DOMAIN}",  # no trailing slash
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError):
        validator.validate(token)


# ---------------------------------------------------------------------------
# §2.6.1: required claims (sub, exp, iat)
# ---------------------------------------------------------------------------


def test_missing_sub_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """§2.6.1 F2: sub is required. PyJWT must enforce via require=[..., 'sub']."""
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        sub=None,
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError):
        validator.validate(token)


def test_missing_identity_claim_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        # identity_claim_uri NOT set on this token
    )
    with pytest.raises(AuthError, match="Required identity claim missing"):
        validator.validate(token)


def test_non_list_identity_claim_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        extra_claims={IDENTITY_CLAIM_URI: "team-member"},  # string, not list
    )
    with pytest.raises(AuthError, match="must be an array"):
        validator.validate(token)


# ---------------------------------------------------------------------------
# §2.6.1: expiry / iat
# ---------------------------------------------------------------------------


def test_expired_token_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        expires_in=-3600,  # expired 1h ago
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError):
        validator.validate(token)


def test_clock_skew_leeway_within_60s(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """§2.6.1: 60s clock skew leeway. Token expired 30s ago is still accepted."""
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        expires_in=-30,  # expired 30s ago, inside 60s leeway
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    # Should NOT raise — within leeway.
    claims = validator.validate(token)
    assert claims.sub == "test-sub"


def test_iat_60s_future_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """§2.6.1: PyJWT's 60s leeway rejects iat > now + 60s.

    The validator's 24h iat cap is defense-in-depth — strictly stricter
    than PyJWT's leeway=60 — and only fires if the leeway check is bypassed
    (e.g., by a future regression that increases ``leeway`` to a pathological
    value). Under the §2.6.1-conforming configuration, the leeway check is
    what users actually hit; this test asserts it.
    """
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        iat_offset=300,  # 5min in the future, well past 60s leeway
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError):
        validator.validate(token)


# ---------------------------------------------------------------------------
# §2.6.1: typ allowlist
# ---------------------------------------------------------------------------


def test_typ_at_jwt_accepted(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        typ="at+jwt",
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    validator.validate(token)  # no raise


def test_typ_absent_accepted(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        typ=None,
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    validator.validate(token)  # no raise


def test_typ_jwt_rejected(
    signing_key: rsa.RSAPrivateKey,
    validator: Auth0Validator,
) -> None:
    """§2.6.1: 'JWT' typ value (used for ID tokens) is not in the allowlist.

    No JWKS fixture: ``check_typ`` runs before ``fetch_jwks`` so the network
    is never touched.
    """
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        typ="JWT",
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError, match="Unsupported JWT typ"):
        validator.validate(token)


# ---------------------------------------------------------------------------
# §2.6.1: algorithm allowlist (RS256 only)
# ---------------------------------------------------------------------------


def test_hs256_token_rejected(
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """§2.6.1: HS256 (and any non-RS256) must be rejected.

    Set ``typ="at+jwt"`` explicitly so ``check_typ`` allows it through to
    PyJWT.decode, where the algorithm allowlist enforcement actually fires.
    """
    payload = {
        "iss": EXPECTED_ISSUER,
        "aud": [AUDIENCE],
        "sub": "test-sub",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        IDENTITY_CLAIM_URI: [],
    }
    token = pyjwt.encode(
        payload,
        "shared-secret-at-least-32-bytes-long-for-hs256",
        algorithm="HS256",
        headers={"kid": "kid-1", "typ": "at+jwt"},
    )
    with pytest.raises(AuthError):
        validator.validate(token)


# ---------------------------------------------------------------------------
# §2.6.1: signature integrity
# ---------------------------------------------------------------------------


def test_invalid_signature_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    validator: Auth0Validator,
) -> None:
    """Token signed with a different key but advertising the same kid → reject."""
    other_key = gen_rsa_key()
    token = mint_token(
        other_key,  # signed by a different key
        kid="kid-1",  # but advertising kid-1, which is the JWKS's key
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError):
        validator.validate(token)


# ---------------------------------------------------------------------------
# §2.6.1: JWKS single-shot kid-miss refresh
# ---------------------------------------------------------------------------


def test_kid_miss_triggers_single_shot_refresh(
    httpx_mock: Any,
    signing_key: rsa.RSAPrivateKey,
    validator: Auth0Validator,
) -> None:
    """§2.6.1: on kid-miss within a cached JWKS, refresh once before failing.

    Defends against the in-window key-rotation race where Auth0 publishes a
    new key partway through our 600s cache: without single-shot refresh,
    requests with the new kid would 401 spuriously until TTL elapses.
    """
    # First fetch: JWKS with kid-1 only (cached).
    first_jwks = {"keys": [public_jwk(signing_key, kid="kid-1")]}
    httpx_mock.add_response(url=JWKS_URL, json=first_jwks)

    # Prime the cache by validating a token with kid-1 first.
    primer_token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    validator.validate(primer_token)  # populates the cache

    # New key rotated in.
    new_key = gen_rsa_key()
    second_jwks = {
        "keys": [
            public_jwk(signing_key, kid="kid-1"),
            public_jwk(new_key, kid="kid-2"),
        ]
    }
    # Single-shot refresh expects exactly one more JWKS fetch on kid-miss.
    httpx_mock.add_response(url=JWKS_URL, json=second_jwks)

    # Token with the NEW kid should validate via single-shot refresh.
    rotated_token = mint_token(
        new_key,
        kid="kid-2",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=["team-member"],
    )
    claims = validator.validate(rotated_token)
    assert claims.roles == ["team-member"]


# ---------------------------------------------------------------------------
# §2.6.1: JWKS outage = 503, not 401
# ---------------------------------------------------------------------------


def test_jwks_unreachable_no_cache_raises_unavailable(
    httpx_mock: Any,
    signing_key: rsa.RSAPrivateKey,
    validator: Auth0Validator,
) -> None:
    """No cache + JWKS endpoint failing → JWKSUnavailableError (503), not AuthError (401)."""
    httpx_mock.add_response(url=JWKS_URL, status_code=503)
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(JWKSUnavailableError):
        validator.validate(token)


def test_stale_cache_kid_miss_raises_unavailable(
    httpx_mock: Any,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Stale-cache kid-miss = service outage (503), not invalid token (401).

    Mapping this to 401 would mislead users into thinking their session was
    revoked when actually Auth0 is unreachable mid-rotation.
    """
    # Validator with a very short stale window so we can exercise stale path.
    v = Auth0Validator(
        domain=DOMAIN,
        audience=AUDIENCE,
        identity_claim_uri=IDENTITY_CLAIM_URI,
        jwks_cache_ttl=0,  # always re-validate
        jwks_max_stale_seconds=86400,
    )
    # First fetch succeeds, populates cache.
    httpx_mock.add_response(url=JWKS_URL, json={"keys": [public_jwk(signing_key, kid="kid-1")]})
    primer = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    v.validate(primer)

    # Now JWKS endpoint goes down. With ttl=0, validator tries to refresh
    # and falls back to stale cache. Token with NEW kid (not in stale set)
    # → 503, not 401.
    httpx_mock.add_response(url=JWKS_URL, status_code=503)
    new_key = gen_rsa_key()
    rotated = mint_token(
        new_key,
        kid="kid-99",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(JWKSUnavailableError):
        v.validate(rotated)


# ---------------------------------------------------------------------------
# §2.6.1: optional azp pinning
# ---------------------------------------------------------------------------


def test_azp_match_accepted(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
) -> None:
    v = Auth0Validator(
        domain=DOMAIN,
        audience=AUDIENCE,
        identity_claim_uri=IDENTITY_CLAIM_URI,
        expected_azp="my-spa-client-id",
    )
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        azp="my-spa-client-id",
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    v.validate(token)  # no raise


def test_azp_mismatch_rejected(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
) -> None:
    v = Auth0Validator(
        domain=DOMAIN,
        audience=AUDIENCE,
        identity_claim_uri=IDENTITY_CLAIM_URI,
        expected_azp="my-spa-client-id",
    )
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=[AUDIENCE],
        azp="some-other-spa",
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with pytest.raises(AuthError, match="azp mismatch"):
        v.validate(token)


# ---------------------------------------------------------------------------
# ID-token-shaped credential signal (diagnostic, does not change rejection)
# ---------------------------------------------------------------------------


def test_id_token_signal_logged(
    signing_key: rsa.RSAPrivateKey,
    mock_jwks_ok: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Audience-rejected token whose aud matches a known SPA client id logs INFO."""
    v = Auth0Validator(
        domain=DOMAIN,
        audience=AUDIENCE,
        identity_claim_uri=IDENTITY_CLAIM_URI,
        known_spa_client_ids=["spa-client-xyz"],
    )
    # Token's aud is the SPA client id (ID token shape) — wrong audience for
    # this validator, but the misuse hint should fire.
    token = mint_token(
        signing_key,
        kid="kid-1",
        issuer=EXPECTED_ISSUER,
        audience=["spa-client-xyz"],
        identity_claim_uri=IDENTITY_CLAIM_URI,
        identity=[],
    )
    with caplog.at_level(logging.INFO, logger="phase_platform_auth.validator"):
        with pytest.raises(AuthError):
            v.validate(token)
    assert any("ID-token-shaped credential" in r.message for r in caplog.records)
