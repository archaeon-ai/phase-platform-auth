"""Test helpers for the §2.6.1 conformance suite.

These helpers let downstream tools run the same conformance tests against
their own validator integration. They are kept in the package (rather than
in ``tests/``) precisely so they can be re-used: the conformance audit
should be cheap to run, not something every tool re-implements.

Typical usage with ``pytest-httpx``::

    import pytest
    from phase_platform_auth import Auth0Validator
    from phase_platform_auth.testing import (
        gen_rsa_key, public_jwk, mint_token,
    )

    @pytest.fixture
    def signing_key():
        return gen_rsa_key()

    @pytest.fixture
    def mock_jwks(httpx_mock, signing_key):
        jwks = {"keys": [public_jwk(signing_key, kid="kid-1")]}
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/jwks.json",
            json=jwks,
        )

    def test_valid_token(mock_jwks, signing_key):
        validator = Auth0Validator(
            domain="auth.example.com",
            audience="https://api.example.com",
            identity_claim_uri="https://example.com/claims/identity",
        )
        token = mint_token(
            signing_key,
            kid="kid-1",
            issuer="https://auth.example.com/",
            audience=["https://api.example.com"],
            sub="user-123",
            identity_claim_uri="https://example.com/claims/identity",
            identity=["team-member"],
        )
        claims = validator.validate(token)
        assert claims.sub == "user-123"
        assert claims.roles == ["team-member"]
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def gen_rsa_key() -> rsa.RSAPrivateKey:
    """Generate a fresh 2048-bit RSA private key for test signing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a private key to PEM bytes (PyJWT input format)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    """Return a public JWK dict suitable for inclusion in a JWKS ``keys`` array."""
    public_numbers = private_key.public_key().public_numbers()

    def _b64url_uint(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return (
            base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()
        )

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }


def mint_token(
    private_key: rsa.RSAPrivateKey,
    *,
    kid: str,
    issuer: str,
    audience: Any,
    sub: str | None = "test-sub",
    email: str | None = "test@example.com",
    expires_in: int = 3600,
    iat_offset: int = 0,
    identity_claim_uri: str | None = None,
    identity: list[str] | None = None,
    azp: str | None = None,
    extra_claims: dict[str, Any] | None = None,
    typ: str | None = "at+jwt",
    algorithm: str = "RS256",
) -> str:
    """Mint a §2.6.1-shaped access-token JWT for testing.

    Defaults reflect the §2.6.1 happy path: ``typ="at+jwt"``, array-shaped
    ``audience``, ``sub`` present, valid ``iat`` and ``exp``. Tests exercise
    the failure paths by overriding these defaults — e.g.

    - Pass ``sub=None`` to omit the ``sub`` claim.
    - Pass ``audience="https://api.example.com"`` (string) to test scalar
      ``aud`` rejection.
    - Pass ``typ="JWT"`` to test the ``typ`` allowlist.
    - Pass ``algorithm="HS256"`` to test the algorithm allowlist (also
      switch to a symmetric secret).
    - Pass ``iat_offset=86400`` to push iat 24h into the future.

    Args:
        private_key: RSA key for signing. Use ``gen_rsa_key()``.
        kid: Key ID for the JWT header. Must match a JWK in the JWKS.
        issuer: ``iss`` claim value. Should match the validator's
            ``expected_issuer`` (note the trailing slash convention).
        audience: ``aud`` claim. Pass a list for §2.6.1-conforming shape;
            pass a string to test scalar-aud rejection. ``None`` produces
            ``aud=[]``.
        sub: ``sub`` claim. ``None`` omits the claim entirely.
        email: ``email`` claim. ``None`` omits.
        expires_in: ``exp`` offset from now in seconds.
        iat_offset: Offset added to ``iat`` (positive → future). Use this
            to test the 24h-future cap.
        identity_claim_uri: If set, adds an identity claim with the
            specified URI.
        identity: Value for the identity claim (list of strings, or
            ``None`` for an empty list).
        azp: ``azp`` claim. ``None`` omits.
        extra_claims: Additional claims to merge into the payload (after
            the canonical claims, so they can override iss/aud/etc. for
            negative testing).
        typ: ``typ`` header. ``None`` omits the header (PyJWT drops it).
        algorithm: Signing algorithm. RS256 by default; pass another value
            to test algorithm allowlist enforcement (caller may need to
            also switch keys).

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(UTC)
    if audience is None:
        audience = []
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "iat": int(now.timestamp()) + iat_offset,
    }
    if sub is not None:
        payload["sub"] = sub
    if email is not None:
        payload["email"] = email
    if identity_claim_uri is not None:
        payload[identity_claim_uri] = identity if identity is not None else []
    if azp is not None:
        payload["azp"] = azp
    if extra_claims:
        payload.update(extra_claims)
    headers: dict[str, Any] = {"kid": kid, "typ": typ}
    return pyjwt.encode(
        payload,
        key_to_pem(private_key),
        algorithm=algorithm,
        headers=headers,
    )


__all__ = [
    "gen_rsa_key",
    "key_to_pem",
    "mint_token",
    "public_jwk",
]
