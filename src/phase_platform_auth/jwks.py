"""JWKS fetch + cache for the §2.6.1 contract.

The cache is per-process, keyed by JWKS URL so distinct issuers cannot share
entries. On a fetch failure the cache is reused within a configurable
max-stale window; outside that window — or with no cache at all —
``JWKSUnavailableError`` is raised so callers surface HTTP 503 (not 401).

Single-shot kid-miss refresh (§2.6.1) is implemented in the validator, not
here, because only the validator knows whether a kid lookup actually failed
against this specific JWKS dict.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx
import jwt
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from phase_platform_auth.errors import AuthError, JWKSUnavailableError

logger = logging.getLogger(__name__)

DEFAULT_JWKS_TTL_SECONDS = 600
DEFAULT_JWKS_MAX_STALE_SECONDS = 86_400
JWKS_FETCH_TIMEOUT_SECONDS = 5.0

# §2.6.1: ``typ`` allowlist. Auth0 emits ``at+jwt`` (RFC 9068); tokens
# without ``typ`` are also acceptable for compatibility with non-Auth0
# issuers. Any other value is a token-shape we do not validate.
ALLOWED_TYP_VALUES = frozenset({"at+jwt"})

_jwks_cache: dict[str, dict[str, Any]] = {}
_jwks_lock = threading.Lock()


def _do_fetch_jwks(url: str) -> dict[str, Any]:
    """Fetch a JWKS URL and shape-validate the response."""
    response = httpx.get(url, timeout=JWKS_FETCH_TIMEOUT_SECONDS)
    response.raise_for_status()
    body = response.json()
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("keys"), list)
        or not body["keys"]
    ):
        raise ValueError("JWKS response missing 'keys' list or empty")
    return body


def fetch_jwks(
    jwks_url: str,
    *,
    ttl_seconds: int = DEFAULT_JWKS_TTL_SECONDS,
    max_stale_seconds: int = DEFAULT_JWKS_MAX_STALE_SECONDS,
    force_refresh: bool = False,
) -> tuple[dict[str, Any], str]:
    """Fetch (and cache) a JWKS dict for ``jwks_url``.

    Behavior:

    - Cache hit AND not expired AND not ``force_refresh`` →
      ``(jwks, "cached")``.
    - Cache miss OR expired OR ``force_refresh`` → attempt fresh fetch:

      - Success → cache it; ``(jwks, "fresh")``.
      - HTTP error / timeout / malformed body, but cache is within
        ``max_stale_seconds`` of last successful fetch → reuse stale cache,
        log WARNING, return ``(jwks, "stale")``. Callers that look up a
        ``kid`` not present in stale JWKS MUST treat that as a service
        outage (503), not invalid token (401).
      - Otherwise → ``JWKSUnavailableError``.

    Args:
        jwks_url: The JWKS endpoint URL.
        ttl_seconds: How long a fresh fetch is considered current. §2.6.1
            specifies 600s (10 min).
        max_stale_seconds: How long after the last successful fetch the
            cache is reused on upstream failure.
        force_refresh: Bypass the TTL check and fetch fresh. Used by the
            validator for single-shot kid-miss refresh.

    Returns:
        ``(jwks_dict, source)`` where ``source`` ∈ ``{"cached", "fresh",
        "stale"}``. The source signal lets the caller decide whether a
        kid-miss should be retried with ``force_refresh=True``.
    """
    now = time.monotonic()
    cached = _jwks_cache.get(jwks_url)

    if (
        not force_refresh
        and cached is not None
        and (now - cached["fetched_at"]) < ttl_seconds
    ):
        return cached["jwks"], "cached"

    try:
        jwks = _do_fetch_jwks(jwks_url)
    except Exception as exc:
        if cached is not None and (now - cached["fetched_at"]) < max_stale_seconds:
            age = int(now - cached["fetched_at"])
            logger.warning(
                "JWKS refresh failed, using stale key (age=%ds) for %s: %s",
                age,
                jwks_url,
                exc,
            )
            return cached["jwks"], "stale"
        raise JWKSUnavailableError(f"JWKS unavailable for {jwks_url}: {exc}") from exc

    with _jwks_lock:
        _jwks_cache[jwks_url] = {"jwks": jwks, "fetched_at": now}
    return jwks, "fresh"


def check_typ(token: str) -> None:
    """Reject tokens whose ``typ`` header is not ``at+jwt`` or absent.

    Per §2.6.1: any other ``typ`` value (e.g. ``"JWT"`` for ID tokens or
    ``"id+jwt"`` extensions) → reject, since they signal a token shape we
    do not validate.

    Raises:
        AuthError: If the JWT header is unreadable or has a non-allowed
            ``typ`` value.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except InvalidTokenError as exc:
        raise AuthError(f"Cannot read JWT header: {exc}") from exc
    typ = unverified_header.get("typ")
    if typ is not None and typ not in ALLOWED_TYP_VALUES:
        raise AuthError(f"Unsupported JWT typ: {typ!r}")


def find_signing_key(token: str, jwks: dict[str, Any]) -> Any:
    """Resolve the signing key for ``token`` from a JWKS dict, by ``kid``.

    Raises:
        PyJWKClientError: If the token header is unreadable, missing
            ``kid``, or no key in the JWKS matches.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except InvalidTokenError as exc:
        raise PyJWKClientError(f"Cannot read JWT header: {exc}") from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise PyJWKClientError("JWT header missing 'kid'")

    for key_dict in jwks.get("keys", []):
        if key_dict.get("kid") == kid:
            return jwt.PyJWK(key_dict).key
    raise PyJWKClientError(f"No matching key for kid={kid!r}")


def reset_cache_for_tests() -> None:
    """Clear the in-process JWKS cache. Test-only helper."""
    with _jwks_lock:
        _jwks_cache.clear()
