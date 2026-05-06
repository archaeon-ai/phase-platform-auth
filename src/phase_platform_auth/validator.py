"""§2.6.1 Auth0 validator — the load-bearing class.

The class is the single source of truth for the §2.6.1 contract. Tools
should construct one per-process per-tenant and reuse it across requests.

Resolution order on every ``validate`` call:

1. ``typ`` header sanity (allowlist).
2. JWKS lookup (with single-shot kid-miss refresh on cached-but-stale).
3. PyJWT decode with ``algorithms=["RS256"]``, ``audience``, ``issuer``,
   ``leeway=60``, ``options={"require": [...]}``.
4. iat 24h-future cap (PyJWT's leeway covers small drift; this caps
   pathological future-dated tokens).
5. ``aud`` array-shape enforcement (PyJWT accepts scalar; §2.6.1 doesn't).
6. Optional ``azp`` check.
7. Required identity-claim presence + array-shape; coerce to roles list.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from phase_platform_auth.claims import TokenClaims
from phase_platform_auth.errors import AuthError, JWKSUnavailableError
from phase_platform_auth.jwks import (
    DEFAULT_JWKS_MAX_STALE_SECONDS,
    DEFAULT_JWKS_TTL_SECONDS,
    check_typ,
    fetch_jwks,
    find_signing_key,
)

logger = logging.getLogger(__name__)

# §2.6.1: iat sanity-cap to defend against pathological future-dated tokens.
# PyJWT's ``leeway=60`` rejects iat > now + 60s; this caps the worst case at
# 24h to keep the 60s clock-skew tolerance while still bounding the window.
IAT_FUTURE_CAP_SECONDS = 24 * 60 * 60


class TokenValidator(Protocol):
    """Validates an opaque token and returns ``TokenClaims`` or raises."""

    def validate(self, token: str) -> TokenClaims: ...


class Auth0Validator:
    """Reference §2.6.1 Auth0 OIDC JWT validator.

    Construct once per (domain, audience, identity_claim_uri) triple at
    process startup; reuse across requests. The instance holds no
    request-scoped state — the JWKS cache is module-level.

    Args:
        domain: Auth0 tenant domain (e.g. ``"auth.m2020-phase.net"``). The
            issuer is always ``f"https://{domain}/"`` per Auth0 convention,
            including the trailing slash. JWKS URL is
            ``f"https://{domain}/.well-known/jwks.json"``.
        audience: Expected ``aud`` value (e.g.
            ``"https://api.m2020-phase.net"``). Tokens whose ``aud`` array
            does not contain this value are rejected.
        identity_claim_uri: The custom claim URI that carries the user's
            identity / role list (e.g.
            ``"https://m2020-phase.net/claims/identity"``). Required by
            §2.6.1; the validator rejects tokens that do not carry this
            claim, or carry it as a non-list. Empty list is valid.
        jwks_cache_ttl: Override the default 600s JWKS cache TTL. Most tools
            should leave this at default; lower values increase request
            latency under JWKS rotation.
        jwks_max_stale_seconds: How long stale JWKS data is reused on
            upstream outage before validation switches to 503 mode.
        expected_azp: Optional pin on the ``azp`` claim. Useful for
            multi-SPA deployments where you want to restrict which client
            id originated the token.
        known_spa_client_ids: Optional list of SPA client ids; if provided,
            audience-rejected tokens whose ``aud`` matches a known SPA
            client id get an INFO log to help diagnose "ID-token-sent-as-
            access-token" misconfigurations. Does not change rejection.
    """

    def __init__(
        self,
        domain: str,
        audience: str,
        identity_claim_uri: str,
        *,
        jwks_cache_ttl: int = DEFAULT_JWKS_TTL_SECONDS,
        jwks_max_stale_seconds: int = DEFAULT_JWKS_MAX_STALE_SECONDS,
        expected_azp: str | None = None,
        known_spa_client_ids: list[str] | None = None,
    ) -> None:
        self.domain = domain
        self.audience = audience
        self.identity_claim_uri = identity_claim_uri
        self.jwks_cache_ttl = jwks_cache_ttl
        self.jwks_max_stale_seconds = jwks_max_stale_seconds
        self.expected_azp = expected_azp
        self.known_spa_client_ids = list(known_spa_client_ids or [])

    @property
    def jwks_url(self) -> str:
        return f"https://{self.domain}/.well-known/jwks.json"

    @property
    def expected_issuer(self) -> str:
        return f"https://{self.domain}/"

    def validate(self, token: str) -> TokenClaims:
        if not token:
            raise AuthError("Missing JWT")

        check_typ(token)

        jwks, source = fetch_jwks(
            self.jwks_url,
            ttl_seconds=self.jwks_cache_ttl,
            max_stale_seconds=self.jwks_max_stale_seconds,
        )
        try:
            signing_key = find_signing_key(token, jwks)
        except (PyJWKClientError, InvalidTokenError) as exc:
            # Stale-cache kid-miss = 503: token might be valid against the
            # current JWKS at the issuer; we can't tell. Mapping to 401
            # would mislead users into thinking their session was revoked.
            if source == "stale":
                raise JWKSUnavailableError(
                    f"JWKS unreachable; token kid not in stale cache for {self.jwks_url}"
                ) from exc
            if source == "cached":
                # §2.6.1 single-shot kid-miss refresh: defends against the
                # in-window key-rotation race where Auth0 publishes a new
                # key partway through our cache window.
                jwks, source = fetch_jwks(
                    self.jwks_url,
                    ttl_seconds=self.jwks_cache_ttl,
                    max_stale_seconds=self.jwks_max_stale_seconds,
                    force_refresh=True,
                )
                if source == "stale":
                    raise JWKSUnavailableError(
                        f"JWKS unreachable on kid-miss refresh for {self.jwks_url}"
                    ) from exc
                try:
                    signing_key = find_signing_key(token, jwks)
                except (PyJWKClientError, InvalidTokenError) as exc2:
                    raise AuthError(
                        f"Could not resolve signing key after refresh: {exc2}"
                    ) from exc2
            else:
                # source == "fresh": JWKS was just-fetched in this call;
                # another refresh would be redundant.
                raise AuthError(f"Could not resolve signing key: {exc}") from exc

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.expected_issuer,
                leeway=60,
                options={"require": ["exp", "iss", "aud", "iat", "sub"]},
            )
        except InvalidTokenError as exc:
            self._maybe_log_id_token_signal(token)
            raise AuthError(f"JWT validation failed: {exc}") from exc

        # §2.6.1: iat 24h-future cap.
        iat = int(claims["iat"])
        if iat > int(time.time()) + IAT_FUTURE_CAP_SECONDS:
            raise AuthError("JWT iat is more than 24h in the future")

        # §2.6.1: aud array-shape required. PyJWT accepts scalar aud by
        # default; reject post-decode.
        if not isinstance(claims.get("aud"), list):
            raise AuthError("JWT aud must be an array per §2.6.1")

        if self.expected_azp is not None:
            azp = claims.get("azp")
            if azp is not None and azp != self.expected_azp:
                raise AuthError(
                    f"JWT azp mismatch: got {azp!r}, expected {self.expected_azp!r}"
                )

        # §2.6.1: identity claim is required. Missing claim → 401. Non-list
        # value → 401. Empty list is valid.
        if self.identity_claim_uri not in claims:
            raise AuthError(f"Required identity claim missing: {self.identity_claim_uri}")
        identity_raw = claims[self.identity_claim_uri]
        if not isinstance(identity_raw, list):
            raise AuthError(f"Identity claim must be an array: {self.identity_claim_uri}")
        roles = [str(r) for r in identity_raw]

        return TokenClaims(
            sub=str(claims["sub"]),
            email=claims.get("email"),
            roles=roles,
            expires_at=datetime.fromtimestamp(int(claims["exp"]), tz=UTC),
        )

    def _maybe_log_id_token_signal(self, token: str) -> None:
        """If the rejected token's ``aud`` matches a known SPA client id,
        log INFO to help diagnose ID-token-sent-as-access-token errors.

        Heuristic only; does not change rejection behavior.
        """
        if not self.known_spa_client_ids:
            return
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return
        aud = unverified.get("aud")
        aud_values = [aud] if isinstance(aud, str) else list(aud or [])
        if any(c in aud_values for c in self.known_spa_client_ids):
            logger.info("rejected ID-token-shaped credential")
