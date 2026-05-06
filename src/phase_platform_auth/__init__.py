"""phase-platform-auth — reference §2.6.1 JWT validation contract.

Spec: PHASE Platform v1.0 Revised++ §2.6.1
(``kenwilliford/m2020-phase/docs/PHASE_PLATFORM_v1.0_SPEC-revised.md``).
"""

from phase_platform_auth.claims import TokenClaims
from phase_platform_auth.errors import AuthError, JWKSUnavailableError
from phase_platform_auth.headers import build_www_authenticate
from phase_platform_auth.validator import Auth0Validator, TokenValidator

__version__ = "0.1.0"

__all__ = [
    "Auth0Validator",
    "AuthError",
    "JWKSUnavailableError",
    "TokenClaims",
    "TokenValidator",
    "build_www_authenticate",
]
