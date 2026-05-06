"""Exception types for the §2.6.1 validation contract.

The 401-vs-503 distinction is load-bearing per §2.6.1: a token that fails
validation gets 401; an upstream JWKS outage that prevents validation gets
503. Conflating them misleads users into thinking their session was revoked
when actually Auth0 is unreachable.
"""

from __future__ import annotations


class AuthError(Exception):
    """Raised when a token fails validation.

    Maps to HTTP 401 in the consuming framework. Per §2.6.1 the failure must
    be logged with a reason code only — never with token contents.
    """


class JWKSUnavailableError(Exception):
    """Raised when the JWKS endpoint cannot be reached and no usable cache exists.

    Maps to HTTP 503 in the consuming framework, never 401. Distinguishes
    "Auth0 is currently unreachable" from "this token is invalid."
    """
