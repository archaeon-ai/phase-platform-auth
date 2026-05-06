"""``WWW-Authenticate`` header builder for §2.6.1 401 responses.

Per §2.6.1: missing-credential 401 responses must surface
``WWW-Authenticate: Bearer realm="<realm>"``. The default realm for the
PHASE Platform is ``m2020-phase``; tools may override per deployment.
"""

from __future__ import annotations

DEFAULT_REALM = "m2020-phase"


def build_www_authenticate(realm: str = DEFAULT_REALM) -> dict[str, str]:
    """Return a ``{"WWW-Authenticate": ...}`` header dict.

    Args:
        realm: The Bearer realm. Defaults to ``"m2020-phase"`` per §2.6.1.

    Returns:
        A single-entry dict suitable for passing to a framework's response
        headers. Tools that compose multiple headers should merge into their
        own dict.
    """
    return {"WWW-Authenticate": f'Bearer realm="{realm}"'}
