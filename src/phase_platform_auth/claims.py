"""Normalized token claims returned by every TokenValidator.validate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """The §2.6.1 contract's normalized claim set.

    Attributes:
        sub: The token's ``sub`` claim. Required by §2.6.1; the validator
            rejects tokens missing it.
        email: The token's ``email`` claim if present. Optional per §2.6.1.
        roles: The contents of the configured ``identity_claim_uri`` claim,
            coerced to a list of strings. May be empty (an empty array means
            "valid token, no roles" — distinct from "claim missing").
        expires_at: The token's ``exp`` as a timezone-aware UTC datetime.
    """

    sub: str
    expires_at: datetime
    email: str | None = None
    roles: list[str] = field(default_factory=list)
