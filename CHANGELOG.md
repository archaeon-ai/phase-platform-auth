# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-05-06

### Added

- `Auth0Validator` — reference §2.6.1 JWT validator (RS256-only, exact iss/aud
  pinning, JWKS cache TTL=600s with single-shot kid-miss refresh, 60s clock
  skew leeway, iat 24h-future cap, `typ` allowlist `{at+jwt, absent}`,
  required identity-claim URI as roles source).
- `TokenClaims` — frozen dataclass with `sub`, `email`, `roles`, `expires_at`.
- `TokenValidator` — Protocol; tools can compose their own implementations.
- `AuthError` / `JWKSUnavailableError` — exception types matching the §2.6.1
  401 vs 503 distinction.
- `build_www_authenticate(realm)` — header builder for missing-credential
  401 responses.
- `phase_platform_auth.testing` — RSA keypair fixture, JWKS-mock-server, and
  token-mint helpers so downstream tools can run the same conformance suite.

### Provenance

- Lifted from the §2.6.1-conformant validator in
  `kenwilliford/sherloc-pipeline-prep` (`src/sherloc_pipeline/web/auth.py`,
  HEAD `74db6c1` after Phase A Round 2 GO).
- Round 1 Codex `/code-review` against the SHERLOC patches found 3 Critical +
  1 Major + 1 Minor contract gaps that a 12-item self-audit had missed
  (m2020-phase `O-FROM-SHERLOC-003`); Round 2 closed all five. The library
  exists so the next PHASE-Platform tool does not re-pay that audit tax.
