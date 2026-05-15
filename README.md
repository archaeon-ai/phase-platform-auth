# phase-platform-auth

Reference implementation of the **PHASE Platform §2.6.1 JWT validation contract**.

`phase-platform-auth` is the single source of truth for how every PHASE-Platform
tool backend validates Auth0-issued access tokens. Every tool depends on this
library rather than reimplementing the contract; the audit history that motivated
the library is recorded in [CHANGELOG.md](./CHANGELOG.md).

## Status

v0.1.0 — Alpha. Public API may change before 1.0.

## Install

```bash
pip install phase-platform-auth
```

Until published to PyPI, install from GitHub:

```bash
pip install "phase-platform-auth @ git+https://github.com/archaeon-ai/phase-platform-auth"
```

## Usage

```python
from phase_platform_auth import Auth0Validator, AuthError, JWKSUnavailableError

validator = Auth0Validator(
    domain="auth.m2020-phase.net",
    audience="https://api.m2020-phase.net",
    identity_claim_uri="https://m2020-phase.net/claims/identity",
)

try:
    claims = validator.validate(token)  # → TokenClaims
except AuthError:
    # → 401 with WWW-Authenticate: Bearer realm="m2020-phase"
    ...
except JWKSUnavailableError:
    # → 503 (Auth0 unreachable + cache exhausted)
    ...
```

The validator handles the full §2.6.1 contract:

- RS256 only (rejects `HS*`, `none`, `ES*`)
- iss exact match including trailing slash
- aud array-shape required (scalar aud rejected)
- JWKS cache TTL 600s with single-shot kid-miss refresh
- 60s clock skew leeway
- iat required + 24h-future cap
- `typ` allowlist: `at+jwt` or absent
- required claims: `sub`, `iss`, `aud`, `exp`, `iat`, plus the configured
  `identity_claim_uri` (must be a list, may be empty)
- Failure logging never includes token contents

## What this library does NOT include

- **HTTP framework integration.** Tools wire the validator into their own
  framework (e.g. FastAPI dependency, Flask before-request, Worker `fetch`
  handler). The validator is plain Python.
- **Role-name semantics.** The validator returns `TokenClaims.roles` as a list
  of strings; it does not interpret `phase:team-member` vs `phase:admin`. Tools
  enforce role-per-API at their own gate.
- **Cookie-based session management.** This is the bearer-token contract. The
  PHASE viewer's session cookie model lives in `m2020-phase/viewer-worker/`.
- **Legacy auth shims.** No Cloudflare Access, no `SHERLOC_AUTH_MODE` selection,
  no dev mode. Each tool can still ship those locally if needed.

## Conformance testing

Downstream tools should run the package's conformance fixtures against their
own integration:

```python
from phase_platform_auth.testing import (
    rsa_keypair, mock_jwks_server, mint_token,
)
# See tests/test_validator.py for the full conformance suite.
```

## License

MIT — see [LICENSE](./LICENSE).
