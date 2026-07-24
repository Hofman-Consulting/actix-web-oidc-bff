# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-24

Initial release: a Backend-for-Frontend (BFF) OIDC relying party for actix-web.
The OAuth 2.0 authorization-code flow runs entirely server-side; tokens never
reach the browser.

### Added

- OIDC authorization-code flow with **PKCE S256** (unconditional), single-use
  `state`, and nonce verification.
- ID-token validation restricted to asymmetric signing algorithms
  (RS*/PS*/ES*); `none` and `HS*` are rejected.
- Routes mounted via `configure`:
  - `GET /auth/login` — starts the flow and redirects to the IdP; optional
    validated `?return_to=/path`.
  - `GET /auth/callback` — code exchange, ID-token validation, and session
    establishment (with `session.renew()` against fixation).
  - `POST /auth/logout` — same-origin check, session purge, RP-initiated logout
    URL, and best-effort token revocation.
  - `GET /auth/me` — identity claims (`sub`, `iss`, `email`, `name`); never
    tokens.
- `Auth` request extractor for protecting downstream handlers, with support for
  extra persisted claims.
- Hardened session cookie middleware (`session_middleware`): `__Host-`-prefixed,
  `Secure`, `HttpOnly`, `SameSite=Lax`, configurable TTL.
- Bring-your-own session storage via the `SessionRepository` trait and
  `DbSessionStore` adapter, making sessions revocable server-side (no database
  dependency in the crate).
- Open-redirect defenses (`return_to` validation) and logout CSRF defenses
  (`Sec-Fetch-Site` with `Origin`/`Referer` origin comparison).
- Configuration from `OIDC_*` environment variables via
  `OidcBffConfig::from_env`.

[Unreleased]: https://github.com/Hofman-Consulting/actix-web-oidc-bff/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Hofman-Consulting/actix-web-oidc-bff/releases/tag/v0.1.0
