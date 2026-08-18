# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-18

> **Breaking release.** Configuration moves from `OIDC_*` environment variables
> to `OidcBffConfig::builder()`.

> **Upgrading logs every user out, once.** Sessions created before this version
> carry no login timestamp and are treated as expired by the new absolute
> session lifetime. On deploy, every existing session is invalidated and every
> user must log in again.

> **A post-auth TTL above 7 days now refuses to boot.** A `post_auth_ttl`
> greater than `max_session_lifetime` (default 7 days) is a `build()` error.
> Values up to 365 days were accepted before, so such a deployment will fail to
> start until it either raises `max_session_lifetime` or lowers the post-auth
> TTL.

### Added

- `DbSessionStore::from_config(repo, &cfg)`: wires the pre-auth TTL and the
  absolute session lifetime from the config in one call. `DbSessionStore::new`
  silently keeps the crate's own defaults no matter what the config says;
  `from_config` is the way to avoid that.
- `impl FromStr for SessionExpiry`, parsing `"fixed"` / `"sliding"`
  case-insensitively (after trimming), so a consumer reading their own
  environment variable can still get a `SessionExpiry` without hand-rolling
  the match. Failure is a standalone `SessionExpiryParseError`, not a
  `ConfigError` — the crate itself never parses a `SessionExpiry` from a
  string, the builder takes the enum.
- `max_session_lifetime` (default 7 days): an absolute session lifetime. A
  login timestamp is stored in the session and the session dies at
  `login_at + max_lifetime` regardless of activity. Enforced in
  `DbSessionStore` (`load`, `save`, `update`, `update_ttl`) and — store
  agnostically — in the `Auth` extractor. Note that `DbSessionStore` must be
  told the configured value: use `DbSessionStore::from_config`, otherwise the
  store keeps its own 7-day default. With `CookieSessionStore` only the
  extractor check applies, so the bound holds solely for handlers that take the
  `Auth` extractor.
- `session_expiry` (`SessionExpiry::Fixed` | `SessionExpiry::Sliding`, default
  `Fixed`), with the enum re-exported from the crate root. `Fixed` keeps the
  post-auth TTL an absolute expiry from login; `Sliding` refreshes it on
  activity. `session_middleware` applies the policy to the underlying
  `actix-session` `PersistentSession`, which makes `SessionRepository::touch`
  reachable — it was previously documented as never invoked. Sliding expiry
  costs an extra session-store read per authenticated request and a
  `Set-Cookie` on every response; renewal writes are coalesced by
  `DbSessionStore` (default one write per 60 s of active use, configurable via
  `DbSessionStore::with_touch_coalesce_secs`). See the README security notes
  before enabling it.
- `pre_auth_ttl` and `post_auth_ttl` to configure session TTLs, previously
  hardcoded.

### Changed

- **BREAKING**: configuration is code-first. `OidcBffConfig::from_env()` and
  every `OIDC_*` environment variable are removed; `OidcBffConfig::builder()`
  is now the only construction path. Consumers that want environment variables
  read them themselves and hand the values to the builder.
  - Config fields are now private with public getters (`cfg.redirect_url()`,
    `cfg.scopes()`, `cfg.post_auth_ttl()`, …). `client_secret` has no getter.
  - TTL setters take `std::time::Duration` instead of `u64` seconds:
    `pre_auth_ttl`, `post_auth_ttl`, `max_session_lifetime`. Each must be a
    whole number of seconds and at least one second — a sub-second or
    fractional `Duration` is a `ConfigError::InvalidTtl`, not a silent
    truncation to `0`.
  - A required field set to an empty or whitespace-only value is reported as
    missing. `std::env::var` yielded `Ok("")` for `FOO=`, so `from_env()`
    could not tell the two apart; an empty `client_secret` only surfaced as
    an opaque token-endpoint rejection at first login.
  - The session key has no default. Pass `.session_key(key)` (an
    `actix_web::cookie::Key`, not raw bytes),
    `.session_key_base64(s)`, or opt in explicitly with
    `.generate_ephemeral_session_key()`. Previously a missing
    `OIDC_SESSION_KEY` was silently replaced by a random key with only a log
    warning — which logs every user out on restart and cannot work across
    replicas. That failure mode is now either impossible or explicit.
  - `ConfigError::MissingEnv` is replaced by
    `ConfigError::MissingFields(Vec<&'static str>)`, which reports every
    missing builder field at once; `ConfigError::InvalidSessionExpiry` is
    removed, because `session_expiry(..)` now takes the `SessionExpiry` enum
    directly — there is no string for `build()` to reject. String parsing did
    not disappear, it moved out of the config error space: `impl FromStr for
    SessionExpiry` (see Added) is a standalone helper for consumers reading
    their own configuration input, and reports failure as its own
    `SessionExpiryParseError`.
  - `jwks_ttl` is deliberately not settable and stays at 900 s. A long JWKS
    cache keeps revoked IdP signing keys trusted.
  - Setters are infallible; all validation — including every cross-field check
    — happens in `build()`.

  Migration, reproducing the old environment-variable behaviour by hand:

  ```rust,ignore
  // Before
  let cfg = OidcBffConfig::from_env()?;

  // After
  use std::{env, str::FromStr, time::Duration};

  let secs = |k: &str, d: u64| -> Duration {
      Duration::from_secs(env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d))
  };

  let mut b = OidcBffConfig::builder()
      .issuer_url(env::var("OIDC_ISSUER_URL")?)
      .client_id(env::var("OIDC_CLIENT_ID")?)
      .client_secret(env::var("OIDC_CLIENT_SECRET")?)
      .redirect_url(env::var("OIDC_REDIRECT_URL")?)
      .session_key_base64(&env::var("OIDC_SESSION_KEY")?)   // no longer optional
      .return_to_prefix(env::var("OIDC_RETURN_TO_PREFIX").unwrap_or_else(|_| "/".into()))
      .pre_auth_ttl(secs("OIDC_PRE_AUTH_TTL_SECS", 600))
      .post_auth_ttl(secs("OIDC_POST_AUTH_TTL_SECS", 28_800))
      .max_session_lifetime(secs("OIDC_MAX_SESSION_LIFETIME_SECS", 604_800));

  if let Ok(s) = env::var("OIDC_SCOPES") {
      b = b.scopes(s.split(',').map(str::trim).filter(|s| !s.is_empty()));
  }
  if let Ok(s) = env::var("OIDC_PERSIST_CLAIMS") {
      b = b.persist_claims(s.split(',').map(str::trim).filter(|s| !s.is_empty()));
  }
  if let Ok(u) = env::var("OIDC_POST_LOGOUT_REDIRECT_URL") {
      b = b.post_logout_redirect_url(u);
  }
  if let Ok(e) = env::var("OIDC_SESSION_EXPIRY") {
      b = b.session_expiry(SessionExpiry::from_str(&e)?);  // "fixed" / "sliding"
  }

  let cfg = b.build()?;
  ```

  The motivation is not only ergonomics. `OidcBffConfig`'s fields were `pub`,
  so every check `from_env()` performed could be trivially undone the line
  after it returned: `cfg.persist_claims.push("access_token".into())` makes the
  `Auth` extractor hand raw tokens to downstream handlers, and
  `cfg.cookie_secure = false` disables the https guard on logout token
  revocation. Validation that a caller can reverse is documentation, not
  enforcement. Closing the fields and funnelling construction through `build()`
  turns those documented invariants into type-system invariants.
- **BREAKING**: a `post_auth_ttl` greater than `max_session_lifetime` is
  rejected by `build()` (see the upgrade note above).
- **BREAKING**: the default `post_auth_ttl` is 8 hours; earlier builds
  defaulted to 12 hours.
- **BREAKING**: `ConfigError` is now `#[non_exhaustive]` — an exhaustive
  `match` on it needs a wildcard arm. It also gains an `InvalidTtl` variant
  (see the TTL validation notes above).
- `OidcBffConfig`'s fields are private, which is what closes external
  construction and destructuring — the struct is deliberately *not*
  `#[non_exhaustive]`, since private fields already provide that guarantee.
  `builder()` + `build()` is the only way to obtain one.

### Fixed

- `session_key_base64(..)` strips ASCII whitespace before decoding, so the
  output of `openssl rand -base64 64` — which wraps at column 64 — is accepted
  verbatim. A caller's `.trim()` removed only the trailing newline, so the
  documented happy path previously failed at startup with "not valid base64".
- `DbSessionStore::update_ttl` applied the full post-auth TTL to anonymous
  rows, bypassing the pre-auth TTL cap. It now reads the row first, applies the
  cap, and skips renewal entirely for anonymous sessions.

### Security

- The pre-auth TTL cap holds under sliding expiry. Because `update_ttl` runs
  for any unchanged session, an unauthenticated flood of `/auth/login` (rows
  correctly capped at `pre_auth_ttl`) followed by a request to any
  endpoint could previously extend every such row to the full post-auth TTL,
  voiding the documented session-store DoS mitigation.

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

[Unreleased]: https://github.com/Hofman-Consulting/actix-web-oidc-bff/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Hofman-Consulting/actix-web-oidc-bff/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Hofman-Consulting/actix-web-oidc-bff/releases/tag/v0.1.0
