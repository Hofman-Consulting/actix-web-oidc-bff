# actix-web-oidc-bff

Backend-for-Frontend (BFF) OIDC relying party for [actix-web].

The OAuth 2.0 authorization-code + PKCE flow happens entirely server-side:
tokens never reach the browser. The cookie carries only a session reference;
identity and tokens live in a server-managed session.

[actix-web]: https://actix.rs

## Features

- **Provider-agnostic**: standard OIDC discovery; works with Keycloak,
  Auth0, Entra ID, Zitadel, etc.
- **PKCE S256 unconditionally**, single-use `state`, nonce verification, and
  ID-token validation restricted to asymmetric algorithms (RS*/PS*/ES*;
  `none` and `HS*` are rejected).
- **Session hardening**: `__Host-`-prefixed, `Secure`, `HttpOnly`,
  `SameSite=Lax` cookie via the bundled `session_middleware` helper;
  `session.renew()` on session establishment against fixation; pre-auth state expires after a
  configurable TTL.
- **Code-first configuration**: no environment variables, no config file
  parsing — `OidcBffConfig::builder()` is the only construction path, and
  `build()` validates the whole config at once (see
  [Configuration](#configuration)).
- **Configurable session TTLs**: pre-auth and post-auth lifetimes are set as
  `std::time::Duration`, expiry is either `SessionExpiry::Fixed` (absolute from
  login) or `SessionExpiry::Sliding` (on activity), and an absolute session
  lifetime bounds the session either way (see [Security
  notes](#security-notes)).
- **Open-redirect & CSRF defenses**: strict `return_to` validation;
  `Sec-Fetch-Site`/`Origin` checks on logout.
- **RP-initiated logout**: `POST /auth/logout` purges the session and returns
  the provider's end-session URL (with `id_token_hint`) when advertised.
- **Bring-your-own session store**: implement `SessionRepository` over
  Postgres/Redis/… to make sessions revocable server-side; the crate has no
  database dependency.

## Routes

| Route | Method | Purpose |
|---|---|---|
| `/auth/login` | GET | Start the flow; redirects to the IdP. Optional `?return_to=/path`. |
| `/auth/logout` | POST | Same-origin check, purge session, return IdP logout URL (200) or 204. |
| `/auth/callback` | GET | Code exchange, ID-token validation, session establishment. |
| `/auth/me` | GET | Identity claims (`sub`, `iss`, `email`, `name`) — never tokens. |

## Quickstart

```rust,ignore
use std::sync::Arc;
use std::time::Duration;
use actix_web::{App, HttpServer};
use actix_session::storage::CookieSessionStore;
use actix_web_oidc_bff as bff;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Secrets come from files here; see "Secrets and keys" below.
    let client_secret = std::fs::read_to_string("/run/secrets/oidc_client_secret")?;
    let session_key_b64 = std::fs::read_to_string("/run/secrets/oidc_session_key")?;

    let cfg = Arc::new(
        bff::OidcBffConfig::builder()
            .issuer_url("https://idp.example.com")
            .client_id("my-client")
            .client_secret(client_secret.trim())
            .redirect_url("https://app.example.com/auth/callback")
            .session_key_base64(session_key_b64.trim())
            .scopes(["openid", "profile", "email", "groups"])
            .persist_claims(["groups"])
            .return_to_prefix("/app")
            .post_logout_redirect_url("https://app.example.com/bye")
            .pre_auth_ttl(Duration::from_secs(600))
            .post_auth_ttl(Duration::from_secs(8 * 3600))
            .max_session_lifetime(Duration::from_secs(7 * 24 * 3600))
            // session_expiry is left at its default, SessionExpiry::Fixed.
            // Sliding is only safe to enable with DbSessionStore — see
            // "Wiring the session store".
            .build()
            .expect("OIDC config"),
    );
    let rp = Arc::new(bff::OidcRp::discover(&cfg).await.expect("OIDC discovery"));

    HttpServer::new(move || {
        App::new()
            .wrap(bff::session_middleware(CookieSessionStore::default(), &cfg))
            .configure(|sc| bff::configure_app_data(sc, rp.clone(), cfg.clone()))
            .configure(bff::configure)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Protect downstream handlers with the extractor:

```rust,ignore
async fn protected(auth: bff::Auth) -> String {
    format!("hello {}", auth.subject)
}
```

> **Register `configure_app_data` at `App` level, not inside a `web::scope(..)`.**
> The `Auth` extractor looks up `OidcBffConfig` in `app_data` to apply the
> absolute session-lifetime check. When it is not there, the extractor fails
> **open**: it logs a warning once and skips that check, rather than returning
> 401. That is deliberate — a wiring mistake should not turn into a total
> outage — but it means scoping `configure_app_data` narrower than the routes
> that take `Auth` silently disables the absolute-lifetime bound for every
> handler outside that scope, with only a single log line to show for it.

> **Warning: `CookieSessionStore` is for local experimentation only.**
> The quickstart above uses it for brevity, but it is **not** a supported
> production configuration:
>
> - It serializes the entire session — including the `access_token`,
>   `refresh_token`, and `id_token` — into the encrypted session cookie. The
>   tokens therefore *do* reach the browser (as ciphertext), which voids this
>   crate's "tokens never reach the browser" model.
> - There is **no server-side revocation**: `POST /auth/logout` /
>   `session.purge()` cannot invalidate an already-issued cookie. It stays valid
>   until its TTL expires.
> - Pre-auth state for concurrent logins (up to 5 slots) can exceed the ~4 KB
>   browser cookie limit and silently break login.
>
> Production deployments must use `DbSessionStore` backed by a
> [`SessionRepository`](#features) implementation (see the
> **Bring-your-own session store** feature), which keeps tokens server-side and
> makes sessions revocable.

## Configuration

`OidcBffConfig::builder()` is the only way to construct a config. Setters are
infallible; all validation happens in `build()`, which returns `ConfigError`.

| Setter | Required | Default | Description |
|---|---|---|---|
| `issuer_url(..)` | yes | — | Issuer URL used for discovery. |
| `client_id(..)` | yes | — | OAuth client id. |
| `client_secret(..)` | yes | — | OAuth client secret (confidential client). No public getter — the config will not hand it back. |
| `redirect_url(..)` | yes | — | Public URL of `/auth/callback`. Its scheme decides cookie security (`https` → `__Host-` + `Secure`); its origin is the CSRF reference origin. |
| `session_key(..)` / `session_key_base64(..)` | yes* | — | 64 CSPRNG bytes of key material. `session_key(..)` takes an already-constructed `actix_web::cookie::Key` (not a byte slice); `session_key_base64(..)` takes anything `AsRef<str>` that base64-decodes to at least 64 bytes. ASCII whitespace is stripped before decoding, so line-wrapped `openssl rand -base64 64` output works verbatim. |
| `generate_ephemeral_session_key()` | yes* | — | Explicit opt-in to a random per-process key. Every restart logs all users out and no two replicas agree — single-process development only. |
| `scopes(..)` | no | `openid`, `profile`, `email` | Any `IntoIterator` of strings; `openid` is always included. |
| `return_to_prefix(..)` | no | `/` | Safe path prefix for post-login redirects; must start with `/`. |
| `persist_claims(..)` | no | empty | Extra ID-token claims to copy into the session (e.g. `["groups", "amr"]`). Reserved internal names and OIDC validation artifacts are rejected. |
| `post_logout_redirect_url(..)` | no | unset | Sent as `post_logout_redirect_uri` during RP-initiated logout; must be registered at the IdP. |
| `pre_auth_ttl(..)` | no | 600 s | Pre-auth (state/PKCE) session TTL. See [TTL rules](#ttl-rules) below. |
| `post_auth_ttl(..)` | no | 8 h | Authenticated session TTL. Additionally must be **at most `max_session_lifetime`** — a larger value fails `build()`. |
| `max_session_lifetime(..)` | no | 7 days | Absolute session lifetime, measured from login. The session dies at `login_at + this`, whatever the expiry policy or ongoing activity. |
| `session_expiry(..)` | no | `SessionExpiry::Fixed` | `Fixed` (post-auth TTL counts down from login) or `Sliding` (TTL refreshed on every authenticated request). See [Security notes](#security-notes). |

\* One of the three session-key setters is required; there is no default key.

Fields are private. Read them back through the getters — `cfg.redirect_url()`,
`cfg.scopes()`, `cfg.post_auth_ttl()` (a `Duration`), and so on. `client_secret`
has no getter by design. The JWKS cache TTL is fixed at 900 s and deliberately
not settable: a long JWKS cache keeps revoked IdP signing keys trusted.

### TTL rules

`pre_auth_ttl`, `post_auth_ttl`, and `max_session_lifetime` each take a
`std::time::Duration` that must be:

- **a whole number of seconds** — a fractional `Duration` is rejected with
  `ConfigError::InvalidTtl` rather than truncated. `Duration::from_millis(600)`
  is not `Duration::ZERO`, so a zero-check alone would pass it through and
  `as_secs()` would then yield `0`; a zero `pre_auth_ttl` expires every pre-auth
  slot the instant it is written, breaking login with no error anywhere.
- **at least one second**, and **at most 365 days**. The upper bound catches a
  units mistake in one direction (`from_secs(600_000)` when you meant minutes),
  the lower bound catches the same mistake in the other
  (`from_millis(600)` when you meant seconds).

### Blank required fields are missing fields

A required setter given an empty or whitespace-only string counts as not called
at all: it is reported in `ConfigError::MissingFields` alongside the setters you
genuinely omitted. This matters when the values come from somewhere that cannot
distinguish "unset" from "set to empty" — `std::env::var` returns `Ok("")` for
`FOO=`. An empty `client_secret` would otherwise surface as an opaque
token-endpoint rejection at first login, and an empty `issuer_url` as a
discovery failure at startup — both a long way from the actual mistake.

### Reading your own environment variables

Nothing stops you from sourcing values from the environment — the crate just
does not do it for you, so the parsing and its failure modes are yours:

```rust,ignore
use std::str::FromStr;

let expiry = match std::env::var("APP_SESSION_EXPIRY") {
    Ok(s) => bff::SessionExpiry::from_str(&s)?,   // "fixed" / "sliding", case-insensitive
    Err(_) => bff::SessionExpiry::Fixed,
};
```

### Standing rule: never derive `Deserialize` or `Default` on `OidcBffConfig`

"Add TOML/YAML support" is the obvious next request now that env parsing is
gone. Do not answer it with a `#[derive(Deserialize)]` on `OidcBffConfig`: a
deserializer constructs the struct field by field and bypasses `build()`, and
`build()` is where every cross-field invariant lives (post-auth TTL ≤ max
lifetime, no https→http downgrade on the post-logout URL, reserved claim names,
`return_to_prefix` validation, session-key length). `Default` is the same
problem with a friendlier name — it would resurrect the "sane-looking config
nobody validated" path. Deserialize into your own DTO, then feed the builder.

## Secrets and keys

The crate no longer reads secrets from anywhere; the sourcing decision is
yours. Ranked, worst to best:

- **Compiled-in literal — never.** It is recoverable from the binary with
  `strings`, it lands in version control, it is present in every build artifact
  and every registry that stores them, and rotating it requires a rebuild and a
  redeploy. There is no threat model in which this is acceptable.
- **Environment variable — acceptable, with caveats.** It is readable via
  `/proc/<pid>/environ` by anything running as the same uid, inherited by every
  child process you spawn, dumped verbatim by many crash reporters and APM
  agents, and visible to anyone with `kubectl describe pod` or
  `docker inspect`. Use it when the alternatives are not available, and keep it
  out of shell history and process arguments.
- **File or secret manager — preferred.** A Kubernetes secret volume, systemd
  `LoadCredential=`, or a vault SDK: the value is not inherited by child
  processes, does not appear in `environ`, is revocable by remounting or
  re-fetching without a restart, and filesystem permissions enforce isolation
  between uids.

Every example in this README reads the secret from a file or the environment,
never from a literal. Keep it that way in your own code.

**The session key** is the other piece of secret material and has stricter
rules than the client secret:

- **64 bytes from a CSPRNG.** It is the master key for the session cookie —
  `openssl rand -base64 64` or equivalent. Shorter or non-random input fails
  `build()` or weakens every session it protects.
- **Identical across all replicas.** A cookie sealed by one instance must be
  readable by the next one the load balancer picks. Per-replica keys look like
  random intermittent logouts.
- **Stored in the same secret store as the client secret**, with the same
  handling rules — it is not configuration, it is a key.
- **Rotating it invalidates every live session.** All users are logged out at
  the moment the new key takes effect. Plan rotations accordingly.

`generate_ephemeral_session_key()` exists so that "I did not think about the
key" cannot happen silently: it is a per-process random key, it logs everyone
out on restart, and it cannot work behind more than one replica. Use it in
development only.

## Wiring the session store

`DbSessionStore::from_config(repo, &cfg)` takes the pre-auth TTL and the
absolute session lifetime from the config in one call:

```rust,ignore
let store = bff::DbSessionStore::from_config(repo, &cfg);

App::new().wrap(bff::session_middleware(store, &cfg))
```

`DbSessionStore::new(repo)` still exists and still uses the crate's own
defaults (7-day max lifetime, 600 s pre-auth TTL) — it does **not** read the
config. That is a footgun: with `new`, setting
`.max_session_lifetime(Duration::from_secs(3600))` bounds only the `Auth`
extractor check, while the stored session row keeps living for the store's
7-day default. Prefer `from_config`. Only `post_auth_ttl` and `session_expiry`
are applied automatically, by `session_middleware`.

`SessionExpiry::Sliding` belongs here rather than in the quickstart: it is only
fully enforced with a store-side check, so pair it with `DbSessionStore`.

```rust,ignore
let cfg = bff::OidcBffConfig::builder()
    // …
    .session_expiry(bff::SessionExpiry::Sliding)
    .build()?;
```

Under `SessionExpiry::Sliding`, `DbSessionStore::with_touch_coalesce_secs`
(default 60 s) controls how often TTL renewals hit the repository; see
[Security notes](#security-notes).

## Security notes

- **Config invariants are type-system invariants.** `OidcBffConfig`'s fields
  are private and there are no setters after `build()`, so a validation that
  `build()` performed cannot be undone at runtime — nothing downstream can
  append `access_token` to `persist_claims` or flip the cookie's `Secure`
  flag off.
- **Tokens stay server-side.** `access_token`, `refresh_token`, and
  `id_token` are stored in the session and are never exposed by `/auth/me` or
  the `Auth` extractor.
- **Encrypt the session store at rest.** With `DbSessionStore`, the session
  state (which includes bearer tokens) is stored as JSON in *your*
  repository — treat it as secret material.
- **`return_to` validation** rejects anything that isn't a printable-ASCII
  absolute path under the configured prefix, plus `//`, `\`, and `:/`
  sequences (protocol-relative, backslash-normalization, and scheme attacks).
- **Logout CSRF** is mitigated via `Sec-Fetch-Site` (modern browsers) with
  `Origin`/`Referer` origin comparison as fallback, measured against the
  origin of the URL passed to `redirect_url(..)`.
- **Session expiry is `Fixed` by default, not sliding.** With
  `SessionExpiry::Fixed`, `post_auth_ttl` counts down from login and is **not**
  reset by ongoing activity — a user who is actively browsing is still logged
  out the instant it elapses. `SessionExpiry::Sliding` refreshes the TTL on
  every authenticated request instead, at a cost:
  - **Store traffic.** `actix-session` loads the session on every request that
    carries a session cookie, under either policy — `Fixed` is *not* zero store
    work. `Fixed` is one store read per request plus a write only when the
    session state changes; `Sliding` is two reads per request (the TTL renewal
    reads the row first to apply the pre-auth cap and the absolute-lifetime
    check). Renewal **writes** are coalesced by `DbSessionStore`: a `touch()`
    is only issued once the expiry would move forward by at least
    `with_touch_coalesce_secs` (default 60 s), so the steady-state write rate
    is roughly **one write per 60 s of active use per session**, not one per
    request. Tune it with `DbSessionStore::with_touch_coalesce_secs`; set it to
    `0` to write on every request.
  - **A `Set-Cookie` on every response**, which defeats shared HTTP caching for
    authenticated responses.
  - **Availability coupling.** `actix-session` maps a TTL-renewal failure to a
    500, so under `Sliding` the session store's availability and latency gate
    every authenticated request.
- **Bound the session with an absolute lifetime.** `Sliding` on its own means a
  session never expires while it is kept warm — a stolen cookie stays valid
  indefinitely. `max_session_lifetime(..)` (default 7 days) is what bounds it:
  a login timestamp is stored in the session and the session is dead at
  `login_at + max_lifetime` regardless of activity. It is enforced in
  `DbSessionStore` and, independently, in the `Auth` extractor — but the two
  are not equivalent:
  - **`DbSessionStore` enforces it unconditionally**, in the store, for every
    request that touches the session. This is the configuration to use.
  - **`CookieSessionStore` has no store-side check**, so only the extractor
    enforces it — and the extractor only runs for handlers that actually take
    the `Auth` extractor. A handler that reads the session directly (e.g.
    `req.get_session().get::<String>("access_token")`) bypasses the absolute
    lifetime entirely, and under `Sliding` the cookie's `Max-Age` keeps being
    refreshed. Treat the absolute lifetime as enforced for `Auth`-mediated
    access only.
  - **`DbSessionStore` must be given the configured value** — use
    `DbSessionStore::from_config`, see
    [Wiring the session store](#wiring-the-session-store).
- **The absolute lifetime bounds the BFF session, not IdP SSO.** When it
  elapses the user is sent back through `/auth/login`, which resets the clock.
  If their SSO session at the IdP is still live, that re-login can complete
  without any visible prompt. Genuinely forcing re-authentication would
  additionally require `max_age`/`prompt` on the authorization request, which
  this crate does not currently send.

## Releasing

Releases are automated with [release-plz]. Every push to `master` updates a
release PR that bumps the version — conventional commits and
[cargo-semver-checks] decide the bump (override it by editing `Cargo.toml` on
the release PR branch).

Before merging the release PR, roll the changelog: rename `[Unreleased]` to
`## [X.Y.Z] - YYYY-MM-DD` in `CHANGELOG.md` and add the `[X.Y.Z]: ...` compare
link reference at the bottom. The `release-gate` CI job blocks the merge until
this section exists.

Merging publishes to crates.io via Trusted Publishing (OIDC, GitHub environment
`release`) and pushes tag `vX.Y.Z`; the tag triggers a workflow that creates the
GitHub Release from the changelog section.

If the crates.io publish succeeded but the tag push failed, push the tag
manually: `git tag vX.Y.Z && git push origin vX.Y.Z`. Re-running the release
job is a no-op once the version is on crates.io.

[release-plz]: https://release-plz.dev
[cargo-semver-checks]: https://github.com/obi1kenobi/cargo-semver-checks

## License

Licensed under either of Apache License, Version 2.0 or MIT license, at your
option.
