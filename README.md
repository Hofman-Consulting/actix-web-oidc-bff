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
| `/auth/callback` | GET | Code exchange, ID-token validation, session establishment. |
| `/auth/logout` | POST | Same-origin check, purge session, return IdP logout URL (200) or 204. |
| `/auth/me` | GET | Identity claims (`sub`, `iss`, `email`, `name`) — never tokens. |

## Quickstart

```rust,ignore
use std::sync::Arc;
use actix_web::{App, HttpServer};
use actix_session::storage::CookieSessionStore;
use actix_web_oidc_bff as bff;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cfg = Arc::new(bff::OidcBffConfig::from_env().expect("OIDC config"));
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

## Configuration (environment variables)

| Variable | Required | Default | Description |
|---|---|---|---|
| `OIDC_ISSUER_URL` | yes | — | Issuer URL used for discovery. |
| `OIDC_CLIENT_ID` | yes | — | OAuth client id. |
| `OIDC_CLIENT_SECRET` | yes | — | OAuth client secret (confidential client). |
| `OIDC_REDIRECT_URL` | yes | — | Public URL of `/auth/callback`. Its scheme decides cookie security (`https` → `__Host-` + `Secure`); its origin is the CSRF reference origin. |
| `OIDC_SESSION_KEY` | no | random (warns) | Base64, ≥64 bytes. Set it in production — a random key invalidates sessions on restart and breaks multi-instance deployments. |
| `OIDC_SCOPES` | no | `openid,profile,email` | Comma-separated; `openid` is always included. |
| `OIDC_RETURN_TO_PREFIX` | no | `/` | Safe path prefix for post-login redirects; must start with `/`. |
| `OIDC_PERSIST_CLAIMS` | no | empty | Extra ID-token claims to copy into the session (e.g. `groups,amr,acr`). Reserved internal names are rejected. |
| `OIDC_POST_LOGOUT_REDIRECT_URL` | no | unset | Sent as `post_logout_redirect_uri` during RP-initiated logout; must be registered at the IdP. |

## Security notes

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
  `OIDC_REDIRECT_URL` origin.

## License

Licensed under either of Apache License, Version 2.0 or MIT license, at your
option.
