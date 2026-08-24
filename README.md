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
- **Login variants**: register extra login routes that add a fixed set of
  authorization-request parameters (`prompt=create`, a provider-specific
  action, …), allowlist callback parameters to forward onto the post-login
  redirect, and require a **verified** fresh authentication with
  `require_auth_within` — the crate checks the returned `auth_time` claim and
  rejects the login if the provider did not honour it (see [Login
  variants](#login-variants)).

## Routes

| Route | Method | Purpose |
|---|---|---|
| `/auth/login` | GET | Start the flow; redirects to the IdP. Optional `?return_to=/path`. |
| `/auth/logout` | POST | Same-origin check, purge session, return IdP logout URL (200) or 204. |
| `/auth/callback` | GET | Code exchange, ID-token validation, session establishment. |
| `/auth/me` | GET | Identity claims (`sub`, `iss`, `email`, `name`) — never tokens. |

`configure` registers exactly these four. Additional **login-variant** routes —
the same flow with a fixed set of extra authorization-request parameters — are
registered separately, at a path you choose, via `login_route`; see
[Login variants](#login-variants).

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

## Login variants

`GET /auth/login` sends exactly the parameters the authorization-code + PKCE
flow needs, and nothing else. Some provider capabilities are reachable only by
adding one more parameter to the authorization request — the standard `prompt`,
or a provider-specific name.

The crate does **not** make `/auth/login` configurable per request: a login
endpoint that copies query parameters into the authorization request is an
authorization-request injection point. Instead you register *additional* login
routes, each pinned at startup to a fixed set of extra parameters.
`/auth/login` itself is byte-for-byte unchanged when no variant is registered.

The motivating case is an **Application-Initiated Action**: a flow that the
application asks the provider to run by name — change password, enrol a
passkey, verify an email address — which happens entirely inside the provider's
own UI, and whose outcome comes back as an extra query parameter on the
callback. Keycloak is one provider that works this way (`kc_action` out,
`kc_action_status` back); the shape is not specific to it, and the crate never
interprets either name.

Both halves of that round trip are shown below. A runnable version lives in
[`examples/login_variants.rs`][login-variants-example].

[login-variants-example]: https://github.com/Hofman-Consulting/actix-web-oidc-bff/blob/master/examples/login_variants.rs

### Registering a variant route

```rust,ignore
use actix_web::{web, App, HttpServer};
use actix_web_oidc_bff as bff;

// Build the parameter sets ONCE, here — not inside the `HttpServer::new`
// closure, which runs per worker thread. `new` validates, so a denied or
// malformed name fails at startup instead of once per worker.
let register = bff::ExtraAuthParams::new([("prompt", "create")])
    .expect("register variant parameters");
let change_password = bff::ExtraAuthParams::new([("kc_action", "UPDATE_PASSWORD")])
    .expect("change-password variant parameters");

HttpServer::new(move || {
    App::new()
        .wrap(bff::session_middleware(store.clone(), &cfg))
        .configure(|sc| bff::configure_app_data(sc, rp.clone(), cfg.clone()))
        .configure(bff::configure)  // the stock four routes, unchanged
        // Public: anyone may start a sign-up.
        .service(web::resource("/auth/register").route(bff::login_route(register.clone())))
        // Privileged: an action on an existing user's credentials, so gate it
        // behind the `Auth` extractor (see below).
        .service(
            web::resource("/auth/account/password")
                .route(bff::login_route(change_password.clone())),
        )
});
```

A variant route accepts `?return_to=` and applies the same `return_to`
validation, pre-auth slot handling, PKCE, and callback processing as
`/auth/login`. The only difference is the extra parameters on the
authorization URL, added through `openidconnect`'s typed `add_extra_param`, so
URL encoding is handled for you.

`ExtraAuthParams::new` validates at construction — so a mistake fails at
startup, not on a user's first login — and returns `AuthParamError` for:

- more than `MAX_EXTRA_AUTH_PARAMS` (8) parameters, a value longer than
  `MAX_EXTRA_AUTH_VALUE_LEN` (512) bytes or containing a control character, a
  duplicate name, or a name that is empty, over 64 bytes, or outside
  `[A-Za-z0-9_.-]`. Rejections name the *parameter*, never the value;
- any name the crate sets itself — `client_id`, `redirect_uri`,
  `response_type`, `scope`, `state`, `nonce`, `code_challenge`,
  `code_challenge_method`. Providers disagree on whether the first or the last
  occurrence of a repeated parameter wins, so a duplicate is at best a broken
  flow and at worst a stolen authorization code;
- `response_mode`, which would move the response off the query string and break
  the `GET /auth/callback` handler;
- `request` / `request_uri` (JAR), which replace the entire request with a
  caller-supplied blob and thereby bypass every entry above;
- credentials that must never travel in a front-channel URL —
  `client_secret`, `client_assertion`, `client_assertion_type`,
  `code_verifier`;
- `max_age`, denied for a reason unlike any of the above: it is not dangerous,
  it is **unverifiable in the hand-rolled form**. Send it through
  [`require_auth_within`](#requiring-a-verified-fresh-authentication) instead,
  which sends it *and* checks the result.

### Gating a privileged variant

"Change the credentials of the current user" is only meaningful for a user who
is already signed in, so put such a variant behind the `Auth` extractor.
`login_route` returns an `actix_web::Route` — an already-built handler — so the
gate goes one level up, on the enclosing scope:

```rust,ignore
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::{from_fn, Next};
use actix_web::{web, Error};

async fn require_auth(
    mut req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // 401 from the extractor when the session has no `sub`.
    let _auth = req.extract::<bff::Auth>().await?;
    next.call(req).await
}

App::new().service(
    web::scope("/auth/account")
        .wrap(from_fn(require_auth))
        .service(web::resource("/password").route(bff::login_route(change_password.clone()))),
);
```

### Getting the outcome back

The callback normally discards every query parameter but `code` and `state`.
`callback_passthrough_params` allowlists names to append — percent-encoded — to
the post-login redirect URL:

```rust,ignore
let cfg = bff::OidcBffConfig::builder()
    // …
    .return_to_prefix("/app")
    .callback_passthrough_params(["kc_action_status"])
    .build()?;
```

The round trip is then: `GET /auth/account/password?return_to=/app/account` →
provider runs the action → `GET /auth/callback?code=…&state=…&kc_action_status=success`
→ `302 Location: /app/account?kc_action_status=success`. The landing page reads
it like any other query parameter:

```rust,ignore
use std::collections::HashMap;
use actix_web::{web, HttpResponse};

async fn account(auth: bff::Auth, q: web::Query<HashMap<String, String>>) -> HttpResponse {
    let status = q.get("kc_action_status");   // untrusted — display only, escaped
    // …
}
```

An empty allowlist (the default) is exactly the pre-0.3 behaviour: the callback
redirects to the stored `return_to` untouched.

Rules applied per parameter, on the way out:

- **Success path only.** An IdP `error=` response returns `400` and never
  redirects, so nothing is appended there.
- Values longer than `MAX_PASSTHROUGH_VALUE_LEN` (256) bytes, containing control
  characters, or containing the Unicode replacement character `U+FFFD`, are
  **dropped with a warning that names the parameter and never the value**. The
  last rule catches bytes that are not valid UTF-8: percent-decoding is lossy,
  so `%FF` arrives as `U+FFFD` rather than as an error.
- Only the **first** occurrence of a repeated name is considered, and the drop
  decision is final: a second, well-formed copy cannot revive a parameter whose
  first copy was rejected.
- A name already present in the `return_to` query string is skipped — the
  application's own parameter wins.
- The appended parameters are bounded in aggregate by
  `MAX_PASSTHROUGH_TOTAL_LEN` (1024) bytes, measured on the *encoded* form. A
  pair that would not fit is skipped and the next one is still tried, so one
  long value cannot starve the shorter parameters behind it.
- At most `MAX_PASSTHROUGH_PARAMS` (8) names, charset `[A-Za-z0-9_.-]`, no
  duplicates. Violations fail `build()` with
  `ConfigError::InvalidPassthroughParam`.
- A config-time deny-list refuses `code`, `state`, `error` /
  `error_description` / `error_uri`, `iss`, `session_state`, any token name,
  and client credentials.

### Requiring a verified fresh authentication

A privileged variant usually wants more than "the user has a session" — it wants
"the user authenticated recently". `require_auth_within` is that, and unlike a
hand-written `max_age` parameter it comes with a check on the way back:

```rust,ignore
use std::time::Duration;

let change_password =
    bff::ExtraAuthParams::new([("kc_action", "UPDATE_PASSWORD"), ("prompt", "login")])
        .expect("change-password variant parameters")
        // Re-authentication no older than five minutes — sent to the provider,
        // and verified against the ID token when the callback returns.
        .require_auth_within(Duration::from_secs(300))
        .expect("re-authentication age");
```

It does three things as one unit:

1. sends `max_age=300` on the authorization request, through `openidconnect`'s
   typed `set_max_age`;
2. records the requirement — a single integer, nothing else — in the pre-auth
   slot, because `/auth/callback` is shared by every login route and would
   otherwise have no idea this flow asked for anything;
3. checks the validated ID token's `auth_time` claim in the callback and
   **rejects the login with `400` and no session established** when the claim is
   absent or too old.

The full round trip: `GET /auth/account/password?return_to=/app/account` →
authorization request carries `max_age=300` → the provider re-authenticates the
user *if its own record of them is older than that* (its UI, its policy) →
`GET /auth/callback?code=…&state=…` → the crate verifies `auth_time` →
`302 Location: /app/account`, or `400` and no session.

**The provider is the enforcement point; this crate verifies that enforcement
happened.** That distinction is the whole feature. The re-prompt happens at the
identity provider — no RP can make a user type a password. What an RP *can* do
is refuse to accept the result when the evidence is missing or stale, which is
exactly the case a bare `max_age` parameter cannot distinguish.
`auth_max_age()` reads the requirement back.

- **`max_age` is not `prompt=login`.** With `max_age=300`, a user who
  authenticated two minutes ago is *not* re-prompted — the provider simply
  returns the existing `auth_time` and the crate accepts it, which is correct
  per OIDC. If you want the user to actually be challenged every time, pair it
  with `("prompt", "login")` as the example above does. `require_auth_within`
  bounds *how old* the authentication may be; `prompt=login` asks for a fresh
  one outright, and only the first of those is verifiable.
- **`auth_time` means what your provider says it means.** Several major
  providers report when the user's SSO *session* began, not when they last
  proved a credential. The crate verifies the provider's claim about freshness;
  the definition of freshness stays the provider's.
- **It fails closed on a missing `auth_time`.** OIDC Core makes the claim
  REQUIRED in the ID token when the request carried `max_age`, so an absent
  claim means the provider did not honour the request — the silent-downgrade
  case this exists to catch. A token with no evidence is not a token that passed.
- **A step-up must complete as the same user.** When a requirement is set and
  the session already holds a subject, a callback that comes back as a
  *different* subject is rejected rather than silently switching accounts — the
  provider's re-prompt commonly offers a "use another account" option, and a
  route that reads as "confirm it's you" must not quietly become someone else's
  session. Plain login routes are unaffected: switching accounts by logging in
  again is ordinary, and that is where it belongs.
- **The age is measured from the authorization request, not from the callback.**
  That is what the provider evaluated, so whatever the user then does at the
  provider — the consent screen, or the very action the variant asked for —
  is not charged against the budget. A five-minute requirement does not reject a
  user who spends six minutes filling in a password form. Total flow duration is
  bounded separately, by `pre_auth_ttl`.
- **Clock skew**: `AUTH_TIME_SKEW_SECS` (60 s) of slack applies in **both**
  directions — it absorbs drift between your clock and the provider's, not
  elapsed time — so the effective window is `max_age + 60s`, and an `auth_time`
  slightly in the future is tolerated rather than treated as malformed.
  `Duration::ZERO` is legal and meaningful: the provider enforces it strictly.
- **`max_age` is deny-listed as a raw parameter.** `ExtraAuthParams::new([("max_age", "300")])`
  fails with `AuthParamError::ReservedName`, so the unverified form is not
  reachable and exactly one `max_age` can ever appear on the URL.
- `require_auth_within` returns `AuthParamError::InvalidMaxAge` for a
  `Duration` that is not a whole number of seconds (rejected rather than
  truncated, matching the crate's TTL handling) or that exceeds
  `MAX_AUTH_AGE_SECS` (365 days).

#### It gates the login, not the session

`require_auth_within` is a **precondition on completing that login**, not a
lasting property of the session it creates. The session it produces is an
ordinary one; nothing marks it as "stepped up". So *arriving* at your
`return_to` is not proof that a step-up happened — the user could equally have
navigated there directly with the session they already had.

If a handler needs to make a decision based on freshness, persist the claim and
check it there:

```rust,ignore
// At startup:
let cfg = bff::OidcBffConfig::builder()
    // …
    .persist_claims(["auth_time"])
    .build()?;

// In the handler that actually needs a recent authentication:
async fn change_email(auth: bff::Auth) -> Result<HttpResponse, actix_web::Error> {
    let recent = auth
        .get_claim("auth_time")
        .and_then(|v| v.as_i64())
        .is_some_and(|t| chrono::Utc::now().timestamp() - t < 300);

    if !recent {
        // Send them through the step-up variant, then back here.
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/auth/step-up?return_to=/app/account/email"))
            .finish());
    }
    // …
}
```

`auth_time` is explicitly allowed in `persist_claims` for this reason. The two
mechanisms compose: the variant guarantees the login could not complete without
a fresh authentication, and the persisted claim lets the handler confirm it
independently.

### Security notes for login variants

- **Parameter values are configuration, not input.** Every value handed to
  `ExtraAuthParams::new` must be a constant supplied by the application at
  startup, **never derived from the incoming request** — not from a query
  parameter, not from a header, not from a session value the user can steer.
  That single rule is what keeps the login endpoints free of
  authorization-request injection. It is **enforced by convention, not by the
  type system**: `ExtraAuthParams::new` takes strings and cannot tell where
  they came from. Reviewing a variant route means tracing every value back to
  its source.
- **A name the provider bakes into its own authorization endpoint can collide.**
  The deny-list covers every parameter *this crate* adds, but some providers
  publish an `authorization_endpoint` that already carries a query string (a
  policy or tenant selector, say). An `ExtraAuthParams` name matching one of
  those becomes a second occurrence of it, and most providers take the last.
  Discovery-dependent and consumer-configured rather than attacker-controlled —
  but if your provider's authorization endpoint has its own query parameters,
  do not reuse their names.
- **Freshness is verified; assurance level is not.** The two halves of "step-up"
  are not equally checkable, and the API deliberately treats them differently:
  - **`max_age`, via `require_auth_within`, is verified.** The requirement rides
    along in the pre-auth slot and the callback checks the returned ID token's
    `auth_time` claim, rejecting the login outright when it is missing or stale.
    A provider that ignored the request is no longer indistinguishable from one
    that honoured it. The provider is still where the re-prompt happens — see
    [Requiring a verified fresh
    authentication](#requiring-a-verified-fresh-authentication) — but the RP no
    longer has to take its word for it. The raw `("max_age", "300")` parameter
    is deny-listed so the unverified form is not reachable.
  - **`acr_values` and a bare `prompt=login` are still transmitted, not
    verified.** They have no machine-checkable postcondition the way `max_age`
    has `auth_time`: `prompt=login` produces no claim at all saying "the user
    was prompted", and `acr` is an opaque provider-defined string whose meaning
    only your application knows. There is nothing for the crate to compare
    against, so it does not pretend to. A route built on them alone carries **no
    RP-side guarantee**. If you need one, persist the claim and check it
    yourself — the crate stays out of interpreting it:

    ```rust,ignore
    let cfg = bff::OidcBffConfig::builder()
        // …
        .persist_claims(["acr"])
        .build()?;

    async fn sensitive(auth: bff::Auth) -> Result<HttpResponse, actix_web::Error> {
        // Your own assurance-level check on auth.get_claim("acr") — which
        // values count as sufficient is application policy.
        // …
    }
    ```

    Pairing an `acr_values` variant with `require_auth_within` at least pins
    down *when* the authentication happened, even though *how* remains
    unverified.

- **Passthrough values are attacker-shaped.** From the application's point of
  view they arrive over a redirect the user's browser performed, from a party
  this crate does not validate the content of. Treat them exactly like any other
  untrusted query parameter: never render one into HTML unescaped, never use one
  as a redirect target, never let one be an authorization input. They are
  display data.
- **Namespace the allowlisted names.** A forwarded parameter lands in *your*
  application's query string, next to your own parameters. A provider-prefixed
  name (`kc_action_status`) already cannot collide; when you get to pick the
  name, give it an `idp_` prefix so it never shadows something your own handler
  reads.
- **Why the URL and not a one-shot session flag.** The URL is the only channel
  that survives the provider's redirect without extra state on either side: the
  provider puts the value on the callback, the callback puts it on the
  `Location` header, and the landing page reads it directly — no extra session
  write, no key to expire, no coordination between the callback and the page.
  The honest trade-off is that a query parameter is *visible*: it lands in
  browser history, in the `Referer` header of the next outbound request, and in
  the access logs of every proxy in front of the app. That visibility is exactly
  why the deny-list exists and why it is not negotiable — an authorization code,
  a token, or `state` in any of those places is a disclosure. A short,
  non-sensitive status string is not.

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
| `callback_passthrough_params(..)` | no | empty | Query-parameter names to forward from the IdP's callback request onto the post-login redirect URL. Empty is the pre-0.3 behaviour. Success path only; values are untrusted. See [Login variants](#login-variants). |
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
  without any visible prompt. Genuinely forcing re-authentication requires
  `max_age`/`prompt=login` on the authorization request, which a
  [login variant](#login-variants) can send.
  `ExtraAuthParams::require_auth_within` is the form to use: it sends `max_age`
  **and** verifies the resulting `auth_time` claim, so a provider that quietly
  reused its SSO session fails the login instead of producing one that only
  looks fresh. See [Requiring a verified fresh
  authentication](#requiring-a-verified-fresh-authentication).

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
