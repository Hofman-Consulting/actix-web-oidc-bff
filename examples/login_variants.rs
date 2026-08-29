//! `actix-web-oidc-bff` login variants: extra authorization-request parameters
//! and callback parameter passthrough.
//!
//! The quickstart example mounts the four `/auth/*` routes and stops there.
//! This one adds the 0.3 pair on top:
//!
//! - **Extra authorization-request parameters.** [`bff::ExtraAuthParams`] plus
//!   [`bff::login_route`] register additional login endpoints that start the
//!   very same authorization-code + PKCE flow, but send a few extra parameters
//!   to the provider. Two are shown: a public `/auth/register` that asks the
//!   provider for its sign-up screen, and a privileged
//!   `/auth/account/password` that asks the provider to run an
//!   Application-Initiated Action (a credential change) before returning.
//! - **Verified fresh authentication.** The privileged variant adds
//!   `ExtraAuthParams::require_auth_within`, which sends `max_age` *and* checks
//!   the returned ID token's `auth_time` claim in the callback — so a provider
//!   that silently reused an existing SSO session fails the login rather than
//!   producing a session that only looks freshly authenticated.
//! - **Callback parameter passthrough.** Providers report the outcome of such
//!   an action by adding a query parameter to the callback URL. The callback
//!   normally discards everything but `code` and `state`;
//!   `callback_passthrough_params` allowlists names to append, percent-encoded,
//!   to the post-login redirect so the landing page can read them.
//!
//! `GET /auth/login` is untouched by any of this — it behaves exactly as it
//! does in the quickstart.
//!
//! # Running
//!
//! ```sh
//! cargo run --example login_variants
//! ```
//!
//! Set the required environment variables first (placeholder values shown).
//! These are **this example's own** variables — the crate itself reads no
//! environment at all:
//!
//! ```sh
//! export OIDC_ISSUER_URL="https://idp.example.com"
//! export OIDC_CLIENT_ID="my-client-id"
//! export OIDC_CLIENT_SECRET="changeme"
//! export OIDC_REDIRECT_URL="http://127.0.0.1:8080/auth/callback"
//! export OIDC_SESSION_KEY_BASE64="$(openssl rand -base64 64)"
//! ```
//!
//! # Provider-specific names
//!
//! The parameter *names* below (`prompt=create`, `kc_action`,
//! `kc_action_status`) are what Keycloak uses; `prompt` is standard OIDC, the
//! `kc_*` pair is not. Substitute your own provider's spelling — the crate
//! itself is provider-agnostic and only validates the shape of the names, never
//! their meaning.
//!
//! # Warning: demo only
//!
//! This example uses `CookieSessionStore` for brevity. It is **not** a
//! supported production configuration:
//!
//! - It serializes the whole session — including the access, refresh, and ID
//!   tokens — into the encrypted cookie, so tokens reach the browser as
//!   ciphertext (voiding the "tokens never reach the browser" model).
//! - There is no server-side revocation: logout / `session.purge()` cannot
//!   invalidate an already-issued cookie; it stays valid until its TTL expires.
//! - Pre-auth state for concurrent logins can exceed the ~4 KB cookie limit and
//!   silently break login.
//! - The absolute session lifetime set via the builder's `max_session_lifetime`
//!   setter (default 7 days) is enforced only for handlers that take the
//!   [`bff::Auth`] extractor. `CookieSessionStore` performs no expiry check of
//!   its own, so a handler reading the session directly is not bounded by it.
//!
//! Production deployments must use `DbSessionStore` with a `SessionRepository`
//! implementation, constructed with `from_config` so the store's TTLs track the
//! config:
//!
//! ```rust,ignore
//! let store = bff::DbSessionStore::from_config(repo, &cfg);
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::{from_fn, Next};
use actix_web::{web, App, Error, HttpResponse, HttpServer};
use actix_web_oidc_bff as bff;
// Via the crate's re-export rather than a direct `actix-session` dependency —
// see "Quickstart" in README.md.
use bff::actix_session::storage::CookieSessionStore;

/// Query-parameter name the provider reports an action's outcome under, and
/// the one name this app allowlists for passthrough.
///
/// Keycloak spells it `kc_action_status`; the provider prefix is what keeps it
/// from ever colliding with one of this app's own query parameters. When you
/// get to pick the name yourself, namespace it the same way (`idp_…`).
const ACTION_STATUS_PARAM: &str = "kc_action_status";

/// Reject the request with `401 Unauthorized` unless it carries an
/// authenticated session.
///
/// [`bff::login_route`] returns an `actix_web::Route`, i.e. an already-built
/// handler — there is no function to delegate to from a wrapper handler that
/// takes [`bff::Auth`] first. So the gate goes one level up: a `from_fn`
/// middleware on the enclosing scope runs the `Auth` extractor and propagates
/// its 401 before the login handler is ever reached.
///
/// Gating matters here because "change the credentials of the current user" is
/// only meaningful *for an already-authenticated user*. Left public, the route
/// is a plain login that happens to carry an extra parameter — harmless to the
/// provider, which authenticates the user regardless, but misleading to read.
async fn require_auth(
    mut req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // The extractor yields 401 when the session has no `sub`, and enforces the
    // absolute session lifetime. Its value is unused — presence is the check.
    let _auth = req.extract::<bff::Auth>().await?;
    next.call(req).await
}

/// Minimal HTML escaping for untrusted text.
///
/// Everything forwarded by the passthrough allowlist originated at the
/// provider's redirect, which means it reached this process through the user's
/// browser and must be treated as attacker-shaped. It is display data and
/// nothing else: never a redirect target, never an authorization input, never
/// interpolated into markup raw.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The page users land on after a login variant completes.
///
/// `return_to` brought them here; the passthrough allowlist appended
/// [`ACTION_STATUS_PARAM`] to that URL when the provider sent it on the
/// callback.
async fn account(auth: bff::Auth, query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let status = match query.get(ACTION_STATUS_PARAM) {
        // Escaped, and used for display only.
        Some(v) => format!("<p>last action: {}</p>", escape_html(v)),
        None => String::new(),
    };
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "<h1>account</h1><p>signed in as {}</p>{status}\
             <p><a href=\"/auth/account/password?return_to=/app/account\">change password</a></p>",
            escape_html(&auth.subject),
        ))
}

/// Landing page for a plain `GET /auth/login`.
async fn index(auth: bff::Auth) -> String {
    format!("hello {}", auth.subject)
}

/// Read a required env var, or fail loudly with a clear message.
fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client_secret = required_env("OIDC_CLIENT_SECRET");
    let session_key_base64 = required_env("OIDC_SESSION_KEY_BASE64");

    let cfg = Arc::new(
        bff::OidcBffConfig::builder()
            .issuer_url(required_env("OIDC_ISSUER_URL"))
            .client_id(required_env("OIDC_CLIENT_ID"))
            .client_secret(client_secret)
            .redirect_url(required_env("OIDC_REDIRECT_URL"))
            .session_key_base64(&session_key_base64)
            .return_to_prefix("/app")
            // The other half of the round trip: without this the callback
            // would drop the provider's outcome parameter, and the landing
            // page would have no way to know how the action went.
            .callback_passthrough_params([ACTION_STATUS_PARAM])
            .build()
            .expect("OIDC config"),
    );
    let rp = Arc::new(
        bff::OidcRp::discover(&cfg)
            .await
            .expect("OIDC provider discovery"),
    );

    // Build the variants ONCE, here — not inside the `HttpServer::new` closure,
    // which runs per worker thread. `bff::ExtraAuthParams::new` validates, so a
    // typo'd or denied parameter name fails at startup rather than per worker.
    //
    // Both values are compile-time constants of this application. That is the
    // rule that keeps these routes safe: a parameter value must never be
    // derived from the incoming request, or the login endpoint becomes an
    // authorization-request injection point. Nothing in the type system
    // enforces it — it is on you.
    let register =
        bff::ExtraAuthParams::new([("prompt", "create")]).expect("register variant parameters");
    // Changing a credential is the textbook case for a *verified* fresh
    // authentication.
    //
    // The two parameters do different jobs, and both are wanted here:
    //   - `prompt=login` asks the provider to challenge the user outright.
    //     Nothing in an ID token proves a challenge happened, so this part is
    //     a request, not a guarantee.
    //   - `require_auth_within` sends `max_age=300` and then *verifies* the
    //     returned `auth_time` claim in the callback, rejecting the login with
    //     400 and no session if the provider did not honour it. On its own,
    //     `max_age=300` would not re-prompt a user who authenticated two
    //     minutes ago — it bounds how old the authentication may be.
    //
    // A hand-written ("max_age", "300") parameter is deny-listed precisely
    // because it would send the request and verify nothing.
    let change_password =
        bff::ExtraAuthParams::new([("kc_action", "UPDATE_PASSWORD"), ("prompt", "login")])
            .expect("change-password variant parameters")
            .require_auth_within(Duration::from_secs(300))
            .expect("re-authentication age");

    HttpServer::new(move || {
        App::new()
            .wrap(bff::session_middleware(CookieSessionStore::default(), &cfg))
            .configure(|sc| bff::configure_app_data(sc, rp.clone(), cfg.clone()))
            // The stock /auth/login, /auth/callback, /auth/logout, /auth/me.
            .configure(bff::configure)
            // Public variant: anyone may start a sign-up. No gate.
            .service(web::resource("/auth/register").route(bff::login_route(register.clone())))
            // Privileged variant: an action against an existing user's
            // credentials, so it is gated behind the `Auth` extractor.
            .service(
                web::scope("/auth/account")
                    .wrap(from_fn(require_auth))
                    .service(
                        web::resource("/password").route(bff::login_route(change_password.clone())),
                    ),
            )
            .route("/app", web::get().to(index))
            .route("/app/account", web::get().to(account))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
