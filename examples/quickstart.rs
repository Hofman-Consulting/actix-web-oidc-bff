//! Minimal `actix-web-oidc-bff` quickstart.
//!
//! Mirrors the README quickstart: it wires OIDC discovery, the hardened session
//! middleware, and the BFF routes into an actix-web app, then exposes one route
//! protected by the [`Auth`](actix_web_oidc_bff::Auth) extractor.
//!
//! # Running
//!
//! ```sh
//! cargo run --example quickstart
//! ```
//!
//! Set the required environment variables first (placeholder values shown).
//! These are **this example's own** variables, read by `required_env` below and
//! handed to the builder — the crate itself reads no environment at all, so a
//! real application is free to name them anything or source the values from
//! files or a secret manager instead.
//!
//! The session key must be a base64-encoded value that decodes to at least
//! 64 bytes, e.g. `openssl rand -base64 64` (its line wrapping is fine —
//! `session_key_base64` strips ASCII whitespace before decoding):
//!
//! ```sh
//! export OIDC_ISSUER_URL="https://idp.example.com"
//! export OIDC_CLIENT_ID="my-client-id"
//! export OIDC_CLIENT_SECRET="changeme"
//! export OIDC_REDIRECT_URL="http://127.0.0.1:8080/auth/callback"
//! export OIDC_SESSION_KEY_BASE64="$(openssl rand -base64 64)"
//! ```
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
//!
//! `DbSessionStore::new(repo)` silently keeps the store's own defaults (600 s /
//! 7 days) regardless of what the config says, so a configured one-hour
//! `max_session_lifetime` would still produce seven-day rows.

use std::sync::Arc;

use actix_session::storage::CookieSessionStore;
use actix_web::{App, HttpServer};
use actix_web_oidc_bff as bff;

/// A downstream handler protected by the [`bff::Auth`] extractor.
///
/// The extractor returns `401 Unauthorized` when there is no authenticated
/// session, so reaching this body means the request is authenticated.
async fn index(auth: bff::Auth) -> String {
    format!("hello {}", auth.subject)
}

/// Read a required env var, or fail loudly with a clear message.
///
/// This checks presence only — a variable set to an empty string (`FOO=`) is
/// returned as `""` and passes here. That is not a gap: `build()` treats an
/// empty or whitespace-only required field as missing and reports it in
/// [`ConfigError::MissingFields`](actix_web_oidc_bff::ConfigError), so the
/// failure still surfaces at startup with the field named.
fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Client secret and session key are read from the environment (or, for
    // orchestration setups that mount secrets as files, `std::fs::read_to_string`
    // works just as well) — never hardcode these, this example gets copy-pasted
    // into production.
    let client_secret = required_env("OIDC_CLIENT_SECRET");
    let session_key_base64 = required_env("OIDC_SESSION_KEY_BASE64");

    let cfg = Arc::new(
        bff::OidcBffConfig::builder()
            .issuer_url(required_env("OIDC_ISSUER_URL"))
            .client_id(required_env("OIDC_CLIENT_ID"))
            .client_secret(client_secret)
            .redirect_url(required_env("OIDC_REDIRECT_URL"))
            .session_key_base64(&session_key_base64)
            .build()
            .expect("OIDC config"),
    );
    let rp = Arc::new(
        bff::OidcRp::discover(&cfg)
            .await
            .expect("OIDC provider discovery"),
    );

    HttpServer::new(move || {
        App::new()
            .wrap(bff::session_middleware(CookieSessionStore::default(), &cfg))
            .configure(|sc| bff::configure_app_data(sc, rp.clone(), cfg.clone()))
            .configure(bff::configure)
            .route("/", actix_web::web::get().to(index))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
