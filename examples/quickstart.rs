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
//! Set the required environment variables first (placeholder values shown):
//!
//! ```sh
//! export OIDC_ISSUER_URL="https://idp.example.com"
//! export OIDC_CLIENT_ID="my-client-id"
//! export OIDC_CLIENT_SECRET="changeme"
//! export OIDC_REDIRECT_URL="http://127.0.0.1:8080/auth/callback"
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
//!
//! Production deployments must use `DbSessionStore` with a `SessionRepository`
//! implementation.

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cfg = Arc::new(bff::OidcBffConfig::from_env().expect("OIDC config from env"));
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
