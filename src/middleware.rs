//! Hardened `SessionMiddleware` construction from [`OidcBffConfig`].

use actix_session::{config::PersistentSession, storage::SessionStore, SessionMiddleware};
use actix_web::cookie::{time::Duration, SameSite};

use crate::config::OidcBffConfig;

/// Build a `SessionMiddleware` wired to the config's security settings:
///
/// - cookie name from [`OidcBffConfig::cookie_name`] (`__Host-`-prefixed when
///   the app runs on https)
/// - `Secure` from [`OidcBffConfig::cookie_secure`]
/// - `HttpOnly`, `SameSite=Lax`, `Path=/` (Lax still sends the cookie on the
///   top-level GET navigation back from the IdP, so the callback works)
/// - persistent session TTL from [`OidcBffConfig::post_auth_ttl_secs`]
/// - signing/encryption key from [`OidcBffConfig::session_key`]
///
/// ## TTL split between middleware and store
///
/// This middleware TTL (`post_auth_ttl_secs`) applies to **authenticated**
/// sessions — it is the TTL passed to the store's `save()`/`update()` on every
/// request. [`crate::DbSessionStore`] independently caps anonymous / pre-auth
/// rows (those without a `sub` key) to a shorter TTL (default 600 s,
/// configurable via `DbSessionStore::with_pre_auth_ttl_secs`) to limit
/// exposure from unauthenticated `/auth/login` flooding. Rate-limiting
/// `/auth/login` at the deployment level (reverse proxy / WAF) is still
/// recommended as a complementary measure.
///
/// Use with any `SessionStore`, e.g. [`crate::DbSessionStore`] or
/// `actix_session::storage::CookieSessionStore`:
///
/// ```rust,ignore
/// App::new()
///     .wrap(session_middleware(DbSessionStore::new(repo), &cfg))
///     .configure(|sc| actix_web_oidc_bff::configure(sc))
/// ```
pub fn session_middleware<S: SessionStore>(store: S, cfg: &OidcBffConfig) -> SessionMiddleware<S> {
    SessionMiddleware::builder(store, cfg.session_key.clone())
        .cookie_name(cfg.cookie_name.clone())
        .cookie_secure(cfg.cookie_secure)
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Lax)
        .cookie_path("/".to_string())
        .session_lifecycle(
            PersistentSession::default().session_ttl(Duration::seconds(cfg.post_auth_ttl_secs)),
        )
        .build()
}
