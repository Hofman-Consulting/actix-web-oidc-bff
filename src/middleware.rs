//! Hardened `SessionMiddleware` construction from [`OidcBffConfig`].

use actix_session::{config::PersistentSession, storage::SessionStore, SessionMiddleware};
use actix_web::cookie::{time::Duration, SameSite};

use crate::config::OidcBffConfig;

/// Build a `SessionMiddleware` wired to the config's security settings:
///
/// - cookie name from [`OidcBffConfig::cookie_name()`] (`__Host-`-prefixed when
///   the app runs on https)
/// - `Secure` from [`OidcBffConfig::cookie_secure()`]
/// - `HttpOnly`, `SameSite=Lax`, `Path=/` (Lax still sends the cookie on the
///   top-level GET navigation back from the IdP, so the callback works)
/// - persistent session TTL from `OidcBffConfig::post_auth_ttl_secs()`
///   (`pub(crate)`, not linkable from here)
/// - TTL extension policy from [`OidcBffConfig::session_expiry()`]
/// - signing/encryption key from [`OidcBffConfig::session_key()`]
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
/// ## Session expiry — fixed vs. sliding
///
/// [`OidcBffConfig::session_expiry()`] decides *when* `post_auth_ttl_secs` is
/// reset, and the two modes have materially different cost and availability
/// profiles. `actix-session`'s `load()` runs unconditionally for every request
/// carrying a session cookie regardless of policy (it is what makes the
/// session available at all), so the numbers below are the *additional* cost
/// each mode adds on top of that baseline read (verified against the vendored
/// actix-session 0.10.1 `SessionMiddleware` implementation):
///
/// - **[`crate::config::SessionExpiry::Fixed`] (the default)**: the TTL is an
///   **absolute expiry from login**. It is only reset when the session state
///   itself changes (or the session key is renewed) — normal request
///   activity does **not** extend it. A user who is actively browsing gets
///   logged out the moment `post_auth_ttl_secs` elapses from login, with no
///   warning. Cost: 1 session-store read per request, no write for an
///   unchanged request.
/// - **[`crate::config::SessionExpiry::Sliding`]**: the TTL becomes a **sliding expiry** —
///   every authenticated request pushes the expiry forward, so an active user
///   is never logged out mid-session. Cost: 2 reads per request (the initial
///   `load`, plus a further `get` inside `update_ttl`) and a `Set-Cookie`
///   header on *every* response — which defeats shared HTTP caching of
///   otherwise-cacheable responses.
///
///   Renewal *writes* are not per-request: [`crate::DbSessionStore`] coalesces
///   them, issuing [`crate::SessionRepository::touch`] only once the expiry
///   would move forward by at least `touch_coalesce_secs` (default 60 s,
///   configurable via [`crate::DbSessionStore::with_touch_coalesce_secs`], or
///   `0` to write on every request). Budget for roughly **1 write per 60 s of
///   active use per session**, not 1 write per request. `touch` is still the
///   hottest method on a `SessionRepository` under `Sliding`, and the session
///   table the highest-churn table in the schema.
///
///   **Availability**: `actix-session` maps an `update_ttl` failure to a 500
///   response. Under `Sliding`, the session store's availability and latency
///   therefore gate *every* authenticated request — a session-store blip
///   turns into a 500 storm across all authenticated traffic. Under `Fixed`,
///   an unchanged request never calls `update_ttl` and so never depends on it.
///
///   **Sliding alone gives an unbounded session lifetime** — an
///   uninterrupted stream of requests keeps pushing the expiry forward
///   forever. [`OidcBffConfig::max_session_lifetime()`] is what bounds it:
///   enforcement lives in [`crate::DbSessionStore`] and, store-agnostically,
///   in the [`crate::Auth`] extractor.
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
    SessionMiddleware::builder(store, cfg.session_key().clone())
        .cookie_name(cfg.cookie_name().to_string())
        .cookie_secure(cfg.cookie_secure())
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Lax)
        .cookie_path("/".to_string())
        .session_lifecycle(
            PersistentSession::default()
                .session_ttl(Duration::seconds(cfg.post_auth_ttl_secs()))
                .session_ttl_extension_policy(cfg.session_expiry().into()),
        )
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, SessionExpiry};
    use actix_session::storage::CookieSessionStore;

    /// `session_middleware` must build successfully regardless of which
    /// `SessionExpiry` variant is configured.
    ///
    /// NOTE: `actix_session::SessionMiddleware` and its internal
    /// `Configuration` (including `ttl_extension_policy`) are entirely
    /// private — the crate exposes no accessor to inspect the policy a
    /// built `SessionMiddleware` was configured with, from inside or
    /// outside `actix-session`. This is therefore only a build smoke check;
    /// the `SessionExpiry -> TtlExtensionPolicy` mapping itself is asserted
    /// in `config.rs`, next to the `impl From` that performs it.
    #[test]
    fn builds_with_either_session_expiry() {
        let cfg = config::test_config_builder()
            .session_expiry(SessionExpiry::Sliding)
            .build()
            .unwrap();
        let _ = session_middleware(CookieSessionStore::default(), &cfg);

        let cfg = config::test_config_builder()
            .session_expiry(SessionExpiry::Fixed)
            .build()
            .unwrap();
        let _ = session_middleware(CookieSessionStore::default(), &cfg);
    }
}
