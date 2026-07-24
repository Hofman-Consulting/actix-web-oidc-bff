use actix_web::web;
use std::sync::Arc;

use crate::config::OidcBffConfig;
use crate::handlers;
use crate::oidc::OidcRp;

/// Register the four `/auth/*` routes:
///   - `GET  /auth/login`    — begin the OIDC authorization-code + PKCE flow
///   - `GET  /auth/callback` — exchange the code, validate the id_token, set session
///   - `POST /auth/logout`   — purge the session
///   - `GET  /auth/me`       — return the current session's identity claims
///
/// Call [`configure_app_data`] as well to register the shared [`OidcRp`] and
/// [`OidcBffConfig`].
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/auth/login").route(web::get().to(handlers::login::login)));
    cfg.service(web::resource("/auth/callback").route(web::get().to(handlers::callback::callback)));
    cfg.service(web::resource("/auth/logout").route(web::post().to(handlers::logout::logout)));
    cfg.service(web::resource("/auth/me").route(web::get().to(handlers::me::me)));
}

/// Register the [`OidcRp`] and [`OidcBffConfig`] as shared `app_data` so the
/// route handlers can extract them via `web::Data`.
pub fn configure_app_data(
    cfg: &mut web::ServiceConfig,
    oidc_rp: Arc<OidcRp>,
    bff_cfg: Arc<OidcBffConfig>,
) {
    cfg.app_data(web::Data::from(oidc_rp));
    cfg.app_data(web::Data::from(bff_cfg));
}
