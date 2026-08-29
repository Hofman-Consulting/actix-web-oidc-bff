#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
//!
//! ## Pieces
//! - [`OidcBffConfig`] — runtime configuration (issuer, client credentials,
//!   cookie/session settings), constructed via [`OidcBffConfig::builder`] /
//!   [`OidcBffConfigBuilder`], which validates every field in `build()`.
//! - [`OidcRp`] — the OIDC relying party: discovery, client construction, and
//!   JWKS metadata refresh.
//! - [`configure`] / [`configure_app_data`] — register the `/auth/*` routes and
//!   shared state on an `actix-web` `ServiceConfig`.
//! - [`Auth`] — a `FromRequest` extractor that yields the authenticated subject.
//! - [`session_middleware`] — builds a hardened `SessionMiddleware` (cookie
//!   flags + TTL) from the config; wrap your `App` with it.
//! - [`SessionRepository`] + [`DbSessionStore`] — bring-your-own persistent
//!   session storage so sessions are revocable (alternatively, use
//!   `actix-session`'s built-in cookie store).
//! - [`ensure_same_origin`] / [`validate_return_to`] — CSRF and open-redirect
//!   defenses.
//! - [`login_route`] / [`ExtraAuthParams`] — register additional login routes
//!   that add fixed extra parameters (e.g. `prompt=create`) to the OIDC
//!   authorization request.

/// Runtime configuration: [`OidcBffConfig`] and [`ConfigError`].
pub mod config;
/// CSRF defenses for state-mutating endpoints: [`ensure_same_origin`].
pub mod csrf;
/// Crate-wide request error type: [`BffError`].
pub mod error;
/// The [`Auth`] session extractor.
pub mod extractor;
/// The `/auth/*` route handlers (`login`, `callback`, `logout`, `me`).
pub mod handlers;
/// Hardened `SessionMiddleware` construction: [`session_middleware`].
pub mod middleware;
/// OIDC discovery and client caching: [`OidcRp`] and [`DiscoveryError`].
pub mod oidc;
pub(crate) mod param_names;
/// Route registration: [`configure`] and [`configure_app_data`].
pub mod routes;
pub(crate) mod session_state;
/// Bring-your-own persistent session storage: [`SessionRepository`] and
/// [`DbSessionStore`].
pub mod store;

/// The `actix-session` this crate is built against, re-exported so consumers
/// do not have to declare it themselves.
///
/// `SessionStore`, `SessionMiddleware` and `TtlExtensionPolicy` appear in this
/// crate's public API ([`session_middleware`], [`DbSessionStore`]), which makes
/// `actix-session` a *public dependency*: a consumer who declares their own
/// semver-incompatible version gets two copies of those types in the graph,
/// and passing a store built from one into an API expecting the other fails to
/// compile with the notoriously opaque `expected SessionStore, found
/// SessionStore`. Going through this re-export makes that impossible, and means
/// a future `actix-session` bump here only breaks consumers who actually touch
/// something that changed upstream — rather than all of them, unconditionally.
pub use actix_session;
pub use config::{
    ConfigError, OidcBffConfig, OidcBffConfigBuilder, SessionExpiry, SessionExpiryParseError,
};
pub use csrf::ensure_same_origin;
pub use error::BffError;
pub use extractor::Auth;
pub use handlers::login::{login_route, validate_return_to, AuthParamError, ExtraAuthParams};
pub use middleware::session_middleware;
pub use oidc::{DiscoveryError, OidcRp};
pub use param_names::MAX_PARAM_NAME_LEN;
pub use routes::{configure, configure_app_data};
pub use store::{DbSessionStore, RepoError, SessionRecord, SessionRepository};
