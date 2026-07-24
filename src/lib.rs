#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
//!
//! ## Pieces
//! - [`OidcBffConfig`] — runtime configuration (issuer, client credentials,
//!   cookie/session settings), buildable from environment variables.
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
/// Route registration: [`configure`] and [`configure_app_data`].
pub mod routes;
pub(crate) mod session_state;
/// Bring-your-own persistent session storage: [`SessionRepository`] and
/// [`DbSessionStore`].
pub mod store;

pub use config::{ConfigError, OidcBffConfig};
pub use csrf::ensure_same_origin;
pub use error::BffError;
pub use extractor::Auth;
pub use handlers::login::validate_return_to;
pub use middleware::session_middleware;
pub use oidc::{DiscoveryError, OidcRp};
pub use routes::{configure, configure_app_data};
pub use store::{DbSessionStore, RepoError, SessionRecord, SessionRepository};
