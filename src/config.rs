use std::str::FromStr;
use std::time::Duration;

use actix_session::config::TtlExtensionPolicy;
use actix_web::cookie::Key;
use base64::prelude::*;
use openidconnect::url::{Origin, Url};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::handlers::login::validate_return_to;
use crate::param_names::{
    validate_param_name, ParamNameError, DENIED_PASSTHROUGH_PARAMS, MAX_PARAM_NAME_LEN,
};
use crate::session_state::RESERVED_SESSION_KEYS;

/// Errors returned by [`OidcBffConfigBuilder::build`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ConfigError {
    /// One or more required setters were not called on the
    /// [`OidcBffConfigBuilder`] before `build()`. Every missing field's
    /// setter name is reported together, so a misconfigured builder doesn't
    /// need multiple build → fix → rebuild cycles to discover them all.
    /// `"session_key"` in this list means none of
    /// [`OidcBffConfigBuilder::session_key`],
    /// [`OidcBffConfigBuilder::session_key_base64`], or
    /// [`OidcBffConfigBuilder::generate_ephemeral_session_key`] was called.
    #[error("Missing required configuration: {0:?}")]
    MissingFields(Vec<&'static str>),
    /// `session_key_base64` input was not valid base64, or decoded to fewer
    /// than 64 bytes.
    #[error("Invalid session key: {0}")]
    InvalidSessionKey(String),
    /// `redirect_url` was unparsable, used a non-http(s) scheme, or had
    /// an opaque origin.
    #[error("Invalid redirect URL: {0}")]
    InvalidRedirectUrl(String),
    /// `post_logout_redirect_url` was unparsable, used a non-http(s)
    /// scheme, had an opaque origin, or was plain http while `redirect_url`
    /// is https.
    #[error("Invalid post-logout redirect URL: {0}")]
    InvalidPostLogoutRedirectUrl(String),
    /// `return_to_prefix` failed [`validate_return_to`].
    #[error("Invalid return_to prefix: {0}")]
    InvalidReturnToPrefix(String),
    /// A `persist_claims` entry collided with a reserved session key or
    /// an OIDC validation-artifact claim name.
    #[error("Reserved claim name: {0}")]
    ReservedClaimName(String),
    /// `pre_auth_ttl`, `post_auth_ttl`, or `max_session_lifetime` was
    /// [`Duration::ZERO`], exceeded the maximum allowed TTL
    /// ([`MAX_TTL_SECS`]), overflowed `i64` seconds, or `post_auth_ttl`
    /// exceeded `max_session_lifetime`.
    #[error("Invalid session TTL: {0}")]
    InvalidTtl(String),
    /// A `callback_passthrough_params` entry was malformed, duplicated, or
    /// named a parameter that must never be forwarded into a browser-visible
    /// URL (the authorization code, a token, `state`, …), or more than
    /// [`MAX_PASSTHROUGH_PARAMS`] entries were supplied.
    #[error("Invalid callback passthrough parameter: {0}")]
    InvalidPassthroughParam(String),
}

/// Runtime configuration for the OIDC relying party and session cookie.
///
/// The only way to construct one is [`OidcBffConfig::builder`] followed by
/// [`OidcBffConfigBuilder::build`], which performs all validation.
pub struct OidcBffConfig {
    /// The OIDC provider's issuer URL, used for discovery.
    issuer_url: String,
    /// The confidential client's ID, as registered with the IdP.
    client_id: String,
    /// The confidential client's secret. Held as a [`SecretString`] so it is
    /// never accidentally logged or `Debug`-printed.
    client_secret: SecretString,
    /// This app's OIDC callback URL, registered at the IdP. Its scheme
    /// determines `cookie_secure`; its origin is precomputed into
    /// `allowed_origin` for CSRF checks.
    redirect_url: String,
    /// Signing/encryption key for the session cookie.
    session_key: Key,
    /// Session cookie name — `__Host-`-prefixed when `cookie_secure` is
    /// true. Computed once in `build()` from `redirect_url`; never
    /// recompute this in a getter — it exists precisely so the per-request
    /// CSRF/cookie logic does not re-parse a URL.
    cookie_name: String,
    /// Whether the session cookie is marked `Secure`; derived from
    /// `redirect_url`'s scheme (`true` for https). Computed once in
    /// `build()` from `redirect_url`; never recompute this in a getter —
    /// it exists precisely so the per-request CSRF/revocation-transport
    /// checks do not re-parse a URL.
    cookie_secure: bool,
    /// Pre-computed ASCII origin of `redirect_url` for CSRF comparisons.
    /// Computed once in `build()` from `redirect_url`; never recompute this
    /// in a getter — it exists precisely so the per-request CSRF check does
    /// not re-parse a URL.
    pub(crate) allowed_origin: String,
    /// Scopes to request from the IdP.
    scopes: Vec<String>,
    /// JWKS metadata refresh interval in seconds. Not configurable via the
    /// builder (deliberate — see [`Self::jwks_ttl_secs`]).
    jwks_ttl_secs: u64,
    /// Pre-auth (state/pkce) session TTL in seconds. Must be greater than 0
    /// and at most [`MAX_TTL_SECS`].
    pre_auth_ttl_secs: i64,
    /// Post-auth session TTL in seconds. Must be greater than 0, at most
    /// [`MAX_TTL_SECS`], and at most `max_session_lifetime_secs`.
    post_auth_ttl_secs: i64,
    /// Absolute ceiling on a session's total life, counted from login,
    /// enforced regardless of the idle/sliding `post_auth_ttl_secs`. Must
    /// be greater than 0, at most [`MAX_TTL_SECS`], and at least
    /// `post_auth_ttl_secs`.
    ///
    /// This field only carries the configured ceiling — enforcement lives in
    /// [`crate::DbSessionStore`] and, store-agnostically, in the
    /// [`crate::Auth`] extractor, both of which reject a session whose login
    /// time has aged past this many seconds. This matters most under
    /// [`SessionExpiry::Sliding`], where `post_auth_ttl_secs` alone would
    /// otherwise permit an unbounded session lifetime.
    max_session_lifetime_secs: i64,
    /// Determines whether `post_auth_ttl_secs` is an absolute expiry from
    /// login ([`SessionExpiry::Fixed`], the default) or a sliding expiry that
    /// resets on every authenticated request ([`SessionExpiry::Sliding`]).
    ///
    /// See [`crate::session_middleware`] for the operational trade-off
    /// between the two modes.
    session_expiry: SessionExpiry,
    /// Path prefix that a `return_to` value must start with. The application
    /// decides where it is safe to redirect back to after login (e.g. `/`,
    /// `/portal/`, `/app/`). See [`crate::validate_return_to`].
    return_to_prefix: String,
    /// Extra ID-token claim names to capture into the server-side session.
    ///
    /// Any claim listed here that is present in the ID token's additional
    /// claims (fields beyond the standard OIDC set) will be serialised as a
    /// JSON value and stored in the session. The [`crate::Auth`] extractor
    /// exposes them via [`crate::Auth::claims`] / [`crate::Auth::get_claim`].
    ///
    /// Claim names that collide with the crate's internal session keys
    /// (`sub`, `access_token`, …) or with OIDC validation-artifact claim
    /// names (`aud`, `exp`, `iat`, `nbf`, `nonce`, `at_hash`, `c_hash`) are
    /// rejected at configuration time.
    persist_claims: Vec<String>,
    /// Where the IdP may redirect the browser after RP-initiated logout.
    /// Optional; when set it is sent as `post_logout_redirect_uri` and must
    /// be registered at the IdP.
    post_logout_redirect_url: Option<String>,
    /// Query-parameter names that, when present on the IdP's callback
    /// request, are appended to the post-login redirect URL.
    ///
    /// Empty by default, which is exactly the pre-0.3 behaviour: the callback
    /// redirects to the stored `return_to` untouched. See
    /// [`Self::callback_passthrough_params`] for the trust model — the values
    /// are untrusted input and reach the application's own query string.
    callback_passthrough_params: Vec<String>,
}

/// OIDC validation-artifact claim names that must not be persisted into the
/// session. They are not secrets but have no persistence use and invite
/// confusion; `auth_time` and `azp` are legitimately useful and stay allowed.
const VALIDATION_ARTIFACT_CLAIMS: &[&str] =
    &["aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash"];

/// Default value (seconds) for [`OidcBffConfigBuilder::pre_auth_ttl`] — 10
/// minutes.
pub const DEFAULT_PRE_AUTH_TTL_SECS: i64 = 600;

/// Default value (seconds) for [`OidcBffConfigBuilder::post_auth_ttl`] — 8
/// hours.
///
/// Deliberately lower than a naive 12-hour default: a shorter idle ceiling
/// reduces the exposure window of a stolen session cookie without
/// materially harming UX for actively used sessions.
pub const DEFAULT_POST_AUTH_TTL_SECS: i64 = 8 * 3600;

/// Default value (seconds) for [`OidcBffConfigBuilder::max_session_lifetime`]
/// — 7 days.
pub const DEFAULT_MAX_SESSION_LIFETIME_SECS: i64 = 7 * 24 * 3600;

/// Maximum allowed value, in seconds, for
/// [`OidcBffConfigBuilder::pre_auth_ttl`],
/// [`OidcBffConfigBuilder::post_auth_ttl`], and
/// [`OidcBffConfigBuilder::max_session_lifetime`] (365 days). A configured
/// TTL beyond this is treated as a configuration error rather than a
/// preference — it's far more likely to be a unit mistake (e.g. milliseconds
/// instead of seconds) than an intentional year-plus-lived session, and an
/// unbounded TTL defeats the point of having one at all.
pub const MAX_TTL_SECS: i64 = 365 * 24 * 3600;

/// Maximum number of entries accepted by
/// [`OidcBffConfigBuilder::callback_passthrough_params`].
///
/// The cap exists because every allowlisted parameter that the IdP actually
/// sends is appended to the post-login `Location` header, and some proxies and
/// older clients cap URLs around 2 KB. Eight names is far more feedback than
/// any real post-login flow needs.
pub const MAX_PASSTHROUGH_PARAMS: usize = 8;

/// Determines whether [`OidcBffConfig::post_auth_ttl()`] is an absolute
/// expiry from login or a sliding expiry that resets on every authenticated
/// request.
///
/// See [`crate::session_middleware`] for the operational trade-off (session
/// store read/write counts, `Set-Cookie` behaviour, and availability blast
/// radius) between the two modes.
///
/// Deliberately named `Fixed` rather than `Absolute`:
/// [`OidcBffConfig::max_session_lifetime()`] is the crate's actual
/// *absolute* ceiling on a session's total life, and having both an
/// `Absolute` variant here and an "absolute ceiling" field elsewhere would
/// read confusingly next to each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionExpiry {
    /// `post_auth_ttl_secs` is an absolute expiry counted from login: it is
    /// only reset when the session state itself changes (or the session key
    /// is renewed), so normal request activity does *not* extend it. Maps to
    /// `actix_session::config::TtlExtensionPolicy::OnStateChanges`.
    #[default]
    Fixed,
    /// `post_auth_ttl_secs` becomes a sliding expiry: every authenticated
    /// request pushes the expiry forward, so an actively browsing user is
    /// never logged out mid-session. Maps to
    /// `actix_session::config::TtlExtensionPolicy::OnEveryRequest`. Combine
    /// with [`OidcBffConfig::max_session_lifetime()`] to bound the
    /// otherwise-unbounded session lifetime this mode produces.
    Sliding,
}

impl From<SessionExpiry> for TtlExtensionPolicy {
    fn from(expiry: SessionExpiry) -> Self {
        match expiry {
            SessionExpiry::Fixed => TtlExtensionPolicy::OnStateChanges,
            SessionExpiry::Sliding => TtlExtensionPolicy::OnEveryRequest,
        }
    }
}

/// Error returned by [`SessionExpiry`]'s [`FromStr`] implementation when the
/// input is neither `"fixed"` nor `"sliding"` (matched case-insensitively,
/// after trimming).
///
/// This is a small standalone error type — not a [`ConfigError`] variant —
/// because [`SessionExpiry`] parsing is a general-purpose helper a consumer
/// may want to use on their own configuration input (e.g. their own env var),
/// independent of the rest of this crate's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid session expiry {0:?}: expected \"fixed\" or \"sliding\"")]
pub struct SessionExpiryParseError(String);

impl FromStr for SessionExpiry {
    type Err = SessionExpiryParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fixed" => Ok(SessionExpiry::Fixed),
            "sliding" => Ok(SessionExpiry::Sliding),
            _ => Err(SessionExpiryParseError(s.to_string())),
        }
    }
}

impl OidcBffConfig {
    /// Start building a config. See [`OidcBffConfigBuilder`].
    #[must_use]
    pub fn builder() -> OidcBffConfigBuilder {
        OidcBffConfigBuilder::default()
    }

    /// The OIDC provider's issuer URL, used for discovery.
    #[inline]
    #[must_use]
    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    /// The confidential client's ID, as registered with the IdP.
    #[inline]
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// This app's OIDC callback URL, registered at the IdP.
    #[inline]
    #[must_use]
    pub fn redirect_url(&self) -> &str {
        &self.redirect_url
    }

    /// Session cookie name — `__Host-`-prefixed when [`Self::cookie_secure`]
    /// is true. Computed once in `build()` from `redirect_url`; never
    /// recompute this — it exists precisely so per-request logic does not
    /// re-parse a URL.
    #[inline]
    #[must_use]
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// Path prefix that a `return_to` value must start with.
    #[inline]
    #[must_use]
    pub fn return_to_prefix(&self) -> &str {
        &self.return_to_prefix
    }

    /// Where the IdP may redirect the browser after RP-initiated logout, if
    /// configured.
    #[inline]
    #[must_use]
    pub fn post_logout_redirect_url(&self) -> Option<&str> {
        self.post_logout_redirect_url.as_deref()
    }

    /// Extra ID-token claim names to capture into the server-side session.
    #[inline]
    #[must_use]
    pub fn persist_claims(&self) -> &[String] {
        &self.persist_claims
    }

    /// Query-parameter names forwarded from the IdP's callback request onto
    /// the post-login redirect URL. Empty by default.
    ///
    /// **The forwarded values are untrusted.** They arrive on the callback
    /// request and are appended, percent-encoded, to the application's own
    /// query string; the crate validates their shape but knows nothing about
    /// their meaning. Never render them into HTML unescaped, and never use one
    /// as a redirect target or an authorization input.
    #[inline]
    #[must_use]
    pub fn callback_passthrough_params(&self) -> &[String] {
        &self.callback_passthrough_params
    }

    /// Scopes to request from the IdP.
    #[inline]
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Whether the session cookie is marked `Secure`; derived from
    /// `redirect_url`'s scheme (`true` for https). Computed once in
    /// `build()` from `redirect_url`; never recompute this — it exists
    /// precisely so the per-request CSRF/revocation-transport checks do not
    /// re-parse a URL.
    #[inline]
    #[must_use]
    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    /// Whether `post_auth_ttl` is an absolute or sliding expiry.
    #[inline]
    #[must_use]
    pub fn session_expiry(&self) -> SessionExpiry {
        self.session_expiry
    }

    /// Signing/encryption key for the session cookie. Returns a borrow;
    /// callers that need an owned `Key` (e.g. to hand to
    /// `SessionMiddleware::builder`) should clone it explicitly.
    #[inline]
    #[must_use]
    pub fn session_key(&self) -> &Key {
        &self.session_key
    }

    /// Pre-computed ASCII origin of `redirect_url`, used for CSRF
    /// comparisons. Computed once in `build()`; never recompute this — it
    /// exists precisely so the per-request CSRF check does not re-parse a
    /// URL.
    #[inline]
    pub(crate) fn allowed_origin(&self) -> &str {
        &self.allowed_origin
    }

    /// The confidential client's secret. Deliberately not public:
    /// `oidc.rs` is the only in-crate consumer, and exposing `&SecretString`
    /// publicly would widen the secret's reach for no known consumer need.
    #[inline]
    pub(crate) fn client_secret(&self) -> &SecretString {
        &self.client_secret
    }

    /// Pre-auth (state/PKCE) session TTL.
    #[inline]
    #[must_use]
    pub fn pre_auth_ttl(&self) -> Duration {
        Duration::from_secs(self.pre_auth_ttl_secs.unsigned_abs())
    }

    /// Post-auth (authenticated) session TTL.
    #[inline]
    #[must_use]
    pub fn post_auth_ttl(&self) -> Duration {
        Duration::from_secs(self.post_auth_ttl_secs.unsigned_abs())
    }

    /// Absolute ceiling on a session's total life, counted from login.
    #[inline]
    #[must_use]
    pub fn max_session_lifetime(&self) -> Duration {
        Duration::from_secs(self.max_session_lifetime_secs.unsigned_abs())
    }

    /// [`Self::pre_auth_ttl`] in whole seconds, for internal call sites that
    /// want `i64` directly rather than repeating the `Duration` conversion.
    #[inline]
    pub(crate) fn pre_auth_ttl_secs(&self) -> i64 {
        self.pre_auth_ttl_secs
    }

    /// [`Self::post_auth_ttl`] in whole seconds, for internal call sites
    /// that want `i64` directly rather than repeating the `Duration`
    /// conversion.
    #[inline]
    pub(crate) fn post_auth_ttl_secs(&self) -> i64 {
        self.post_auth_ttl_secs
    }

    /// [`Self::max_session_lifetime`] in whole seconds, for internal call
    /// sites that want `i64` directly rather than repeating the `Duration`
    /// conversion.
    #[inline]
    pub(crate) fn max_session_lifetime_secs(&self) -> i64 {
        self.max_session_lifetime_secs
    }

    /// JWKS metadata refresh interval in seconds. Internal-only, and
    /// deliberately has no builder setter: a long JWKS cache keeps revoked
    /// IdP signing keys trusted, and there is no migration need since no
    /// env var exposed this before either.
    #[inline]
    pub(crate) fn jwks_ttl_secs(&self) -> u64 {
        self.jwks_ttl_secs
    }
}

/// Captures which of [`OidcBffConfigBuilder::session_key`],
/// [`OidcBffConfigBuilder::session_key_base64`], or
/// [`OidcBffConfigBuilder::generate_ephemeral_session_key`] was called most
/// recently — repeat calls to any of the three replace the prior choice,
/// they never combine.
enum SessionKeySource {
    Explicit(Key),
    /// Holds the base64 decode/length-check result computed eagerly in the
    /// setter (so the setter itself never panics); surfaced by `build()`.
    Base64(Result<Key, ConfigError>),
    Ephemeral,
}

/// Builder for [`OidcBffConfig`] — the crate's only construction path.
///
/// Setters are infallible and perform **no validation**; they only store the
/// raw value, so setter call order never matters. All validation — including
/// cross-field checks like `post_auth_ttl <= max_session_lifetime`, and
/// derived-field consistency like `cookie_secure` following whichever
/// `redirect_url` was set last — happens once, in a fixed order, inside
/// [`Self::build`]. Repeat calls to the same setter replace the previously
/// stored value; they never append.
///
/// # Example
///
/// ```
/// use actix_web_oidc_bff::OidcBffConfig;
///
/// // NOTE: the literal secret and ephemeral key below keep this example
/// // self-contained so it compiles as a doctest. Real deployments must load
/// // the secret from a file or secret manager and supply a persistent
/// // `session_key` — see the crate README's "Secrets and keys" section.
/// let cfg = OidcBffConfig::builder()
///     .issuer_url("https://idp.example.com")
///     .client_id("my-client")
///     .client_secret("my-secret")
///     .redirect_url("https://app.example.com/auth/callback")
///     .generate_ephemeral_session_key()
///     .build()
///     .unwrap();
/// assert_eq!(cfg.issuer_url(), "https://idp.example.com");
/// ```
#[derive(Default)]
pub struct OidcBffConfigBuilder {
    issuer_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    redirect_url: Option<String>,
    session_key_source: Option<SessionKeySource>,
    scopes: Option<Vec<String>>,
    persist_claims: Option<Vec<String>>,
    callback_passthrough_params: Option<Vec<String>>,
    return_to_prefix: Option<String>,
    post_logout_redirect_url: Option<String>,
    pre_auth_ttl: Option<Duration>,
    post_auth_ttl: Option<Duration>,
    max_session_lifetime: Option<Duration>,
    session_expiry: Option<SessionExpiry>,
}

impl OidcBffConfigBuilder {
    /// The OIDC provider's issuer URL, used for discovery. Required.
    #[must_use]
    pub fn issuer_url(mut self, issuer_url: impl Into<String>) -> Self {
        self.issuer_url = Some(issuer_url.into());
        self
    }

    /// The confidential client's ID, as registered with the IdP. Required.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// The confidential client's secret. Wrapped into a [`SecretString`]
    /// immediately in this setter, so the builder never holds a bare
    /// `String` — this shortens the window in which a core dump or panic
    /// backtrace could contain it. Required.
    #[must_use]
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(SecretString::new(client_secret.into()));
        self
    }

    /// This app's OIDC callback URL, registered at the IdP. Its scheme
    /// determines `cookie_secure`; its origin is precomputed into
    /// `allowed_origin` for CSRF checks. Required.
    #[must_use]
    pub fn redirect_url(mut self, redirect_url: impl Into<String>) -> Self {
        self.redirect_url = Some(redirect_url.into());
        self
    }

    /// Signing/encryption key for the session cookie, as an already-decoded
    /// [`Key`]. Mutually exclusive with [`Self::session_key_base64`] and
    /// [`Self::generate_ephemeral_session_key`] — whichever of the three is
    /// called last wins. One of the three must be called.
    #[must_use]
    pub fn session_key(mut self, key: Key) -> Self {
        self.session_key_source = Some(SessionKeySource::Explicit(key));
        self
    }

    /// Signing/encryption key for the session cookie, base64-encoded. Must
    /// decode to at least 64 bytes; bytes beyond the first 64 are silently
    /// ignored.
    ///
    /// This setter never panics: `actix_web::cookie::Key::from` panics on
    /// input shorter than 64 bytes, so the decode and length check happen
    /// here, and any failure is deferred to [`Self::build`] as a typed
    /// [`ConfigError::InvalidSessionKey`] instead. Mutually exclusive with
    /// [`Self::session_key`] and [`Self::generate_ephemeral_session_key`] —
    /// whichever of the three is called last wins. One of the three must be
    /// called.
    #[must_use]
    pub fn session_key_base64(mut self, base64: impl AsRef<str>) -> Self {
        // Strip ASCII whitespace before decoding. `BASE64_STANDARD` does not
        // skip it, and the command every doc example recommends —
        // `openssl rand -base64 64` — wraps its output at column 64, so the
        // value contains an embedded newline as well as a trailing one. A
        // caller's `.trim()` removes only the latter, so without this the
        // documented happy path fails at startup with "not valid base64".
        let cleaned: String = base64
            .as_ref()
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let result = BASE64_STANDARD
            .decode(&cleaned)
            .map_err(|e| ConfigError::InvalidSessionKey(format!("not valid base64: {e}")))
            .and_then(|bytes| {
                if bytes.len() < 64 {
                    Err(ConfigError::InvalidSessionKey(format!(
                        "must decode to at least 64 bytes, got {}",
                        bytes.len()
                    )))
                } else {
                    Ok(Key::from(&bytes[..64]))
                }
            });
        self.session_key_source = Some(SessionKeySource::Base64(result));
        self
    }

    /// Generate a random session cookie key at [`Self::build`] time. This is
    /// an explicit opt-in — not a fallback default — and logs a warning when
    /// `build()` runs. Before choosing this:
    ///
    /// - Sessions die on every process restart (the key isn't persisted
    ///   anywhere).
    /// - **Multi-replica deployments are broken, not degraded**: each
    ///   replica generates its own independent key, so a replica cannot
    ///   decrypt a cookie signed by another — requests intermittently 401
    ///   depending on which replica handles them.
    /// - There is no key-rotation path.
    /// - This is intended for local development and tests only. Production
    ///   deployments should use [`Self::session_key`] or
    ///   [`Self::session_key_base64`] with a stable, persisted key.
    ///
    /// Mutually exclusive with [`Self::session_key`] and
    /// [`Self::session_key_base64`] — whichever of the three is called last
    /// wins. One of the three must be called.
    #[must_use]
    pub fn generate_ephemeral_session_key(mut self) -> Self {
        self.session_key_source = Some(SessionKeySource::Ephemeral);
        self
    }

    /// Scopes to request from the IdP. `openid` is mandatory for the OIDC
    /// flow: at [`Self::build`] time, if the provided list omits it, it is
    /// prepended. An empty (or all-whitespace) iterator defaults to
    /// `["openid", "profile", "email"]`. Repeat calls replace, they do not
    /// append.
    #[must_use]
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = Some(scopes.into_iter().map(Into::into).collect());
        self
    }

    /// Extra ID-token claim names to capture into the server-side session.
    /// Entries are trimmed and empties dropped at [`Self::build`] time, and
    /// names colliding with the crate's reserved session keys or OIDC
    /// validation-artifact claim names are rejected there. Repeat calls
    /// replace, they do not append — this matters because a second call
    /// must not be able to smuggle a reserved name past the first call's
    /// (deferred) validation.
    #[must_use]
    pub fn persist_claims(mut self, claims: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.persist_claims = Some(claims.into_iter().map(Into::into).collect());
        self
    }

    /// Query-parameter names to forward from the IdP's callback request onto
    /// the post-login redirect URL. Defaults to empty, which is exactly the
    /// pre-0.3 behaviour.
    ///
    /// The motivating case is post-login feedback: an identity provider that
    /// redirects back with, say, `some_action_status=success` after a
    /// credential change can only tell the application about it through the
    /// callback URL, and the callback otherwise discards everything but
    /// `code` and `state`. Allowlisting the name forwards it to the page the
    /// user lands on.
    ///
    /// Only the **success** path forwards anything: an IdP `error=` response
    /// returns a `400` and never redirects, so nothing is appended there.
    ///
    /// **Forwarded values are untrusted** — see
    /// [`OidcBffConfig::callback_passthrough_params`]. Prefer namespaced names
    /// (an `idp_` prefix, say) so a forwarded value can never collide with one
    /// of the application's own query parameters.
    ///
    /// Entries are trimmed and empties dropped at [`Self::build`] time, where
    /// malformed names, duplicates, names that must never reach a
    /// browser-visible URL, and more than [`MAX_PASSTHROUGH_PARAMS`] entries
    /// are all rejected. Repeat calls replace, they do not append — a second
    /// call must not be able to smuggle a denied name past the first call's
    /// (deferred) validation.
    #[must_use]
    pub fn callback_passthrough_params(
        mut self,
        params: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.callback_passthrough_params = Some(params.into_iter().map(Into::into).collect());
        self
    }

    /// Path prefix that a `return_to` value must start with. Defaults to
    /// `"/"`. See [`crate::validate_return_to`].
    #[must_use]
    pub fn return_to_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.return_to_prefix = Some(prefix.into());
        self
    }

    /// Where the IdP may redirect the browser after RP-initiated logout.
    /// Optional; when set it is sent as `post_logout_redirect_uri` and must
    /// be registered at the IdP.
    #[must_use]
    pub fn post_logout_redirect_url(mut self, url: impl Into<String>) -> Self {
        self.post_logout_redirect_url = Some(url.into());
        self
    }

    /// Pre-auth (state/PKCE) session TTL. Defaults to
    /// [`DEFAULT_PRE_AUTH_TTL_SECS`] (10 minutes).
    #[must_use]
    pub fn pre_auth_ttl(mut self, ttl: Duration) -> Self {
        self.pre_auth_ttl = Some(ttl);
        self
    }

    /// Post-auth (authenticated) session TTL. Defaults to
    /// [`DEFAULT_POST_AUTH_TTL_SECS`] (8 hours).
    #[must_use]
    pub fn post_auth_ttl(mut self, ttl: Duration) -> Self {
        self.post_auth_ttl = Some(ttl);
        self
    }

    /// Absolute ceiling on a session's total life, counted from login.
    /// Defaults to [`DEFAULT_MAX_SESSION_LIFETIME_SECS`] (7 days).
    #[must_use]
    pub fn max_session_lifetime(mut self, ttl: Duration) -> Self {
        self.max_session_lifetime = Some(ttl);
        self
    }

    /// Whether `post_auth_ttl` is an absolute expiry
    /// ([`SessionExpiry::Fixed`], the default) or a sliding one
    /// ([`SessionExpiry::Sliding`]). See [`crate::session_middleware`] for
    /// the operational trade-off between the two.
    #[must_use]
    pub fn session_expiry(mut self, expiry: SessionExpiry) -> Self {
        self.session_expiry = Some(expiry);
        self
    }

    /// Validate every field and construct the immutable [`OidcBffConfig`].
    ///
    /// Validates in a fixed order — `redirect_url` first, then the fields
    /// derived from it (`cookie_secure`, `cookie_name`, `allowed_origin`),
    /// then everything that depends on those — regardless of the order
    /// setters were called in. Required-field presence is checked first and
    /// reported together via [`ConfigError::MissingFields`]; value
    /// validation is fail-fast after that.
    pub fn build(self) -> Result<OidcBffConfig, ConfigError> {
        // ---- Required fields, checked together ----
        // A required field set to an empty or whitespace-only string counts as
        // missing. `from_env` could not distinguish these (`std::env::var`
        // returns `Ok("")` for `FOO=`), but a builder can: an empty
        // `client_secret` would otherwise surface as an opaque token-endpoint
        // rejection at first login, and an empty `issuer_url` as a discovery
        // failure at startup — both far from the actual mistake.
        let mut missing: Vec<&'static str> = Vec::new();
        let is_blank = |v: &Option<String>| v.as_ref().is_none_or(|s| s.trim().is_empty());

        if is_blank(&self.issuer_url) {
            missing.push("issuer_url");
        }
        if is_blank(&self.client_id) {
            missing.push("client_id");
        }
        if self
            .client_secret
            .as_ref()
            .is_none_or(|s| s.expose_secret().trim().is_empty())
        {
            missing.push("client_secret");
        }
        if is_blank(&self.redirect_url) {
            missing.push("redirect_url");
        }
        if self.session_key_source.is_none() {
            missing.push("session_key");
        }
        if !missing.is_empty() {
            return Err(ConfigError::MissingFields(missing));
        }
        let issuer_url = self.issuer_url.expect("checked above");
        let client_id = self.client_id.expect("checked above");
        let client_secret = self.client_secret.expect("checked above");
        let redirect_url_raw = self.redirect_url.expect("checked above");

        // ---- redirect_url, then the fields derived from it ----
        //
        // Trim whitespace before parsing so that inadvertent leading/
        // trailing spaces don't silently break cookie security or origin
        // comparisons.
        let redirect_url = redirect_url_raw.trim().to_string();
        let parsed_redirect = Url::parse(&redirect_url).map_err(|e| {
            ConfigError::InvalidRedirectUrl(format!("redirect_url is not a valid URL: {e}"))
        })?;

        // Only http and https are sensible callback schemes. Reject ftp:,
        // javascript:, etc. up-front rather than letting them produce a
        // confusingly insecure cookie.
        let scheme = parsed_redirect.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ConfigError::InvalidRedirectUrl(format!(
                "redirect_url scheme must be http or https, got {scheme:?}"
            )));
        }

        let cookie_secure = scheme == "https";
        let cookie_name = if cookie_secure {
            "__Host-oidc_bff_session".to_string()
        } else {
            "oidc_bff_session".to_string()
        };

        // Pre-compute the ASCII origin for CSRF checks (scheme + host + port,
        // default ports omitted). Reject opaque origins — they must never match.
        let allowed_origin = match parsed_redirect.origin() {
            origin @ Origin::Tuple(..) => origin.ascii_serialization(),
            Origin::Opaque(_) => {
                return Err(ConfigError::InvalidRedirectUrl(
                    "redirect_url has an opaque origin".to_string(),
                ));
            }
        };

        // ---- session key ----
        let session_key = match self.session_key_source.expect("checked above") {
            SessionKeySource::Explicit(key) => key,
            SessionKeySource::Base64(result) => result?,
            SessionKeySource::Ephemeral => {
                log::warn!(
                    "generate_ephemeral_session_key() is in effect — generating a random \
                     session key. Server restarts and multi-replica deployments will \
                     invalidate/desync sessions. Use session_key() or session_key_base64() \
                     with a stable key for production."
                );
                Key::generate()
            }
        };

        // ---- return_to_prefix ----
        let return_to_prefix = self.return_to_prefix.unwrap_or_else(|| "/".to_string());

        // Validate the prefix by running it through the same path-safety check
        // applied to individual return_to values. This guarantees the default
        // (/auth/login with no return_to) always validates successfully.
        if !validate_return_to(&return_to_prefix, &return_to_prefix) {
            return Err(ConfigError::InvalidReturnToPrefix(format!(
                "return_to_prefix is not a valid return_to value: {return_to_prefix:?}"
            )));
        }

        // ---- scopes ----
        let scopes = normalize_scopes(self.scopes);

        // ---- persist_claims ----
        let persist_claims: Vec<String> = self
            .persist_claims
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        for claim in &persist_claims {
            if RESERVED_SESSION_KEYS.contains(&claim.as_str()) {
                return Err(ConfigError::ReservedClaimName(format!(
                    "persist_claims must not contain the reserved name {claim:?}; \
                     reserved names: {RESERVED_SESSION_KEYS:?}"
                )));
            }
            if VALIDATION_ARTIFACT_CLAIMS.contains(&claim.as_str()) {
                return Err(ConfigError::ReservedClaimName(format!(
                    "persist_claims must not contain the validation-artifact claim \
                     name {claim:?}; these have no persistence use and invite confusion"
                )));
            }
        }

        // ---- callback_passthrough_params ----
        let callback_passthrough_params =
            normalize_passthrough_params(self.callback_passthrough_params)?;

        // ---- post_logout_redirect_url (depends on cookie_secure) ----
        let post_logout_redirect_url = match self.post_logout_redirect_url {
            None => None,
            Some(raw) => {
                // Trim whitespace so that inadvertent spaces don't silently
                // break the IdP redirect match.
                let trimmed = raw.trim().to_string();

                let parsed = Url::parse(&trimmed).map_err(|e| {
                    ConfigError::InvalidPostLogoutRedirectUrl(format!(
                        "post_logout_redirect_url is not a valid URL: {e}"
                    ))
                })?;

                // Only http and https are sensible post-logout schemes.
                let scheme = parsed.scheme();
                if scheme != "http" && scheme != "https" {
                    return Err(ConfigError::InvalidPostLogoutRedirectUrl(format!(
                        "post_logout_redirect_url scheme must be http or https, got {scheme:?}"
                    )));
                }

                // Reject opaque/host-less origins (same guard as
                // redirect_url — they must never be compared as origins).
                match parsed.origin() {
                    Origin::Tuple(..) => {}
                    Origin::Opaque(_) => {
                        return Err(ConfigError::InvalidPostLogoutRedirectUrl(
                            "post_logout_redirect_url has an opaque origin".to_string(),
                        ));
                    }
                }

                // When the app is served over https (cookie_secure), a
                // plain-http post-logout URL is inconsistent and would send
                // session-related parameters over an unencrypted channel.
                // Require https in that case.
                if cookie_secure && scheme != "https" {
                    return Err(ConfigError::InvalidPostLogoutRedirectUrl(
                        "post_logout_redirect_url must be https when redirect_url is https"
                            .to_string(),
                    ));
                }

                Some(trimmed)
            }
        };

        // ---- TTLs ----
        let pre_auth_ttl_secs = duration_to_ttl_secs(
            self.pre_auth_ttl
                .unwrap_or(Duration::from_secs(DEFAULT_PRE_AUTH_TTL_SECS as u64)),
            "pre_auth_ttl",
        )?;
        let post_auth_ttl_secs = duration_to_ttl_secs(
            self.post_auth_ttl
                .unwrap_or(Duration::from_secs(DEFAULT_POST_AUTH_TTL_SECS as u64)),
            "post_auth_ttl",
        )?;
        let max_session_lifetime_secs = duration_to_ttl_secs(
            self.max_session_lifetime.unwrap_or(Duration::from_secs(
                DEFAULT_MAX_SESSION_LIFETIME_SECS as u64,
            )),
            "max_session_lifetime",
        )?;

        // The idle/sliding TTL must never exceed the absolute ceiling — that
        // combination makes post_auth_ttl_secs dead code (the session always
        // expires via the absolute cap first).
        if post_auth_ttl_secs > max_session_lifetime_secs {
            return Err(ConfigError::InvalidTtl(format!(
                "post_auth_ttl ({post_auth_ttl_secs}s) must not exceed \
                 max_session_lifetime ({max_session_lifetime_secs}s); raise \
                 max_session_lifetime or lower post_auth_ttl"
            )));
        }

        // ---- session expiry ----
        let session_expiry = self.session_expiry.unwrap_or_default();

        Ok(OidcBffConfig {
            issuer_url,
            client_id,
            client_secret,
            redirect_url,
            session_key,
            cookie_name,
            cookie_secure,
            allowed_origin,
            scopes,
            jwks_ttl_secs: 900,
            pre_auth_ttl_secs,
            post_auth_ttl_secs,
            max_session_lifetime_secs,
            session_expiry,
            return_to_prefix,
            persist_claims,
            post_logout_redirect_url,
            callback_passthrough_params,
        })
    }
}

/// Normalize and validate a builder-supplied callback-passthrough allowlist.
///
/// Entries are trimmed and empties dropped (so a list assembled from optional
/// sources doesn't need pre-filtering), then each surviving name must pass
/// [`validate_param_name`] against [`DENIED_PASSTHROUGH_PARAMS`] and be unique
/// within the list. The count is checked **after** normalization, so dropped
/// empties don't consume the budget.
fn normalize_passthrough_params(params: Option<Vec<String>>) -> Result<Vec<String>, ConfigError> {
    let names: Vec<String> = params
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if names.len() > MAX_PASSTHROUGH_PARAMS {
        return Err(ConfigError::InvalidPassthroughParam(format!(
            "at most {MAX_PASSTHROUGH_PARAMS} callback_passthrough_params are allowed, got {}",
            names.len()
        )));
    }

    for (i, name) in names.iter().enumerate() {
        match validate_param_name(name, DENIED_PASSTHROUGH_PARAMS) {
            Ok(()) => {}
            Err(ParamNameError::Empty) => {
                // Unreachable: empties were filtered above. Handled rather
                // than `unreachable!()` so a future change to the filter
                // cannot turn this into a panic in a consumer's startup path.
                return Err(ConfigError::InvalidPassthroughParam(
                    "callback_passthrough_params must not contain empty names".to_string(),
                ));
            }
            Err(ParamNameError::TooLong) => {
                return Err(ConfigError::InvalidPassthroughParam(format!(
                    "callback_passthrough_params name must be at most \
                     {MAX_PARAM_NAME_LEN} bytes, got {} bytes",
                    name.len()
                )));
            }
            Err(ParamNameError::InvalidCharset) => {
                return Err(ConfigError::InvalidPassthroughParam(format!(
                    "callback_passthrough_params name {name:?} must contain only \
                     ASCII letters, digits, '_', '.', or '-'"
                )));
            }
            Err(ParamNameError::Denied) => {
                return Err(ConfigError::InvalidPassthroughParam(format!(
                    "callback_passthrough_params must not contain {name:?}: forwarding it \
                     into the post-login URL would expose it in browser history, the \
                     Referer header, and access logs; denied names: \
                     {DENIED_PASSTHROUGH_PARAMS:?}"
                )));
            }
        }

        if names[..i].iter().any(|earlier| earlier == name) {
            return Err(ConfigError::InvalidPassthroughParam(format!(
                "callback_passthrough_params contains {name:?} more than once"
            )));
        }
    }

    Ok(names)
}

/// Normalize a builder-supplied scope list.
///
/// - `None`, or a list that is empty/whitespace-only after trimming, yields
///   the default `["openid", "profile", "email"]`.
/// - Otherwise entries are trimmed and empties dropped.
/// - `openid` is mandatory: if the resulting non-empty list lacks it, it is
///   prepended so the OIDC authorization-code flow always works.
fn normalize_scopes(scopes: Option<Vec<String>>) -> Vec<String> {
    let default = || {
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]
    };

    let Some(raw) = scopes else {
        return default();
    };

    let mut scopes: Vec<String> = raw
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if scopes.is_empty() {
        return default();
    }

    if !scopes.iter().any(|s| s == "openid") {
        scopes.insert(0, "openid".to_string());
    }

    scopes
}

/// Convert a builder-supplied [`Duration`] into whole-second `i64` TTL,
/// rejecting anything under one second, values exceeding [`MAX_TTL_SECS`],
/// and values that would overflow `i64` seconds (the latter is unreachable in
/// practice once the `MAX_TTL_SECS` check passes, but is checked explicitly
/// rather than relying on that ordering).
///
/// Sub-second values are rejected rather than truncated. Truncation would be
/// silent and severe: `Duration::from_millis(500)` is not `Duration::ZERO`, so
/// a `is_zero()` guard lets it through, and `as_secs()` then yields `0` — a
/// zero `pre_auth_ttl` makes every pre-auth slot expire the instant it is
/// written, permanently breaking login with no error anywhere. It also escapes
/// [`crate::DbSessionStore::from_config`], which assigns these values directly
/// on the assumption that `build()` guarantees them positive. `MAX_TTL_SECS`
/// catches a units mistake in one direction (`from_secs(600_000)`); this
/// catches the same mistake in the other (`from_millis(600)`).
fn duration_to_ttl_secs(d: Duration, field: &'static str) -> Result<i64, ConfigError> {
    if d.as_secs() == 0 {
        return Err(ConfigError::InvalidTtl(format!(
            "{field} must be at least one second, got {d:?}"
        )));
    }
    if d.subsec_nanos() != 0 {
        return Err(ConfigError::InvalidTtl(format!(
            "{field} must be a whole number of seconds, got {d:?}"
        )));
    }
    if d.as_secs() > MAX_TTL_SECS as u64 {
        return Err(ConfigError::InvalidTtl(format!(
            "{field} must not exceed {MAX_TTL_SECS} seconds (365 days), got {}",
            d.as_secs()
        )));
    }
    i64::try_from(d.as_secs()).map_err(|_| {
        ConfigError::InvalidTtl(format!("{field} is too large to represent as i64 seconds"))
    })
}

/// Shared test fixture: a builder pre-populated with the minimal set of
/// required fields (issuer/client/secret/redirect URL, an ephemeral session
/// key), so each test can override individual fields before building —
/// avoids duplicating this builder chain across the test modules of
/// `middleware.rs` and the `handlers/*.rs` handler files.
#[cfg(test)]
pub(crate) fn test_config_builder() -> OidcBffConfigBuilder {
    OidcBffConfig::builder()
        .issuer_url("https://idp.example.com")
        .client_id("test-client")
        .client_secret("test-secret")
        .redirect_url("https://app.example.com/auth/callback")
        .generate_ephemeral_session_key()
}

/// Convenience wrapper around [`test_config_builder`] for tests that don't
/// need to override any field.
#[cfg(test)]
pub(crate) fn test_config() -> OidcBffConfig {
    test_config_builder().build().unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{test_config, test_config_builder};

    // ── Required fields / MissingFields ───────────────────────────────────

    #[test]
    fn missing_fields_lists_all_missing_required_fields_together() {
        let err = super::OidcBffConfig::builder().build().err().unwrap();
        match err {
            super::ConfigError::MissingFields(fields) => {
                assert!(fields.contains(&"issuer_url"));
                assert!(fields.contains(&"client_id"));
                assert!(fields.contains(&"client_secret"));
                assert!(fields.contains(&"redirect_url"));
                assert!(fields.contains(&"session_key"));
            }
            other => panic!("expected MissingFields, got: {other}"),
        }
    }

    #[test]
    fn missing_fields_reports_only_unset_fields() {
        let err = super::OidcBffConfig::builder()
            .issuer_url("https://idp.example.com")
            .client_id("client")
            .build()
            .err()
            .unwrap();
        match err {
            super::ConfigError::MissingFields(fields) => {
                assert!(!fields.contains(&"issuer_url"));
                assert!(!fields.contains(&"client_id"));
                assert!(fields.contains(&"client_secret"));
                assert!(fields.contains(&"redirect_url"));
                assert!(fields.contains(&"session_key"));
            }
            other => panic!("expected MissingFields, got: {other}"),
        }
    }

    // ── Hostile setter ordering ────────────────────────────────────────────

    /// Setting `post_logout_redirect_url` (as plain http) *before*
    /// `redirect_url` is switched to https must still be rejected: `build()`
    /// computes `cookie_secure` from the final `redirect_url` value, not
    /// from setter call order, so the https-downgrade guard cannot be
    /// bypassed by reordering calls.
    #[test]
    fn hostile_setter_order_post_logout_before_redirect_url_still_validates() {
        let err = test_config_builder()
            .post_logout_redirect_url("http://app.example.com/bye")
            .redirect_url("https://app.example.com/auth/callback")
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl, got: {err}"
        );
    }

    /// The same guard must also catch the case where `redirect_url` is set
    /// to http *after* an https-only post-logout URL was already configured
    /// — no ordering of `.redirect_url(..)` calls should leave
    /// `cookie_secure` inconsistent with the final URL.
    #[test]
    fn hostile_setter_order_redirect_url_downgraded_after_being_set_twice() {
        let cfg = test_config_builder()
            .redirect_url("https://app.example.com/auth/callback")
            .redirect_url("http://app.example.com/auth/callback")
            .build()
            .unwrap();
        assert!(!cfg.cookie_secure());
        // http post-logout URL is fine now, since cookie_secure ended up false.
        let cfg = test_config_builder()
            .redirect_url("https://app.example.com/auth/callback")
            .redirect_url("http://app.example.com/auth/callback")
            .post_logout_redirect_url("http://app.example.com/bye")
            .build()
            .unwrap();
        assert!(!cfg.cookie_secure());
    }

    /// The upgrade direction: an http `redirect_url` replaced by an https one
    /// must end up `cookie_secure`. A builder that memoised the derived
    /// fields inside `.redirect_url()` instead of computing them in `build()`
    /// would leave `cookie_secure == false` on an https app — a silently
    /// non-Secure session cookie, and the https-downgrade guard disabled.
    #[test]
    fn redirect_url_upgraded_to_https_derives_secure_cookie() {
        let cfg = test_config_builder()
            .redirect_url("http://app.example.com/auth/callback")
            .redirect_url("https://app.example.com/auth/callback")
            .build()
            .unwrap();
        assert!(
            cfg.cookie_secure(),
            "the final https redirect_url must drive cookie_secure"
        );
        assert!(cfg.cookie_name().starts_with("__Host-"));
        assert_eq!(cfg.allowed_origin(), "https://app.example.com");
    }

    /// A `redirect_url` whose origin is opaque (no host) must be rejected —
    /// `allowed_origin` would otherwise be meaningless and the logout CSRF
    /// check would compare against nonsense.
    #[test]
    fn redirect_url_with_opaque_origin_is_rejected() {
        let err = test_config_builder()
            .redirect_url("http://")
            .build()
            .err()
            .expect("a hostless redirect_url must not build");
        assert!(
            matches!(err, super::ConfigError::InvalidRedirectUrl(_)),
            "expected InvalidRedirectUrl, got: {err}"
        );
    }

    // ── Required fields ───────────────────────────────────────────────────

    /// An empty or whitespace-only required field counts as missing. The old
    /// env path could not tell these apart (`std::env::var` yields `Ok("")`
    /// for `FOO=`), so an empty secret only surfaced as a token-endpoint
    /// rejection at first login.
    #[test]
    fn blank_required_fields_are_reported_as_missing() {
        let err = super::OidcBffConfig::builder()
            .issuer_url("   ")
            .client_id("")
            .client_secret("")
            .redirect_url("https://app.example.com/auth/callback")
            .generate_ephemeral_session_key()
            .build()
            .err()
            .expect("blank required fields must not build");

        match err {
            super::ConfigError::MissingFields(fields) => {
                for expected in ["issuer_url", "client_id", "client_secret"] {
                    assert!(
                        fields.contains(&expected),
                        "expected {expected:?} to be reported missing, got {fields:?}"
                    );
                }
                assert!(
                    !fields.contains(&"redirect_url"),
                    "redirect_url was supplied and must not be reported, got {fields:?}"
                );
            }
            other => panic!("expected MissingFields, got: {other}"),
        }
    }

    // ── Repeat-call replace semantics ─────────────────────────────────────

    /// A second `persist_claims` call must fully replace the first, not
    /// append to it — with append semantics a second call could smuggle a
    /// reserved name past a first, already-validated call.
    #[test]
    fn repeat_persist_claims_call_replaces_not_appends() {
        let cfg = test_config_builder()
            .persist_claims(["access_token"])
            .persist_claims(["groups"])
            .build()
            .unwrap();
        assert_eq!(
            cfg.persist_claims()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["groups"]
        );
    }

    #[test]
    fn repeat_scopes_call_replaces_not_appends() {
        let cfg = test_config_builder()
            .scopes(["profile"])
            .scopes(["email"])
            .build()
            .unwrap();
        assert_eq!(
            cfg.scopes().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["openid", "email"]
        );
    }

    /// Whichever of the three session-key setters is called last wins —
    /// here an invalid `session_key_base64` choice is discarded by a
    /// subsequent `generate_ephemeral_session_key()` call.
    #[test]
    fn repeat_session_key_setter_replaces_prior_choice() {
        test_config_builder()
            .session_key_base64("not-valid-base64!!!")
            .generate_ephemeral_session_key()
            .build()
            .unwrap();
    }

    // ── session_key_base64 ─────────────────────────────────────────────────

    #[test]
    fn session_key_base64_rejects_invalid_base64_without_panicking() {
        let err = test_config_builder()
            .session_key_base64("not-valid-base64!!!")
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidSessionKey(_)),
            "expected InvalidSessionKey, got: {err}"
        );
    }

    #[test]
    fn session_key_base64_rejects_short_input_without_panicking() {
        use base64::prelude::*;
        // Valid base64, but decodes to only 32 bytes — below the 64-byte
        // minimum. Must be a typed error, not a panic from Key::from.
        let short = BASE64_STANDARD.encode([0u8; 32]);
        let err = test_config_builder()
            .session_key_base64(&short)
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidSessionKey(_)),
            "expected InvalidSessionKey, got: {err}"
        );
    }

    #[test]
    fn session_key_base64_accepts_64_bytes_and_ignores_the_rest() {
        use base64::prelude::*;
        let long = BASE64_STANDARD.encode([7u8; 100]);
        test_config_builder()
            .session_key_base64(&long)
            .build()
            .unwrap();
    }

    /// Whitespace inside the base64 is stripped before decoding.
    ///
    /// This is the documented happy path, not an edge case: every doc example
    /// recommends `openssl rand -base64 64`, which wraps its output at column
    /// 64 — so the value carries an embedded newline as well as a trailing
    /// one, and a caller's `.trim()` only removes the latter. Without the
    /// strip, following the README verbatim fails at startup.
    #[test]
    fn session_key_base64_tolerates_openssl_style_line_wrapping() {
        use base64::prelude::*;
        let raw = BASE64_STANDARD.encode([9u8; 64]);
        // Reproduce `openssl rand -base64 64` output: wrapped at 64 chars
        // with a trailing newline.
        let wrapped = format!("{}\n{}\n", &raw[..64], &raw[64..]);
        assert!(wrapped.contains('\n'));

        let cfg = test_config_builder()
            .session_key_base64(&wrapped)
            .build()
            .expect("line-wrapped base64 must be accepted");

        let unwrapped = test_config_builder()
            .session_key_base64(&raw)
            .build()
            .unwrap();
        assert_eq!(
            cfg.session_key().master(),
            unwrapped.session_key().master(),
            "wrapped and unwrapped forms must yield the same key"
        );
    }

    // ── persist_claims ──────────────────────────────────────────────────────

    #[test]
    fn persist_claims_defaults_to_empty() {
        let cfg = test_config();
        assert!(cfg.persist_claims().is_empty());
    }

    #[test]
    fn persist_claims_trimmed_and_empties_dropped() {
        let cfg = test_config_builder()
            .persist_claims(["groups", " amr ", " acr ", "", "   "])
            .build()
            .unwrap();
        assert_eq!(
            cfg.persist_claims()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["groups", "amr", "acr"]
        );
    }

    #[test]
    fn persist_claims_single_entry() {
        let cfg = test_config_builder()
            .persist_claims(["groups"])
            .build()
            .unwrap();
        assert_eq!(
            cfg.persist_claims()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["groups"]
        );
    }

    #[test]
    fn persist_claims_only_whitespace_entries_yields_empty() {
        let cfg = test_config_builder()
            .persist_claims([" ", "  ", ""])
            .build()
            .unwrap();
        assert!(cfg.persist_claims().is_empty());
    }

    /// Reserved internal session keys are rejected as persistable claims —
    /// a collision would expose raw tokens through the `Auth` extractor.
    #[test]
    fn persist_claims_reserved_names_rejected() {
        for reserved in ["access_token", "sub", "id_token", "__bff_claim_keys"] {
            let err = test_config_builder()
                .persist_claims(["groups", reserved])
                .build()
                .err()
                .unwrap();
            assert!(
                matches!(err, super::ConfigError::ReservedClaimName(_)),
                "expected ReservedClaimName for {reserved}"
            );
        }
    }

    #[test]
    fn persist_claims_rejects_validation_artifact_names() {
        for artifact in ["aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash"] {
            let err = test_config_builder()
                .persist_claims(["groups", artifact])
                .build()
                .err()
                .unwrap();
            assert!(
                matches!(err, super::ConfigError::ReservedClaimName(_)),
                "expected ReservedClaimName for artifact claim {artifact}"
            );
        }
    }

    // ── return_to_prefix ────────────────────────────────────────────────────

    #[test]
    fn return_to_prefix_defaults_to_slash() {
        assert_eq!(test_config().return_to_prefix(), "/");
    }

    #[test]
    fn return_to_prefix_must_start_with_slash() {
        let err = test_config_builder()
            .return_to_prefix("portal/")
            .build()
            .err()
            .unwrap();
        assert!(matches!(err, super::ConfigError::InvalidReturnToPrefix(_)));
    }

    #[test]
    fn return_to_prefix_double_slash_rejected() {
        let err = test_config_builder()
            .return_to_prefix("//evil.com")
            .build()
            .err()
            .unwrap();
        assert!(matches!(err, super::ConfigError::InvalidReturnToPrefix(_)));
    }

    #[test]
    fn return_to_prefix_backslash_rejected() {
        let err = test_config_builder()
            .return_to_prefix("/\\evil.com")
            .build()
            .err()
            .unwrap();
        assert!(matches!(err, super::ConfigError::InvalidReturnToPrefix(_)));
    }

    #[test]
    fn return_to_prefix_scheme_attack_rejected() {
        let err = test_config_builder()
            .return_to_prefix("/foo:/bar")
            .build()
            .err()
            .unwrap();
        assert!(matches!(err, super::ConfigError::InvalidReturnToPrefix(_)));
    }

    #[test]
    fn return_to_prefix_slash_accepted() {
        test_config_builder().return_to_prefix("/").build().unwrap();
    }

    #[test]
    fn return_to_prefix_portal_accepted() {
        test_config_builder()
            .return_to_prefix("/portal/")
            .build()
            .unwrap();
    }

    // ── post_logout_redirect_url ───────────────────────────────────────────

    #[test]
    fn post_logout_redirect_url_optional() {
        let cfg = test_config();
        assert!(cfg.post_logout_redirect_url().is_none());

        let cfg = test_config_builder()
            .post_logout_redirect_url("https://app.example.com/")
            .build()
            .unwrap();
        assert_eq!(
            cfg.post_logout_redirect_url(),
            Some("https://app.example.com/")
        );
    }

    #[test]
    fn post_logout_redirect_url_trimmed_and_validated() {
        let cfg = test_config_builder()
            .post_logout_redirect_url("  https://app.example.com/x  ")
            .build()
            .unwrap();
        assert_eq!(
            cfg.post_logout_redirect_url(),
            Some("https://app.example.com/x")
        );
    }

    #[test]
    fn post_logout_redirect_url_invalid_rejected() {
        let err = test_config_builder()
            .post_logout_redirect_url("not a url")
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl, got: {err}"
        );
    }

    #[test]
    fn post_logout_redirect_url_bad_scheme_rejected() {
        let err = test_config_builder()
            .post_logout_redirect_url("javascript:x")
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl for javascript: scheme, got: {err}"
        );
    }

    /// When the redirect URL is https (cookie_secure), an http post-logout URL
    /// must be rejected — mixing a secure cookie context with a plain-http
    /// redirect leaks the session reference on the wire.
    #[test]
    fn post_logout_redirect_url_http_rejected_when_redirect_is_https() {
        let err = test_config_builder()
            .post_logout_redirect_url("http://app.example.com/logged-out")
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl for http when cookie_secure, got: {err}"
        );
    }

    #[test]
    fn post_logout_redirect_url_opaque_origin_rejected() {
        let err = test_config_builder()
            .post_logout_redirect_url("data:text/plain,hello")
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl for opaque origin, got: {err}"
        );
    }

    // ── redirect_url / cookie_secure / allowed_origin ──────────────────────

    #[test]
    fn cookie_secure_true_for_uppercase_scheme() {
        let cfg = test_config_builder()
            .redirect_url("HTTPS://app.example.com/auth/callback")
            .build()
            .unwrap();
        assert!(cfg.cookie_secure(), "HTTPS scheme should set cookie_secure");
        assert!(
            cfg.cookie_name().starts_with("__Host-"),
            "cookie name must be __Host- prefixed for secure cookies"
        );
    }

    #[test]
    fn redirect_url_whitespace_trimmed() {
        let cfg = test_config_builder()
            .redirect_url("  https://app.example.com/auth/callback  ")
            .build()
            .unwrap();
        assert_eq!(cfg.redirect_url(), "https://app.example.com/auth/callback");
        assert!(cfg.cookie_secure());
    }

    #[test]
    fn http_scheme_gives_insecure_cookie() {
        let cfg = test_config_builder()
            .redirect_url("http://localhost:8080/auth/callback")
            .build()
            .unwrap();
        assert!(!cfg.cookie_secure());
        assert!(!cfg.cookie_name().starts_with("__Host-"));
    }

    #[test]
    fn non_http_scheme_rejected() {
        for scheme_url in ["ftp://example.com/callback", "javascript:alert(1)"] {
            let err = test_config_builder()
                .redirect_url(scheme_url)
                .build()
                .err()
                .unwrap();
            assert!(
                matches!(err, super::ConfigError::InvalidRedirectUrl(_)),
                "expected InvalidRedirectUrl for {scheme_url}, got: {err}"
            );
        }
    }

    /// `allowed_origin` must be the normalized ASCII origin of the redirect
    /// URL: lowercased scheme/host, explicit default port omitted, non-default
    /// port retained. This is what CSRF comparisons run against.
    #[test]
    fn allowed_origin_is_normalized_ascii_origin() {
        let cfg = test_config_builder()
            .redirect_url("HTTPS://App.Example.com:443/auth/callback")
            .build()
            .unwrap();
        assert_eq!(cfg.allowed_origin(), "https://app.example.com");

        let cfg = test_config_builder()
            .redirect_url("http://localhost:8080/auth/callback")
            .build()
            .unwrap();
        assert_eq!(cfg.allowed_origin(), "http://localhost:8080");
    }

    #[test]
    fn unparsable_redirect_url_rejected() {
        let err = test_config_builder()
            .redirect_url("not a url at all ::::")
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidRedirectUrl(_)),
            "expected InvalidRedirectUrl for unparsable URL, got: {err}"
        );
    }

    // ── scopes ──────────────────────────────────────────────────────────────

    #[test]
    fn scopes_default_when_unset() {
        let cfg = test_config();
        assert_eq!(
            cfg.scopes().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["openid", "profile", "email"]
        );
    }

    #[test]
    fn scopes_trimmed_and_empties_dropped() {
        let cfg = test_config_builder()
            .scopes([
                "openid",
                " profile ",
                "email",
                "groups",
                "ebasket_authctx",
                "",
                "  ",
            ])
            .build()
            .unwrap();
        assert_eq!(
            cfg.scopes().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["openid", "profile", "email", "groups", "ebasket_authctx"]
        );
    }

    #[test]
    fn scopes_empty_iterator_uses_default() {
        let cfg = test_config_builder()
            .scopes(Vec::<String>::new())
            .build()
            .unwrap();
        assert_eq!(
            cfg.scopes().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["openid", "profile", "email"]
        );
    }

    #[test]
    fn scopes_whitespace_only_entries_use_default() {
        let cfg = test_config_builder()
            .scopes([" ", "   ", ""])
            .build()
            .unwrap();
        assert_eq!(
            cfg.scopes().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["openid", "profile", "email"]
        );
    }

    #[test]
    fn scopes_prepend_openid_when_missing() {
        let cfg = test_config_builder()
            .scopes(["profile", "email", "groups"])
            .build()
            .unwrap();
        assert_eq!(
            cfg.scopes().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["openid", "profile", "email", "groups"]
        );
    }

    #[test]
    fn scopes_openid_not_duplicated() {
        let cfg = test_config_builder()
            .scopes(["profile", "openid", "groups"])
            .build()
            .unwrap();
        assert_eq!(
            cfg.scopes().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["profile", "openid", "groups"]
        );
    }

    // ── Session TTLs ────────────────────────────────────────────────────────

    #[test]
    fn ttls_default_when_unset() {
        let cfg = test_config();
        assert_eq!(cfg.pre_auth_ttl_secs(), 600);
        assert_eq!(cfg.post_auth_ttl_secs(), 28_800);
        assert_eq!(cfg.max_session_lifetime_secs(), 604_800);
    }

    #[test]
    fn ttls_set_via_builder() {
        let cfg = test_config_builder()
            .pre_auth_ttl(std::time::Duration::from_secs(120))
            .post_auth_ttl(std::time::Duration::from_secs(7200))
            .build()
            .unwrap();
        assert_eq!(cfg.pre_auth_ttl_secs(), 120);
        assert_eq!(cfg.post_auth_ttl_secs(), 7200);
    }

    #[test]
    fn ttl_getters_return_matching_duration() {
        let cfg = test_config_builder()
            .pre_auth_ttl(std::time::Duration::from_secs(120))
            .build()
            .unwrap();
        assert_eq!(cfg.pre_auth_ttl(), std::time::Duration::from_secs(120));
    }

    /// Sub-second TTLs are rejected rather than truncated to zero.
    ///
    /// `Duration::from_millis(500).is_zero()` is `false`, so a zero-check
    /// alone lets it through and `as_secs()` then yields `0`. A zero
    /// `pre_auth_ttl` makes every pre-auth slot expire the instant it is
    /// written — login breaks permanently with no error anywhere — and it
    /// escapes `DbSessionStore::from_config`, which trusts `build()` to have
    /// guaranteed a positive value. Fractional values are rejected too, so
    /// `from_millis(1500)` cannot silently become 1 s.
    #[test]
    fn ttls_reject_sub_second_and_fractional_values() {
        type Setter =
            fn(super::OidcBffConfigBuilder, std::time::Duration) -> super::OidcBffConfigBuilder;
        let setters: [(&str, Setter); 3] = [
            ("pre_auth_ttl", super::OidcBffConfigBuilder::pre_auth_ttl),
            ("post_auth_ttl", super::OidcBffConfigBuilder::post_auth_ttl),
            (
                "max_session_lifetime",
                super::OidcBffConfigBuilder::max_session_lifetime,
            ),
        ];

        for (name, setter) in setters {
            for bad in [
                std::time::Duration::from_millis(500),
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(1500),
                std::time::Duration::from_nanos(1),
            ] {
                let err = setter(test_config_builder(), bad)
                    .build()
                    .err()
                    .unwrap_or_else(|| panic!("{name}: {bad:?} must be rejected, not truncated"));
                assert!(
                    matches!(err, super::ConfigError::InvalidTtl(_)),
                    "{name}: expected InvalidTtl for {bad:?}, got: {err}"
                );
            }
        }
    }

    /// `Duration::ZERO` and values exceeding `MAX_TTL_SECS` are rejected for
    /// all three TTL setters; exactly `MAX_TTL_SECS` is accepted.
    #[test]
    fn ttls_reject_zero_and_overflow_accept_exact_max() {
        type Setter =
            fn(super::OidcBffConfigBuilder, std::time::Duration) -> super::OidcBffConfigBuilder;
        let setters: [(&str, Setter); 3] = [
            ("pre_auth_ttl", super::OidcBffConfigBuilder::pre_auth_ttl),
            ("post_auth_ttl", super::OidcBffConfigBuilder::post_auth_ttl),
            (
                "max_session_lifetime",
                super::OidcBffConfigBuilder::max_session_lifetime,
            ),
        ];

        for (name, setter) in setters {
            let err = setter(test_config_builder(), std::time::Duration::ZERO)
                .build()
                .err()
                .unwrap();
            assert!(
                matches!(err, super::ConfigError::InvalidTtl(_)),
                "{name}: expected InvalidTtl for zero, got: {err}"
            );

            let over_max = std::time::Duration::from_secs(super::MAX_TTL_SECS as u64 + 1);
            let err = setter(test_config_builder(), over_max)
                .build()
                .err()
                .unwrap();
            assert!(
                matches!(err, super::ConfigError::InvalidTtl(_)),
                "{name}: expected InvalidTtl over MAX_TTL_SECS, got: {err}"
            );

            // Exactly MAX_TTL_SECS is accepted. When testing post_auth_ttl,
            // max_session_lifetime must be raised to match, or the
            // post_auth_ttl <= max_session_lifetime guard below would reject
            // this otherwise-valid value.
            let exact_max = std::time::Duration::from_secs(super::MAX_TTL_SECS as u64);
            let mut builder = setter(test_config_builder(), exact_max);
            if name == "post_auth_ttl" {
                builder = builder.max_session_lifetime(exact_max);
            }
            builder.build().unwrap();
        }
    }

    #[test]
    fn max_session_lifetime_set_via_builder() {
        let cfg = test_config_builder()
            .max_session_lifetime(std::time::Duration::from_secs(1_209_600))
            .build()
            .unwrap();
        assert_eq!(cfg.max_session_lifetime_secs(), 1_209_600);
    }

    /// `post_auth_ttl` strictly greater than `max_session_lifetime` is
    /// rejected — that combination makes the idle TTL dead code.
    #[test]
    fn post_auth_ttl_exceeding_max_session_lifetime_rejected() {
        let err = test_config_builder()
            .post_auth_ttl(std::time::Duration::from_secs(1000))
            .max_session_lifetime(std::time::Duration::from_secs(999))
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, super::ConfigError::InvalidTtl(_)),
            "expected InvalidTtl when post_auth_ttl exceeds max_session_lifetime, got: {err}"
        );
    }

    #[test]
    fn post_auth_ttl_equal_to_max_session_lifetime_accepted() {
        test_config_builder()
            .post_auth_ttl(std::time::Duration::from_secs(1000))
            .max_session_lifetime(std::time::Duration::from_secs(1000))
            .build()
            .unwrap();
    }

    // ── Session expiry ─────────────────────────────────────────────────────

    #[test]
    fn session_expiry_defaults_to_fixed() {
        assert_eq!(test_config().session_expiry(), super::SessionExpiry::Fixed);
    }

    #[test]
    fn session_expiry_set_via_builder() {
        let cfg = test_config_builder()
            .session_expiry(super::SessionExpiry::Sliding)
            .build()
            .unwrap();
        assert_eq!(cfg.session_expiry(), super::SessionExpiry::Sliding);
    }

    #[test]
    fn session_expiry_maps_to_ttl_extension_policy() {
        assert!(matches!(
            actix_session::config::TtlExtensionPolicy::from(super::SessionExpiry::Fixed),
            actix_session::config::TtlExtensionPolicy::OnStateChanges
        ));
        assert!(matches!(
            actix_session::config::TtlExtensionPolicy::from(super::SessionExpiry::Sliding),
            actix_session::config::TtlExtensionPolicy::OnEveryRequest
        ));
    }

    // ── SessionExpiry::FromStr ──────────────────────────────────────────────

    #[test]
    fn session_expiry_from_str_case_insensitive() {
        for (raw, expected) in [
            ("fixed", super::SessionExpiry::Fixed),
            ("FIXED", super::SessionExpiry::Fixed),
            ("  Fixed  ", super::SessionExpiry::Fixed),
            ("sliding", super::SessionExpiry::Sliding),
            ("SLIDING", super::SessionExpiry::Sliding),
            ("  Sliding  ", super::SessionExpiry::Sliding),
        ] {
            assert_eq!(
                raw.parse::<super::SessionExpiry>().unwrap(),
                expected,
                "unexpected session_expiry for input {raw:?}"
            );
        }
    }

    #[test]
    fn session_expiry_from_str_rejects_unknown_value() {
        let err = "on_every_request"
            .parse::<super::SessionExpiry>()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid session expiry \"on_every_request\": expected \"fixed\" or \"sliding\""
        );
    }

    // ── callback_passthrough_params ─────────────────────────────────────────

    use super::{ConfigError, MAX_PASSTHROUGH_PARAMS};
    use crate::param_names::{DENIED_PASSTHROUGH_PARAMS, MAX_PARAM_NAME_LEN};

    /// Unconfigured is the pre-0.3 behaviour: nothing is forwarded.
    #[test]
    fn callback_passthrough_params_default_empty() {
        assert!(test_config().callback_passthrough_params().is_empty());
    }

    #[test]
    fn callback_passthrough_params_are_trimmed_and_empties_dropped() {
        let cfg = test_config_builder()
            .callback_passthrough_params(["  kc_action  ", "", "   ", "kc_action_status"])
            .build()
            .unwrap();
        assert_eq!(
            cfg.callback_passthrough_params(),
            ["kc_action", "kc_action_status"]
        );
    }

    /// Repeat calls replace rather than append — otherwise a second call could
    /// smuggle a denied name past the first call's deferred validation.
    #[test]
    fn callback_passthrough_params_repeat_call_replaces() {
        let cfg = test_config_builder()
            .callback_passthrough_params(["first"])
            .callback_passthrough_params(["second"])
            .build()
            .unwrap();
        assert_eq!(cfg.callback_passthrough_params(), ["second"]);
    }

    /// Every denied name must be rejected, in either case. Forwarding any of
    /// these would put a credential — or a value an app might trust — into the
    /// browser's address bar.
    #[test]
    fn callback_passthrough_params_rejects_every_denied_name() {
        for denied in DENIED_PASSTHROUGH_PARAMS {
            for name in [denied.to_string(), denied.to_ascii_uppercase()] {
                let err = test_config_builder()
                    .callback_passthrough_params([name.clone()])
                    .build()
                    .err()
                    .unwrap_or_else(|| panic!("{name:?} must be rejected"));
                assert!(
                    matches!(err, ConfigError::InvalidPassthroughParam(_)),
                    "expected InvalidPassthroughParam for {name:?}, got: {err}"
                );
            }
        }
    }

    #[test]
    fn callback_passthrough_params_rejects_malformed_names() {
        let too_long = "a".repeat(MAX_PARAM_NAME_LEN + 1);
        for bad in ["kc action", "a&b", "a=b", "a/b", "a\u{e9}", &too_long] {
            let err = test_config_builder()
                .callback_passthrough_params([bad])
                .build()
                .err()
                .unwrap_or_else(|| panic!("{bad:?} must be rejected"));
            assert!(
                matches!(err, ConfigError::InvalidPassthroughParam(_)),
                "expected InvalidPassthroughParam for {bad:?}, got: {err}"
            );
        }
    }

    #[test]
    fn callback_passthrough_params_rejects_duplicates() {
        let err = test_config_builder()
            .callback_passthrough_params(["kc_action", "kc_action"])
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, ConfigError::InvalidPassthroughParam(_)),
            "expected InvalidPassthroughParam, got: {err}"
        );
    }

    #[test]
    fn callback_passthrough_params_rejects_more_than_the_cap() {
        let names: Vec<String> = (0..=MAX_PASSTHROUGH_PARAMS)
            .map(|i| format!("param{i}"))
            .collect();
        let err = test_config_builder()
            .callback_passthrough_params(names)
            .build()
            .err()
            .unwrap();
        assert!(
            matches!(err, ConfigError::InvalidPassthroughParam(_)),
            "expected InvalidPassthroughParam, got: {err}"
        );

        // Exactly at the cap is fine.
        let names: Vec<String> = (0..MAX_PASSTHROUGH_PARAMS)
            .map(|i| format!("param{i}"))
            .collect();
        let cfg = test_config_builder()
            .callback_passthrough_params(names)
            .build()
            .unwrap();
        assert_eq!(
            cfg.callback_passthrough_params().len(),
            MAX_PASSTHROUGH_PARAMS
        );
    }

    /// Dropped empties must not consume the budget: the cap is applied after
    /// normalization, not before.
    #[test]
    fn callback_passthrough_params_cap_counts_surviving_names_only() {
        let mut names: Vec<String> = (0..MAX_PASSTHROUGH_PARAMS)
            .map(|i| format!("param{i}"))
            .collect();
        names.push("   ".to_string());
        let cfg = test_config_builder()
            .callback_passthrough_params(names)
            .build()
            .unwrap();
        assert_eq!(
            cfg.callback_passthrough_params().len(),
            MAX_PASSTHROUGH_PARAMS
        );
    }

    // ── Getter smoke test ───────────────────────────────────────────────────

    #[test]
    fn getters_return_expected_values() {
        let cfg = test_config();
        assert_eq!(cfg.issuer_url(), "https://idp.example.com");
        assert_eq!(cfg.client_id(), "test-client");
        assert_eq!(cfg.redirect_url(), "https://app.example.com/auth/callback");
        assert_eq!(cfg.cookie_name(), "__Host-oidc_bff_session");
        assert!(cfg.cookie_secure());
        assert_eq!(cfg.allowed_origin(), "https://app.example.com");
    }
}
