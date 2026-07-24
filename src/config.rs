use actix_web::cookie::Key;
use base64::prelude::*;
use openidconnect::url::{Origin, Url};
use secrecy::SecretString;
use thiserror::Error;

use crate::handlers::login::validate_return_to;
use crate::session_state::RESERVED_SESSION_KEYS;

/// Errors returned by [`OidcBffConfig::from_env`].
#[derive(Error, Debug)]
pub enum ConfigError {
    /// A required `OIDC_*` environment variable was not set.
    #[error("Missing required environment variable: {0}")]
    MissingEnv(&'static str),
    /// `OIDC_SESSION_KEY` was not valid base64 or decoded to fewer than 64 bytes.
    #[error("Invalid session key: {0}")]
    InvalidSessionKey(String),
    /// `OIDC_REDIRECT_URL` was unparsable, used a non-http(s) scheme, or had
    /// an opaque origin.
    #[error("Invalid redirect URL: {0}")]
    InvalidRedirectUrl(String),
    /// `OIDC_POST_LOGOUT_REDIRECT_URL` was unparsable, used a non-http(s)
    /// scheme, had an opaque origin, or was plain http while the redirect URL
    /// is https.
    #[error("Invalid post-logout redirect URL: {0}")]
    InvalidPostLogoutRedirectUrl(String),
    /// `OIDC_RETURN_TO_PREFIX` failed [`validate_return_to`].
    #[error("Invalid return_to prefix: {0}")]
    InvalidReturnToPrefix(String),
    /// An `OIDC_PERSIST_CLAIMS` entry collided with a reserved session key or
    /// an OIDC validation-artifact claim name.
    #[error("Reserved claim name: {0}")]
    ReservedClaimName(String),
}

/// Runtime configuration for the OIDC relying party and session cookie.
pub struct OidcBffConfig {
    /// The OIDC provider's issuer URL, used for discovery. Configured via
    /// `OIDC_ISSUER_URL`.
    pub issuer_url: String,
    /// The confidential client's ID, as registered with the IdP. Configured
    /// via `OIDC_CLIENT_ID`.
    pub client_id: String,
    /// The confidential client's secret. Held as a [`SecretString`] so it is
    /// never accidentally logged or `Debug`-printed. Configured via
    /// `OIDC_CLIENT_SECRET`.
    pub client_secret: SecretString,
    /// This app's OIDC callback URL, registered at the IdP. Its scheme
    /// determines `cookie_secure`; its origin is precomputed into
    /// `allowed_origin` for CSRF checks. Configured via `OIDC_REDIRECT_URL`.
    pub redirect_url: String,
    /// Signing/encryption key for the session cookie. Configured via the
    /// base64-encoded `OIDC_SESSION_KEY`, or randomly generated (with a
    /// warning) when unset.
    pub session_key: Key,
    /// Session cookie name — `__Host-`-prefixed when `cookie_secure` is true.
    pub cookie_name: String,
    /// Whether the session cookie is marked `Secure`; derived from
    /// `redirect_url`'s scheme (`true` for https).
    pub cookie_secure: bool,
    /// Pre-computed ASCII origin of `redirect_url` for CSRF comparisons.
    pub(crate) allowed_origin: String,
    /// Scopes to request from the IdP.
    pub scopes: Vec<String>,
    /// JWKS metadata refresh interval in seconds.
    pub jwks_ttl_secs: u64,
    /// Pre-auth (state/pkce) session TTL in seconds.
    pub pre_auth_ttl_secs: i64,
    /// Post-auth session TTL in seconds.
    pub post_auth_ttl_secs: i64,
    /// Path prefix that a `return_to` value must start with. The application
    /// decides where it is safe to redirect back to after login (e.g. `/`,
    /// `/portal/`, `/app/`). See [`crate::validate_return_to`].
    pub return_to_prefix: String,
    /// Extra ID-token claim names to capture into the server-side session.
    ///
    /// Any claim listed here that is present in the ID token's additional
    /// claims (fields beyond the standard OIDC set) will be serialised as a
    /// JSON value and stored in the session. The [`crate::Auth`] extractor
    /// exposes them via [`crate::Auth::claims`] / [`crate::Auth::get_claim`].
    ///
    /// Configured via the comma-separated `OIDC_PERSIST_CLAIMS` environment
    /// variable (e.g. `groups,amr,acr`). Defaults to an empty list.
    ///
    /// Claim names that collide with the crate's internal session keys
    /// (`sub`, `access_token`, …) or with OIDC validation-artifact claim
    /// names (`aud`, `exp`, `iat`, `nbf`, `nonce`, `at_hash`, `c_hash`) are
    /// rejected at configuration time.
    pub persist_claims: Vec<String>,
    /// Where the IdP may redirect the browser after RP-initiated logout.
    /// Optional; when set it is sent as `post_logout_redirect_uri` and must be
    /// registered at the IdP. Configured via `OIDC_POST_LOGOUT_REDIRECT_URL`.
    pub post_logout_redirect_url: Option<String>,
}

/// OIDC validation-artifact claim names that must not be persisted into the
/// session. They are not secrets but have no persistence use and invite
/// confusion; `auth_time` and `azp` are legitimately useful and stay allowed.
const VALIDATION_ARTIFACT_CLAIMS: &[&str] =
    &["aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash"];

impl OidcBffConfig {
    /// Build an `OidcBffConfig` from environment variables.
    ///
    /// Required env vars:
    ///   - `OIDC_ISSUER_URL`
    ///   - `OIDC_CLIENT_ID`
    ///   - `OIDC_CLIENT_SECRET`
    ///   - `OIDC_REDIRECT_URL`
    ///
    /// Optional:
    ///   - `OIDC_SESSION_KEY` — base64-encoded 64-byte cookie key. If absent a
    ///     new key is generated and a warning is logged.
    ///   - `OIDC_RETURN_TO_PREFIX` — path prefix for post-login redirects
    ///     (defaults to `/`).
    ///   - `OIDC_SCOPES` — comma-separated list of scopes to request from the
    ///     IdP (e.g. `openid,profile,email,groups`). Defaults to
    ///     `openid,profile,email`. `openid` is always included; if the parsed
    ///     list omits it, it is prepended.
    ///   - `OIDC_PERSIST_CLAIMS` — comma-separated extra ID-token claim names
    ///     to persist into the session. Reserved internal names are rejected.
    ///   - `OIDC_POST_LOGOUT_REDIRECT_URL` — sent as
    ///     `post_logout_redirect_uri` during RP-initiated logout when set.
    ///
    /// Returns `Err(ConfigError)` if any required variable is missing or any
    /// value is invalid.
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer_url = std::env::var("OIDC_ISSUER_URL")
            .map_err(|_| ConfigError::MissingEnv("OIDC_ISSUER_URL"))?;
        let client_id = std::env::var("OIDC_CLIENT_ID")
            .map_err(|_| ConfigError::MissingEnv("OIDC_CLIENT_ID"))?;
        let client_secret_raw = std::env::var("OIDC_CLIENT_SECRET")
            .map_err(|_| ConfigError::MissingEnv("OIDC_CLIENT_SECRET"))?;

        // Trim whitespace before parsing the redirect URL so that inadvertent
        // leading/trailing spaces in the env value don't silently break cookie
        // security or origin comparisons.
        let redirect_url_raw = std::env::var("OIDC_REDIRECT_URL")
            .map_err(|_| ConfigError::MissingEnv("OIDC_REDIRECT_URL"))?;
        let redirect_url_trimmed = redirect_url_raw.trim().to_string();

        let parsed_redirect = Url::parse(&redirect_url_trimmed).map_err(|e| {
            ConfigError::InvalidRedirectUrl(format!("OIDC_REDIRECT_URL is not a valid URL: {e}"))
        })?;

        // Only http and https are sensible callback schemes. Reject ftp:,
        // javascript:, etc. up-front rather than letting them produce a
        // confusingly insecure cookie.
        let scheme = parsed_redirect.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ConfigError::InvalidRedirectUrl(format!(
                "OIDC_REDIRECT_URL scheme must be http or https, got {scheme:?}"
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
                    "OIDC_REDIRECT_URL has an opaque origin".to_string(),
                ));
            }
        };

        let session_key = match std::env::var("OIDC_SESSION_KEY") {
            Ok(b64) => {
                let bytes = BASE64_STANDARD.decode(&b64).map_err(|e| {
                    ConfigError::InvalidSessionKey(format!(
                        "OIDC_SESSION_KEY is not valid base64: {e}"
                    ))
                })?;
                if bytes.len() < 64 {
                    return Err(ConfigError::InvalidSessionKey(format!(
                        "OIDC_SESSION_KEY must decode to at least 64 bytes, got {}",
                        bytes.len()
                    )));
                }
                Key::from(&bytes[..64])
            }
            Err(_) => {
                log::warn!(
                    "OIDC_SESSION_KEY is not set — generating a random session key. \
                     Server restarts and multi-instance deployments will invalidate \
                     existing sessions. Set OIDC_SESSION_KEY to a stable base64-encoded \
                     64-byte value to avoid this."
                );
                Key::generate()
            }
        };

        let return_to_prefix =
            std::env::var("OIDC_RETURN_TO_PREFIX").unwrap_or_else(|_| "/".to_string());

        // Validate the prefix by running it through the same path-safety check
        // applied to individual return_to values. This guarantees the default
        // (/auth/login with no return_to) always validates successfully.
        if !validate_return_to(&return_to_prefix, &return_to_prefix) {
            return Err(ConfigError::InvalidReturnToPrefix(format!(
                "OIDC_RETURN_TO_PREFIX is not a valid return_to value: {return_to_prefix:?}"
            )));
        }

        // Parse the optional comma-separated list of scopes to request. When
        // unset/empty, default to the standard OIDC scope set. `openid` is
        // mandatory for the OIDC flow, so it is always included.
        let scopes = parse_scopes(std::env::var("OIDC_SCOPES").ok().as_deref());

        // Parse the optional comma-separated list of extra claim names to persist.
        let persist_claims: Vec<String> = std::env::var("OIDC_PERSIST_CLAIMS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        for claim in &persist_claims {
            if RESERVED_SESSION_KEYS.contains(&claim.as_str()) {
                return Err(ConfigError::ReservedClaimName(format!(
                    "OIDC_PERSIST_CLAIMS must not contain the reserved name {claim:?}; \
                     reserved names: {RESERVED_SESSION_KEYS:?}"
                )));
            }
            if VALIDATION_ARTIFACT_CLAIMS.contains(&claim.as_str()) {
                return Err(ConfigError::ReservedClaimName(format!(
                    "OIDC_PERSIST_CLAIMS must not contain the validation-artifact claim \
                     name {claim:?}; these have no persistence use and invite confusion"
                )));
            }
        }

        let post_logout_redirect_url = match std::env::var("OIDC_POST_LOGOUT_REDIRECT_URL").ok() {
            None => None,
            Some(raw) => {
                // Trim whitespace so that inadvertent spaces in the env
                // value don't silently break the IdP redirect match.
                let trimmed = raw.trim().to_string();

                let parsed = Url::parse(&trimmed).map_err(|e| {
                    ConfigError::InvalidPostLogoutRedirectUrl(format!(
                        "OIDC_POST_LOGOUT_REDIRECT_URL is not a valid URL: {e}"
                    ))
                })?;

                // Only http and https are sensible post-logout schemes.
                let scheme = parsed.scheme();
                if scheme != "http" && scheme != "https" {
                    return Err(ConfigError::InvalidPostLogoutRedirectUrl(format!(
                        "OIDC_POST_LOGOUT_REDIRECT_URL scheme must be http or https, \
                             got {scheme:?}"
                    )));
                }

                // Reject opaque/host-less origins (same guard as
                // redirect_url — they must never be compared as origins).
                match parsed.origin() {
                    Origin::Tuple(..) => {}
                    Origin::Opaque(_) => {
                        return Err(ConfigError::InvalidPostLogoutRedirectUrl(
                            "OIDC_POST_LOGOUT_REDIRECT_URL has an opaque origin".to_string(),
                        ));
                    }
                }

                // When the app is served over https (cookie_secure), a
                // plain-http post-logout URL is inconsistent and would
                // send session-related parameters over an unencrypted
                // channel. Require https in that case.
                if cookie_secure && scheme != "https" {
                    return Err(ConfigError::InvalidPostLogoutRedirectUrl(
                        "OIDC_POST_LOGOUT_REDIRECT_URL must be https when the redirect \
                             URL is https"
                            .to_string(),
                    ));
                }

                Some(trimmed)
            }
        };

        Ok(OidcBffConfig {
            issuer_url,
            client_id,
            client_secret: SecretString::new(client_secret_raw),
            redirect_url: redirect_url_trimmed,
            session_key,
            cookie_name,
            cookie_secure,
            allowed_origin,
            scopes,
            jwks_ttl_secs: 900,
            pre_auth_ttl_secs: 600,
            post_auth_ttl_secs: 12 * 3600,
            return_to_prefix,
            persist_claims,
            post_logout_redirect_url,
        })
    }
}

/// Parse the comma-separated `OIDC_SCOPES` value into a scope list.
///
/// - `None`/empty/whitespace-only input → the default `["openid", "profile",
///   "email"]`.
/// - Otherwise entries are split on commas, trimmed, and empties dropped.
/// - `openid` is mandatory: if a non-empty parsed list lacks it, it is
///   prepended so the OIDC authorization-code flow always works.
fn parse_scopes(raw: Option<&str>) -> Vec<String> {
    let default = || {
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]
    };

    let Some(raw) = raw else {
        return default();
    };

    let mut scopes: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();

    if scopes.is_empty() {
        return default();
    }

    if !scopes.iter().any(|s| s == "openid") {
        scopes.insert(0, "openid".to_string());
    }

    scopes
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    // Serialise environment-variable tests because they mutate process state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper that sets a minimal set of required env vars, runs the closure,
    /// then cleans up regardless of the result.
    fn with_required_env<F, R>(persist_claims_val: Option<&str>, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        std::env::set_var("OIDC_ISSUER_URL", "https://idp.example.com");
        std::env::set_var("OIDC_CLIENT_ID", "client");
        std::env::set_var("OIDC_CLIENT_SECRET", "secret");
        std::env::set_var("OIDC_REDIRECT_URL", "https://app.example.com/auth/callback");
        if let Some(v) = persist_claims_val {
            std::env::set_var("OIDC_PERSIST_CLAIMS", v);
        } else {
            std::env::remove_var("OIDC_PERSIST_CLAIMS");
        }
        // Scope tests set OIDC_SCOPES themselves; ensure a clean baseline here.
        std::env::remove_var("OIDC_SCOPES");
        std::env::remove_var("OIDC_RETURN_TO_PREFIX");
        std::env::remove_var("OIDC_POST_LOGOUT_REDIRECT_URL");
        // Ensure no stale session key from a previous test leaks in.
        std::env::remove_var("OIDC_SESSION_KEY");

        let result = f();

        std::env::remove_var("OIDC_ISSUER_URL");
        std::env::remove_var("OIDC_CLIENT_ID");
        std::env::remove_var("OIDC_CLIENT_SECRET");
        std::env::remove_var("OIDC_REDIRECT_URL");
        std::env::remove_var("OIDC_PERSIST_CLAIMS");
        std::env::remove_var("OIDC_SCOPES");
        std::env::remove_var("OIDC_RETURN_TO_PREFIX");
        std::env::remove_var("OIDC_POST_LOGOUT_REDIRECT_URL");
        std::env::remove_var("OIDC_SESSION_KEY");

        result
    }

    /// When `OIDC_PERSIST_CLAIMS` is absent the field must be an empty `Vec`.
    #[test]
    fn persist_claims_defaults_to_empty() {
        let cfg = with_required_env(None, || super::OidcBffConfig::from_env().unwrap());
        assert!(cfg.persist_claims.is_empty());
    }

    /// A comma-separated value is split, trimmed, and empties dropped.
    #[test]
    fn persist_claims_parsed_from_env() {
        let cfg = with_required_env(Some("groups, amr , acr,,"), || {
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(cfg.persist_claims, vec!["groups", "amr", "acr"]);
    }

    /// A single entry with no commas is still accepted.
    #[test]
    fn persist_claims_single_entry() {
        let cfg = with_required_env(Some("groups"), || super::OidcBffConfig::from_env().unwrap());
        assert_eq!(cfg.persist_claims, vec!["groups"]);
    }

    /// An all-whitespace / only-commas value yields an empty list.
    #[test]
    fn persist_claims_only_commas_and_spaces() {
        let cfg = with_required_env(Some(" , , "), || super::OidcBffConfig::from_env().unwrap());
        assert!(cfg.persist_claims.is_empty());
    }

    /// Reserved internal session keys are rejected as persistable claims —
    /// a collision would expose raw tokens through the `Auth` extractor.
    #[test]
    fn persist_claims_reserved_names_rejected() {
        for reserved in ["access_token", "sub", "id_token", "__bff_claim_keys"] {
            let err = with_required_env(Some(&format!("groups,{reserved}")), || {
                super::OidcBffConfig::from_env().err().unwrap()
            });
            assert!(
                matches!(err, super::ConfigError::ReservedClaimName(_)),
                "expected ReservedClaimName for {reserved}"
            );
        }
    }

    /// OIDC validation-artifact claim names are rejected.
    #[test]
    fn persist_claims_rejects_validation_artifact_names() {
        for artifact in ["aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash"] {
            let err = with_required_env(Some(&format!("groups,{artifact}")), || {
                super::OidcBffConfig::from_env().err().unwrap()
            });
            assert!(
                matches!(err, super::ConfigError::ReservedClaimName(_)),
                "expected ReservedClaimName for artifact claim {artifact}"
            );
        }
    }

    /// `OIDC_RETURN_TO_PREFIX` must be an absolute path and pass the
    /// `validate_return_to` check (no `//`, `\`, `:/`, etc.).
    #[test]
    fn return_to_prefix_must_start_with_slash() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_RETURN_TO_PREFIX", "portal/");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(
            matches!(err, super::ConfigError::InvalidReturnToPrefix(_)),
            "expected InvalidReturnToPrefix, got: {err}"
        );
    }

    #[test]
    fn return_to_prefix_double_slash_rejected() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_RETURN_TO_PREFIX", "//evil.com");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(matches!(err, super::ConfigError::InvalidReturnToPrefix(_)));
    }

    #[test]
    fn return_to_prefix_backslash_rejected() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_RETURN_TO_PREFIX", "/\\evil.com");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(matches!(err, super::ConfigError::InvalidReturnToPrefix(_)));
    }

    #[test]
    fn return_to_prefix_scheme_attack_rejected() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_RETURN_TO_PREFIX", "/foo:/bar");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(matches!(err, super::ConfigError::InvalidReturnToPrefix(_)));
    }

    #[test]
    fn return_to_prefix_slash_accepted() {
        with_required_env(None, || {
            std::env::set_var("OIDC_RETURN_TO_PREFIX", "/");
            super::OidcBffConfig::from_env().unwrap();
        });
    }

    #[test]
    fn return_to_prefix_portal_accepted() {
        with_required_env(None, || {
            std::env::set_var("OIDC_RETURN_TO_PREFIX", "/portal/");
            super::OidcBffConfig::from_env().unwrap();
        });
    }

    /// `OIDC_POST_LOGOUT_REDIRECT_URL` is optional and defaults to `None`.
    #[test]
    fn post_logout_redirect_url_optional() {
        let cfg = with_required_env(None, || super::OidcBffConfig::from_env().unwrap());
        assert!(cfg.post_logout_redirect_url.is_none());

        let cfg = with_required_env(None, || {
            std::env::set_var("OIDC_POST_LOGOUT_REDIRECT_URL", "https://app.example.com/");
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(
            cfg.post_logout_redirect_url.as_deref(),
            Some("https://app.example.com/")
        );
    }

    // ── C-1: OIDC_POST_LOGOUT_REDIRECT_URL validation ────────────────────────

    /// Leading/trailing whitespace is trimmed before parsing; the stored value
    /// is the trimmed form.
    #[test]
    fn post_logout_redirect_url_trimmed_and_validated() {
        let cfg = with_required_env(None, || {
            std::env::set_var(
                "OIDC_POST_LOGOUT_REDIRECT_URL",
                "  https://app.example.com/x  ",
            );
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(
            cfg.post_logout_redirect_url.as_deref(),
            Some("https://app.example.com/x")
        );
    }

    /// A value that is not a valid URL must be rejected with
    /// `InvalidPostLogoutRedirectUrl`.
    #[test]
    fn post_logout_redirect_url_invalid_rejected() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_POST_LOGOUT_REDIRECT_URL", "not a url");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl, got: {err}"
        );
    }

    /// Non-http/https schemes (e.g. `javascript:`) must be rejected.
    #[test]
    fn post_logout_redirect_url_bad_scheme_rejected() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_POST_LOGOUT_REDIRECT_URL", "javascript:x");
            super::OidcBffConfig::from_env().err().unwrap()
        });
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
        let err = with_required_env(None, || {
            // redirect_url is already https (set by with_required_env).
            std::env::set_var(
                "OIDC_POST_LOGOUT_REDIRECT_URL",
                "http://app.example.com/logged-out",
            );
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl for http when cookie_secure, got: {err}"
        );
    }

    /// An opaque or host-less origin must be rejected (same guard as the
    /// redirect URL).
    #[test]
    fn post_logout_redirect_url_opaque_origin_rejected() {
        let err = with_required_env(None, || {
            // data: URLs produce an opaque origin.
            std::env::set_var("OIDC_POST_LOGOUT_REDIRECT_URL", "data:text/plain,hello");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(
            matches!(err, super::ConfigError::InvalidPostLogoutRedirectUrl(_)),
            "expected InvalidPostLogoutRedirectUrl for opaque origin, got: {err}"
        );
    }

    // ── S1.3: ConfigError typed variants ─────────────────────────────────────

    #[test]
    fn missing_env_var_yields_missing_env_variant() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("OIDC_ISSUER_URL");
        std::env::remove_var("OIDC_CLIENT_ID");
        std::env::remove_var("OIDC_CLIENT_SECRET");
        std::env::remove_var("OIDC_REDIRECT_URL");
        let err = super::OidcBffConfig::from_env().err().unwrap();
        assert!(
            matches!(err, super::ConfigError::MissingEnv(_)),
            "expected MissingEnv, got: {err}"
        );
    }

    #[test]
    fn invalid_session_key_yields_variant() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_SESSION_KEY", "not-valid-base64!!!");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(
            matches!(err, super::ConfigError::InvalidSessionKey(_)),
            "expected InvalidSessionKey, got: {err}"
        );
    }

    // ── S1.4: Robust cookie_secure ────────────────────────────────────────────

    #[test]
    fn cookie_secure_true_for_uppercase_scheme() {
        let cfg = with_required_env(None, || {
            std::env::set_var("OIDC_REDIRECT_URL", "HTTPS://app.example.com/auth/callback");
            super::OidcBffConfig::from_env().unwrap()
        });
        assert!(cfg.cookie_secure, "HTTPS scheme should set cookie_secure");
        assert!(
            cfg.cookie_name.starts_with("__Host-"),
            "cookie name must be __Host- prefixed for secure cookies"
        );
    }

    #[test]
    fn redirect_url_whitespace_trimmed() {
        let cfg = with_required_env(None, || {
            std::env::set_var(
                "OIDC_REDIRECT_URL",
                "  https://app.example.com/auth/callback  ",
            );
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(cfg.redirect_url, "https://app.example.com/auth/callback");
        assert!(cfg.cookie_secure);
    }

    #[test]
    fn http_scheme_gives_insecure_cookie() {
        let cfg = with_required_env(None, || {
            std::env::set_var("OIDC_REDIRECT_URL", "http://localhost:8080/auth/callback");
            super::OidcBffConfig::from_env().unwrap()
        });
        assert!(!cfg.cookie_secure);
        assert!(!cfg.cookie_name.starts_with("__Host-"));
    }

    #[test]
    fn non_http_scheme_rejected() {
        for scheme_url in ["ftp://example.com/callback", "javascript:alert(1)"] {
            let err = with_required_env(None, || {
                std::env::set_var("OIDC_REDIRECT_URL", scheme_url);
                super::OidcBffConfig::from_env().err().unwrap()
            });
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
        // Uppercase scheme+host with explicit default port → normalized.
        let cfg = with_required_env(None, || {
            std::env::set_var(
                "OIDC_REDIRECT_URL",
                "HTTPS://App.Example.com:443/auth/callback",
            );
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(cfg.allowed_origin, "https://app.example.com");

        // Non-default port must be retained.
        let cfg = with_required_env(None, || {
            std::env::set_var("OIDC_REDIRECT_URL", "http://localhost:8080/auth/callback");
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(cfg.allowed_origin, "http://localhost:8080");
    }

    #[test]
    fn unparsable_redirect_url_rejected() {
        let err = with_required_env(None, || {
            std::env::set_var("OIDC_REDIRECT_URL", "not a url at all ::::");
            super::OidcBffConfig::from_env().err().unwrap()
        });
        assert!(
            matches!(err, super::ConfigError::InvalidRedirectUrl(_)),
            "expected InvalidRedirectUrl for unparsable URL, got: {err}"
        );
    }

    // ── OIDC_SCOPES ─────────────────────────────────────────────────────────

    /// When `OIDC_SCOPES` is unset the default scope set is used.
    #[test]
    fn scopes_default_when_unset() {
        let cfg = with_required_env(None, || super::OidcBffConfig::from_env().unwrap());
        assert_eq!(cfg.scopes, vec!["openid", "profile", "email"]);
    }

    /// A configured value is split, trimmed, and empties dropped.
    #[test]
    fn scopes_parsed_from_env() {
        let cfg = with_required_env(None, || {
            std::env::set_var(
                "OIDC_SCOPES",
                "openid, profile ,email,groups,ebasket_authctx,,",
            );
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(
            cfg.scopes,
            vec!["openid", "profile", "email", "groups", "ebasket_authctx"]
        );
    }

    /// An empty / whitespace-only value falls back to the default set.
    #[test]
    fn scopes_empty_value_uses_default() {
        let cfg = with_required_env(None, || {
            std::env::set_var("OIDC_SCOPES", " , , ");
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(cfg.scopes, vec!["openid", "profile", "email"]);
    }

    /// `openid` is prepended when a non-empty list omits it.
    #[test]
    fn scopes_prepend_openid_when_missing() {
        let cfg = with_required_env(None, || {
            std::env::set_var("OIDC_SCOPES", "profile,email,groups");
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(cfg.scopes, vec!["openid", "profile", "email", "groups"]);
    }

    /// `openid` is not duplicated when already present (even mid-list).
    #[test]
    fn scopes_openid_not_duplicated() {
        let cfg = with_required_env(None, || {
            std::env::set_var("OIDC_SCOPES", "profile,openid,groups");
            super::OidcBffConfig::from_env().unwrap()
        });
        assert_eq!(cfg.scopes, vec!["profile", "openid", "groups"]);
    }
}
