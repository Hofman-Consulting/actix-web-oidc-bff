//! Integration tests exercising the crate as an *external consumer*.
//!
//! Every other test in this crate is a `#[cfg(test)]` unit test with access to
//! `pub(crate)` items, so none of them can catch the failure mode this change
//! set is most likely to introduce: a getter that a consumer genuinely needs
//! never being made public. This file is compiled as a separate crate and may
//! therefore only touch the public API — if it compiles, the documented
//! consumer wiring is actually reachable.
//!
//! It is deliberately thin on assertions. The *compilation* is the test.

use std::time::Duration;

use actix_web_oidc_bff as bff;
use bff::{ConfigError, OidcBffConfig, SessionExpiry};

/// Unwrap the error from a `build()` that must fail.
///
/// `Result::expect_err` is unavailable here: `OidcBffConfig` deliberately does
/// not implement `Debug` so the client secret cannot be printed. That the
/// bound fails to resolve is itself a property worth preserving — if this
/// helper ever becomes unnecessary, `Debug` has been added to a type holding a
/// secret.
fn expect_build_err(result: Result<OidcBffConfig, ConfigError>, what: &str) -> ConfigError {
    match result {
        Ok(_) => panic!("{what}"),
        Err(e) => e,
    }
}

/// Build a config through the public builder with every setter exercised.
fn full_config() -> OidcBffConfig {
    OidcBffConfig::builder()
        .issuer_url("https://idp.example.com")
        .client_id("my-client")
        .client_secret("s3cret")
        .redirect_url("https://app.example.com/auth/callback")
        .generate_ephemeral_session_key()
        .scopes(["openid", "profile", "email", "groups"])
        .persist_claims(["groups"])
        .return_to_prefix("/app")
        .post_logout_redirect_url("https://app.example.com/bye")
        .pre_auth_ttl(Duration::from_secs(600))
        .post_auth_ttl(Duration::from_secs(8 * 3600))
        .max_session_lifetime(Duration::from_secs(7 * 24 * 3600))
        .session_expiry(SessionExpiry::Sliding)
        .build()
        .expect("builder should accept a fully-specified valid config")
}

/// Every getter a consumer might reasonably need is public and returns a
/// borrow rather than an owned clone.
#[test]
fn public_getters_are_reachable() {
    let cfg = full_config();

    let _: &str = cfg.issuer_url();
    let _: &str = cfg.client_id();
    let _: &str = cfg.redirect_url();
    let _: &str = cfg.cookie_name();
    let _: &str = cfg.return_to_prefix();
    let _: Option<&str> = cfg.post_logout_redirect_url();
    let _: &[String] = cfg.scopes();
    let _: &[String] = cfg.persist_claims();
    let _: bool = cfg.cookie_secure();
    let _: SessionExpiry = cfg.session_expiry();
    let _: Duration = cfg.pre_auth_ttl();
    let _: Duration = cfg.post_auth_ttl();
    let _: Duration = cfg.max_session_lifetime();

    assert_eq!(cfg.issuer_url(), "https://idp.example.com");
    assert_eq!(cfg.return_to_prefix(), "/app");
    assert!(
        cfg.cookie_secure(),
        "https redirect URL implies a Secure cookie"
    );
    assert!(
        cfg.cookie_name().starts_with("__Host-"),
        "a Secure cookie must carry the __Host- prefix, got {:?}",
        cfg.cookie_name()
    );
    assert_eq!(
        cfg.max_session_lifetime(),
        Duration::from_secs(7 * 24 * 3600)
    );
}

/// `scopes` is normalised: entries trimmed, empties dropped, `openid`
/// guaranteed present even when the caller omits it.
#[test]
fn scopes_are_normalised() {
    let cfg = OidcBffConfig::builder()
        .issuer_url("https://idp.example.com")
        .client_id("my-client")
        .client_secret("s3cret")
        .redirect_url("https://app.example.com/auth/callback")
        .generate_ephemeral_session_key()
        .scopes(["  profile  ", "", "groups"])
        .build()
        .expect("valid config");

    assert!(
        cfg.scopes().iter().any(|s| s == "openid"),
        "openid must be added when omitted, got {:?}",
        cfg.scopes()
    );
    assert!(
        cfg.scopes().iter().any(|s| s == "profile"),
        "entries must be trimmed, got {:?}",
        cfg.scopes()
    );
    assert!(
        !cfg.scopes().iter().any(|s| s.is_empty()),
        "empty entries must be dropped, got {:?}",
        cfg.scopes()
    );
}

/// Missing required fields are reported together, not one per build attempt.
#[test]
fn missing_required_fields_are_reported_together() {
    let err = expect_build_err(
        OidcBffConfig::builder()
            .issuer_url("https://idp.example.com")
            .build(),
        "a config missing client_id/secret/redirect_url must not build",
    );

    match err {
        ConfigError::MissingFields(fields) => {
            assert!(
                fields.len() >= 3,
                "expected every missing field at once, got {fields:?}"
            );
        }
        other => panic!("expected MissingFields, got: {other}"),
    }
}

/// Setter order must not affect validation. Setting a plain-http post-logout
/// URL *before* the https redirect URL is the case that would slip past any
/// implementation that validated inside the setters.
#[test]
fn hostile_setter_order_is_still_rejected() {
    let err = expect_build_err(
        OidcBffConfig::builder()
            .post_logout_redirect_url("http://app.example.com/bye")
            .issuer_url("https://idp.example.com")
            .client_id("my-client")
            .client_secret("s3cret")
            .redirect_url("https://app.example.com/auth/callback")
            .generate_ephemeral_session_key()
            .build(),
        "an http post-logout URL under an https app must be rejected",
    );

    assert!(
        matches!(err, ConfigError::InvalidPostLogoutRedirectUrl(_)),
        "expected InvalidPostLogoutRedirectUrl, got: {err}"
    );
}

/// A claim name colliding with an internal session key must be rejected —
/// otherwise the `Auth` extractor could be made to surface a raw token.
#[test]
fn reserved_claim_names_are_rejected() {
    let err = expect_build_err(
        OidcBffConfig::builder()
            .issuer_url("https://idp.example.com")
            .client_id("my-client")
            .client_secret("s3cret")
            .redirect_url("https://app.example.com/auth/callback")
            .generate_ephemeral_session_key()
            .persist_claims(["access_token"])
            .build(),
        "a reserved session key must not be usable as a persisted claim",
    );

    assert!(
        matches!(err, ConfigError::ReservedClaimName(_)),
        "expected ReservedClaimName, got: {err}"
    );
}

/// `SessionExpiry` parses from a string, so a consumer reading their own
/// environment variable can still map it without reimplementing the parse.
#[test]
fn session_expiry_parses_from_str() {
    assert_eq!(
        "sliding".parse::<SessionExpiry>().expect("sliding parses"),
        SessionExpiry::Sliding
    );
    assert_eq!(
        "  FIXED  "
            .parse::<SessionExpiry>()
            .expect("trimmed, case-insensitive"),
        SessionExpiry::Fixed
    );
    assert!("nonsense".parse::<SessionExpiry>().is_err());
}

/// The documented consumer wiring compiles: `session_middleware` accepts the
/// config, and `ensure_same_origin` accepts the public `redirect_url()` getter
/// (the crate's own logout handler uses a precomputed origin internally, which
/// consumers cannot reach).
#[test]
fn documented_wiring_compiles() {
    use actix_session::storage::CookieSessionStore;

    let cfg = full_config();
    let _middleware = bff::session_middleware(CookieSessionStore::default(), &cfg);

    let req = actix_web::test::TestRequest::post()
        .insert_header(("Origin", "https://app.example.com"))
        .to_http_request();
    assert!(
        bff::ensure_same_origin(&req, cfg.redirect_url()).is_ok(),
        "a matching Origin header must pass the same-origin check"
    );
}

/// A consumer can implement `SessionRepository` and wire the store from the
/// config in one call. `from_config` exists because `DbSessionStore::new`
/// silently keeps the store's own defaults regardless of the config — this
/// test's real job is to prove the recommended path is publicly reachable.
#[test]
fn session_repository_is_implementable_and_wires_from_config() {
    use bff::{RepoError, SessionRecord, SessionRepository};
    use chrono::{DateTime, Utc};

    struct NoopRepo;

    #[async_trait::async_trait]
    impl SessionRepository for NoopRepo {
        async fn get(&self, _key: &str) -> Result<Option<SessionRecord>, RepoError> {
            Ok(None)
        }
        async fn insert(&self, _record: &SessionRecord) -> Result<(), RepoError> {
            Ok(())
        }
        async fn update(
            &self,
            _key: &str,
            _state: &str,
            _expires_at: DateTime<Utc>,
        ) -> Result<bool, RepoError> {
            Ok(true)
        }
        async fn touch(&self, _key: &str, _expires_at: DateTime<Utc>) -> Result<(), RepoError> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> Result<(), RepoError> {
            Ok(())
        }
    }

    let cfg = full_config();
    let store = bff::DbSessionStore::from_config(NoopRepo, &cfg);
    let _middleware = bff::session_middleware(store, &cfg);
}
