use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreSubjectIdentifierType, CoreTokenType,
    },
    AdditionalProviderMetadata, Client, ClientId, ClientSecret, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, ProviderMetadata,
    RedirectUrl, StandardErrorResponse, StandardTokenResponse,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::config::OidcBffConfig;

// ── HTTP client constants ─────────────────────────────────────────────────────

/// Total request timeout for all HTTP calls (discovery, JWKS, token endpoint).
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP connection timeout; the overall [`HTTP_TIMEOUT`] still applies.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum interval between forced JWKS refreshes triggered by validation
/// failures. Limits the DoS impact of an attacker repeatedly sending tokens
/// that fail validation.
const FORCED_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

// ── DiscoveryError ────────────────────────────────────────────────────────────

/// Errors that can occur during OIDC provider discovery or metadata refresh.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The configured issuer URL could not be parsed.
    #[error("Invalid issuer URL: {0}")]
    InvalidIssuerUrl(String),

    /// The configured redirect URL could not be parsed.
    #[error("Invalid redirect URL: {0}")]
    InvalidRedirectUrl(String),

    /// Failed to build the HTTP client (e.g. TLS initialisation failure).
    #[error("HTTP client error: {0}")]
    HttpClient(String),

    /// The OIDC discovery request failed or returned an invalid document.
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),

    /// The provider does not advertise any asymmetric signing algorithm in its
    /// discovery document.  Only asymmetric algorithms are accepted for
    /// ID-token validation.
    #[error("Provider advertises no supported asymmetric signing algorithm: {0}")]
    NoAsymmetricAlg(String),
}

// ── Additional-claims type ────────────────────────────────────────────────────

/// Captures any extra claims present in the ID token via a flattened JSON map.
///
/// Only this type is ever used as the `AC` generic parameter inside the crate.
/// It is intentionally **not** exposed as a generic parameter in any public
/// handler or extractor — consumers configure which keys to persist via
/// [`OidcBffConfig::persist_claims`].
///
/// The inner `HashMap` field uses `#[serde(flatten)]` so that, when this
/// struct is embedded inside an `IdTokenClaims<…>`, every extra key-value pair
/// from the JSON ID token is captured directly into the map rather than being
/// dropped.  `#[serde(flatten)]` is only supported on named fields (not tuple /
/// newtype structs), hence the `inner` field name.
///
/// # Example
/// ```rust
/// use actix_web_oidc_bff::oidc::BffAdditionalClaims;
/// use serde_json::json;
///
/// let json_str = r#"{"groups":["admin","users"],"amr":["pwd"]}"#;
/// let claims: BffAdditionalClaims = serde_json::from_str(json_str).unwrap();
/// assert_eq!(claims.inner["groups"], json!(["admin", "users"]));
/// let round_tripped = serde_json::to_string(&claims).unwrap();
/// let back: BffAdditionalClaims = serde_json::from_str(&round_tripped).unwrap();
/// assert_eq!(back.inner["amr"], json!(["pwd"]));
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BffAdditionalClaims {
    /// Every extra ID-token claim keyed by name, flattened in from the JSON
    /// payload (see the struct docs above for why `#[serde(flatten)]` needs
    /// a named field).
    #[serde(flatten)]
    pub inner: HashMap<String, serde_json::Value>,
}

impl openidconnect::AdditionalClaims for BffAdditionalClaims {}

// ── Additional provider metadata ─────────────────────────────────────────────

/// Captures optional endpoints from the discovery document that
/// `openidconnect`'s core metadata type does not expose:
/// `end_session_endpoint` (OpenID Connect RP-Initiated Logout) and
/// `revocation_endpoint` (RFC 7009, advertised per RFC 8414).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BffExtraProviderMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
}

impl AdditionalProviderMetadata for BffExtraProviderMetadata {}

/// `CoreProviderMetadata` with [`BffExtraProviderMetadata`] grafted on.
pub(crate) type BffProviderMetadata = ProviderMetadata<
    BffExtraProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

// ── Internal type aliases ─────────────────────────────────────────────────────
//
// These replace `CoreClient` / `CoreIdToken` etc. throughout the crate.
// They are `pub(crate)` so that callback.rs can name them; they are NOT part
// of the public API.

pub(crate) type BffIdTokenFields = IdTokenFields<
    BffAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub(crate) type BffTokenResponse = StandardTokenResponse<BffIdTokenFields, CoreTokenType>;

/// Typestate of the client returned by `from_provider_metadata`: the
/// authorization endpoint is required in OIDC discovery (`EndpointSet`); the
/// token/introspection/revocation/user-info endpoints are optional
/// (`EndpointMaybeSet`), so their request builders return `Result`s.
pub(crate) type BffClient = Client<
    BffAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    BffTokenResponse,
    // TokenIntrospectionResponse — same as Core (additional claims not used there)
    openidconnect::core::CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,      // auth URL
    EndpointNotSet,   // device auth URL
    EndpointNotSet,   // introspection URL
    EndpointNotSet,   // revocation URL
    EndpointMaybeSet, // token URL
    EndpointMaybeSet, // user-info URL
>;

// ── RpInner ───────────────────────────────────────────────────────────────────

/// Holds the cached provider metadata and the pre-built client together so that
/// a single write-lock swap replaces both atomically on JWKS refresh.
struct RpInner {
    metadata: BffProviderMetadata,
    client: Arc<BffClient>,
}

/// Build a [`BffClient`] from provider metadata and credentials.
fn build_client(
    metadata: BffProviderMetadata,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
) -> Arc<BffClient> {
    Arc::new(
        BffClient::from_provider_metadata(metadata, client_id, Some(client_secret))
            .set_redirect_uri(redirect_url),
    )
}

// ── OidcRp ───────────────────────────────────────────────────────────────────

/// Wraps the OIDC client together with a lock-protected copy of the provider
/// metadata so that JWKS can be refreshed without restarting.
pub struct OidcRp {
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
    inner: Arc<RwLock<RpInner>>,
    jwks_ttl: Duration,
    last_refresh: RwLock<Instant>,
    /// Clock for forced-refresh rate-limiting: tracks when the last forced
    /// refresh attempt was made (distinct from the ordinary TTL clock).
    last_forced_refresh: RwLock<Option<Instant>>,
    http_client: openidconnect::reqwest::Client,
}

impl OidcRp {
    /// Discover the OIDC provider metadata and build an `OidcRp`.
    ///
    /// Asserts that the provider advertises at least one asymmetric signing
    /// algorithm (see [`OidcRp::allowed_algs`]). Returns a [`DiscoveryError`]
    /// if discovery fails so the caller can log + exit.
    ///
    /// Note: PKCE S256 is enforced unconditionally at login time via
    /// `PkceCodeChallenge::new_random_sha256()`.
    pub async fn discover(cfg: &OidcBffConfig) -> Result<Self, DiscoveryError> {
        let issuer = IssuerUrl::new(cfg.issuer_url.clone())
            .map_err(|e| DiscoveryError::InvalidIssuerUrl(e.to_string()))?;

        // Redirects MUST stay disabled: following them from the token/JWKS
        // endpoints would enable SSRF-style attacks via a malicious provider.
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .build()
            .map_err(|e| DiscoveryError::HttpClient(e.to_string()))?;

        let metadata = BffProviderMetadata::discover_async(issuer, &http_client)
            .await
            .map_err(|e| DiscoveryError::Discovery(e.to_string()))?;

        // Ensure the provider supports at least one asymmetric ID-token signing alg.
        let allowed = Self::allowed_algs();
        let supported = metadata.id_token_signing_alg_values_supported();
        let has_asymmetric = supported.iter().any(|alg| allowed.contains(alg));
        if !has_asymmetric {
            return Err(DiscoveryError::NoAsymmetricAlg(format!("{supported:?}")));
        }

        let client_id = ClientId::new(cfg.client_id.clone());
        let client_secret = ClientSecret::new(cfg.client_secret.expose_secret().to_owned());
        let redirect_url = RedirectUrl::new(cfg.redirect_url.clone())
            .map_err(|e| DiscoveryError::InvalidRedirectUrl(e.to_string()))?;

        let client = build_client(
            metadata.clone(),
            client_id.clone(),
            client_secret.clone(),
            redirect_url.clone(),
        );

        Ok(OidcRp {
            client_id,
            client_secret,
            redirect_url,
            inner: Arc::new(RwLock::new(RpInner { metadata, client })),
            jwks_ttl: Duration::from_secs(cfg.jwks_ttl_secs),
            last_refresh: RwLock::new(Instant::now()),
            last_forced_refresh: RwLock::new(None),
            http_client,
        })
    }

    /// The shared (redirect-disabled) HTTP client for token-endpoint calls.
    pub(crate) fn http_client(&self) -> &openidconnect::reqwest::Client {
        &self.http_client
    }

    /// Return a cached [`BffClient`] wrapped in an [`Arc`], transparently
    /// refreshing the metadata (and thus the JWKS) when it is older than
    /// [`OidcBffConfig::jwks_ttl_secs`].
    ///
    /// The returned client carries [`BffAdditionalClaims`] so that arbitrary
    /// extra ID-token claims are preserved for selective session persistence.
    /// Callers receive an `Arc` clone — no deep-clone of the client occurs.
    pub(crate) async fn client(&self) -> Arc<BffClient> {
        self.refresh_if_stale().await;
        Arc::clone(&self.inner.read().await.client)
    }

    /// Refresh the cached metadata when it is older than the JWKS TTL.
    /// Concurrent callers don't stampede: whoever holds the `last_refresh`
    /// write lock refreshes; everyone else proceeds with cached metadata.
    async fn refresh_if_stale(&self) {
        let Ok(mut last) = self.last_refresh.try_write() else {
            return;
        };
        if last.elapsed() < self.jwks_ttl {
            return;
        }
        // Reset the clock before refreshing so a failing IdP is retried once
        // per TTL window rather than on every request.
        *last = Instant::now();
        drop(last); // release the TTL lock before hitting the network
        if let Err(e) = self.refresh_metadata().await {
            log::warn!("OIDC metadata refresh failed; continuing with cached metadata: {e}");
        }
    }

    /// Re-fetch the OIDC discovery document and replace the cached metadata and
    /// the pre-built client.
    ///
    /// The network fetch is performed **before** taking the write lock on
    /// `inner` — the write lock is never held across an `await`.
    pub async fn refresh_metadata(&self) -> Result<(), DiscoveryError> {
        let issuer = self.inner.read().await.metadata.issuer().clone();

        // Fetch outside the write lock so we never hold the lock across an await.
        let new_metadata = BffProviderMetadata::discover_async(issuer, &self.http_client)
            .await
            .map_err(|e| DiscoveryError::Discovery(e.to_string()))?;

        let new_client = build_client(
            new_metadata.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
            self.redirect_url.clone(),
        );

        let mut guard = self.inner.write().await;
        guard.metadata = new_metadata;
        guard.client = new_client;

        Ok(())
    }

    /// Attempt a forced JWKS refresh after an ID-token validation failure.
    ///
    /// Returns `true` when the refresh succeeded (the caller should retry
    /// validation with the freshly fetched JWKS), or `false` when:
    /// - another refresh is already in progress (stampede guard), or
    /// - the last forced refresh happened within [`FORCED_REFRESH_MIN_INTERVAL`]
    ///   (rate limit to bound worst-case DoS impact — one full retry round-trip
    ///   can take up to ~30 s with three sequential 10-second timeouts), or
    /// - the metadata fetch itself failed.
    ///
    /// On failure the existing cached metadata is retained and a `warn` is
    /// logged.
    pub(crate) async fn force_refresh_for_retry(&self) -> bool {
        // Stampede guard: only one concurrent caller proceeds.
        let Ok(mut forced_last) = self.last_forced_refresh.try_write() else {
            return false;
        };

        // Rate limit: at most one forced refresh per FORCED_REFRESH_MIN_INTERVAL.
        if let Some(last) = *forced_last {
            if last.elapsed() < FORCED_REFRESH_MIN_INTERVAL {
                return false;
            }
        }

        // Record the attempt time before hitting the network.
        *forced_last = Some(Instant::now());

        match self.refresh_metadata().await {
            Ok(()) => {
                // Reset the ordinary TTL clock so the next scheduled refresh
                // doesn't fire immediately after a forced one.
                if let Ok(mut last) = self.last_refresh.try_write() {
                    *last = Instant::now();
                }
                true
            }
            Err(e) => {
                log::warn!("Forced OIDC metadata refresh failed: {e}");
                false
            }
        }
    }

    /// The provider's `end_session_endpoint` (RP-initiated logout), if it
    /// advertises one in its discovery document.
    pub async fn end_session_endpoint(&self) -> Option<String> {
        self.inner
            .read()
            .await
            .metadata
            .additional_metadata()
            .end_session_endpoint
            .clone()
    }

    /// The provider's OAuth2 token-revocation endpoint (RFC 7009), if it
    /// advertises one in its discovery document.
    pub async fn revocation_endpoint(&self) -> Option<String> {
        self.inner
            .read()
            .await
            .metadata
            .additional_metadata()
            .revocation_endpoint
            .clone()
    }

    /// Return the allowed signing algorithms for ID-token validation.
    ///
    /// Only asymmetric algorithms are permitted. `none` and all `HS*`
    /// (symmetric) algorithms are excluded.
    #[must_use]
    pub fn allowed_algs() -> &'static [CoreJwsSigningAlgorithm] {
        use CoreJwsSigningAlgorithm::{
            EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, RsaSsaPkcs1V15Sha256,
            RsaSsaPkcs1V15Sha384, RsaSsaPkcs1V15Sha512, RsaSsaPssSha256, RsaSsaPssSha384,
            RsaSsaPssSha512,
        };
        static ALLOWED_ALGS: [CoreJwsSigningAlgorithm; 9] = [
            RsaSsaPkcs1V15Sha256,
            RsaSsaPkcs1V15Sha384,
            RsaSsaPkcs1V15Sha512,
            RsaSsaPssSha256,
            RsaSsaPssSha384,
            RsaSsaPssSha512,
            EcdsaP256Sha256,
            EcdsaP384Sha384,
            EcdsaP521Sha512,
        ];
        &ALLOWED_ALGS
    }

    /// Construct a minimal [`BffProviderMetadata`] suitable for use in tests.
    ///
    /// `extra` controls the optional `end_session_endpoint` and
    /// `revocation_endpoint` fields; pass `BffExtraProviderMetadata::default()`
    /// for a metadata doc with neither.
    #[cfg(test)]
    pub(crate) fn test_metadata(extra: BffExtraProviderMetadata) -> BffProviderMetadata {
        let json = serde_json::json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
            "token_endpoint": "https://idp.example.com/oauth2/token",
            "jwks_uri": "https://idp.example.com/oauth2/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "end_session_endpoint": extra.end_session_endpoint,
            "revocation_endpoint": extra.revocation_endpoint,
        });
        serde_json::from_value(json).expect("test metadata must be valid")
    }

    /// Construct an [`OidcRp`] from pre-fetched metadata for use in tests.
    ///
    /// The returned instance uses a timeout-configured, redirect-disabled HTTP
    /// client and a one-hour JWKS TTL so the TTL never fires during unit tests.
    /// `last_refresh` is set to `now` so `refresh_if_stale` is a no-op for the
    /// life of the test.
    #[cfg(test)]
    pub(crate) fn for_tests(metadata: BffProviderMetadata) -> Self {
        let client_id = ClientId::new("test-client".to_owned());
        let client_secret = ClientSecret::new("test-secret".to_owned());
        let redirect_url =
            RedirectUrl::new("https://app.example.com/auth/callback".to_owned()).unwrap();

        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .build()
            .expect("test HTTP client must build");

        let client = build_client(
            metadata.clone(),
            client_id.clone(),
            client_secret.clone(),
            redirect_url.clone(),
        );

        OidcRp {
            client_id,
            client_secret,
            redirect_url,
            inner: Arc::new(RwLock::new(RpInner { metadata, client })),
            jwks_ttl: Duration::from_secs(3600),
            last_refresh: RwLock::new(Instant::now()),
            last_forced_refresh: RwLock::new(None),
            http_client,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── BffAdditionalClaims serde ─────────────────────────────────────────────

    /// `BffAdditionalClaims` must round-trip through JSON preserving all
    /// arbitrary key types, including string-array values such as `groups`.
    #[test]
    fn bff_additional_claims_serde_round_trip() {
        let json_str = r#"{"groups":["admin","users"],"amr":["pwd"],"acr":"urn:example:low"}"#;
        let claims: BffAdditionalClaims = serde_json::from_str(json_str).unwrap();

        assert_eq!(claims.inner["groups"], json!(["admin", "users"]));
        assert_eq!(claims.inner["amr"], json!(["pwd"]));
        assert_eq!(claims.inner["acr"], json!("urn:example:low"));

        // Round-trip: serialize and deserialize again.
        let serialized = serde_json::to_string(&claims).unwrap();
        let back: BffAdditionalClaims = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.inner["groups"], json!(["admin", "users"]));
        assert_eq!(back.inner["amr"], json!(["pwd"]));
        assert_eq!(back.inner["acr"], json!("urn:example:low"));
    }

    /// An empty additional-claims object must serialize to `{}` and deserialize
    /// back to an empty map (flatten semantics).
    #[test]
    fn bff_additional_claims_empty() {
        let claims: BffAdditionalClaims = serde_json::from_str("{}").unwrap();
        assert!(claims.inner.is_empty());
        let serialized = serde_json::to_string(&claims).unwrap();
        assert_eq!(serialized, "{}");
    }

    /// Numeric and boolean values must also survive the round-trip.
    #[test]
    fn bff_additional_claims_mixed_types() {
        let json_str = r#"{"count":42,"active":true,"tags":["a","b"]}"#;
        let claims: BffAdditionalClaims = serde_json::from_str(json_str).unwrap();
        assert_eq!(claims.inner["count"], json!(42));
        assert_eq!(claims.inner["active"], json!(true));
        assert_eq!(claims.inner["tags"], json!(["a", "b"]));
    }

    // ── DiscoveryError ────────────────────────────────────────────────────────

    /// Each `DiscoveryError` variant must produce a human-readable `Display`
    /// message that includes both the variant-specific context and the payload.
    #[test]
    fn discovery_error_display_messages() {
        let e = DiscoveryError::InvalidIssuerUrl("bad url".to_owned());
        assert!(e.to_string().contains("Invalid issuer URL"));
        assert!(e.to_string().contains("bad url"));

        let e = DiscoveryError::InvalidRedirectUrl("not a url".to_owned());
        assert!(e.to_string().contains("Invalid redirect URL"));
        assert!(e.to_string().contains("not a url"));

        let e = DiscoveryError::HttpClient("TLS error".to_owned());
        assert!(e.to_string().contains("HTTP client error"));
        assert!(e.to_string().contains("TLS error"));

        let e = DiscoveryError::Discovery("connection refused".to_owned());
        assert!(e.to_string().contains("OIDC discovery failed"));
        assert!(e.to_string().contains("connection refused"));

        let e = DiscoveryError::NoAsymmetricAlg("[HS256]".to_owned());
        assert!(e.to_string().contains("asymmetric"));
        assert!(e.to_string().contains("[HS256]"));
    }

    // ── allowed_algs ─────────────────────────────────────────────────────────

    /// The allowed-algs list must contain exactly 9 entries, all asymmetric,
    /// with no symmetric (`HS*`) or `none` algorithms.
    #[test]
    fn allowed_algs_excludes_symmetric_and_none() {
        let algs = OidcRp::allowed_algs();
        assert_eq!(algs.len(), 9, "expected exactly 9 asymmetric algorithms");

        let forbidden = [
            CoreJwsSigningAlgorithm::HmacSha256,
            CoreJwsSigningAlgorithm::HmacSha384,
            CoreJwsSigningAlgorithm::HmacSha512,
            CoreJwsSigningAlgorithm::None,
        ];
        for alg in &forbidden {
            assert!(
                !algs.contains(alg),
                "symmetric/none algorithm {alg:?} must not appear in allowed_algs"
            );
        }

        // All 9 expected asymmetric variants must be present.
        let expected = [
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
            CoreJwsSigningAlgorithm::RsaSsaPssSha256,
            CoreJwsSigningAlgorithm::RsaSsaPssSha384,
            CoreJwsSigningAlgorithm::RsaSsaPssSha512,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            CoreJwsSigningAlgorithm::EcdsaP384Sha384,
            CoreJwsSigningAlgorithm::EcdsaP521Sha512,
        ];
        for alg in &expected {
            assert!(
                algs.contains(alg),
                "asymmetric algorithm {alg:?} is missing from allowed_algs"
            );
        }
    }

    // ── Client caching (Arc identity) ─────────────────────────────────────────

    /// Two successive calls to `client()` on a freshly constructed `OidcRp`
    /// (with a huge TTL so no refresh fires) must return `Arc`s pointing to the
    /// same allocation — no rebuild occurs between calls.
    #[actix_web::test]
    async fn client_returns_same_arc_until_refresh() {
        let metadata = OidcRp::test_metadata(BffExtraProviderMetadata::default());
        let rp = OidcRp::for_tests(metadata);

        let first = rp.client().await;
        let second = rp.client().await;

        assert!(
            Arc::ptr_eq(&first, &second),
            "client() must return the same Arc between TTL refreshes"
        );
    }

    // ── force_refresh_for_retry ───────────────────────────────────────────────

    /// Stampede guard: while another caller holds the `last_forced_refresh`
    /// write lock (i.e. a forced refresh is in flight), `force_refresh_for_retry`
    /// must return `false` immediately — `try_write` fails, so no network call
    /// is made.
    #[actix_web::test]
    async fn force_refresh_stampede_guard_returns_false_when_lock_held() {
        let metadata = OidcRp::test_metadata(BffExtraProviderMetadata::default());
        let rp = OidcRp::for_tests(metadata);

        // Simulate a concurrent forced refresh holding the guard lock.
        let _held = rp.last_forced_refresh.write().await;

        let result = rp.force_refresh_for_retry().await;
        assert!(
            !result,
            "force_refresh_for_retry must return false while the guard lock is held"
        );
    }

    /// A second forced-refresh call within 60 seconds must return `false`
    /// regardless of whether the first succeeded.
    #[actix_web::test]
    async fn second_forced_refresh_within_60s_returns_false() {
        let metadata = OidcRp::test_metadata(BffExtraProviderMetadata::default());
        let rp = OidcRp::for_tests(metadata);

        // Simulate that a forced refresh was attempted just now.
        {
            let mut guard = rp.last_forced_refresh.write().await;
            *guard = Some(Instant::now());
        }

        let result = rp.force_refresh_for_retry().await;
        assert!(
            !result,
            "second force_refresh_for_retry within 60s must return false"
        );
    }

    // ── Test constructors ─────────────────────────────────────────────────────

    /// `for_tests` must correctly expose `end_session_endpoint` and
    /// `revocation_endpoint` from the `BffExtraProviderMetadata` passed to
    /// `test_metadata`.
    #[actix_web::test]
    async fn for_tests_exposes_end_session_and_revocation_endpoints() {
        let extra = BffExtraProviderMetadata {
            end_session_endpoint: Some("https://idp.example.com/logout".to_owned()),
            revocation_endpoint: Some("https://idp.example.com/revoke".to_owned()),
        };
        let metadata = OidcRp::test_metadata(extra);
        let rp = OidcRp::for_tests(metadata);

        assert_eq!(
            rp.end_session_endpoint().await,
            Some("https://idp.example.com/logout".to_owned())
        );
        assert_eq!(
            rp.revocation_endpoint().await,
            Some("https://idp.example.com/revoke".to_owned())
        );
    }

    /// `test_metadata` with no endpoints must produce `None` for both.
    #[actix_web::test]
    async fn for_tests_with_no_extra_endpoints() {
        let metadata = OidcRp::test_metadata(BffExtraProviderMetadata::default());
        let rp = OidcRp::for_tests(metadata);

        assert_eq!(rp.end_session_endpoint().await, None);
        assert_eq!(rp.revocation_endpoint().await, None);
    }
}
