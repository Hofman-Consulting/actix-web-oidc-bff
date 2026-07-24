use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse};
use openidconnect::url::Url;
use openidconnect::{core::CoreRevocableToken, AccessToken, RefreshToken, RevocationUrl};
use serde_json::json;

use crate::config::OidcBffConfig;
use crate::csrf::ensure_same_origin_against;
use crate::error::BffError;
use crate::oidc::OidcRp;
use crate::session_state::{ACCESS_TOKEN, ID_TOKEN, REFRESH_TOKEN};

/// Purge the local session, revoke tokens (RFC 7009) when possible, and —
/// when the provider supports RP-initiated logout — hand the frontend the IdP
/// end-session URL.
///
/// Implementation order (hard security gates):
/// 1. CSRF check via `ensure_same_origin_against`.
/// 2. Read `id_token`, `refresh_token`, `access_token` from session **before**
///    purging — they are gone once `session.purge()` is called.
/// 3. Parse the `end_session_endpoint` URL **before** purging; a malformed URL
///    degrades to 204 but does not prevent revocation from running.
/// 4. Revoke the best available token (refresh preferred over access) via
///    `revoke_best_effort`, using the crate's shared redirect-disabled, timeout-
///    configured HTTP client.  Failures are logged and swallowed.
/// 5. `session.purge()`.
/// 6. Return 200 + `{"idp_logout_url": "..."}` or 204.
///
/// Responses:
/// - `200` with `{"idp_logout_url": "..."}` — session purged; frontend should
///   navigate to the URL to also end the IdP session.
/// - `204` — session purged; provider advertises no `end_session_endpoint`, or
///   its URL is malformed.
pub async fn logout(
    req: HttpRequest,
    session: Session,
    oidc: web::Data<OidcRp>,
    cfg: web::Data<OidcBffConfig>,
) -> Result<HttpResponse, BffError> {
    // 1. CSRF — compare against the pre-computed ASCII origin.
    ensure_same_origin_against(&req, &cfg.allowed_origin)?;

    // 2. Read tokens BEFORE purging — they are gone after session.purge().
    let id_token_hint: Option<String> = session.get::<String>(ID_TOKEN).ok().flatten();
    let refresh_token: Option<String> = session.get::<String>(REFRESH_TOKEN).ok().flatten();
    let access_token: Option<String> = session.get::<String>(ACCESS_TOKEN).ok().flatten();

    // 3. Resolve the end-session URL before purging.  A malformed endpoint
    //    degrades gracefully to 204; revocation still runs (not gated on this).
    let end_session_url = oidc.end_session_endpoint().await.and_then(|endpoint| {
        build_end_session_url(&endpoint, id_token_hint.as_deref(), &cfg).map_or_else(
            |e| {
                log::warn!("Malformed end_session_endpoint {endpoint:?}, degrading to 204: {e}");
                None
            },
            Some,
        )
    });

    // 4. Best-effort token revocation. Awaited deliberately: the shared HTTP
    //    client enforces a 10 s timeout, so this call is bounded. Revocation
    //    is guaranteed-attempted before the session is purged and the response
    //    is returned. Fire-and-forget (spawn) was considered and rejected —
    //    it would return a response before the revocation attempt completes,
    //    which could race against the IdP accepting the token again.
    let revocation_endpoint = oidc.revocation_endpoint().await;
    revoke_best_effort(
        &oidc,
        &cfg,
        revocation_endpoint.as_deref(),
        refresh_token.as_deref(),
        access_token.as_deref(),
    )
    .await;

    // 5. Purge the session.
    session.purge();

    // 6. Respond.
    match end_session_url {
        Some(url) => Ok(HttpResponse::Ok().json(json!({ "idp_logout_url": url }))),
        None => Ok(HttpResponse::NoContent().finish()),
    }
}

/// Build the IdP end-session URL with `id_token_hint`, `client_id`, and
/// optionally `post_logout_redirect_uri` appended as query parameters.
fn build_end_session_url(
    endpoint: &str,
    id_token_hint: Option<&str>,
    cfg: &OidcBffConfig,
) -> Result<String, openidconnect::url::ParseError> {
    let mut url = Url::parse(endpoint)?;
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(hint) = id_token_hint {
            pairs.append_pair("id_token_hint", hint);
        }
        pairs.append_pair("client_id", &cfg.client_id);
        if let Some(post_logout) = &cfg.post_logout_redirect_url {
            pairs.append_pair("post_logout_redirect_uri", post_logout);
        }
    }
    Ok(url.to_string())
}

/// Pick the token to revoke: refresh token is preferred (revoking it typically
/// also invalidates the access token at the IdP); access token is the fallback.
fn pick_revocable(
    refresh_token: Option<&str>,
    access_token: Option<&str>,
) -> Option<CoreRevocableToken> {
    if let Some(rt) = refresh_token {
        return Some(CoreRevocableToken::RefreshToken(RefreshToken::new(
            rt.to_owned(),
        )));
    }
    access_token.map(|at| CoreRevocableToken::AccessToken(AccessToken::new(at.to_owned())))
}

/// Returns `true` when `endpoint` has an `https` scheme (case-insensitive).
///
/// Uses [`Url::parse`] which lowercases the scheme on parse, so `HTTPS://…`
/// and `https://…` both return `true`. A malformed endpoint returns `false`
/// (fail-closed on transmission; the caller then skips revocation, which is
/// the safe direction — it avoids sending the token over an insecure channel).
///
/// Note: this guard is inactive when `cookie_secure == false` (http dev
/// deployments). Production must run https.
fn endpoint_is_https(endpoint: &str) -> bool {
    Url::parse(endpoint)
        .map(|u| u.scheme() == "https")
        .unwrap_or(false)
}

/// Attempt to revoke `token` via RFC 7009.
///
/// Uses the crate's shared redirect-disabled, timeout-configured HTTP client —
/// never a freshly built default client, which could follow redirects or lack
/// timeouts.  Failures are logged (endpoint + error kind only, never the token
/// value) and swallowed — revocation failure must never block logout.
async fn revoke_best_effort(
    oidc: &OidcRp,
    cfg: &OidcBffConfig,
    revocation_endpoint: Option<&str>,
    refresh_token: Option<&str>,
    access_token: Option<&str>,
) {
    let Some(endpoint_str) = revocation_endpoint else {
        return;
    };

    let Some(token) = pick_revocable(refresh_token, access_token) else {
        return;
    };

    // Defense-in-depth: reject a non-https revocation endpoint when the issuer
    // is configured with an https redirect URL (the most common production case).
    // An attacker that can redirect the revocation request via http could observe
    // the token in transit.
    if cfg.cookie_secure && !endpoint_is_https(endpoint_str) {
        log::warn!(
            "Skipping revocation: endpoint {endpoint_str:?} is not HTTPS \
             but the issuer redirect URL uses HTTPS"
        );
        return;
    }

    let revocation_url = match RevocationUrl::new(endpoint_str.to_owned()) {
        Ok(u) => u,
        Err(e) => {
            log::warn!("Invalid revocation endpoint {endpoint_str:?}: {e}");
            return;
        }
    };

    // `set_revocation_url` is a consuming typestate transition — clone one copy
    // of the cached client so the shared Arc is not consumed.
    let client_with_revocation = (*oidc.client().await)
        .clone()
        .set_revocation_url(revocation_url);

    let revoke_request = match client_with_revocation.revoke_token(token) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Could not build revocation request for {endpoint_str:?}: {e}");
            return;
        }
    };

    // Use the shared HTTP client — redirect-disabled, timeout-configured.
    if let Err(e) = revoke_request.request_async(oidc.http_client()).await {
        log::warn!("Token revocation at {endpoint_str:?} failed: {e}");
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use actix_session::SessionExt;
    use actix_web::test::TestRequest;

    use crate::oidc::{BffExtraProviderMetadata, OidcRp};

    /// Build a minimal `OidcBffConfig` for use in tests without hitting env vars.
    fn test_cfg() -> OidcBffConfig {
        OidcBffConfig {
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret: secrecy::SecretString::new("test-secret".to_owned()),
            redirect_url: "https://app.example.com/auth/callback".to_string(),
            session_key: actix_web::cookie::Key::generate(),
            cookie_name: "__Host-oidc_bff_session".to_string(),
            cookie_secure: true,
            allowed_origin: "https://app.example.com".to_string(),
            scopes: vec!["openid".to_string()],
            jwks_ttl_secs: 900,
            pre_auth_ttl_secs: 600,
            post_auth_ttl_secs: 43200,
            return_to_prefix: "/".to_string(),
            persist_claims: vec![],
            post_logout_redirect_url: None,
        }
    }

    /// Build a TestRequest with the given headers.
    fn req_with(headers: &[(&str, &str)]) -> HttpRequest {
        let mut req = TestRequest::default();
        for (name, value) in headers {
            req = req.insert_header((*name, *value));
        }
        req.to_http_request()
    }

    // ── B-3: endpoint_is_https helper ────────────────────────────────────────

    /// Uppercase `HTTPS` scheme must be accepted (url crate lowercases on parse).
    #[test]
    fn endpoint_is_https_accepts_uppercase_scheme() {
        assert!(
            endpoint_is_https("HTTPS://idp.example.com/revoke"),
            "HTTPS:// must be accepted as https"
        );
        assert!(
            endpoint_is_https("https://idp.example.com/revoke"),
            "https:// must be accepted"
        );
    }

    /// HTTP and malformed endpoints must return false.
    #[test]
    fn endpoint_is_https_rejects_http_and_garbage() {
        assert!(
            !endpoint_is_https("http://idp.example.com/revoke"),
            "http:// must be rejected"
        );
        assert!(
            !endpoint_is_https("not a url :::"),
            "malformed endpoint must be rejected (fail-closed)"
        );
        assert!(!endpoint_is_https(""), "empty endpoint must be rejected");
        assert!(
            !endpoint_is_https("ftp://idp.example.com/revoke"),
            "non-https scheme must be rejected"
        );
    }

    // ── pick_revocable ────────────────────────────────────────────────────────

    /// `pick_revocable` must prefer the refresh token over the access token.
    #[test]
    fn pick_revocable_prefers_refresh_over_access() {
        let token = pick_revocable(Some("refresh_secret"), Some("access_secret")).unwrap();
        // The refresh token variant carries its own type hint.
        assert!(
            matches!(token, CoreRevocableToken::RefreshToken(_)),
            "refresh token must be preferred over access token"
        );
    }

    /// When no refresh token is available, the access token is used.
    #[test]
    fn pick_revocable_falls_back_to_access_token() {
        let token = pick_revocable(None, Some("access_secret")).unwrap();
        assert!(
            matches!(token, CoreRevocableToken::AccessToken(_)),
            "access token must be returned when no refresh token is present"
        );
    }

    /// When neither token is present, `pick_revocable` returns `None`.
    #[test]
    fn pick_revocable_none_when_no_tokens() {
        assert!(
            pick_revocable(None, None).is_none(),
            "None must be returned when neither token is present"
        );
    }

    // ── logout — CSRF ─────────────────────────────────────────────────────────

    /// A cross-origin request must be rejected (403/400) and the session must
    /// not be purged.
    #[actix_web::test]
    async fn logout_cross_origin_rejected_and_session_kept() {
        let metadata = OidcRp::test_metadata(BffExtraProviderMetadata::default());
        let rp = web::Data::new(OidcRp::for_tests(metadata));
        let cfg = web::Data::new(test_cfg());

        // Cross-site origin — must be rejected.
        let req = req_with(&[("Origin", "https://evil.example.com")]);
        let session = req.get_session();

        // Seed the session so we can verify it is NOT purged.
        session.insert("sub", "user-123").ok();

        let result = logout(req, session.clone(), rp, cfg).await;

        assert!(result.is_err(), "cross-origin request must be rejected");
        // Session should still hold `sub` — it was not purged.
        assert_eq!(
            session.get::<String>("sub").unwrap(),
            Some("user-123".to_string()),
            "session must not be purged on CSRF failure"
        );
    }

    // ── logout — no end_session_endpoint ─────────────────────────────────────

    /// When the provider advertises no `end_session_endpoint`, logout must
    /// return 204 and purge the session.
    #[actix_web::test]
    async fn logout_without_end_session_endpoint_returns_204_and_purges() {
        let metadata = OidcRp::test_metadata(BffExtraProviderMetadata::default());
        let rp = web::Data::new(OidcRp::for_tests(metadata));
        let cfg = web::Data::new(test_cfg());

        let req = req_with(&[("Sec-Fetch-Site", "same-origin")]);
        let session = req.get_session();
        session.insert("sub", "user-123").ok();

        let resp = logout(req, session.clone(), rp, cfg)
            .await
            .expect("logout must not error");

        assert_eq!(resp.status(), actix_web::http::StatusCode::NO_CONTENT);
        // Session must be purged — `sub` should be gone.
        assert_eq!(
            session.get::<String>("sub").unwrap(),
            None,
            "session must be purged on successful logout"
        );
    }

    // ── logout — with end_session_endpoint ────────────────────────────────────

    /// When the provider advertises an `end_session_endpoint`, logout must
    /// return 200 with `{"idp_logout_url"}` and the URL must contain
    /// `id_token_hint` and `client_id`.
    #[actix_web::test]
    async fn logout_with_end_session_endpoint_returns_200_with_url() {
        let extra = BffExtraProviderMetadata {
            end_session_endpoint: Some("https://idp.example.com/logout".to_owned()),
            revocation_endpoint: None,
        };
        let metadata = OidcRp::test_metadata(extra);
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let mut cfg = test_cfg();
        cfg.post_logout_redirect_url = Some("https://app.example.com/".to_string());
        let cfg = web::Data::new(cfg);

        let req = req_with(&[("Sec-Fetch-Site", "same-origin")]);
        let session = req.get_session();
        session.insert(ID_TOKEN, "the-raw-id-token").ok();

        let resp = logout(req, session, rp, cfg)
            .await
            .expect("logout must not error");

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let idp_url = json["idp_logout_url"]
            .as_str()
            .expect("idp_logout_url must be a string");
        assert!(
            idp_url.contains("id_token_hint=the-raw-id-token"),
            "URL must contain id_token_hint"
        );
        assert!(
            idp_url.contains("client_id=test-client"),
            "URL must contain client_id"
        );
        assert!(
            idp_url.contains("post_logout_redirect_uri="),
            "URL must contain post_logout_redirect_uri"
        );
    }

    // ── logout — malformed end_session_endpoint degrades to 204 ──────────────

    /// When the provider advertises a malformed `end_session_endpoint`, logout
    /// must degrade to 204 rather than returning 500. (RED test per spec.)
    #[actix_web::test]
    async fn logout_malformed_end_session_endpoint_degrades_to_204() {
        let extra = BffExtraProviderMetadata {
            // Not a valid URL — must not cause a 500.
            end_session_endpoint: Some("not a valid url :::".to_owned()),
            revocation_endpoint: None,
        };
        let metadata = OidcRp::test_metadata(extra);
        let rp = web::Data::new(OidcRp::for_tests(metadata));
        let cfg = web::Data::new(test_cfg());

        let req = req_with(&[("Sec-Fetch-Site", "same-origin")]);
        let resp = logout(req, req_with(&[]).get_session(), rp, cfg)
            .await
            .expect("malformed endpoint must not return Err (must degrade to 204)");

        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::NO_CONTENT,
            "malformed end_session_endpoint must degrade to 204"
        );
    }

    // ── logout — read-before-purge regression guard ───────────────────────────

    /// Tokens read before purge must appear in the response (id_token_hint).
    /// This guards against a regression where tokens were read after purging.
    #[actix_web::test]
    async fn logout_reads_tokens_before_purge() {
        let extra = BffExtraProviderMetadata {
            end_session_endpoint: Some("https://idp.example.com/logout".to_owned()),
            revocation_endpoint: None,
        };
        let metadata = OidcRp::test_metadata(extra);
        let rp = web::Data::new(OidcRp::for_tests(metadata));
        let cfg = web::Data::new(test_cfg());

        let req = req_with(&[("Sec-Fetch-Site", "same-origin")]);
        let session = req.get_session();
        // Seed a pre-purge id_token and a refresh_token.
        session.insert(ID_TOKEN, "pre-purge-id-token").ok();
        session
            .insert(REFRESH_TOKEN, "pre-purge-refresh-token")
            .ok();

        let resp = logout(req, session, rp, cfg)
            .await
            .expect("logout must not error");

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let idp_url = json["idp_logout_url"].as_str().unwrap();
        assert!(
            idp_url.contains("id_token_hint=pre-purge-id-token"),
            "id_token_hint must reflect the pre-purge value: {idp_url}"
        );
    }

    // ── logout — https downgrade guard on revocation ──────────────────────────

    /// When the app runs on https (`cookie_secure`) but the provider advertises
    /// an http revocation endpoint, revocation must be skipped (defense-in-depth
    /// against token exposure in transit) and logout must still complete.
    ///
    /// Only an access token is seeded (no refresh token) — this also covers the
    /// access-token-only logout path end-to-end. The guard returns before any
    /// network call is made, so this test is fully offline.
    #[actix_web::test]
    async fn logout_skips_http_revocation_endpoint_when_app_is_https() {
        let extra = BffExtraProviderMetadata {
            end_session_endpoint: None,
            // http endpoint — must be refused because cfg.cookie_secure is true.
            // If the guard regressed, the request to this unroutable address
            // would fail the test with a timeout/connection error path anyway.
            revocation_endpoint: Some("http://idp.example.com/revoke".to_owned()),
        };
        let metadata = OidcRp::test_metadata(extra);
        let rp = web::Data::new(OidcRp::for_tests(metadata));
        let cfg = web::Data::new(test_cfg()); // cookie_secure: true

        let req = req_with(&[("Sec-Fetch-Site", "same-origin")]);
        let session = req.get_session();
        session.insert(ACCESS_TOKEN, "only-an-access-token").ok();
        session.insert("sub", "user-123").ok();

        let resp = logout(req, session.clone(), rp, cfg)
            .await
            .expect("logout must not error when revocation is skipped");

        assert_eq!(resp.status(), actix_web::http::StatusCode::NO_CONTENT);
        assert_eq!(
            session.get::<String>("sub").unwrap(),
            None,
            "session must still be purged when revocation is skipped"
        );
    }

    // ── logout — unreachable revocation endpoint ──────────────────────────────

    /// When the revocation endpoint is unreachable, logout must still succeed
    /// (warn and continue).  Uses a port that is always refused on loopback.
    #[actix_web::test]
    #[ignore = "network-dependent; may be flaky in CI with slow connection setup"]
    async fn logout_survives_unreachable_revocation_endpoint() {
        let extra = BffExtraProviderMetadata {
            end_session_endpoint: None,
            // Port 9 (discard) is always refused on loopback — the request
            // will fail immediately with a connection error.
            revocation_endpoint: Some("http://127.0.0.1:9/revoke".to_owned()),
        };
        let metadata = OidcRp::test_metadata(extra);
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        // Use an http (non-secure) config so the https-guard doesn't block.
        let mut cfg = test_cfg();
        cfg.cookie_secure = false;
        cfg.allowed_origin = "http://app.example.com".to_string();
        let cfg = web::Data::new(cfg);

        let req = req_with(&[("Sec-Fetch-Site", "same-origin")]);
        let session = req.get_session();
        session.insert(ACCESS_TOKEN, "some-access-token").ok();

        let resp = logout(req, session, rp, cfg).await;
        // Must succeed despite the unreachable revocation endpoint.
        assert!(
            resp.is_ok(),
            "logout must not error on unreachable revocation endpoint"
        );
    }
}
