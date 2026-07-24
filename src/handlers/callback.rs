use actix_session::Session;
use actix_web::{web, HttpResponse};
use openidconnect::{
    core::CoreJsonWebKey, AuthorizationCode, IdTokenVerifier, Nonce, OAuth2TokenResponse,
    PkceCodeVerifier, TokenResponse,
};
use serde::Deserialize;

use crate::config::OidcBffConfig;
use crate::error::BffError;
use crate::oidc::{BffClient, OidcRp};
use crate::session_state::{
    insert_or_internal, prune_expired, take_matching, ACCESS_TOKEN, CLAIM_KEYS, EMAIL, ID_TOKEN,
    ISS, NAME, POST_AUTH_SCRUB_KEYS, PRE_AUTH, REFRESH_TOKEN, SUB,
};

/// Query parameters `GET /auth/callback` is invoked with by the IdP.
#[derive(Deserialize)]
pub struct CallbackQuery {
    /// The authorization code to exchange for tokens, on success.
    pub code: Option<String>,
    /// The CSRF/pre-auth-slot state value echoed back by the IdP.
    pub state: Option<String>,
    /// OAuth error code the IdP redirects back with when the flow fails
    /// (e.g. `access_denied`, `login_required`).
    pub error: Option<String>,
    /// Human-readable detail accompanying `error`. Logged but never
    /// reflected into the response.
    pub error_description: Option<String>,
}

/// Build an ID token verifier from `client` with the crate's static allowed
/// algorithms applied.
///
/// This single construction point guarantees that both the initial validation
/// and the post-JWKS-refresh retry use the same algorithm allow-list, so
/// `set_allowed_algs` cannot silently diverge between the two call sites.
fn bff_verifier(client: &BffClient) -> IdTokenVerifier<'_, CoreJsonWebKey> {
    client
        .id_token_verifier()
        .set_allowed_algs(OidcRp::allowed_algs().iter().cloned())
}

/// Select claim values from a flat JSON object by name.
///
/// Returns `(name, value)` pairs for every entry in `names` that is present
/// in `obj`. Used to pick the `persist_claims` subset from the serialised
/// ID-token claims — works uniformly for typed fields (`amr`, `acr`,
/// `preferred_username`) and the flattened `additional_claims`.
fn select_claims<'a>(
    obj: &'a serde_json::Value,
    names: &'a [String],
) -> impl Iterator<Item = (&'a str, serde_json::Value)> + 'a {
    names
        .iter()
        .filter_map(|name| obj.get(name.as_str()).cloned().map(|v| (name.as_str(), v)))
}

/// `GET /auth/callback` — exchanges the authorization code for tokens,
/// validates the ID token, and establishes the authenticated session.
///
/// See the numbered comments in the implementation for the full ordering of
/// security-relevant steps (pre-auth slot consumption, session renewal,
/// scrubbing, claim persistence, token storage). On success, redirects to the
/// `return_to` path stored in the matched pre-auth slot.
pub async fn callback(
    session: Session,
    query: web::Query<CallbackQuery>,
    oidc: web::Data<OidcRp>,
    cfg: web::Data<OidcBffConfig>,
) -> Result<HttpResponse, BffError> {
    let query = query.into_inner();

    // (1) Remove the pre-auth slot vec from the session.
    let entries = session
        .remove_as::<Vec<crate::session_state::PreAuthEntry>>(PRE_AUTH)
        .and_then(Result::ok)
        .unwrap_or_default();

    let now = chrono::Utc::now().timestamp();
    let entries = prune_expired(entries, now, cfg.pre_auth_ttl_secs);

    // (2) IdP signalled an error. If a `state` is present consume only the
    // matching pre-auth slot and write the remainder back; if no `state` is
    // present the vec is written back untouched. Never reflect the
    // (attacker-suppliable) error strings into the response.
    if let Some(error) = query.error {
        log::warn!(
            "OIDC callback returned error {error:?}: {}",
            query.error_description.as_deref().unwrap_or("")
        );
        let preserved = if let Some(ref state) = query.state {
            let (_, rest) = take_matching(entries, state);
            rest
        } else {
            entries
        };
        insert_or_internal(&session, PRE_AUTH, &preserved)?;
        return Err(BffError::BadRequest(
            "Authorization failed at the identity provider".to_string(),
        ));
    }

    // (3) Require both code and state. Write the vec back first so that a
    // stray parameterless request does not destroy concurrent tabs' slots.
    let (Some(code), Some(state)) = (query.code, query.state) else {
        insert_or_internal(&session, PRE_AUTH, &entries)?;
        return Err(BffError::BadRequest("Missing code or state".to_string()));
    };

    // (4) Find the matching pre-auth entry; write `rest` back before any
    // subsequent failure so that concurrent tabs retain their slots.
    let (matched, rest) = take_matching(entries, &state);
    insert_or_internal(&session, PRE_AUTH, &rest)?;

    let entry = match matched {
        Some(e) => e,
        None => {
            log::warn!("OIDC callback: no matching pre-auth entry for state (unknown or expired)");
            return Err(BffError::BadRequest(
                "Unknown or expired login attempt".to_string(),
            ));
        }
    };

    // (5) Reconstruct the PKCE verifier from the raw secret stored in the slot.
    let pkce_verifier = PkceCodeVerifier::new(entry.pkce_verifier);

    let client = oidc.client().await;

    // (6) Exchange the authorization code for tokens.
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| {
            log::error!("OIDC provider has no token endpoint: {e}");
            BffError::Internal
        })?
        .set_pkce_verifier(pkce_verifier)
        .request_async(oidc.http_client())
        .await
        .map_err(|e| {
            log::error!("OIDC token exchange failed: {e}");
            BffError::BadRequest("Token exchange failed".to_string())
        })?;

    let nonce = Nonce::new(entry.nonce);

    let id_token = token_response
        .id_token()
        .ok_or_else(|| BffError::BadRequest("No id_token in response".to_string()))?;

    let verifier = bff_verifier(&client);

    // (7) Validate the ID token; on failure attempt one forced JWKS refresh
    // and retry once (rate-limited to 60 s to bound DoS impact).
    let claims = match id_token.claims(&verifier, &nonce) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("ID token validation failed: {e}");
            if oidc.force_refresh_for_retry().await {
                let fresh_client = oidc.client().await;
                let fresh_verifier = bff_verifier(&fresh_client);
                id_token.claims(&fresh_verifier, &nonce).map_err(|e2| {
                    log::warn!("ID token validation failed after JWKS refresh: {e2}");
                    BffError::BadRequest("ID token validation failed".to_string())
                })?
            } else {
                return Err(BffError::BadRequest(
                    "ID token validation failed".to_string(),
                ));
            }
        }
    };

    // SENSITIVE: capture the raw (validated) id_token so logout can use it
    // as the `id_token_hint` for RP-initiated end-session.
    let id_token_raw = id_token.to_string();
    let return_to = entry.return_to;

    // (8) Rotate session key to prevent session fixation.
    session.renew();

    // (9) Scrub keys from any previous login. `renew()` keeps the session
    // state, so stale tokens and optional identity fields must be explicitly
    // removed before writing the new login's values.
    for key in POST_AUTH_SCRUB_KEYS {
        session.remove(key);
    }
    let old_claim_keys: Vec<String> = session
        .remove_as::<Vec<String>>(CLAIM_KEYS)
        .and_then(Result::ok)
        .unwrap_or_default();
    for key in &old_claim_keys {
        session.remove(key);
    }

    // (10) Standard claims.
    let sub = claims.subject().to_string();
    let iss = claims.issuer().to_string();
    let email = claims.email().map(|e| e.to_string());
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string());

    insert_or_internal(&session, SUB, &sub)?;
    insert_or_internal(&session, ISS, &iss)?;
    if let Some(ref email_val) = email {
        insert_or_internal(&session, EMAIL, email_val)?;
    }
    if let Some(ref name_val) = name {
        insert_or_internal(&session, NAME, name_val)?;
    }

    // (11) Configurable extra claims. Serialize the entire claims struct to a
    // flat JSON object and pick from it by name. This handles typed fields
    // (`amr`, `acr`, `preferred_username`) and `additional_claims` uniformly
    // without special-casing — the fixture test gates this approach.
    let claims_json = serde_json::to_value(claims).map_err(|e| {
        log::error!("Failed to serialise ID-token claims: {e}");
        BffError::Internal
    })?;

    let mut persisted_keys: Vec<String> = Vec::new();
    for (name, value) in select_claims(&claims_json, &cfg.persist_claims) {
        insert_or_internal(&session, name, &value)?;
        persisted_keys.push(name.to_string());
    }
    insert_or_internal(&session, CLAIM_KEYS, &persisted_keys)?;

    // (12) Server-side token storage. SENSITIVE: the session store must be
    // encrypted at rest (or use DbSessionStore). Step 9 scrubbed any stale
    // tokens from a previous login before writing these.
    insert_or_internal(
        &session,
        ACCESS_TOKEN,
        token_response.access_token().secret(),
    )?;
    if let Some(refresh_token) = token_response.refresh_token() {
        insert_or_internal(&session, REFRESH_TOKEN, refresh_token.secret())?;
    }
    insert_or_internal(&session, ID_TOKEN, &id_token_raw)?;

    Ok(HttpResponse::Found()
        .append_header(("Location", return_to.as_str()))
        .finish())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::BffAdditionalClaims;
    use openidconnect::{core::CoreGenderClaim, IdTokenClaims};
    use serde_json::json;
    use std::collections::HashMap;

    // ── S4.2 HARD GATE: id_token_claims serialize flattens additional claims ───

    /// Confirms that `serde_json::to_value(IdTokenClaims<BffAdditionalClaims>)`
    /// surfaces `amr` and `acr` as top-level keys (not nested), alongside
    /// `preferred_username` and a flattened extra claim like `groups`.
    ///
    /// This test is the hard gate that proves the uniform serialization
    /// approach works before the amr/acr special-case is removed.
    #[test]
    fn id_token_claims_serialize_flattens_additional_claims() {
        // Build a raw JSON object that looks like a real ID token payload,
        // including typed OIDC fields and an extra flattened claim.
        let raw_json = json!({
            "iss": "https://idp.example.com",
            "sub": "user-123",
            "aud": ["client"],
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp(),
            "acr": "urn:example:gold",
            "amr": ["pwd", "otp"],
            "preferred_username": "jdoe",
            "groups": ["admin", "users"]
        });

        // Parse into the exact type the callback works with.
        // openidconnect 4.x: IdTokenClaims<AC, GC> — only two type parameters.
        let parsed: IdTokenClaims<BffAdditionalClaims, CoreGenderClaim> =
            serde_json::from_value(raw_json).expect("test claims must parse");

        // This is the operation the new callback performs.
        let as_value = serde_json::to_value(&parsed).expect("claims must serialize");

        // All claim names must appear as top-level keys.
        assert!(
            as_value.get("acr").is_some(),
            "acr must be a top-level key; got: {as_value}"
        );
        assert!(
            as_value.get("amr").is_some(),
            "amr must be a top-level key; got: {as_value}"
        );
        assert!(
            as_value.get("preferred_username").is_some(),
            "preferred_username must be a top-level key; got: {as_value}"
        );
        assert!(
            as_value.get("groups").is_some(),
            "groups (extra flattened claim) must be a top-level key; got: {as_value}"
        );

        // Values must be correct.
        assert_eq!(as_value["acr"], json!("urn:example:gold"));
        assert_eq!(as_value["amr"], json!(["pwd", "otp"]));
        assert_eq!(as_value["preferred_username"], json!("jdoe"));
        assert_eq!(as_value["groups"], json!(["admin", "users"]));
    }

    // ── S4.2: select_claims ───────────────────────────────────────────────────

    #[test]
    fn select_claims_picks_typed_and_additional_uniformly() {
        let obj = json!({
            "sub": "user-123",
            "acr": "urn:example:gold",
            "amr": ["pwd", "otp"],
            "groups": ["admin"],
            "preferred_username": "jdoe"
        });

        let names: Vec<String> = vec![
            "acr".to_string(),
            "amr".to_string(),
            "groups".to_string(),
            "preferred_username".to_string(),
        ];

        let picked: HashMap<_, _> = select_claims(&obj, &names).collect();
        assert_eq!(picked.len(), 4);
        assert_eq!(picked["acr"], json!("urn:example:gold"));
        assert_eq!(picked["amr"], json!(["pwd", "otp"]));
        assert_eq!(picked["groups"], json!(["admin"]));
        assert_eq!(picked["preferred_username"], json!("jdoe"));
    }

    #[test]
    fn select_claims_skips_absent_names() {
        let obj = json!({ "sub": "user-123", "acr": "low" });
        let names: Vec<String> = vec!["acr".to_string(), "groups".to_string()];

        let picked: HashMap<_, _> = select_claims(&obj, &names).collect();
        assert_eq!(picked.len(), 1);
        assert!(picked.contains_key("acr"));
        assert!(!picked.contains_key("groups"));
    }

    /// A claim that is present with a JSON `null` value is still selected —
    /// `null` is a legitimate claim value and distinct from "absent".
    #[test]
    fn select_claims_includes_null_and_nested_values() {
        let obj = json!({
            "middle_name": null,
            "address": { "country": "NL", "locality": "Amsterdam" }
        });
        let names: Vec<String> = vec!["middle_name".to_string(), "address".to_string()];

        let picked: HashMap<_, _> = select_claims(&obj, &names).collect();
        assert_eq!(picked.len(), 2);
        assert_eq!(picked["middle_name"], json!(null));
        assert_eq!(
            picked["address"],
            json!({ "country": "NL", "locality": "Amsterdam" }),
            "nested object values must be preserved verbatim"
        );
    }

    // ── S4.2: handler error paths (network-free — return before token exchange) ─

    use crate::config::OidcBffConfig;
    use crate::oidc::{BffExtraProviderMetadata, OidcRp};
    use crate::session_state::PreAuthEntry;
    use actix_session::SessionExt;
    use actix_web::{test::TestRequest, web};

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

    fn test_rp() -> web::Data<OidcRp> {
        web::Data::new(OidcRp::for_tests(OidcRp::test_metadata(
            BffExtraProviderMetadata::default(),
        )))
    }

    fn seed_entry(state: &str, started_at: i64) -> PreAuthEntry {
        PreAuthEntry {
            state: state.to_string(),
            pkce_verifier: format!("verifier_{state}"),
            nonce: format!("nonce_{state}"),
            return_to: "/".to_string(),
            started_at,
        }
    }

    fn query(
        code: Option<&str>,
        state: Option<&str>,
        error: Option<&str>,
    ) -> web::Query<CallbackQuery> {
        web::Query(CallbackQuery {
            code: code.map(str::to_owned),
            state: state.map(str::to_owned),
            error: error.map(str::to_owned),
            error_description: None,
        })
    }

    /// An IdP error redirect carrying no `state` must return 400, leave the
    /// pre-auth vec intact (prune-expired only), and never reflect the
    /// attacker-suppliable error string in the response.
    #[actix_web::test]
    async fn error_redirect_without_state_preserves_slots() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let now = chrono::Utc::now().timestamp();
        session
            .insert(
                PRE_AUTH,
                vec![seed_entry("state_a", now), seed_entry("state_b", now)],
            )
            .unwrap();

        let result = callback(
            session.clone(),
            query(None, None, Some("access_denied")),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await;

        let err = result.expect_err("IdP error redirect must yield 400");
        match &err {
            BffError::BadRequest(msg) => assert!(
                !msg.contains("access_denied"),
                "IdP error string must never be reflected, got: {msg}"
            ),
            other => panic!("expected BadRequest, got: {other:?}"),
        }

        let preserved: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();
        assert_eq!(
            preserved.len(),
            2,
            "a stateless error redirect must not nuke concurrent tabs' slots"
        );
        assert_eq!(preserved[0].state, "state_a");
        assert_eq!(preserved[1].state, "state_b");
    }

    /// An IdP error redirect that carries a `state` consumes only the matching
    /// slot; other concurrent attempts keep theirs.
    #[actix_web::test]
    async fn error_redirect_with_state_consumes_only_matching_slot() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let now = chrono::Utc::now().timestamp();
        session
            .insert(
                PRE_AUTH,
                vec![seed_entry("state_a", now), seed_entry("state_b", now)],
            )
            .unwrap();

        let result = callback(
            session.clone(),
            query(None, Some("state_a"), Some("access_denied")),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await;
        assert!(result.is_err(), "IdP error redirect must yield 400");

        let preserved: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();
        assert_eq!(preserved.len(), 1, "only the matching slot is consumed");
        assert_eq!(preserved[0].state, "state_b");
    }

    /// A callback with an unknown `state` must return the merged 400 and
    /// preserve all existing slots (written back before the failure).
    #[actix_web::test]
    async fn unknown_state_returns_400_and_preserves_slots() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let now = chrono::Utc::now().timestamp();
        session
            .insert(
                PRE_AUTH,
                vec![seed_entry("state_a", now), seed_entry("state_b", now)],
            )
            .unwrap();

        let result = callback(
            session.clone(),
            query(Some("some-code"), Some("state_unknown"), None),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await;

        match result.expect_err("unknown state must yield 400") {
            BffError::BadRequest(msg) => {
                assert_eq!(msg, "Unknown or expired login attempt");
            }
            other => panic!("expected BadRequest, got: {other:?}"),
        }

        let preserved: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();
        assert_eq!(preserved.len(), 2, "concurrent tabs' slots must survive");
    }

    /// A callback missing `code` and/or `state` (and no `error`) must be a 400.
    #[actix_web::test]
    async fn missing_code_or_state_returns_400() {
        for (code, state) in [(None, None), (Some("c"), None), (None, Some("s"))] {
            let req = TestRequest::default().to_http_request();
            let session = req.get_session();

            let result = callback(
                session,
                query(code, state, None),
                test_rp(),
                web::Data::new(test_cfg()),
            )
            .await;
            assert!(
                matches!(result, Err(BffError::BadRequest(_))),
                "code={code:?} state={state:?} must yield BadRequest"
            );
        }
    }

    /// A callback missing `code` or `state` (and no `error`) must write the
    /// pre-auth vec back so concurrent tabs' slots are not lost.
    #[actix_web::test]
    async fn missing_code_or_state_preserves_slots() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let now = chrono::Utc::now().timestamp();
        session
            .insert(
                PRE_AUTH,
                vec![seed_entry("state_a", now), seed_entry("state_b", now)],
            )
            .unwrap();

        // No code, no state, no error — bare parameterless GET /auth/callback.
        let result = callback(
            session.clone(),
            query(None, None, None),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await;

        assert!(
            matches!(result, Err(BffError::BadRequest(_))),
            "missing code/state must yield BadRequest"
        );

        let preserved: Vec<PreAuthEntry> = session
            .get(PRE_AUTH)
            .expect("session read must not error")
            .expect("PRE_AUTH must be present after the call");
        assert_eq!(
            preserved.len(),
            2,
            "concurrent tabs' slots must survive a parameterless callback hit"
        );
        assert_eq!(preserved[0].state, "state_a");
        assert_eq!(preserved[1].state, "state_b");
    }

    /// An expired pre-auth slot must not match: the attempt is rejected with
    /// the merged 400 even when the state string is otherwise correct.
    #[actix_web::test]
    async fn expired_slot_yields_unknown_or_expired_400() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let now = chrono::Utc::now().timestamp();
        // Started 601 s ago — one past the 600 s TTL.
        session
            .insert(PRE_AUTH, vec![seed_entry("state_a", now - 601)])
            .unwrap();

        let result = callback(
            session.clone(),
            query(Some("some-code"), Some("state_a"), None),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await;

        match result.expect_err("expired slot must yield 400") {
            BffError::BadRequest(msg) => {
                assert_eq!(msg, "Unknown or expired login attempt");
            }
            other => panic!("expected BadRequest, got: {other:?}"),
        }
    }
}
