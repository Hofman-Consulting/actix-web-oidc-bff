use actix_session::Session;
use actix_web::{web, HttpResponse};
use openidconnect::{core::CoreAuthenticationFlow, CsrfToken, Nonce, PkceCodeChallenge, Scope};
use serde::Deserialize;

use crate::config::OidcBffConfig;
use crate::error::BffError;
use crate::oidc::OidcRp;
use crate::session_state::{
    insert_or_internal, prune_expired, push_pre_auth, PreAuthEntry, PRE_AUTH,
};

/// Query parameters `GET /auth/login` accepts.
#[derive(Deserialize)]
pub struct LoginQuery {
    /// Path to redirect back to after a successful login. Must pass
    /// [`validate_return_to`] against `cfg.return_to_prefix`; absent or empty
    /// defaults to `cfg.return_to_prefix`.
    pub return_to: Option<String>,
}

/// Maximum accepted length for a `return_to` value.
pub const MAX_RETURN_TO_LEN: usize = 512;

/// Validate that a `return_to` value is safe (no open-redirect).
///
/// Rules:
/// - Must be non-empty, at most [`MAX_RETURN_TO_LEN`] bytes, and printable
///   ASCII (rejects CR/LF header injection and other control characters)
/// - Must start with `/` (an absolute path on this host) regardless of the
///   configured prefix
/// - Must start with `prefix` (the application-configured safe path prefix) at
///   a path-segment boundary: it must equal `prefix` exactly or the character
///   after the prefix must be `/` — prefix `/app` accepts `/app` and `/app/x`
///   but rejects `/appointments`
/// - Must NOT contain `//` (protocol-relative URL attack)
/// - Must NOT contain `\` — browsers normalize backslashes to slashes in
///   redirect targets, so `/\evil.com` would become `//evil.com`
/// - Must NOT contain `:/` (scheme attack, e.g. `javascript:/`, `https:/`)
pub fn validate_return_to(return_to: &str, prefix: &str) -> bool {
    if return_to.is_empty() || return_to.len() > MAX_RETURN_TO_LEN {
        return false;
    }
    if !return_to.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return false;
    }
    if !return_to.starts_with('/') {
        return false;
    }
    // Boundary-aware prefix check: require an exact match OR that the
    // character immediately after the prefix is `/` (i.e. a path-segment
    // boundary).  Safe byte indexing via `.as_bytes().get(prefix.len())`
    // avoids any panic on hostile input — this function is pub and called
    // with attacker-controlled strings.
    let prefix_ok = return_to == prefix
        || (return_to.starts_with(prefix)
            && (prefix.ends_with('/') || return_to.as_bytes().get(prefix.len()) == Some(&b'/')));
    if !prefix_ok {
        return false;
    }
    if return_to.contains("//") || return_to.contains('\\') {
        return false;
    }
    // Reject anything that looks like a scheme (e.g. javascript:/, https:/)
    if return_to.contains(":/") {
        return false;
    }
    true
}

/// `GET /auth/login` — begins the OIDC authorization-code + PKCE flow.
///
/// Validates `return_to`, generates state/nonce/PKCE, stores a pre-auth entry
/// in the session's pre-auth slot vec (FIFO-evicting at the 5-slot cap), and
/// redirects the browser to the IdP's authorization endpoint.
pub async fn login(
    session: Session,
    query: web::Query<LoginQuery>,
    oidc: web::Data<OidcRp>,
    cfg: web::Data<OidcBffConfig>,
) -> Result<HttpResponse, BffError> {
    let return_to = query
        .into_inner()
        .return_to
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| cfg.return_to_prefix.clone());

    if !validate_return_to(&return_to, &cfg.return_to_prefix) {
        return Err(BffError::BadRequest("invalid return_to".to_string()));
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let client = oidc.client().await;

    // Filter `openid` from cfg.scopes: authorize_url auto-adds the openid
    // scope, so passing it again would duplicate it in the request URL.
    let scopes: Vec<Scope> = cfg
        .scopes
        .iter()
        .filter(|s| s.as_str() != "openid")
        .map(|s| Scope::new(s.clone()))
        .collect();

    let mut auth_request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge);

    for scope in scopes {
        auth_request = auth_request.add_scope(scope);
    }

    let (auth_url, csrf_out, nonce_out) = auth_request.url();

    let now = chrono::Utc::now().timestamp();

    // Load the existing pre-auth vec, prune expired entries, push the new
    // entry (FIFO-evict at PRE_AUTH_MAX_SLOTS), then write back in one insert.
    let existing = session
        .remove_as::<Vec<PreAuthEntry>>(PRE_AUTH)
        .and_then(Result::ok)
        .unwrap_or_default();

    let pruned = prune_expired(existing, now, cfg.pre_auth_ttl_secs);
    let updated = push_pre_auth(
        pruned,
        PreAuthEntry {
            state: csrf_out.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            nonce: nonce_out.secret().clone(),
            return_to,
            started_at: now,
        },
    );

    insert_or_internal(&session, PRE_AUTH, &updated)?;

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.as_str()))
        .finish())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{login, validate_return_to, LoginQuery, MAX_RETURN_TO_LEN};
    use crate::config::OidcBffConfig;
    use crate::oidc::{BffExtraProviderMetadata, OidcRp};
    use crate::session_state::{PreAuthEntry, PRE_AUTH};
    use actix_session::SessionExt;
    use actix_web::{test::TestRequest, web};
    use openidconnect::url::Url;
    use std::collections::HashMap;

    /// Build a minimal `OidcBffConfig` for tests without touching env vars.
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
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
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
            pkce_verifier: "seed-verifier".to_string(),
            nonce: "seed-nonce".to_string(),
            return_to: "/".to_string(),
            started_at,
        }
    }

    /// Extract the Location header of a redirect response and its query params.
    fn location_params(resp: &actix_web::HttpResponse) -> (Url, HashMap<String, String>) {
        let location = resp
            .headers()
            .get("Location")
            .expect("Location header must be present")
            .to_str()
            .unwrap();
        let url = Url::parse(location).expect("Location must be a valid URL");
        let params: HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        (url, params)
    }

    // ── S4.1: login handler ──────────────────────────────────────────────────

    #[actix_web::test]
    async fn login_redirects_to_authorization_endpoint() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let resp = login(
            session,
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await
        .expect("login must succeed");

        assert_eq!(resp.status(), actix_web::http::StatusCode::FOUND);

        let (url, params) = location_params(&resp);
        assert!(
            url.as_str()
                .starts_with("https://idp.example.com/oauth2/authorize"),
            "must redirect to the authorization endpoint, got: {url}"
        );
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["code_challenge_method"], "S256");
        assert!(!params["code_challenge"].is_empty());
        assert!(!params["state"].is_empty());
        assert!(!params["nonce"].is_empty());
        assert_eq!(
            params["redirect_uri"],
            "https://app.example.com/auth/callback"
        );

        // `openid` must appear exactly once (authorize_url auto-adds it; the
        // handler filters it from cfg.scopes to avoid duplication).
        let scope_words: Vec<&str> = params["scope"].split_whitespace().collect();
        assert_eq!(
            scope_words.iter().filter(|s| **s == "openid").count(),
            1,
            "openid must appear exactly once in scope, got: {:?}",
            params["scope"]
        );
        assert!(scope_words.contains(&"profile"));
        assert!(scope_words.contains(&"email"));
    }

    #[actix_web::test]
    async fn login_stores_pre_auth_entry_matching_redirect() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let resp = login(
            session.clone(),
            web::Query(LoginQuery {
                return_to: Some("/dashboard".to_string()),
            }),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await
        .expect("login must succeed");

        let (_, params) = location_params(&resp);

        let entries: Vec<PreAuthEntry> = session
            .get(PRE_AUTH)
            .unwrap()
            .expect("pre-auth vec must be stored");
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        // B4 acceptance: stored state/nonce equal the Location query params.
        assert_eq!(entry.state, params["state"]);
        assert_eq!(entry.nonce, params["nonce"]);
        assert_eq!(entry.return_to, "/dashboard");
        // B3: pkce_verifier is the raw secret, not a JSON-encoded string.
        assert!(!entry.pkce_verifier.is_empty());
        assert!(
            !entry.pkce_verifier.starts_with('"'),
            "pkce_verifier must be a raw (non-JSON) string"
        );
    }

    #[actix_web::test]
    async fn login_caps_concurrent_attempts_at_five() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let now = chrono::Utc::now().timestamp();
        let existing: Vec<PreAuthEntry> = (0..5)
            .map(|i| seed_entry(&format!("state{i}"), now))
            .collect();
        session.insert(PRE_AUTH, &existing).unwrap();

        let resp = login(
            session.clone(),
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await
        .expect("login must succeed");

        let (_, params) = location_params(&resp);
        let entries: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();

        assert_eq!(entries.len(), 5, "slot count must stay capped at 5");
        assert!(
            !entries.iter().any(|e| e.state == "state0"),
            "oldest slot must be evicted"
        );
        assert_eq!(
            entries.last().unwrap().state,
            params["state"],
            "newest slot must be the freshly issued state"
        );
    }

    #[actix_web::test]
    async fn login_prunes_expired_entries() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let now = chrono::Utc::now().timestamp();
        // Both entries are far beyond the 600 s pre-auth TTL.
        let stale = vec![
            seed_entry("stale_a", now - 10_000),
            seed_entry("stale_b", now - 10_000),
        ];
        session.insert(PRE_AUTH, &stale).unwrap();

        let resp = login(
            session.clone(),
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await
        .expect("login must succeed");

        let (_, params) = location_params(&resp);
        let entries: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();

        assert_eq!(entries.len(), 1, "expired entries must be pruned");
        assert_eq!(entries[0].state, params["state"]);
    }

    #[actix_web::test]
    async fn login_rejects_invalid_return_to() {
        for bad in ["//evil.com", "https://evil.com", "/\\evil.com"] {
            let req = TestRequest::default().to_http_request();
            let session = req.get_session();

            let result = login(
                session.clone(),
                web::Query(LoginQuery {
                    return_to: Some(bad.to_string()),
                }),
                test_rp(),
                web::Data::new(test_cfg()),
            )
            .await;

            assert!(
                matches!(result, Err(crate::error::BffError::BadRequest(_))),
                "return_to {bad:?} must be rejected with BadRequest"
            );
            // No pre-auth slot may be created for a rejected attempt.
            assert!(
                session
                    .get::<Vec<PreAuthEntry>>(PRE_AUTH)
                    .unwrap()
                    .is_none(),
                "no pre-auth entry may be stored for rejected return_to {bad:?}"
            );
        }
    }

    #[test]
    fn accepts_simple_paths() {
        assert!(validate_return_to("/", "/"));
        assert!(validate_return_to("/dashboard", "/"));
        assert!(validate_return_to("/a/b/c?x=1&y=2", "/"));
        assert!(validate_return_to("/portal/home", "/portal/"));
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(!validate_return_to("/admin", "/portal/"));
        assert!(!validate_return_to("/portalx", "/portal/"));
    }

    #[test]
    fn rejects_protocol_relative() {
        assert!(!validate_return_to("//evil.com", "/"));
        assert!(!validate_return_to("/foo//bar", "/"));
    }

    #[test]
    fn rejects_backslash_variants() {
        // Browsers normalize `\` to `/` in redirects: `/\evil.com` → `//evil.com`.
        assert!(!validate_return_to("/\\evil.com", "/"));
        assert!(!validate_return_to("/\\/evil.com", "/"));
        assert!(!validate_return_to("/foo\\bar", "/"));
    }

    #[test]
    fn rejects_schemes() {
        assert!(!validate_return_to("https://evil.com", "/"));
        assert!(!validate_return_to("https:/evil.com", "/"));
        assert!(!validate_return_to("javascript:alert(1)", "/"));
        // Even with an empty prefix nothing without a leading `/` passes.
        assert!(!validate_return_to("javascript:alert(1)", ""));
        assert!(!validate_return_to("data:text/html,x", ""));
    }

    #[test]
    fn rejects_non_path_starts() {
        assert!(!validate_return_to("", "/"));
        assert!(!validate_return_to("dashboard", "/"));
        assert!(!validate_return_to(" /dashboard", "/"));
    }

    #[test]
    fn rejects_control_characters() {
        // CR/LF would be header injection if they ever reached the Location
        // header; tab and NUL are equally malformed.
        assert!(!validate_return_to("/foo\r\nSet-Cookie:x=y", "/"));
        assert!(!validate_return_to("/foo\nbar", "/"));
        assert!(!validate_return_to("/foo\tbar", "/"));
        assert!(!validate_return_to("/foo\0bar", "/"));
        assert!(!validate_return_to("/foo\u{e9}", "/"));
    }

    #[test]
    fn rejects_overlong_values() {
        let long = format!("/{}", "a".repeat(MAX_RETURN_TO_LEN));
        assert!(!validate_return_to(&long, "/"));
        let max = format!("/{}", "a".repeat(MAX_RETURN_TO_LEN - 1));
        assert!(validate_return_to(&max, "/"));
    }

    // ── B-1: segment-boundary prefix tests ───────────────────────────────────

    /// Prefix `/app` must reject sibling paths (`/appointments`, `/app-evil`)
    /// that share the string prefix but differ at the segment boundary.
    #[test]
    fn prefix_without_trailing_slash_rejects_sibling_paths() {
        // These share the `/app` string but are NOT under the `/app` segment.
        assert!(
            !validate_return_to("/appointments", "/app"),
            "/appointments must be rejected by prefix /app"
        );
        assert!(
            !validate_return_to("/app-evil", "/app"),
            "/app-evil must be rejected by prefix /app"
        );
        assert!(
            !validate_return_to("/apple", "/app"),
            "/apple must be rejected by prefix /app"
        );
    }

    /// Prefix `/app` must accept `/app` (exact) and `/app/x` (child).
    /// Prefix `/app/` must accept `/app/` (exact).
    #[test]
    fn prefix_matches_exact_and_child_paths() {
        // Exact match.
        assert!(
            validate_return_to("/app", "/app"),
            "/app must match prefix /app"
        );
        // Child path — byte at prefix.len() is `/`.
        assert!(
            validate_return_to("/app/dashboard", "/app"),
            "/app/dashboard must match prefix /app"
        );
        assert!(
            validate_return_to("/app/x?q=1", "/app"),
            "/app/x?q=1 must match prefix /app"
        );
        // Trailing-slash prefix: exact match.
        assert!(
            validate_return_to("/app/", "/app/"),
            "/app/ must match prefix /app/"
        );
        // Trailing-slash prefix: child path.
        assert!(
            validate_return_to("/app/home", "/app/"),
            "/app/home must match prefix /app/"
        );
    }

    /// Prefix `/` accepts every otherwise-valid path.
    #[test]
    fn root_prefix_unchanged() {
        assert!(validate_return_to("/", "/"));
        assert!(validate_return_to("/foo", "/"));
        assert!(validate_return_to("/foo/bar", "/"));
        assert!(validate_return_to("/foo?x=1", "/"));
    }

    /// Percent-encoded paths are treated as same-origin (no decode step):
    /// `/app%2f..` does not contain a literal `/` after the prefix, so it is
    /// rejected by the boundary check — this pins the current (safe) behaviour.
    #[test]
    fn percent_encoded_traversal_stays_same_origin() {
        // `/app%2f..` — encoded slash, no decode happens; the byte after
        // prefix `/app` is `%`, not `/`, so boundary check rejects it.
        assert!(
            !validate_return_to("/app%2f..", "/app"),
            "/app%2f.. must be rejected by boundary check (no decode)"
        );
        // A valid percent-encoded segment under the prefix is allowed.
        assert!(
            validate_return_to("/app/hello%20world", "/app"),
            "/app/hello%20world must be accepted under prefix /app"
        );
    }

    // ── B-2: empty return_to defaults to prefix ───────────────────────────────

    /// `?return_to=` (empty string) must fall back to the prefix, not 400.
    #[actix_web::test]
    async fn login_empty_return_to_defaults_to_prefix() {
        let req = actix_web::test::TestRequest::default().to_http_request();
        let session = req.get_session();

        let cfg = {
            let mut c = test_cfg();
            c.return_to_prefix = "/app".to_string();
            c
        };
        // Validate that the prefix itself passes validation (sanity).
        assert!(
            validate_return_to("/app", "/app"),
            "prefix /app must be self-valid"
        );

        let resp = login(
            session.clone(),
            web::Query(LoginQuery {
                return_to: Some(String::new()),
            }),
            test_rp(),
            web::Data::new(cfg),
        )
        .await
        .expect("empty return_to must fall back to prefix and succeed");

        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::FOUND,
            "empty return_to must produce a 302"
        );

        // The stored pre-auth entry must use the prefix as return_to.
        let entries: Vec<crate::session_state::PreAuthEntry> = session
            .get(PRE_AUTH)
            .unwrap()
            .expect("pre-auth vec must be stored");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].return_to, "/app",
            "empty return_to must default to the configured prefix"
        );
    }
}
