use actix_session::SessionExt;
use actix_web::{dev::Payload, web::Data, FromRequest, HttpRequest};
use std::{collections::HashMap, future, sync::Once};

use crate::config::OidcBffConfig;
use crate::error::BffError;
use crate::session_state::{
    login_at_from_json, CLAIM_KEYS, EMAIL, ISS, LOGIN_AT, LOGIN_AT_FUTURE_SKEW_SECS, NAME, SUB,
};

/// Ensures the "`OidcBffConfig` missing from app_data" warning is logged only
/// once per process, not on every request — a missing config is a one-time
/// wiring mistake, not something that should flood logs indefinitely.
static MISSING_CONFIG_WARNED: Once = Once::new();

/// Session-backed authentication extractor.
///
/// Reads the `actix_session::Session` from the request and checks for the
/// `"sub"` key. Returns [`BffError::Unauthorized`] if absent.
///
/// Standard identity fields (`subject`, `issuer`, `email`, `name`) are always
/// populated when available. The `claims` map contains any extra claims that
/// were listed in [`crate::OidcBffConfig::persist_claims()`] and were present in
/// the ID token at login time.
///
/// # Example
/// ```rust,ignore
/// async fn protected(auth: Auth) -> impl Responder {
///     // Standard field
///     println!("subject: {}", auth.subject);
///
///     // Extra claim stored at login (e.g. persist_claims = ["groups"])
///     if let Some(groups) = auth.get_claim("groups") {
///         println!("groups: {groups}");
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Auth {
    /// The ID token's `sub` claim — the stable, IdP-scoped user identifier.
    pub subject: String,
    /// The ID token's `iss` claim.
    pub issuer: Option<String>,
    /// The ID token's `email` claim, if the IdP and requested scopes provided one.
    pub email: Option<String>,
    /// The ID token's `name` claim, if the IdP and requested scopes provided one.
    pub name: Option<String>,
    /// Extra claims that were configured for persistence via
    /// [`crate::OidcBffConfig::persist_claims()`].
    ///
    /// Keys are claim names; values are the original JSON values from the ID
    /// token (stored as `serde_json::Value` in the session).
    pub claims: HashMap<String, serde_json::Value>,
}

impl Auth {
    /// Look up an extra claim by name.
    ///
    /// Returns `None` if the claim was not configured for persistence, was not
    /// present in the ID token, or has since expired from the session.
    ///
    /// # Example
    /// ```rust,ignore
    /// let groups: Option<&serde_json::Value> = auth.get_claim("groups");
    /// ```
    #[must_use]
    pub fn get_claim(&self, name: &str) -> Option<&serde_json::Value> {
        self.claims.get(name)
    }

    fn extract(req: &HttpRequest) -> Result<Self, BffError> {
        let session = req.get_session();

        let sub = session
            .get::<String>(SUB)
            .map_err(|_| BffError::Unauthorized)?
            .ok_or(BffError::Unauthorized)?;

        // Store-agnostic enforcement of the absolute session lifetime.
        //
        // `DbSessionStore` also enforces this, but `session_middleware` is
        // generic over `SessionStore` and the crate advertises
        // `CookieSessionStore` as supported — its `update_ttl` is a no-op and
        // its `load` performs no expiry check at all, so without this the
        // configured `max_session_lifetime_secs` would be written and never
        // read. This check is what makes the guarantee hold for every store;
        // the store-side checks are defense-in-depth on top of it.
        //
        // A missing `OidcBffConfig` in app_data means `configure_app_data()`
        // was never called — a wiring mistake, not a security signal. We
        // deliberately do not 401 on that: turning a wiring bug into a total
        // outage is worse than the (store-side-covered) miss.
        if let Some(cfg) = req.app_data::<Data<OidcBffConfig>>() {
            let now = chrono::Utc::now().timestamp();
            // Read as a raw `serde_json::Value` and resolve it through the
            // shared `login_at_from_json` helper — `Session::insert` JSON-
            // encodes an `i64` as a bare number, but `DbSessionStore`
            // deliberately also tolerates a quoted digit-string, so the
            // extractor must accept both encodings too. Diverging here would
            // mean the two enforcement points disagree about which sessions
            // are alive.
            let expired = match session.get::<serde_json::Value>(LOGIN_AT) {
                Ok(Some(value)) => match login_at_from_json(&value) {
                    Some(login_at) => {
                        // Reject a `login_at` far in the future (bad/corrupt
                        // timestamp would otherwise yield an unbounded
                        // session). The `checked_add` overflow guard below is
                        // unreachable-by-construction for any positive
                        // `max_session_lifetime_secs`: overflow would require
                        // `login_at > i64::MAX - max_session_lifetime_secs`,
                        // which is always beyond the skew bound above and so
                        // already rejected by the first condition. Kept as
                        // defence in depth — do not remove it or assume a
                        // test can exercise it.
                        login_at > now + LOGIN_AT_FUTURE_SKEW_SECS
                            || cfg
                                .max_session_lifetime_secs()
                                .checked_add(login_at)
                                .is_none_or(|deadline| deadline <= now)
                    }
                    // Value present but not a bare number or digit-string.
                    None => true,
                },
                // Missing or unparsable `login_at` is treated as expired —
                // `sub` present without `login_at` is a combination the
                // session store considers dead (see `DbSessionStore`).
                _ => true,
            };
            if expired {
                session.purge();
                return Err(BffError::Unauthorized);
            }
        } else {
            MISSING_CONFIG_WARNED.call_once(|| {
                log::warn!(
                    "Auth extractor: OidcBffConfig not found in app_data; skipping the \
                     absolute session-lifetime check (did configure_app_data() run?). \
                     This message is logged once per process."
                );
            });
        }

        let issuer = session.get::<String>(ISS).ok().flatten();
        let email = session.get::<String>(EMAIL).ok().flatten();
        let name = session.get::<String>(NAME).ok().flatten();

        // Read the list of extra claim names that the callback stored, then
        // load each value from the session as a `serde_json::Value` directly.
        let claim_keys: Vec<String> = session
            .get::<Vec<String>>(CLAIM_KEYS)
            .ok()
            .flatten()
            .unwrap_or_default();

        let mut claims: HashMap<String, serde_json::Value> =
            HashMap::with_capacity(claim_keys.len());

        for key in &claim_keys {
            if let Some(value) = session
                .get::<serde_json::Value>(key.as_str())
                .ok()
                .flatten()
            {
                claims.insert(key.clone(), value);
            }
        }

        Ok(Auth {
            subject: sub,
            issuer,
            email,
            name,
            claims,
        })
    }
}

impl FromRequest for Auth {
    type Error = BffError;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        future::ready(Auth::extract(req))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use actix_session::SessionExt;
    use actix_web::test::TestRequest;
    use serde_json::json;

    /// Helper: build an `Auth` value directly (no HTTP round-trip needed).
    fn make_auth(claims: HashMap<String, serde_json::Value>) -> Auth {
        Auth {
            subject: "user-123".to_string(),
            issuer: Some("https://idp.example.com".to_string()),
            email: None,
            name: None,
            claims,
        }
    }

    /// `get_claim` returns `Some` for a present array-valued claim.
    #[test]
    fn get_claim_returns_array_value() {
        let mut claims = HashMap::new();
        claims.insert("groups".to_string(), json!(["admin", "users"]));
        let auth = make_auth(claims);

        let groups = auth.get_claim("groups").expect("groups should be present");
        assert_eq!(*groups, json!(["admin", "users"]));
    }

    /// `get_claim` returns `None` for a key that was never persisted.
    #[test]
    fn get_claim_returns_none_for_absent() {
        let auth = make_auth(HashMap::new());
        assert!(auth.get_claim("groups").is_none());
        assert!(auth.get_claim("amr").is_none());
    }

    /// `get_claim` works for string-valued claims too.
    #[test]
    fn get_claim_returns_string_value() {
        let mut claims = HashMap::new();
        claims.insert("acr".to_string(), json!("urn:example:gold"));
        let auth = make_auth(claims);

        let acr = auth.get_claim("acr").expect("acr should be present");
        assert_eq!(*acr, json!("urn:example:gold"));
    }

    /// Multiple claims can coexist in the map.
    #[test]
    fn get_claim_multiple_claims() {
        let mut claims = HashMap::new();
        claims.insert("groups".to_string(), json!(["admin"]));
        claims.insert("amr".to_string(), json!(["pwd", "otp"]));
        let auth = make_auth(claims);

        assert_eq!(*auth.get_claim("groups").unwrap(), json!(["admin"]));
        assert_eq!(*auth.get_claim("amr").unwrap(), json!(["pwd", "otp"]));
        assert!(auth.get_claim("missing").is_none());
    }

    // ── S4.3: FromRequest sync extraction ─────────────────────────────────────

    /// A request with no session `sub` key must yield `Unauthorized`.
    #[test]
    fn from_request_without_sub_is_unauthorized() {
        let req = TestRequest::default().to_http_request();
        let result = Auth::extract(&req);
        assert!(
            matches!(result, Err(BffError::Unauthorized)),
            "expected Unauthorized, got: {result:?}"
        );
    }

    /// When the session contains a `sub` and `serde_json::Value` claims,
    /// the extractor must rehydrate them without double-decoding.
    #[test]
    fn from_request_rehydrates_value_claims() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        session.insert(SUB, "user-42").unwrap();
        session
            .insert(CLAIM_KEYS, vec!["groups".to_string()])
            .unwrap();
        // Store as a serde_json::Value (the new contract).
        session.insert("groups", json!(["admin", "users"])).unwrap();

        let auth = Auth::extract(&req).expect("extract must succeed");
        assert_eq!(auth.subject, "user-42");
        assert_eq!(
            *auth.get_claim("groups").unwrap(),
            json!(["admin", "users"])
        );
    }

    /// Standard fields (`issuer`, `email`, `name`) are populated from the session.
    #[test]
    fn from_request_populates_standard_fields() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        session.insert(SUB, "user-99").unwrap();
        session.insert(ISS, "https://idp.example.com").unwrap();
        session.insert(EMAIL, "user@example.com").unwrap();
        session.insert(NAME, "Jane Doe").unwrap();
        session.insert(CLAIM_KEYS, Vec::<String>::new()).unwrap();

        let auth = Auth::extract(&req).expect("extract must succeed");
        assert_eq!(auth.subject, "user-99");
        assert_eq!(auth.issuer.as_deref(), Some("https://idp.example.com"));
        assert_eq!(auth.email.as_deref(), Some("user@example.com"));
        assert_eq!(auth.name.as_deref(), Some("Jane Doe"));
        assert!(auth.claims.is_empty());
    }

    // ── Absolute session-lifetime enforcement ───────────────────────────────

    use crate::config::test_config;

    /// Helper: a request carrying `sub` + `login_at` and `cfg` in app_data.
    fn req_with_login_at(login_at: i64, cfg: OidcBffConfig) -> HttpRequest {
        let req = TestRequest::default()
            .app_data(Data::new(cfg))
            .to_http_request();
        let session = req.get_session();
        session.insert(SUB, "user-1").unwrap();
        session.insert(LOGIN_AT, login_at).unwrap();
        session.insert(CLAIM_KEYS, Vec::<String>::new()).unwrap();
        req
    }

    /// A session within its configured lifetime authenticates successfully.
    #[test]
    fn within_lifetime_succeeds() {
        let now = chrono::Utc::now().timestamp();
        let req = req_with_login_at(now - 10, test_config());

        let auth = Auth::extract(&req).expect("extract must succeed");
        assert_eq!(auth.subject, "user-1");
    }

    /// A `login_at` older than `max_session_lifetime_secs` yields
    /// `Unauthorized` and purges the session.
    #[test]
    fn expired_lifetime_is_unauthorized_and_purges() {
        let now = chrono::Utc::now().timestamp();
        // post_auth_ttl must not exceed max_session_lifetime, so lower both
        // together — only max_session_lifetime_secs is under test here.
        let cfg = crate::config::test_config_builder()
            .post_auth_ttl(std::time::Duration::from_secs(3600))
            .max_session_lifetime(std::time::Duration::from_secs(3600))
            .build()
            .unwrap();
        let req = req_with_login_at(now - 3601, cfg);
        let session = req.get_session();

        let result = Auth::extract(&req);
        assert!(matches!(result, Err(BffError::Unauthorized)));
        assert!(
            session.get::<String>(SUB).unwrap().is_none(),
            "expired session must be purged"
        );
    }

    /// `sub` present without a `login_at` key must be treated as expired.
    #[test]
    fn missing_login_at_is_unauthorized() {
        let req = TestRequest::default()
            .app_data(Data::new(test_config()))
            .to_http_request();
        let session = req.get_session();
        session.insert(SUB, "user-1").unwrap();

        let result = Auth::extract(&req);
        assert!(matches!(result, Err(BffError::Unauthorized)));
    }

    /// An unparsable `login_at` (wrong JSON shape) must be treated as expired,
    /// not panic or bypass the check.
    #[test]
    fn unparsable_login_at_is_unauthorized() {
        let req = TestRequest::default()
            .app_data(Data::new(test_config()))
            .to_http_request();
        let session = req.get_session();
        session.insert(SUB, "user-1").unwrap();
        session.insert(LOGIN_AT, "not-a-number").unwrap();

        let result = Auth::extract(&req);
        assert!(matches!(result, Err(BffError::Unauthorized)));
    }

    /// A `login_at` far in the future (beyond the clock-skew allowance) is
    /// rejected — a bad timestamp must not yield an unbounded session.
    #[test]
    fn login_at_far_in_future_is_unauthorized() {
        let now = chrono::Utc::now().timestamp();
        let req = req_with_login_at(now + 3600, test_config());

        let result = Auth::extract(&req);
        assert!(matches!(result, Err(BffError::Unauthorized)));
    }

    /// A `login_at` only a few seconds ahead of now is accepted (clock-skew
    /// allowance).
    #[test]
    fn login_at_within_skew_allowance_succeeds() {
        let now = chrono::Utc::now().timestamp();
        let req = req_with_login_at(now + 5, test_config());

        let auth = Auth::extract(&req).expect("extract must succeed within skew allowance");
        assert_eq!(auth.subject, "user-1");
    }

    /// A `login_at` near `i64::MAX` is rejected without panicking.
    ///
    /// Note: this does not exercise the `checked_add` overflow guard on
    /// `max_session_lifetime_secs` — `||` short-circuits on the preceding
    /// future-skew check, which already rejects any `login_at` this far
    /// ahead of `now`. The overflow guard is unreachable by construction for
    /// any positive `max_session_lifetime_secs` (see the comment at its call
    /// site); this test only verifies the far-future case is rejected
    /// cleanly.
    #[test]
    fn login_at_far_future_near_i64_max_is_unauthorized_no_panic() {
        let req = req_with_login_at(i64::MAX - 10, test_config());

        let result = Auth::extract(&req);
        assert!(matches!(result, Err(BffError::Unauthorized)));
    }

    /// A `login_at` encoded as a quoted digit-string (the alternate encoding
    /// `DbSessionStore` tolerates) is accepted when within the configured
    /// lifetime — the extractor must agree with the store on this encoding.
    #[test]
    fn login_at_as_quoted_string_within_lifetime_succeeds() {
        let now = chrono::Utc::now().timestamp();
        let req = TestRequest::default()
            .app_data(Data::new(test_config()))
            .to_http_request();
        let session = req.get_session();
        session.insert(SUB, "user-1").unwrap();
        session.insert(LOGIN_AT, (now - 10).to_string()).unwrap();
        session.insert(CLAIM_KEYS, Vec::<String>::new()).unwrap();

        let auth = Auth::extract(&req).expect("quoted-string login_at must be accepted");
        assert_eq!(auth.subject, "user-1");
    }

    /// When `OidcBffConfig` is absent from app_data (e.g.
    /// `configure_app_data()` was never called), extraction must still
    /// succeed rather than 401 the whole application.
    #[test]
    fn missing_config_skips_lifetime_check() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        session.insert(SUB, "user-1").unwrap();
        // No LOGIN_AT, no cfg in app_data: the check must be skipped, not
        // fail because LOGIN_AT is absent.
        session.insert(CLAIM_KEYS, Vec::<String>::new()).unwrap();

        let auth = Auth::extract(&req).expect("extract must succeed with no config wired");
        assert_eq!(auth.subject, "user-1");
    }

    /// `LOGIN_AT` is present as a raw session key (used only for the
    /// lifetime check) but must never surface through `Auth::claims` /
    /// `Auth::get_claim`. In production `CLAIM_KEYS` can never contain it —
    /// `RESERVED_SESSION_KEYS` blocks `persist_claims` from colliding with
    /// it — so this asserts the rehydration path (which only ever reads
    /// keys listed in `CLAIM_KEYS`) does not pick it up incidentally.
    #[test]
    fn login_at_never_appears_in_claims() {
        let now = chrono::Utc::now().timestamp();
        let req = req_with_login_at(now, test_config());

        let auth = Auth::extract(&req).expect("extract must succeed");
        assert!(
            !auth.claims.contains_key(LOGIN_AT),
            "LOGIN_AT must never be exposed via Auth::claims"
        );
        assert!(auth.get_claim(LOGIN_AT).is_none());
    }
}
