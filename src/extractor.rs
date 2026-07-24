use actix_session::SessionExt;
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use std::{collections::HashMap, future};

use crate::error::BffError;
use crate::session_state::{CLAIM_KEYS, EMAIL, ISS, NAME, SUB};

/// Session-backed authentication extractor.
///
/// Reads the `actix_session::Session` from the request and checks for the
/// `"sub"` key. Returns [`BffError::Unauthorized`] if absent.
///
/// Standard identity fields (`subject`, `issuer`, `email`, `name`) are always
/// populated when available. The `claims` map contains any extra claims that
/// were listed in [`crate::OidcBffConfig::persist_claims`] and were present in
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
    /// [`crate::OidcBffConfig::persist_claims`].
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
}
