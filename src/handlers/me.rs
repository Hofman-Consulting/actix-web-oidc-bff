use actix_web::HttpResponse;
use serde_json::json;

use crate::error::BffError;
use crate::extractor::Auth;

/// Return the authenticated user's standard identity claims.
///
/// Responses:
/// - `200` with `{"sub", "iss", "email", "name"}` — all four fields are
///   always present; optional fields (`iss`, `email`, `name`) are `null` when
///   the ID token did not carry them.
/// - `401` — produced by the [`Auth`] extractor when the session has no `sub`.
///
/// Tokens and extra claims are intentionally never included; consumers that
/// need them must read the session server-side.
pub async fn me(auth: Auth) -> Result<HttpResponse, BffError> {
    Ok(HttpResponse::Ok().json(json!({
        "sub":   auth.subject,
        "iss":   auth.issuer,
        "email": auth.email,
        "name":  auth.name,
    })))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;

    /// Build an `Auth` directly (no HTTP round-trip needed for unit tests).
    fn make_auth_full() -> Auth {
        Auth {
            subject: "user-abc".to_string(),
            issuer: Some("https://idp.example.com".to_string()),
            email: Some("user@example.com".to_string()),
            name: Some("Alice".to_string()),
            claims: HashMap::new(),
        }
    }

    fn make_auth_minimal() -> Auth {
        Auth {
            subject: "user-xyz".to_string(),
            issuer: None,
            email: None,
            name: None,
            claims: HashMap::new(),
        }
    }

    fn make_auth_with_extra() -> Auth {
        let mut claims = HashMap::new();
        claims.insert("groups".to_string(), serde_json::json!(["admin"]));
        claims.insert("amr".to_string(), serde_json::json!(["pwd"]));
        Auth {
            subject: "user-extras".to_string(),
            issuer: Some("https://idp.example.com".to_string()),
            email: Some("user@example.com".to_string()),
            name: None,
            claims,
        }
    }

    /// `me` must return exactly the four standard identity keys.
    #[actix_web::test]
    async fn me_returns_identity_json() {
        let resp = me(make_auth_full()).await.unwrap();
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["sub"], "user-abc");
        assert_eq!(json["iss"], "https://idp.example.com");
        assert_eq!(json["email"], "user@example.com");
        assert_eq!(json["name"], "Alice");
    }

    /// `me` must never expose tokens or extra (persisted) claims — exactly
    /// the four standard keys must be present, nothing more.
    #[actix_web::test]
    async fn me_never_exposes_tokens_or_extra_claims() {
        let resp = me(make_auth_with_extra()).await.unwrap();
        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let obj = json.as_object().expect("response must be a JSON object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();

        // Exactly these four keys and no others.
        let expected: std::collections::HashSet<&str> =
            ["sub", "iss", "email", "name"].iter().copied().collect();
        assert_eq!(
            keys, expected,
            "me must expose exactly [sub, iss, email, name], got: {keys:?}"
        );

        // Confirm that neither tokens nor extra claims leaked through.
        for forbidden in ["access_token", "refresh_token", "id_token", "groups", "amr"] {
            assert!(
                !obj.contains_key(forbidden),
                "me must not expose {forbidden}"
            );
        }
    }

    /// Optional standard fields are `null` when absent from the ID token.
    #[actix_web::test]
    async fn me_optional_fields_are_null_when_absent() {
        let resp = me(make_auth_minimal()).await.unwrap();
        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["sub"], "user-xyz");
        assert!(json["iss"].is_null(), "absent iss must be null");
        assert!(json["email"].is_null(), "absent email must be null");
        assert!(json["name"].is_null(), "absent name must be null");
    }
}
