use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde_json::json;
use thiserror::Error;

/// Errors surfaced by the BFF auth flow.
///
/// Kept deliberately small and free of any consumer-crate coupling. Maps to
/// RFC 9457 Problem JSON responses via [`ResponseError`].
#[derive(Error, Debug)]
pub enum BffError {
    /// Client-supplied input was invalid (bad `return_to`, missing code/state,
    /// CSRF check failure, …). The detail string is included in the response.
    #[error("Bad request: {0}")]
    BadRequest(String),
    /// No authenticated session (no `sub` in the session).
    #[error("Unauthorized")]
    Unauthorized,
    /// An unexpected server-side failure (e.g. session write error). The
    /// detail is never exposed to the client — only the generic message.
    #[error("Internal server error")]
    Internal,
}

impl ResponseError for BffError {
    fn status_code(&self) -> StatusCode {
        match self {
            BffError::BadRequest(_) => StatusCode::BAD_REQUEST,
            BffError::Unauthorized => StatusCode::UNAUTHORIZED,
            BffError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let detail = match self {
            BffError::BadRequest(detail) => detail.clone(),
            BffError::Unauthorized => "Unauthorized".to_string(),
            BffError::Internal => "Internal server error".to_string(),
        };

        HttpResponse::build(status)
            .insert_header(("Content-Type", "application/problem+json"))
            .json(json!({
                "type": "about:blank",
                "title": status.canonical_reason().unwrap_or("Error"),
                "status": status.as_u16(),
                "detail": detail,
            }))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;

    fn to_response(e: BffError) -> HttpResponse {
        e.error_response()
    }

    #[test]
    fn status_codes_match_variants() {
        assert_eq!(
            BffError::BadRequest("x".to_string()).status_code(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            BffError::Unauthorized.status_code(),
            actix_web::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            BffError::Internal.status_code(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[actix_web::test]
    async fn problem_json_body_shape() {
        let resp = to_response(BffError::BadRequest("some detail".to_string()));

        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["type"], "about:blank");
        assert!(json["title"].is_string(), "title must be a string");
        assert_eq!(json["status"], 400);
        assert_eq!(json["detail"], "some detail");
    }

    #[actix_web::test]
    async fn internal_error_leaks_no_detail() {
        let resp = to_response(BffError::Internal);
        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // The detail must be a generic message — never a stack trace or
        // internal path.
        let detail = json["detail"].as_str().unwrap();
        assert!(!detail.is_empty(), "detail should not be empty");
        // Must not contain anything that looks like an internal error trace.
        assert!(
            !detail.to_lowercase().contains("panic"),
            "detail must not leak panic info"
        );
        assert_eq!(json["status"], 500);
        // The detail must be exactly the generic message.
        assert_eq!(detail, "Internal server error");
    }
}
