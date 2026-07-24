use actix_web::HttpRequest;
use openidconnect::url::{Origin, Url};

use crate::error::BffError;

/// CSRF defense for state-mutating endpoints (POST, PATCH, DELETE) that rely
/// on the session cookie for authentication.
///
/// `allowed_origin` is a full URL whose origin (scheme + host + port) defines
/// the application's public origin — the crate passes
/// [`crate::OidcBffConfig::redirect_url`], which necessarily lives on the
/// app's public origin.
///
/// Checks, in order:
/// 1. `Sec-Fetch-Site` (sent by all modern browsers): `same-origin` passes,
///    any other value fails.
/// 2. `Origin` header: parsed as a URL and compared by origin. Opaque origins
///    (e.g. `null` from sandboxed iframes) are rejected.
/// 3. `Referer` header as a fallback, same comparison.
///
/// Fails closed when none of the headers are present.
pub fn ensure_same_origin(req: &HttpRequest, allowed_origin: &str) -> Result<(), BffError> {
    let expected = tuple_origin(allowed_origin).ok_or(BffError::Internal)?;
    ensure_same_origin_against(req, &expected)
}

/// CSRF check using an already-serialized ASCII origin string (fast path).
///
/// Equivalent to [`ensure_same_origin`] but accepts the pre-computed ASCII
/// origin (as produced by `Origin::Tuple(..).ascii_serialization()`) rather
/// than a full URL. Use [`crate::OidcBffConfig::allowed_origin`] here to
/// avoid re-parsing the redirect URL on every request.
pub(crate) fn ensure_same_origin_against(
    req: &HttpRequest,
    expected: &str,
) -> Result<(), BffError> {
    if let Some(site) = header(req, "sec-fetch-site") {
        return if site.eq_ignore_ascii_case("same-origin") {
            Ok(())
        } else {
            Err(BffError::BadRequest("CSRF check failed".to_string()))
        };
    }

    if let Some(origin) = header(req, "origin") {
        return check_origin(origin, expected);
    }

    if let Some(referer) = header(req, "referer") {
        return check_origin(referer, expected);
    }

    Err(BffError::BadRequest(
        "CSRF check failed: missing Sec-Fetch-Site/Origin/Referer".to_string(),
    ))
}

fn header<'r>(req: &'r HttpRequest, name: &str) -> Option<&'r str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Parse a URL and return its ASCII origin serialization
/// (`scheme://host[:port]`, default ports omitted). Returns `None` for
/// unparsable URLs and opaque origins (`null`, `data:`, …), which must never
/// match anything.
fn tuple_origin(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    match url.origin() {
        origin @ Origin::Tuple(..) => Some(origin.ascii_serialization()),
        Origin::Opaque(_) => None,
    }
}

fn check_origin(raw: &str, expected: &str) -> Result<(), BffError> {
    match tuple_origin(raw) {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(BffError::BadRequest("CSRF check failed".to_string())),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    const APP: &str = "https://app.example.com/auth/callback";

    fn req_with(headers: &[(&str, &str)]) -> HttpRequest {
        let mut req = TestRequest::default();
        for (name, value) in headers {
            req = req.insert_header((*name, *value));
        }
        req.to_http_request()
    }

    #[test]
    fn sec_fetch_site_same_origin_passes() {
        let req = req_with(&[("Sec-Fetch-Site", "same-origin")]);
        assert!(ensure_same_origin(&req, APP).is_ok());
    }

    #[test]
    fn sec_fetch_site_cross_site_fails_even_with_matching_origin() {
        let req = req_with(&[
            ("Sec-Fetch-Site", "cross-site"),
            ("Origin", "https://app.example.com"),
        ]);
        assert!(ensure_same_origin(&req, APP).is_err());
    }

    #[test]
    fn matching_origin_passes() {
        let req = req_with(&[("Origin", "https://app.example.com")]);
        assert!(ensure_same_origin(&req, APP).is_ok());
    }

    #[test]
    fn mismatched_origin_fails() {
        let req = req_with(&[("Origin", "https://evil.example.com")]);
        assert!(ensure_same_origin(&req, APP).is_err());
    }

    #[test]
    fn scheme_downgrade_fails() {
        let req = req_with(&[("Origin", "http://app.example.com")]);
        assert!(ensure_same_origin(&req, APP).is_err());
    }

    #[test]
    fn port_mismatch_fails() {
        let req = req_with(&[("Origin", "https://app.example.com:8443")]);
        assert!(ensure_same_origin(&req, APP).is_err());
    }

    #[test]
    fn null_origin_fails() {
        let req = req_with(&[("Origin", "null")]);
        assert!(ensure_same_origin(&req, APP).is_err());
    }

    #[test]
    fn prefix_confusion_fails() {
        // Naive string matching would let these through.
        let req = req_with(&[("Origin", "https://app.example.com.evil.com")]);
        assert!(ensure_same_origin(&req, APP).is_err());
        let req = req_with(&[("Referer", "https://evil.com/https://app.example.com")]);
        assert!(ensure_same_origin(&req, APP).is_err());
    }

    #[test]
    fn matching_referer_fallback_passes() {
        let req = req_with(&[("Referer", "https://app.example.com/some/page")]);
        assert!(ensure_same_origin(&req, APP).is_ok());
    }

    #[test]
    fn missing_headers_fail_closed() {
        let req = req_with(&[]);
        assert!(ensure_same_origin(&req, APP).is_err());
    }

    #[test]
    fn explicit_default_port_matches() {
        // `https://host:443` and `https://host` are the same origin.
        let req = req_with(&[("Origin", "https://app.example.com:443")]);
        assert!(ensure_same_origin(&req, APP).is_ok());
    }

    // ── S1.6: precomputed origin matches parse path ───────────────────────────

    #[test]
    fn precomputed_origin_matches_parse_path() {
        // Pre-compute the expected origin the same way OidcBffConfig does.
        use openidconnect::url::{Origin, Url};
        let precomputed = match Url::parse(APP).unwrap().origin() {
            origin @ Origin::Tuple(..) => origin.ascii_serialization(),
            Origin::Opaque(_) => panic!("APP must not be opaque"),
        };

        // Verify ensure_same_origin_against produces the same result as
        // ensure_same_origin for every header combination used above.
        let cases: &[(&str, &str, bool)] = &[
            ("Sec-Fetch-Site", "same-origin", true),
            ("Sec-Fetch-Site", "cross-site", false),
            ("Origin", "https://app.example.com", true),
            ("Origin", "https://evil.example.com", false),
            ("Origin", "http://app.example.com", false),
            ("Origin", "null", false),
            ("Referer", "https://app.example.com/some/page", true),
        ];

        for (header_name, header_value, expect_ok) in cases {
            let req = req_with(&[(header_name, header_value)]);
            let via_url = ensure_same_origin(&req, APP);
            let via_precomputed = ensure_same_origin_against(&req, &precomputed);
            assert_eq!(
                via_url.is_ok(),
                via_precomputed.is_ok(),
                "mismatch for {header_name}: {header_value}"
            );
            assert_eq!(
                via_precomputed.is_ok(),
                *expect_ok,
                "{header_name}: {header_value} expected ok={expect_ok}"
            );
        }
    }
}
