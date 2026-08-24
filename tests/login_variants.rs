//! Integration test exercising [`bff::login_route`] as an *external consumer*
//! would: a real `actix_web::App`, the crate's own [`bff::configure_app_data`],
//! a variant resource registered via `login_route`, and a real (in-process,
//! loopback-only) OIDC discovery round trip through [`bff::OidcRp::discover`].
//!
//! `OidcRp::discover` is the crate's only public constructor for `OidcRp` —
//! there is no test-only escape hatch reachable from outside the crate — so
//! this file runs a tiny hand-rolled HTTP/1.1 server on `127.0.0.1` to answer
//! the two requests discovery makes (the `.well-known/openid-configuration`
//! document and the JWKS document it references). No new dependency is
//! introduced for this: only `std::net`/`std::io`, already available.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use actix_web::{test, web, App};
use actix_web_oidc_bff as bff;
use openidconnect::url::Url;

/// Spawn a minimal OIDC discovery + JWKS server on an ephemeral loopback port
/// and return its issuer URL.
///
/// Runs for the lifetime of the test process (the background thread is never
/// joined) — acceptable for a short-lived test binary; the OS reclaims the
/// socket on exit.
fn spawn_mock_idp() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock IdP listener");
    let addr = listener.local_addr().expect("mock IdP local_addr");
    let issuer = format!("http://{addr}");
    let issuer_for_thread = issuer.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };

            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();

            let body = if path == "/.well-known/openid-configuration" {
                format!(
                    r#"{{"issuer":"{issuer_for_thread}","authorization_endpoint":"{issuer_for_thread}/oauth2/authorize","token_endpoint":"{issuer_for_thread}/oauth2/token","jwks_uri":"{issuer_for_thread}/oauth2/jwks","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}}"#
                )
            } else if path == "/oauth2/jwks" {
                r#"{"keys":[]}"#.to_string()
            } else {
                "{}".to_string()
            };

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    issuer
}

/// Build an `OidcRp` and `OidcBffConfig` pair against the mock IdP.
async fn test_state() -> (Arc<bff::OidcRp>, Arc<bff::OidcBffConfig>) {
    let issuer = spawn_mock_idp();

    let cfg = bff::OidcBffConfig::builder()
        .issuer_url(issuer)
        .client_id("test-client")
        .client_secret("test-secret")
        .redirect_url("https://app.example.com/auth/callback")
        .generate_ephemeral_session_key()
        .build()
        .expect("valid config");

    let oidc_rp = bff::OidcRp::discover(&cfg)
        .await
        .expect("discovery against the mock IdP must succeed");

    (Arc::new(oidc_rp), Arc::new(cfg))
}

/// `login_route` produces a 302 whose `Location` carries the configured extra
/// parameters, correctly URL-encoded, alongside the usual state/nonce/PKCE
/// parameters the plain `/auth/login` route also emits.
#[actix_web::test]
async fn login_route_variant_carries_extra_params_and_pkce() {
    let (oidc_rp, bff_cfg) = test_state().await;

    let passkey =
        bff::ExtraAuthParams::new([("prompt", "create"), ("kc_action", "UPDATE_PASSWORD")])
            .expect("valid extra auth params");

    let app = test::init_service(
        App::new()
            .configure(|cfg| bff::configure_app_data(cfg, oidc_rp.clone(), bff_cfg.clone()))
            .service(web::resource("/auth/passkey").route(bff::login_route(passkey))),
    )
    .await;

    let req = test::TestRequest::get().uri("/auth/passkey").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.status(),
        actix_web::http::StatusCode::FOUND,
        "login_route variant must redirect"
    );

    let location = resp
        .headers()
        .get("Location")
        .expect("Location header must be present")
        .to_str()
        .expect("Location must be valid UTF-8")
        .to_string();
    let url = Url::parse(&location).expect("Location must be a valid URL");
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // Extra params configured on this variant.
    assert_eq!(params["prompt"], "create");
    assert_eq!(params["kc_action"], "UPDATE_PASSWORD");

    // Still a normal OIDC authorization-code + PKCE request.
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["client_id"], "test-client");
    assert_eq!(
        params["redirect_uri"],
        "https://app.example.com/auth/callback"
    );
    assert_eq!(params["code_challenge_method"], "S256");
    assert!(!params["code_challenge"].is_empty());
    assert!(!params["state"].is_empty());
    assert!(!params["nonce"].is_empty());
}

/// A step-up variant routed through a real `App`: `require_auth_within` must
/// survive the `login_route` closure and reach the authorization URL.
///
/// Every other test of this feature calls the crate-internal `login_impl`
/// directly, which bypasses the closure `login_route` builds — this is the only
/// coverage that the requirement makes it through actual routing.
#[actix_web::test]
async fn login_route_variant_carries_a_verified_freshness_requirement() {
    let (oidc_rp, bff_cfg) = test_state().await;

    let step_up = bff::ExtraAuthParams::new([("prompt", "login")])
        .expect("valid extra auth params")
        .require_auth_within(std::time::Duration::from_secs(300))
        .expect("300s is a valid re-authentication age");

    let app = test::init_service(
        App::new()
            .configure(|cfg| bff::configure_app_data(cfg, oidc_rp.clone(), bff_cfg.clone()))
            .service(web::resource("/auth/step-up").route(bff::login_route(step_up))),
    )
    .await;

    let req = test::TestRequest::get().uri("/auth/step-up").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::FOUND);

    let location = resp
        .headers()
        .get("Location")
        .expect("Location header must be present")
        .to_str()
        .expect("Location must be valid UTF-8")
        .to_string();
    let url = Url::parse(&location).expect("Location must be a valid URL");
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    assert_eq!(params["max_age"], "300");
    assert_eq!(params["prompt"], "login");
    assert_eq!(
        url.query_pairs().filter(|(k, _)| k == "max_age").count(),
        1,
        "max_age must appear exactly once, got: {url}"
    );
    // Still a normal PKCE authorization request.
    assert_eq!(params["code_challenge_method"], "S256");
    assert!(!params["nonce"].is_empty());
}

/// The raw parameter is refused, so the verified path is the only way to send
/// `max_age` — checked from outside the crate, where a consumer would hit it.
#[actix_web::test]
async fn raw_max_age_parameter_is_rejected_for_external_callers() {
    let err = bff::ExtraAuthParams::new([("max_age", "300")])
        .expect_err("a raw max_age must be rejected in favour of require_auth_within");
    assert!(
        matches!(err, bff::AuthParamError::ReservedName(_)),
        "expected ReservedName, got: {err}"
    );
}
