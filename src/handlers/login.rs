use std::sync::Arc;
use std::time::Duration;

use actix_session::Session;
use actix_web::{web, HttpResponse};
use openidconnect::{core::CoreAuthenticationFlow, CsrfToken, Nonce, PkceCodeChallenge, Scope};
use serde::Deserialize;
use thiserror::Error;

use crate::config::OidcBffConfig;
use crate::error::BffError;
use crate::oidc::OidcRp;
use crate::param_names::{
    has_control_chars, validate_param_name, ParamNameError, DENIED_AUTH_PARAMS,
};
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

// ── Extra authorization-request parameters ──────────────────────────────────────

/// Maximum number of parameters accepted by [`ExtraAuthParams::new`].
pub const MAX_EXTRA_AUTH_PARAMS: usize = 8;

/// Maximum accepted length, in bytes, for an [`ExtraAuthParams`] value.
pub const MAX_EXTRA_AUTH_VALUE_LEN: usize = 512;

/// Maximum re-authentication age, in seconds, accepted by
/// [`ExtraAuthParams::require_auth_within`] (365 days).
///
/// A value beyond this is far more likely to be a units mistake than an
/// intentional year-long freshness window, and a `max_age` that large asserts
/// nothing anyway. Numerically equal to `config::MAX_TTL_SECS`, which bounds
/// the configured session TTLs for the same reason; they stay separate
/// constants because the validation around them differs — a zero TTL is
/// invalid, a zero `max_age` is meaningful.
pub const MAX_AUTH_AGE_SECS: u64 = 365 * 24 * 3600;

/// Clock-skew allowance, in seconds, applied to the `auth_time` check that
/// backs [`ExtraAuthParams::require_auth_within`].
///
/// This absorbs **clock drift between this server and the provider**, not
/// elapsed time — the age is measured from the authorization request, so the
/// user's time at the provider is already outside the budget. Applied in both
/// directions: the effective window is `max_age + AUTH_TIME_SKEW_SECS`, and an
/// `auth_time` up to this far in the future is tolerated rather than treated as
/// malformed. Without it, two machines a few seconds apart would fail a genuine
/// `Duration::ZERO` re-authentication. Mirrors `LOGIN_AT_FUTURE_SKEW_SECS` in
/// `session_state.rs`.
pub const AUTH_TIME_SKEW_SECS: i64 = 60;

/// Errors returned by [`ExtraAuthParams::new`].
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthParamError {
    /// More than [`MAX_EXTRA_AUTH_PARAMS`] pairs were supplied.
    #[error("at most {max} extra authorization parameters are allowed, got {got}")]
    TooMany {
        /// The configured maximum ([`MAX_EXTRA_AUTH_PARAMS`]).
        max: usize,
        /// How many pairs were actually supplied.
        got: usize,
    },
    /// A name was empty, exceeded the shared parameter-name length limit, or
    /// contained a character outside `[A-Za-z0-9_.-]`.
    #[error("invalid extra authorization parameter name: {0:?}")]
    InvalidName(String),
    /// The name is set by the crate itself, or is otherwise on the crate's
    /// authorize-parameter deny-list, and must never be overridden.
    #[error(
        "extra authorization parameter name {0:?} is reserved: it is set by \
         the crate or must never appear in an authorization request"
    )]
    ReservedName(String),
    /// The same name appeared more than once in one [`ExtraAuthParams::new`]
    /// call.
    #[error("duplicate extra authorization parameter name: {0:?}")]
    DuplicateName(String),
    /// A value exceeded [`MAX_EXTRA_AUTH_VALUE_LEN`] bytes.
    #[error("extra authorization parameter {name:?} value must be at most {max} bytes, got {got}")]
    ValueTooLong {
        /// The parameter name (never the value).
        name: String,
        /// The configured maximum ([`MAX_EXTRA_AUTH_VALUE_LEN`]).
        max: usize,
        /// The value's actual length in bytes.
        got: usize,
    },
    /// A value contained a control character (C0, DEL, or C1). Carries the
    /// parameter **name**, never the value, so a rejected value is never
    /// echoed back into an error message or log line.
    #[error("extra authorization parameter {0:?} value contains a control character")]
    InvalidValue(String),
    /// The [`Duration`] handed to [`ExtraAuthParams::require_auth_within`] was
    /// not a whole number of seconds, or exceeded [`MAX_AUTH_AGE_SECS`].
    #[error("invalid re-authentication age: {0}")]
    InvalidMaxAge(String),
}

/// A fixed set of extra parameters (e.g. `prompt=create`) added to the OIDC
/// authorization request built by a [`login_route`] variant.
///
/// Cheap to clone: the validated pairs are stored once behind an `Arc<[..]>`
/// (one allocation at startup), so every request handled by a [`login_route`]
/// variant only bumps a refcount rather than re-allocating or re-validating.
///
/// # Construction-time only
///
/// The parameters here are meant to be **construction-time (startup) data**
/// — decided once, when the application wires up its routes — and **never
/// derived from an incoming request**. That is the property that keeps
/// `/auth/login` and its [`login_route`] variants free of authorize-request
/// injection: nothing an attacker can influence about a request ever reaches
/// the authorization URL through this path. This is an enforced-by-convention
/// rule, not a type-system guarantee — nothing stops a caller from passing a
/// request-derived string into [`ExtraAuthParams::new`] — so treat it as a
/// hard rule for callers of this API, not as a property the compiler checks
/// for you.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtraAuthParams {
    params: Arc<[(String, String)]>,
    /// Set by [`ExtraAuthParams::require_auth_within`]. Drives both the
    /// `max_age` authorization parameter and the callback's `auth_time` check.
    ///
    /// `u64`, not `i64`, so a negative value is unrepresentable rather than
    /// merely unreachable. The two consumers derive from this one field and
    /// must never disagree — a negative would have been sent as a *positive*
    /// `max_age` on the URL while the callback compared against the negative,
    /// so the crate would request one thing and enforce another.
    max_age_secs: Option<u64>,
}

/// Prints parameter *names* only, with every value redacted.
///
/// Hand-written rather than derived on purpose: [`AuthParamError`] is careful
/// never to carry a value, and a derived `Debug` would undo that the first
/// time a set reached a log line or a panic message. Values are ordinary
/// configuration, not secrets — but `login_hint` and friends carry personal
/// data, and there is no use for the values in a debug dump that justifies
/// the risk.
impl std::fmt::Debug for ExtraAuthParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtraAuthParams")
            .field(
                "params",
                &self
                    .params
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("max_age_secs", &self.max_age_secs)
            .finish()
    }
}

impl ExtraAuthParams {
    /// Validate and construct a fixed set of extra authorization-request
    /// parameters.
    ///
    /// Names are trimmed before validation; values are **not** trimmed (a
    /// value may legitimately be significant whitespace) — an empty value is
    /// allowed (flag-style parameters).
    ///
    /// Rejects, in order:
    /// - more than [`MAX_EXTRA_AUTH_PARAMS`] pairs
    ///   ([`AuthParamError::TooMany`])
    /// - a name that is empty, over [`crate::MAX_PARAM_NAME_LEN`]
    ///   bytes, or outside the `[A-Za-z0-9_.-]` charset
    ///   ([`AuthParamError::InvalidName`])
    /// - a name on the crate's authorize-parameter deny-list — the ones it
    ///   sets itself (`client_id`, `redirect_uri`, `state`, …), plus a few
    ///   others that would break or subvert the flow
    ///   ([`AuthParamError::ReservedName`])
    /// - a name repeated within this call ([`AuthParamError::DuplicateName`])
    /// - a value over [`MAX_EXTRA_AUTH_VALUE_LEN`] bytes
    ///   ([`AuthParamError::ValueTooLong`])
    /// - a value containing a control character (C0 `\u{0}`..=`\u{1f}`, DEL
    ///   `\u{7f}`, or C1 `\u{80}`..=`\u{9f}`) ([`AuthParamError::InvalidValue`])
    ///
    /// Non-ASCII values are otherwise accepted: `openidconnect` percent-
    /// encodes them when building the authorization URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use actix_web_oidc_bff::ExtraAuthParams;
    ///
    /// let params = ExtraAuthParams::new([("prompt", "create")]).unwrap();
    /// assert_eq!(params.len(), 1);
    /// assert!(!params.is_empty());
    /// ```
    pub fn new(
        params: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Result<Self, AuthParamError> {
        let raw: Vec<(String, String)> = params
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();

        if raw.len() > MAX_EXTRA_AUTH_PARAMS {
            return Err(AuthParamError::TooMany {
                max: MAX_EXTRA_AUTH_PARAMS,
                got: raw.len(),
            });
        }

        let mut validated: Vec<(String, String)> = Vec::with_capacity(raw.len());
        for (name, value) in raw {
            let name = name.trim().to_string();

            match validate_param_name(&name, DENIED_AUTH_PARAMS) {
                Ok(()) => {}
                Err(ParamNameError::Denied) => return Err(AuthParamError::ReservedName(name)),
                Err(
                    ParamNameError::Empty
                    | ParamNameError::TooLong
                    | ParamNameError::InvalidCharset,
                ) => return Err(AuthParamError::InvalidName(name)),
            }

            // Case-insensitive, matching the deny-list check above. Identity
            // providers treat names case-sensitively, so `Prompt` and `prompt`
            // really are two parameters — but a caller who writes both has
            // made a mistake worth surfacing rather than silently sending two.
            if validated
                .iter()
                .any(|(existing, _)| existing.eq_ignore_ascii_case(&name))
            {
                return Err(AuthParamError::DuplicateName(name));
            }

            if value.len() > MAX_EXTRA_AUTH_VALUE_LEN {
                return Err(AuthParamError::ValueTooLong {
                    name,
                    max: MAX_EXTRA_AUTH_VALUE_LEN,
                    got: value.len(),
                });
            }

            if has_control_chars(&value) {
                return Err(AuthParamError::InvalidValue(name));
            }

            validated.push((name, value));
        }

        Ok(Self {
            params: validated.into(),
            max_age_secs: None,
        })
    }

    /// Require that the user authenticated at the identity provider within
    /// `max_age` of this login, and **verify it** when the callback returns.
    ///
    /// This is the difference between asking for a fresh authentication and
    /// knowing you got one. It does three things as a unit:
    ///
    /// 1. sends `max_age=<seconds>` on the authorization request, so the
    ///    provider itself enforces the requirement (this is where the actual
    ///    enforcement lives — the user is re-prompted there, not here);
    /// 2. records the requirement in the pre-auth slot, because
    ///    `/auth/callback` is shared by every login route and would otherwise
    ///    have no idea this flow asked for anything;
    /// 3. checks the returned ID token's `auth_time` claim in the callback and
    ///    **rejects the login** — with no session established — if the claim is
    ///    absent or too old.
    ///
    /// Step 3 is what a bare `("max_age", "300")` parameter could not give you:
    /// a provider that ignored the request would be indistinguishable from one
    /// that honoured it. `max_age` is on the crate's authorize-parameter
    /// deny-list precisely so that the unverified form is not reachable — this
    /// method is the only way to send it.
    ///
    /// # Clock skew
    ///
    /// The check allows [`AUTH_TIME_SKEW_SECS`] of slack in both directions.
    /// The authorization round trip takes real time and clocks drift, so a
    /// literal comparison would fail a genuine `Duration::ZERO`
    /// re-authentication. `Duration::ZERO` is still meaningful and still worth
    /// sending: the provider enforces it strictly, and the slack applies only
    /// to this crate's sanity check on the result.
    ///
    /// # Errors
    ///
    /// [`AuthParamError::InvalidMaxAge`] if `max_age` is not a whole number of
    /// seconds (rejected rather than truncated, matching the crate's TTL
    /// handling) or exceeds [`MAX_AUTH_AGE_SECS`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use actix_web_oidc_bff::ExtraAuthParams;
    ///
    /// let step_up = ExtraAuthParams::new([("prompt", "login")])
    ///     .unwrap()
    ///     .require_auth_within(Duration::from_secs(300))
    ///     .unwrap();
    /// assert_eq!(step_up.auth_max_age(), Some(Duration::from_secs(300)));
    /// ```
    pub fn require_auth_within(mut self, max_age: Duration) -> Result<Self, AuthParamError> {
        if max_age.subsec_nanos() != 0 {
            return Err(AuthParamError::InvalidMaxAge(format!(
                "must be a whole number of seconds, got {max_age:?}"
            )));
        }
        let secs = max_age.as_secs();
        if secs > MAX_AUTH_AGE_SECS {
            return Err(AuthParamError::InvalidMaxAge(format!(
                "must not exceed {MAX_AUTH_AGE_SECS} seconds, got {secs}"
            )));
        }
        self.max_age_secs = Some(secs);
        Ok(self)
    }

    /// The re-authentication age set by [`Self::require_auth_within`], if any.
    #[must_use]
    pub fn auth_max_age(&self) -> Option<Duration> {
        self.max_age_secs.map(Duration::from_secs)
    }

    /// Whether this set has no name/value parameters.
    ///
    /// **Reports on the parameter pairs only.** A set carrying just a
    /// [`Self::require_auth_within`] requirement is still "empty" by this
    /// measure, even though it very much changes the authorization request —
    /// so do not use `is_empty()` to decide whether a variant is worth
    /// registering, or you will silently drop the requirement. Check
    /// [`Self::auth_max_age`] as well.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// The number of name/value parameters in this set.
    ///
    /// Counts the parameter pairs only. A set carrying a
    /// [`Self::require_auth_within`] requirement and nothing else has a `len`
    /// of `0` — see [`Self::is_empty`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// The validated `(name, value)` pairs, in insertion order.
    pub(crate) fn as_slice(&self) -> &[(String, String)] {
        &self.params
    }

    /// The re-authentication requirement in whole seconds, for the in-crate
    /// call sites that store it in the pre-auth slot.
    pub(crate) fn max_age_secs(&self) -> Option<i64> {
        // Lossless: `require_auth_within` caps the value at MAX_AUTH_AGE_SECS
        // (365 days), far inside i64. The slot stores i64 to match the rest of
        // the crate's epoch-second arithmetic.
        self.max_age_secs.map(|secs| secs as i64)
    }
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
    login_impl(session, query, oidc, cfg, None).await
}

/// Register a login route variant that adds a fixed set of extra parameters
/// (e.g. `prompt=create`, or a provider-specific action hint) to the
/// authorization request, otherwise behaving exactly like [`login`].
///
/// `params` — see [`ExtraAuthParams`] for the construction-time-only rule
/// that keeps this safe: it must be fixed at startup, never derived from an
/// incoming request.
///
/// Returns a concrete [`actix_web::Route`] rather than exposing a bare
/// closure or the underlying [`actix_web::Handler`] machinery in the public
/// signature, so callers only need `actix_web::web::resource(..).route(..)`:
///
/// ```
/// use actix_web::web;
/// use actix_web_oidc_bff::ExtraAuthParams;
///
/// fn configure(cfg: &mut web::ServiceConfig) {
///     let passkey =
///         ExtraAuthParams::new([("prompt", "create")]).expect("valid extra auth params");
///     cfg.service(web::resource("/auth/passkey").route(actix_web_oidc_bff::login_route(passkey)));
/// }
/// ```
#[must_use]
pub fn login_route(params: ExtraAuthParams) -> actix_web::Route {
    // `actix_web::Handler::Future` carries no lifetime tied to `&self`, so
    // `params` cannot be borrowed into the returned future — it is cloned
    // (an `Arc` refcount bump) and moved in by value on every call.
    web::get().to(
        move |session: Session,
              query: web::Query<LoginQuery>,
              oidc: web::Data<OidcRp>,
              cfg: web::Data<OidcBffConfig>| {
            login_impl(session, query, oidc, cfg, Some(params.clone()))
        },
    )
}

/// Shared implementation behind [`login`] and every [`login_route`] variant.
///
/// `extra` is `None` on the default `/auth/login` path (byte-identical
/// behaviour to before extra params existed) and `Some` for a
/// [`login_route`]-registered variant, in which case its parameters are
/// appended to the authorization request after scopes and before the URL is
/// finalized.
async fn login_impl(
    session: Session,
    query: web::Query<LoginQuery>,
    oidc: web::Data<OidcRp>,
    cfg: web::Data<OidcBffConfig>,
    extra: Option<ExtraAuthParams>,
) -> Result<HttpResponse, BffError> {
    let return_to = query
        .into_inner()
        .return_to
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| cfg.return_to_prefix().to_string());

    if !validate_return_to(&return_to, cfg.return_to_prefix()) {
        return Err(BffError::BadRequest("invalid return_to".to_string()));
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let client = oidc.client().await;

    // Filter `openid` from cfg.scopes: authorize_url auto-adds the openid
    // scope, so passing it again would duplicate it in the request URL.
    let scopes: Vec<Scope> = cfg
        .scopes()
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

    // Extra parameters (login_route variants only) are fixed, construction-
    // time data — never derived from `query`/`session`/the request. See
    // ExtraAuthParams's docs for why that property matters.
    if let Some(extra) = &extra {
        for (name, value) in extra.as_slice() {
            auth_request = auth_request.add_extra_param(name.as_str(), value.as_str());
        }
        // `max_age` goes through openidconnect's typed setter rather than
        // add_extra_param, and is deny-listed for consumers, so exactly one
        // `max_age` can ever appear on the URL. The matching `auth_time`
        // check happens in the callback, keyed off the pre-auth slot below.
        if let Some(max_age) = extra.auth_max_age() {
            auth_request = auth_request.set_max_age(max_age);
        }
    }

    let (auth_url, csrf_out, nonce_out) = auth_request.url();

    let now = chrono::Utc::now().timestamp();

    // Load the existing pre-auth vec, prune expired entries, push the new
    // entry (FIFO-evict at PRE_AUTH_MAX_SLOTS), then write back in one insert.
    let existing = session
        .remove_as::<Vec<PreAuthEntry>>(PRE_AUTH)
        .and_then(Result::ok)
        .unwrap_or_default();

    let pruned = prune_expired(existing, now, cfg.pre_auth_ttl_secs());
    let updated = push_pre_auth(
        pruned,
        PreAuthEntry {
            state: csrf_out.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            nonce: nonce_out.secret().clone(),
            return_to,
            started_at: now,
            // The *only* thing a variant contributes to the slot: a single
            // integer the callback needs to enforce the requirement. Extra
            // parameters themselves must never be stored here — see
            // `PreAuthEntry::max_age_secs` for the size budget that forbids it.
            max_age_secs: extra.as_ref().and_then(ExtraAuthParams::max_age_secs),
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
    use std::time::Duration;

    use super::{
        login, login_route, validate_return_to, AuthParamError, ExtraAuthParams, LoginQuery,
        MAX_AUTH_AGE_SECS, MAX_EXTRA_AUTH_PARAMS, MAX_EXTRA_AUTH_VALUE_LEN, MAX_RETURN_TO_LEN,
    };
    use crate::config::OidcBffConfig;
    use crate::oidc::{BffExtraProviderMetadata, OidcRp};
    use crate::param_names::DENIED_AUTH_PARAMS;
    use crate::session_state::{PreAuthEntry, PRE_AUTH};
    use actix_session::SessionExt;
    use actix_web::{test::TestRequest, web};
    use openidconnect::url::Url;
    use std::collections::{HashMap, HashSet};

    /// Build a minimal `OidcBffConfig` for tests without touching env vars.
    fn test_cfg() -> OidcBffConfig {
        crate::config::test_config_builder()
            .scopes(["openid", "profile", "email"])
            .build()
            .unwrap()
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
            max_age_secs: None,
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

        let cfg = crate::config::test_config_builder()
            .scopes(["openid", "profile", "email"])
            .return_to_prefix("/app")
            .build()
            .unwrap();
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

    // ── ExtraAuthParams / AuthParamError ──────────────────────────────────────

    #[test]
    fn extra_auth_params_new_accepts_a_valid_set() {
        let params = ExtraAuthParams::new([("prompt", "create"), ("kc_action", "UPDATE_PASSWORD")])
            .expect("a valid set must be accepted");
        assert_eq!(params.len(), 2);
        assert!(!params.is_empty());

        let empty = ExtraAuthParams::new(Vec::<(&str, &str)>::new()).expect("empty set is valid");
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn extra_auth_params_rejects_too_many() {
        let pairs: Vec<(String, String)> = (0..=MAX_EXTRA_AUTH_PARAMS)
            .map(|i| (format!("p{i}"), "x".to_string()))
            .collect();
        let got = pairs.len();
        let err = ExtraAuthParams::new(pairs).unwrap_err();
        assert_eq!(
            err,
            AuthParamError::TooMany {
                max: MAX_EXTRA_AUTH_PARAMS,
                got,
            }
        );
    }

    /// Every name on the crate's authorize-parameter deny-list must be
    /// rejected as `ReservedName`, in both its original casing and uppercase
    /// (deny-list matching is ASCII-case-insensitive).
    #[test]
    fn extra_auth_params_rejects_every_denied_name_case_insensitively() {
        for denied in DENIED_AUTH_PARAMS {
            let err = ExtraAuthParams::new([(*denied, "x")]).unwrap_err();
            assert_eq!(
                err,
                AuthParamError::ReservedName((*denied).to_string()),
                "{denied:?} must be rejected as ReservedName"
            );

            let upper = denied.to_ascii_uppercase();
            let err = ExtraAuthParams::new([(upper.as_str(), "x")]).unwrap_err();
            assert_eq!(
                err,
                AuthParamError::ReservedName(upper.clone()),
                "{upper:?} must be rejected as ReservedName"
            );
        }
    }

    #[test]
    fn extra_auth_params_rejects_invalid_names() {
        assert!(matches!(
            ExtraAuthParams::new([("", "x")]).unwrap_err(),
            AuthParamError::InvalidName(_)
        ));

        let long_name = "a".repeat(crate::param_names::MAX_PARAM_NAME_LEN + 1);
        assert!(matches!(
            ExtraAuthParams::new([(long_name.as_str(), "x")]).unwrap_err(),
            AuthParamError::InvalidName(_)
        ));

        assert!(matches!(
            ExtraAuthParams::new([("bad name", "x")]).unwrap_err(),
            AuthParamError::InvalidName(_)
        ));
    }

    #[test]
    fn extra_auth_params_rejects_duplicate_name() {
        let err = ExtraAuthParams::new([("prompt", "a"), ("prompt", "b")]).unwrap_err();
        assert_eq!(err, AuthParamError::DuplicateName("prompt".to_string()));
    }

    /// Duplicate detection is case-insensitive, matching the deny-list check.
    /// IdPs treat parameter names case-sensitively, so `Prompt` and `prompt`
    /// really would be sent as two parameters — a caller who writes both has
    /// made a mistake, and the two checks disagreeing about case would be
    /// confusing on its own.
    #[test]
    fn extra_auth_params_rejects_duplicate_name_case_insensitively() {
        let err = ExtraAuthParams::new([("prompt", "a"), ("PROMPT", "b")]).unwrap_err();
        assert_eq!(err, AuthParamError::DuplicateName("PROMPT".to_string()));
    }

    // ── require_auth_within ──────────────────────────────────────────────────

    #[test]
    fn require_auth_within_accepts_whole_seconds_including_zero() {
        for secs in [0_u64, 1, 300, MAX_AUTH_AGE_SECS] {
            let params = ExtraAuthParams::new([("prompt", "login")])
                .unwrap()
                .require_auth_within(Duration::from_secs(secs))
                .unwrap_or_else(|e| panic!("{secs}s must be accepted, got: {e}"));
            assert_eq!(params.auth_max_age(), Some(Duration::from_secs(secs)));
        }
    }

    /// Unset by default — `/auth/login` and plain variants must carry no
    /// requirement, which is what keeps their behaviour unchanged.
    #[test]
    fn require_auth_within_is_unset_by_default() {
        let params = ExtraAuthParams::new([("prompt", "login")]).unwrap();
        assert_eq!(params.auth_max_age(), None);
        assert_eq!(params.max_age_secs(), None);
    }

    /// Sub-second durations are rejected rather than truncated, matching how
    /// the config builder treats TTLs. Truncating `from_millis(500)` to `0`
    /// would silently convert "within half a second" into "must reauthenticate
    /// right now" — a different requirement than the caller wrote.
    #[test]
    fn require_auth_within_rejects_sub_second_durations() {
        let err = ExtraAuthParams::new([("prompt", "login")])
            .unwrap()
            .require_auth_within(Duration::from_millis(500))
            .unwrap_err();
        assert!(
            matches!(err, AuthParamError::InvalidMaxAge(_)),
            "expected InvalidMaxAge, got: {err}"
        );
    }

    #[test]
    fn require_auth_within_rejects_ages_over_the_cap() {
        let err = ExtraAuthParams::new([("prompt", "login")])
            .unwrap()
            .require_auth_within(Duration::from_secs(MAX_AUTH_AGE_SECS + 1))
            .unwrap_err();
        assert!(
            matches!(err, AuthParamError::InvalidMaxAge(_)),
            "expected InvalidMaxAge, got: {err}"
        );
    }

    /// `max_age` must not be settable as a raw parameter: the hand-rolled form
    /// sends the request but verifies nothing, which is exactly the false
    /// assurance `require_auth_within` exists to prevent.
    #[test]
    fn max_age_is_not_settable_as_a_raw_parameter() {
        for name in ["max_age", "MAX_AGE", "Max_Age"] {
            let err = ExtraAuthParams::new([(name, "300")]).unwrap_err();
            assert!(
                matches!(err, AuthParamError::ReservedName(_)),
                "{name:?} must be reserved, got: {err}"
            );
        }
    }

    /// A requirement set on a variant must reach the authorization URL as
    /// exactly one `max_age` parameter, in seconds.
    #[actix_web::test]
    async fn require_auth_within_emits_max_age_once() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let params = ExtraAuthParams::new([("prompt", "login")])
            .unwrap()
            .require_auth_within(Duration::from_secs(300))
            .unwrap();

        let resp = super::login_impl(
            session,
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(params),
        )
        .await
        .expect("login must succeed");

        let (url, query) = location_params(&resp);
        assert_eq!(query["max_age"], "300");
        assert_eq!(
            url.query_pairs().filter(|(k, _)| k == "max_age").count(),
            1,
            "max_age must appear exactly once, got: {url}"
        );
    }

    /// The URL and the slot must carry the **same** number. They are derived
    /// through two different accessors (`auth_max_age` for the request,
    /// `max_age_secs` for the slot), and the entire guarantee rests on them
    /// agreeing: a mismatch means the crate asks the provider for one window
    /// and then enforces a different one.
    #[actix_web::test]
    async fn emitted_max_age_and_recorded_requirement_agree() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let params = ExtraAuthParams::new([("prompt", "login")])
            .unwrap()
            .require_auth_within(Duration::from_secs(137))
            .unwrap();

        let resp = super::login_impl(
            session.clone(),
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(params),
        )
        .await
        .expect("login must succeed");

        let (_, query) = location_params(&resp);
        let entries: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();
        assert_eq!(
            query["max_age"].parse::<i64>().unwrap(),
            entries[0].max_age_secs.unwrap(),
            "the max_age sent to the provider and the requirement stored for \
             the callback must be the same value"
        );
    }

    /// A requirement with **no** extra parameters still has to work: this is
    /// the shape most exposed to a future "skip the block when the set is
    /// empty" optimisation, which would drop `max_age` from the URL while
    /// still recording the requirement — turning every such login into a 400.
    #[actix_web::test]
    async fn require_auth_within_works_without_any_extra_params() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let params = ExtraAuthParams::new(Vec::<(&str, &str)>::new())
            .unwrap()
            .require_auth_within(Duration::from_secs(300))
            .unwrap();
        assert!(
            params.is_empty(),
            "is_empty() reports on the parameter pairs, which are genuinely empty here"
        );

        let resp = super::login_impl(
            session.clone(),
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(params),
        )
        .await
        .expect("login must succeed");

        let (_, query) = location_params(&resp);
        assert_eq!(query["max_age"], "300");
        let entries: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();
        assert_eq!(entries[0].max_age_secs, Some(300));
    }

    /// The requirement must land in the pre-auth slot — the callback is shared
    /// by every login route and has no other way to learn about it.
    #[actix_web::test]
    async fn require_auth_within_is_recorded_in_the_pre_auth_slot() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let params = ExtraAuthParams::new([("prompt", "login")])
            .unwrap()
            .require_auth_within(Duration::from_secs(300))
            .unwrap();

        super::login_impl(
            session.clone(),
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(params),
        )
        .await
        .expect("login must succeed");

        let entries: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();
        assert_eq!(entries[0].max_age_secs, Some(300));
    }

    /// Plain `/auth/login`, and a variant that did not ask for freshness, must
    /// leave the slot's requirement unset and emit no `max_age`.
    #[actix_web::test]
    async fn plain_login_records_no_auth_age_requirement() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let resp = login(
            session.clone(),
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await
        .expect("login must succeed");

        let (_, query) = location_params(&resp);
        assert!(
            !query.contains_key("max_age"),
            "plain login must not send max_age"
        );

        let entries: Vec<PreAuthEntry> = session.get(PRE_AUTH).unwrap().unwrap();
        assert_eq!(entries[0].max_age_secs, None);
    }

    /// `Debug` must print names only. `AuthParamError` deliberately never
    /// carries a value; a derived `Debug` on the params themselves would undo
    /// that the first time a set reached a log line or a panic message
    /// (`login_hint`, for instance, carries personal data).
    #[test]
    fn extra_auth_params_debug_redacts_values() {
        let params = ExtraAuthParams::new([("login_hint", "person@example.com")]).unwrap();
        let rendered = format!("{params:?}");
        assert!(
            rendered.contains("login_hint"),
            "the name must still be visible, got: {rendered}"
        );
        assert!(
            !rendered.contains("person@example.com"),
            "the value must never appear in Debug output, got: {rendered}"
        );
    }

    #[test]
    fn extra_auth_params_rejects_overlong_value() {
        let long_value = "a".repeat(MAX_EXTRA_AUTH_VALUE_LEN + 1);
        let err = ExtraAuthParams::new([("prompt", long_value.as_str())]).unwrap_err();
        assert_eq!(
            err,
            AuthParamError::ValueTooLong {
                name: "prompt".to_string(),
                max: MAX_EXTRA_AUTH_VALUE_LEN,
                got: long_value.len(),
            }
        );

        // Exactly at the cap is fine.
        let max_value = "a".repeat(MAX_EXTRA_AUTH_VALUE_LEN);
        assert!(ExtraAuthParams::new([("prompt", max_value.as_str())]).is_ok());
    }

    #[test]
    fn extra_auth_params_rejects_control_characters_in_value() {
        for bad in ["a\r\nb", "a\nb", "a\tb", "a\0b", "a\u{7f}b", "a\u{9f}b"] {
            let err = ExtraAuthParams::new([("prompt", bad)]).unwrap_err();
            assert_eq!(
                err,
                AuthParamError::InvalidValue("prompt".to_string()),
                "{bad:?} must be rejected as InvalidValue"
            );
        }
    }

    #[test]
    fn extra_auth_params_accepts_empty_and_non_ascii_value() {
        let params = ExtraAuthParams::new([("prompt", ""), ("locale", "caf\u{e9}")])
            .expect("an empty value and a non-ascii value must both be accepted");
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn login_route_constructs_a_route() {
        // Smoke test: the public factory builds successfully. End-to-end
        // behaviour when actually dispatched through an App is covered by
        // tests/login_variants.rs.
        let params = ExtraAuthParams::new([("prompt", "create")]).unwrap();
        let _route: actix_web::Route = login_route(params);
    }

    // ── S4: extra params reach the authorization request ─────────────────────

    /// Deny-list completeness: build real authorization URLs, parse their
    /// query-parameter NAMES, and assert every one of them appears in
    /// `DENIED_AUTH_PARAMS`. This is what fails the day someone adds another
    /// crate-set parameter to the authorize request (e.g. a new PKCE or OIDC
    /// extension field) without also updating the deny-list — without this
    /// test, `ExtraAuthParams::new` would silently start accepting a name that
    /// can override a crate-set parameter.
    ///
    /// Both paths are covered, because they emit different sets: plain
    /// `/auth/login`, and a variant using every crate-set-parameter feature a
    /// variant has (`require_auth_within`, which adds `max_age`). A variant's
    /// *consumer-supplied* names are deliberately excluded from the assertion —
    /// those are the ones that are supposed to be settable.
    #[actix_web::test]
    async fn deny_list_covers_every_crate_set_authorize_param() {
        // Plain login.
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
        let (_, plain) = location_params(&resp);

        // A variant exercising every crate-set parameter a variant can add.
        // `consumer_set` is the one name we supply ourselves, so it is
        // excluded below — everything else on this URL came from the crate.
        let consumer_set = "prompt";
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let resp = super::login_impl(
            session,
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(
                ExtraAuthParams::new([(consumer_set, "login")])
                    .unwrap()
                    .require_auth_within(Duration::from_secs(300))
                    .unwrap(),
            ),
        )
        .await
        .expect("variant login must succeed");
        let (_, variant) = location_params(&resp);

        assert!(
            variant.contains_key("max_age"),
            "the variant URL must actually exercise max_age, got: {:?}",
            variant.keys().collect::<Vec<_>>()
        );

        for name in plain.keys().chain(variant.keys()) {
            if name == consumer_set {
                continue;
            }
            assert!(
                DENIED_AUTH_PARAMS.contains(&name.as_str()),
                "authorize parameter {name:?} is emitted by the crate but missing from \
                 DENIED_AUTH_PARAMS — an ExtraAuthParams caller could then override it"
            );
        }
    }

    /// Extra params appear in the `Location` query, correctly URL-encoded:
    /// a value containing a space, `&`, `=`, and a non-ASCII character.
    #[actix_web::test]
    async fn login_impl_appends_extra_params_url_encoded() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let extra = ExtraAuthParams::new([
            ("prompt", "create"),
            ("kc_action", "a value with spaces"),
            ("weird", "a&b=c"),
            ("locale", "caf\u{e9}"),
        ])
        .unwrap();

        let resp = super::login_impl(
            session,
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(extra),
        )
        .await
        .expect("login_impl with extra params must succeed");

        let (url, params) = location_params(&resp);
        assert_eq!(params["prompt"], "create");
        assert_eq!(params["kc_action"], "a value with spaces");
        assert_eq!(params["weird"], "a&b=c");
        assert_eq!(params["locale"], "caf\u{e9}");

        // The raw query string is application/x-www-form-urlencoded (space
        // becomes `+`); `&` and `=` inside a value must be percent-encoded so
        // they cannot be mistaken for query-string delimiters.
        let raw_query = url.query().expect("Location must carry a query string");
        assert!(
            raw_query.contains("kc_action=a+value+with+spaces"),
            "space must be encoded as '+', got: {raw_query}"
        );
        assert!(
            !raw_query.contains("weird=a&b=c"),
            "an unencoded & from a value must never appear raw in the query string, got: \
             {raw_query}"
        );
        assert!(
            raw_query.contains("weird=a%26b%3Dc"),
            "& and = inside a value must be percent-encoded, got: {raw_query}"
        );
        assert!(
            raw_query.contains("locale=caf%C3%A9"),
            "non-ASCII must be percent-encoded, got: {raw_query}"
        );
    }

    /// No-regression pin: `login_impl` with an empty `ExtraAuthParams` (the
    /// shape `login_route(ExtraAuthParams::new([])?)` produces) and plain
    /// `login` must expose the exact same set of query-parameter names, and
    /// every crate-set parameter must appear exactly once in both.
    #[actix_web::test]
    async fn login_route_with_empty_extra_matches_plain_login() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let resp_plain = login(
            session,
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
        )
        .await
        .expect("plain login must succeed");

        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let empty = ExtraAuthParams::new(Vec::<(&str, &str)>::new()).unwrap();
        let resp_variant = super::login_impl(
            session,
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(empty),
        )
        .await
        .expect("login_impl with an empty extra set must succeed");

        let (plain_url, plain_params) = location_params(&resp_plain);
        let (variant_url, variant_params) = location_params(&resp_variant);

        let plain_names: HashSet<&str> = plain_params.keys().map(String::as_str).collect();
        let variant_names: HashSet<&str> = variant_params.keys().map(String::as_str).collect();
        assert_eq!(
            plain_names, variant_names,
            "an empty ExtraAuthParams set must not change the emitted parameter names"
        );

        for name in [
            "client_id",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
        ] {
            let plain_count = plain_url.query_pairs().filter(|(k, _)| k == name).count();
            let variant_count = variant_url.query_pairs().filter(|(k, _)| k == name).count();
            assert_eq!(
                plain_count, 1,
                "{name} must appear exactly once in plain login"
            );
            assert_eq!(
                variant_count, 1,
                "{name} must appear exactly once in the empty-extra variant"
            );
        }
    }

    /// With extra params configured, the stored `PreAuthEntry` must be
    /// unchanged in shape (still exactly state/pkce_verifier/nonce/return_to/
    /// started_at) and must contain none of the extra param names or values —
    /// extra params are authorization-request-only and must never leak into
    /// session storage. `state`/`nonce` in the stored entry must still match
    /// the ones in the `Location` header.
    #[actix_web::test]
    async fn login_impl_does_not_leak_extra_params_into_pre_auth_entry() {
        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        let extra = ExtraAuthParams::new([
            ("prompt", "create"),
            ("kc_action", "super-secret-action-value"),
        ])
        .unwrap();

        let resp = super::login_impl(
            session.clone(),
            web::Query(LoginQuery { return_to: None }),
            test_rp(),
            web::Data::new(test_cfg()),
            Some(extra),
        )
        .await
        .expect("login_impl with extra params must succeed");

        let (_, params) = location_params(&resp);

        let entries: Vec<PreAuthEntry> = session
            .get(PRE_AUTH)
            .unwrap()
            .expect("pre-auth vec must be stored");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];

        // state/nonce still match the Location.
        assert_eq!(entry.state, params["state"]);
        assert_eq!(entry.nonce, params["nonce"]);

        // None of the extra param names/values leak into the stored entry —
        // serialize it and scan for the extra strings rather than trusting
        // the struct's field list alone.
        let serialized = serde_json::to_string(entry).expect("PreAuthEntry must serialize");
        assert!(
            !serialized.contains("kc_action"),
            "extra param name must not appear in the stored pre-auth entry"
        );
        assert!(
            !serialized.contains("super-secret-action-value"),
            "extra param value must not appear in the stored pre-auth entry"
        );
        assert!(
            !serialized.contains("\"prompt\""),
            "extra param name must not appear in the stored pre-auth entry"
        );
    }
}
