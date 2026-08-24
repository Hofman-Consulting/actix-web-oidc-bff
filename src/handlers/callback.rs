use std::borrow::Cow;

use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse};
use openidconnect::{
    core::CoreJsonWebKey, url::form_urlencoded, AuthorizationCode, IdTokenVerifier, Nonce,
    OAuth2TokenResponse, PkceCodeVerifier, TokenResponse,
};
use serde::Deserialize;

use crate::config::OidcBffConfig;
use crate::error::BffError;
use crate::handlers::login::AUTH_TIME_SKEW_SECS;
use crate::oidc::{BffClient, OidcRp};
use crate::session_state::{
    insert_or_internal, prune_expired, take_matching, ACCESS_TOKEN, CLAIM_KEYS, EMAIL, ID_TOKEN,
    ISS, LOGIN_AT, NAME, POST_AUTH_SCRUB_KEYS, PRE_AUTH, REFRESH_TOKEN, SUB,
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

/// Maximum accepted length, in bytes, for a single passed-through parameter
/// *value* (not name — names are already capped by
/// [`crate::MAX_PARAM_NAME_LEN`]). Bounds both the memory a single hostile
/// value can occupy and how much of the aggregate budget below one value can
/// consume.
///
/// This bounds the value as **decoded**. The aggregate budget below is spent
/// in *encoded* bytes, which percent-encoding can inflate up to threefold.
pub const MAX_PASSTHROUGH_VALUE_LEN: usize = 256;

/// Maximum total bytes of *encoded* `name=value` pairs appended to
/// `return_to`. `MAX_PASSTHROUGH_PARAMS` (8) times a near-cap value each
/// would otherwise be able to push the `Location` header past the ~2 KB
/// some proxies enforce.
///
/// A pair that would not fit is skipped and the next one is still tried, so
/// one fat value cannot starve the short ones behind it.
pub const MAX_PASSTHROUGH_TOTAL_LEN: usize = 1024;

/// Final belt-and-braces bound on the fully composed redirect target
/// (`return_to` plus whatever passthrough survived).
///
/// `handlers::login::MAX_RETURN_TO_LEN` (512) plus
/// [`MAX_PASSTHROUGH_TOTAL_LEN`] (1024) plus a separator already caps the
/// composed value at 1537, so this bound is **not reachable** through the
/// normal path — like the rest of [`is_safe_composed_redirect`], it is a
/// backstop against a future change to either of those caps, not a constraint
/// that does work today.
const MAX_COMPOSED_REDIRECT_LEN: usize = 2048;

/// A passthrough value is dropped — never appended, name logged, value
/// never logged — when it is oversized or contains anything that has no
/// legitimate place in a query-string value being reflected into a
/// redirect target.
///
/// The U+FFFD check is the one easy to miss: `form_urlencoded::parse`
/// decodes percent-encoded bytes as UTF-8 *lossily*, so a byte sequence
/// like `%FF` (not valid UTF-8) silently becomes the replacement character
/// rather than an error. A bare control-character scan would let that
/// through; checking for U+FFFD explicitly catches it.
fn is_droppable_passthrough_value(value: &str) -> bool {
    value.len() > MAX_PASSTHROUGH_VALUE_LEN
        || crate::param_names::has_control_chars(value)
        || value.contains('\u{fffd}')
}

/// Enforce a login variant's re-authentication requirement against the
/// validated ID token's `auth_time` claim.
///
/// Called only when the matched pre-auth slot carries a `max_age_secs`, i.e.
/// the flow was started by a route built with
/// [`crate::ExtraAuthParams::require_auth_within`].
///
/// **Fails closed on an absent claim.** OIDC Core makes `auth_time` REQUIRED in
/// the ID token when the request carried `max_age`, so a provider that omits it
/// has not honoured the request — which is precisely the silent-downgrade case
/// this check exists to catch. Accepting the token because the evidence is
/// missing would defeat the entire feature.
///
/// # What the age is measured against
///
/// `started_at` — when this flow's authorization request was made — and **not**
/// callback arrival. That is deliberate, and it is the only correct reference
/// point: the provider evaluates `max_age` when it receives the authorization
/// request, so everything the user does at the provider *afterwards* (consent,
/// account selection, and in particular the very Application-Initiated Action
/// a step-up variant asked for) happens once the provider's clock has already
/// stopped.
///
/// Measuring from callback arrival would charge that time to the budget and
/// reject logins the provider honoured perfectly — a user who authenticates
/// promptly and then spends four minutes on the change-password form would fail
/// a five-minute requirement. Total flow duration is already bounded, and
/// bounded independently, by the pre-auth slot TTL.
///
/// [`AUTH_TIME_SKEW_SECS`] of slack applies in both directions, because
/// provider clocks drift: a marginally-too-old `auth_time` is tolerated, and so
/// is one slightly in the future.
fn verify_auth_freshness(
    auth_time: Option<chrono::DateTime<chrono::Utc>>,
    max_age_secs: i64,
    started_at: i64,
    now: i64,
) -> Result<(), BffError> {
    let Some(auth_time) = auth_time else {
        log::warn!(
            "login required re-authentication within {max_age_secs}s but the ID token \
             carries no auth_time claim; the provider did not honour max_age"
        );
        return Err(BffError::BadRequest(
            "Re-authentication required".to_string(),
        ));
    };
    let auth_ts = auth_time.timestamp();

    // How stale the authentication already was when this flow's authorization
    // request was made. Negative just means the user authenticated after
    // starting the flow — the ordinary case.
    let age_at_request = started_at.saturating_sub(auth_ts);

    if age_at_request > max_age_secs.saturating_add(AUTH_TIME_SKEW_SECS) {
        log::warn!(
            "login required re-authentication within {max_age_secs}s but auth_time was \
             already {age_at_request}s old when the authorization request was made"
        );
        return Err(BffError::BadRequest(
            "Re-authentication required".to_string(),
        ));
    }

    // An auth_time meaningfully in the future is drift at best, malformed or
    // hostile at worst. Compare against real time, not the flow start.
    let ahead = auth_ts.saturating_sub(now);
    if ahead > AUTH_TIME_SKEW_SECS {
        log::warn!(
            "ID token auth_time is {ahead}s in the future, beyond the \
             {AUTH_TIME_SKEW_SECS}s skew allowance"
        );
        return Err(BffError::BadRequest(
            "Re-authentication required".to_string(),
        ));
    }

    Ok(())
}

/// Append allowlisted query parameters from the callback request onto
/// `return_to`, producing the final post-login redirect target.
///
/// `allow` is `cfg.callback_passthrough_params()` — names are already
/// validated (charset, length, dedup, deny-list) at config `build()` time;
/// this function does not re-validate names, only values.
///
/// See the call site for the "allowlist empty → skip entirely" fast path;
/// this function itself still handles an empty `allow` correctly (returns
/// `return_to` borrowed) so it stays independently testable and correct if
/// ever called directly.
fn append_passthrough<'a>(return_to: &'a str, query: &str, allow: &[String]) -> Cow<'a, str> {
    if allow.is_empty() {
        return Cow::Borrowed(return_to);
    }

    // Single pass over the callback's query pairs. For each pair, a linear
    // scan against `allow` (at most MAX_PASSTHROUGH_PARAMS = 8 entries) is
    // cheaper than building and hashing into a map at this size. Only the
    // *first* occurrence of each allowlisted name is kept: a poisoned first
    // copy must drop the parameter entirely, so an attacker appending a
    // second, clean copy of the same name cannot override the outcome.
    // `selected[idx]` distinguishes three states: `None` = not seen yet,
    // `Some(None)` = seen but unusable (dropped), `Some(Some(v))` = usable.
    // The middle state is what makes "first occurrence wins" a security
    // property rather than a preference — once a name has been seen, a later
    // copy can never revive it.
    #[allow(clippy::option_option)]
    let mut selected: Vec<Option<Option<String>>> = vec![None; allow.len()];
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let Some(idx) = allow.iter().position(|allowed| allowed == name.as_ref()) else {
            continue;
        };
        if selected[idx].is_some() {
            continue; // already decided by the first occurrence.
        }
        // Check the borrowed value against the cap *before* `into_owned()`, so
        // an oversized value is never allocated at all.
        selected[idx] = Some(if is_droppable_passthrough_value(&value) {
            // Never log the value itself, only which parameter was dropped.
            log::warn!("callback passthrough parameter {name:?} dropped: invalid value");
            None
        } else {
            Some(value.into_owned())
        });
    }

    // Split at the first `#` so the fragment is never touched by the query
    // splice: `/app#tab` must not become `/app#tab?x=1`.
    let (before_fragment, fragment) = match return_to.find('#') {
        Some(i) => (&return_to[..i], &return_to[i..]),
        None => (return_to, ""),
    };
    let has_query = before_fragment.contains('?');
    let existing_query = before_fragment.split_once('?').map_or("", |(_, q)| q);

    // `return_to` is allowed to carry its own `?query`. A name already present
    // there is skipped rather than appended: `validate_return_to` permits `?`
    // in `return_to`, and `?tab=1&tab=<idp-value>` is a parameter-pollution
    // primitive — many routers/frameworks read the last occurrence of a
    // repeated name. Collected once rather than re-parsed per allowlist entry.
    let existing_names: Vec<String> = form_urlencoded::parse(existing_query.as_bytes())
        .map(|(name, _)| name.into_owned())
        .collect();

    let mut appended = String::new();
    for (idx, name) in allow.iter().enumerate() {
        // `None` = absent from this request; `Some(None)` = present but
        // dropped as invalid (already warned about above).
        let Some(Some(value)) = selected[idx].take() else {
            continue;
        };
        if existing_names.iter().any(|existing| existing == name) {
            continue;
        }

        // Percent-encode this single pair so names/values (and therefore any
        // CR/LF a hostile value contained) cannot survive into the `Location`
        // header, then enforce the aggregate cap before committing it.
        let encoded_pair = form_urlencoded::Serializer::new(String::new())
            .append_pair(name, &value)
            .finish();
        let joiner_len = usize::from(!appended.is_empty());
        if appended.len() + joiner_len + encoded_pair.len() > MAX_PASSTHROUGH_TOTAL_LEN {
            // Skip this pair and keep going rather than stopping: the budget
            // is spent in *encoded* bytes, which percent-encoding can inflate
            // threefold, so one fat non-ASCII value must not be able to starve
            // every short parameter behind it.
            log::warn!(
                "callback passthrough parameter {name:?} dropped: \
                 would exceed the {MAX_PASSTHROUGH_TOTAL_LEN}-byte total cap"
            );
            continue;
        }
        if !appended.is_empty() {
            appended.push('&');
        }
        appended.push_str(&encoded_pair);
    }

    if appended.is_empty() {
        return Cow::Borrowed(return_to);
    }

    let separator = if has_query { '&' } else { '?' };
    Cow::Owned(format!("{before_fragment}{separator}{appended}{fragment}"))
}

/// Final defence-in-depth guard applied to the fully composed redirect
/// target right before it is written into the `Location` header.
///
/// By construction this should be unreachable: `return_to` already passed
/// [`crate::validate_return_to`] at `/auth/login` time, allowlisted names
/// are restricted to `[A-Za-z0-9_.-]`, and every appended value is
/// percent-encoded by [`append_passthrough`]. The check exists anyway —
/// the same redundant-but-cheap defence-in-depth style `store.rs` uses for
/// its expiry re-check on `load()`. Login must never fail because of a
/// cosmetic feedback parameter, so the caller degrades to a known-good target
/// rather than erroring the request.
///
/// The rules mirror [`crate::validate_return_to`] rather than a weaker
/// prefix-only variant: `//`, `\` and `:/` are rejected **anywhere** in the
/// string, not just at the front. The encoder makes all three unreachable
/// today — which is exactly why this must not quietly assume it.
fn is_safe_composed_redirect(target: &str) -> bool {
    target.len() <= MAX_COMPOSED_REDIRECT_LEN
        && target.starts_with('/')
        && !target.contains("//")
        && !target.contains('\\')
        && !target.contains(":/")
        && target.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// `GET /auth/callback` — exchanges the authorization code for tokens,
/// validates the ID token, and establishes the authenticated session.
///
/// See the numbered comments in the implementation for the full ordering of
/// security-relevant steps (pre-auth slot consumption, session renewal,
/// scrubbing, claim persistence, token storage). On success, redirects to the
/// `return_to` path stored in the matched pre-auth slot.
pub async fn callback(
    req: HttpRequest,
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
    let entries = prune_expired(entries, now, cfg.pre_auth_ttl_secs());

    // (2) IdP signalled an error. If a `state` is present consume only the
    // matching pre-auth slot and write the remainder back; if no `state` is
    // present the vec is written back untouched. Never reflect the
    // (attacker-suppliable) error strings into the response.
    if let Some(error) = query.error {
        // `{:?}` (not `{}`) for error_description like the neighbouring
        // `error` value: both are attacker-suppliable, and raw CR/LF in
        // either could otherwise forge log lines.
        log::warn!(
            "OIDC callback returned error {error:?}: {:?}",
            query.error_description.as_deref().unwrap_or("")
        );
        let preserved = if let Some(ref state) = query.state {
            let (_, rest) = take_matching(entries, state);
            rest
        } else {
            entries
        };
        insert_or_internal(&session, PRE_AUTH, &preserved)?;
        // Passthrough deliberately does not apply here: the error path
        // returns a 400 with no redirect, so there is no `Location` to
        // append feedback parameters onto.
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
            // `{:?}`, not `{}`: this error's Display can embed the token
            // endpoint's own `error_description` verbatim, so CR/LF in a
            // hostile or misbehaving IdP's response body would otherwise
            // forge log lines. Same reasoning as the step-(2) warning above.
            log::error!("OIDC token exchange failed: {e:?}");
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
            // `{:?}` — see the token-exchange error above; claim values from
            // the (not yet trusted) token can reach this message.
            log::warn!("ID token validation failed: {e:?}");
            if oidc.force_refresh_for_retry().await {
                let fresh_client = oidc.client().await;
                let fresh_verifier = bff_verifier(&fresh_client);
                id_token.claims(&fresh_verifier, &nonce).map_err(|e2| {
                    log::warn!("ID token validation failed after JWKS refresh: {e2:?}");
                    BffError::BadRequest("ID token validation failed".to_string())
                })?
            } else {
                return Err(BffError::BadRequest(
                    "ID token validation failed".to_string(),
                ));
            }
        }
    };

    // (8) Enforce the login variant's re-authentication requirement, if it
    // asked for one. This MUST stay ahead of `session.renew()` and every
    // session write below: a login that fails either check must leave no
    // authenticated session behind, otherwise a rejected step-up would still
    // hand the caller a usable session.
    if let Some(max_age_secs) = entry.max_age_secs {
        verify_auth_freshness(
            claims.auth_time(),
            max_age_secs,
            entry.started_at,
            chrono::Utc::now().timestamp(),
        )?;

        // A step-up must re-authenticate *the same user*. The provider's
        // re-prompt commonly offers account switching, so without this a route
        // that reads as "confirm it's you before changing your password" can be
        // satisfied by signing in as somebody else — and the session silently
        // becomes that account's, while the application resumes at a
        // `return_to` it chose for the original subject.
        //
        // Read before `renew()`: `renew()` keeps the state, but this must
        // happen before anything is overwritten either way. Only enforced when
        // a requirement was set — a plain login route is how you switch
        // accounts, and this must not break that.
        if let Some(previous_sub) = session.get::<String>(SUB).ok().flatten() {
            if previous_sub != claims.subject().as_str() {
                log::warn!(
                    "re-authentication completed as a different subject than the session \
                     held; rejecting rather than silently switching accounts"
                );
                return Err(BffError::BadRequest(
                    "Re-authentication required".to_string(),
                ));
            }
        }
    }

    // SENSITIVE: capture the raw (validated) id_token so logout can use it
    // as the `id_token_hint` for RP-initiated end-session.
    let id_token_raw = id_token.to_string();
    let return_to = entry.return_to;

    // (9) Rotate session key to prevent session fixation.
    session.renew();

    // (10) Stamp the absolute session start time. This MUST happen
    // immediately after `renew()` and before any of the fallible inserts
    // below: `Auth::extract` (and `DbSessionStore`) treat `sub` present
    // without `login_at` as a dead session, so no later failure path may
    // leave the two out of sync. Deliberately not scrubbed by
    // `POST_AUTH_SCRUB_KEYS` — every successful login overwrites it anyway.
    insert_or_internal(&session, LOGIN_AT, &chrono::Utc::now().timestamp())?;

    // (11) Scrub keys from any previous login. `renew()` keeps the session
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

    // (12) Standard claims.
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

    // (13) Configurable extra claims. Serialize the entire claims struct to a
    // flat JSON object and pick from it by name. This handles typed fields
    // (`amr`, `acr`, `preferred_username`) and `additional_claims` uniformly
    // without special-casing — the fixture test gates this approach.
    let claims_json = serde_json::to_value(claims).map_err(|e| {
        log::error!("Failed to serialise ID-token claims: {e}");
        BffError::Internal
    })?;

    let mut persisted_keys: Vec<String> = Vec::new();
    for (name, value) in select_claims(&claims_json, cfg.persist_claims()) {
        insert_or_internal(&session, name, &value)?;
        persisted_keys.push(name.to_string());
    }
    insert_or_internal(&session, CLAIM_KEYS, &persisted_keys)?;

    // (14) Server-side token storage. SENSITIVE: the session store must be
    // encrypted at rest (or use DbSessionStore). Step 10 scrubbed any stale
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

    // (15) Callback parameter passthrough, success path only, after every
    // session write above. Existing consumers (empty allowlist) skip the
    // query-string parse and every allocation it would imply — matching the
    // "precompute / don't do per-request work" discipline `cfg.allowed_origin`
    // already uses elsewhere in this crate. (They still pay the one byte-scan
    // in the guard below, which is deliberate: it is the check, not an
    // optimisation.)
    let allow = cfg.callback_passthrough_params();
    let location = if allow.is_empty() {
        Cow::Borrowed(return_to.as_str())
    } else {
        append_passthrough(&return_to, req.query_string(), allow)
    };

    // Defence-in-depth only — see `is_safe_composed_redirect` doc comment.
    // The fallback is the configured prefix, not `return_to`: the only way the
    // guard can trip is if `return_to` itself is unsafe, so degrading to it
    // would emit precisely the value the check just rejected. The prefix is
    // validated by `build()` and is therefore always a safe target.
    let location = if is_safe_composed_redirect(&location) {
        location
    } else {
        log::warn!(
            "composed callback redirect failed the final safety guard; \
             falling back to the configured return_to prefix"
        );
        Cow::Borrowed(cfg.return_to_prefix())
    };

    Ok(HttpResponse::Found()
        .append_header(("Location", location.as_ref()))
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

    // ── append_passthrough ───────────────────────────────────────────────────

    /// Build a raw (already percent-encoded) query string from `name=value`
    /// pairs, the way a real callback request's query string would look.
    fn raw_query(pairs: &[(&str, &str)]) -> String {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            ser.append_pair(k, v);
        }
        ser.finish()
    }

    #[test]
    fn empty_allowlist_returns_input_borrowed() {
        let result = append_passthrough("/app?x=1", "y=2", &[]);
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "empty allowlist must not allocate"
        );
        assert_eq!(result, "/app?x=1");
    }

    #[test]
    fn appends_onto_path_with_no_query() {
        let allow = vec!["x".to_string()];
        let result = append_passthrough("/app", &raw_query(&[("x", "1")]), &allow);
        assert_eq!(result, "/app?x=1");
    }

    #[test]
    fn appends_onto_path_with_existing_query() {
        let allow = vec!["x".to_string()];
        let result = append_passthrough("/app?a=1", &raw_query(&[("x", "1")]), &allow);
        assert_eq!(result, "/app?a=1&x=1");
    }

    /// `return_to` ending in a bare `?` already "contains ?", so the `&`
    /// branch of the separator rule applies even though there is nothing
    /// before it — a leading `&` before the first real pair is a harmless,
    /// well-formed empty pair to any query-string parser (this crate's own
    /// `form_urlencoded::parse` included).
    #[test]
    fn appends_after_bare_trailing_question_mark() {
        let allow = vec!["x".to_string()];
        let result = append_passthrough("/app?", &raw_query(&[("x", "1")]), &allow);
        assert_eq!(result, "/app?&x=1");
    }

    #[test]
    fn fragment_is_preserved_after_query() {
        let allow = vec!["x".to_string()];
        let result = append_passthrough("/app#tab", &raw_query(&[("x", "1")]), &allow);
        assert_eq!(result, "/app?x=1#tab");
    }

    /// The only case where both branches interact: `return_to` already has a
    /// query (so the `&` separator is used) *and* a fragment (so the splice
    /// must still land before the `#`).
    #[test]
    fn existing_query_and_fragment_together() {
        let allow = vec!["x".to_string()];
        let result = append_passthrough("/app?a=1#tab", &raw_query(&[("x", "1")]), &allow);
        assert_eq!(result, "/app?a=1&x=1#tab");
    }

    /// A `#` inside the query part must not be mistaken for the fragment
    /// delimiter twice — the split is on the *first* `#` only.
    #[test]
    fn only_the_first_fragment_delimiter_splits() {
        let allow = vec!["x".to_string()];
        let result = append_passthrough("/app#a#b", &raw_query(&[("x", "1")]), &allow);
        assert_eq!(result, "/app?x=1#a#b");
    }

    #[test]
    fn value_needing_escaping_is_percent_encoded() {
        let allow = vec!["y".to_string()];
        let raw_value = "a b&c=d é";
        let result = append_passthrough("/app", &raw_query(&[("y", raw_value)]), &allow);
        // Round-trip through the same decoder the crate uses elsewhere to
        // confirm the escaped value decodes back to the original.
        let decoded: std::collections::HashMap<_, _> =
            form_urlencoded::parse(result.split_once('?').unwrap().1.as_bytes()).collect();
        assert_eq!(decoded["y"], raw_value);
        // And the raw separators must not survive unescaped.
        assert!(!result.contains("a b&c=d"));
    }

    #[test]
    fn allowlisted_param_absent_from_query_is_skipped() {
        let allow = vec!["missing".to_string()];
        let result = append_passthrough("/app", &raw_query(&[("other", "1")]), &allow);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "/app");
    }

    #[test]
    fn control_character_value_dropped_siblings_survive() {
        let allow = vec!["a".to_string(), "b".to_string()];
        // `%07` decodes to a BEL control character.
        let query = "a=x%07y&b=ok";
        let result = append_passthrough("/app", query, &allow);
        assert!(!result.contains("a="), "poisoned value must be dropped");
        assert!(result.contains("b=ok"), "sibling value must survive");
    }

    #[test]
    fn overlong_value_is_dropped() {
        let allow = vec!["a".to_string(), "b".to_string()];
        let long_value = "x".repeat(MAX_PASSTHROUGH_VALUE_LEN + 1);
        let query = raw_query(&[("a", &long_value), ("b", "ok")]);
        let result = append_passthrough("/app", &query, &allow);
        assert!(!result.contains("a="), "overlong value must be dropped");
        assert!(result.contains("b=ok"));
    }

    /// `%FF` is not valid UTF-8; `form_urlencoded::parse` decodes it lossily
    /// to U+FFFD rather than erroring, so the explicit U+FFFD check is what
    /// catches it.
    #[test]
    fn replacement_character_value_is_dropped() {
        let allow = vec!["a".to_string(), "b".to_string()];
        let query = "a=%FF&b=ok";
        let result = append_passthrough("/app", query, &allow);
        assert!(!result.contains("a="), "U+FFFD value must be dropped");
        assert!(result.contains("b=ok"));
    }

    #[test]
    fn first_occurrence_wins_when_repeated() {
        let allow = vec!["a".to_string()];
        let query = "a=first&a=second";
        let result = append_passthrough("/app", query, &allow);
        assert_eq!(result, "/app?a=first");
    }

    /// The security-relevant half of "first occurrence wins": a poisoned first
    /// copy drops the parameter outright, so appending a second, clean copy
    /// cannot revive it. Without this, anyone able to add a query parameter to
    /// the callback URL could override the value the IdP actually sent.
    #[test]
    fn poisoned_first_occurrence_is_not_revived_by_a_clean_second() {
        let allow = vec!["a".to_string()];
        let result = append_passthrough("/app", "a=%07bad&a=clean", &allow);
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "a dropped first occurrence must not be replaced by a later copy"
        );
        assert_eq!(result, "/app");
    }

    /// An over-length first copy must behave the same way — the drop decision
    /// is made once, on first sight, regardless of *why* it was dropped.
    #[test]
    fn oversized_first_occurrence_is_not_revived_by_a_clean_second() {
        let allow = vec!["a".to_string()];
        let long = "x".repeat(MAX_PASSTHROUGH_VALUE_LEN + 1);
        let query = format!("{}&a=clean", raw_query(&[("a", &long)]));
        let result = append_passthrough("/app", &query, &allow);
        assert_eq!(result, "/app");
    }

    #[test]
    fn name_already_in_return_to_query_is_skipped() {
        let allow = vec!["a".to_string()];
        let result = append_passthrough("/app?a=1", &raw_query(&[("a", "2")]), &allow);
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "no append when the name is already present"
        );
        assert_eq!(result, "/app?a=1");
    }

    #[test]
    fn non_allowlisted_parameter_is_ignored() {
        let allow = vec!["a".to_string()];
        let result = append_passthrough("/app", &raw_query(&[("z", "1")]), &allow);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "/app");
    }

    /// Four single-character-name values of exactly `MAX_PASSTHROUGH_VALUE_LEN`
    /// bytes push the running total past `MAX_PASSTHROUGH_TOTAL_LEN` on the
    /// fourth pair (258 + 1 + 258 + 1 + 258 = 776, then + 1 + 258 = 1035 >
    /// 1024): the first three are appended, the fourth is not.
    #[test]
    fn aggregate_cap_drops_the_pair_that_does_not_fit() {
        let allow = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let value = "x".repeat(MAX_PASSTHROUGH_VALUE_LEN);
        let query = raw_query(&[("a", &value), ("b", &value), ("c", &value), ("d", &value)]);
        let result = append_passthrough("/app", &query, &allow);
        assert!(result.contains("a="));
        assert!(result.contains("b="));
        assert!(result.contains("c="));
        assert!(!result.contains("d="), "cap must drop the fourth pair");
    }

    /// The cap **skips** an oversized pair and keeps going; it does not stop
    /// appending. The budget is spent in *encoded* bytes, which percent-
    /// encoding can inflate threefold, so a `break` here would let one fat
    /// non-ASCII value starve every short parameter behind it.
    ///
    /// Four near-cap values followed by a tiny one: with `break` the tiny
    /// parameter would be lost, with `continue` it survives.
    #[test]
    fn aggregate_cap_still_appends_a_later_pair_that_fits() {
        let allow = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];
        let value = "x".repeat(MAX_PASSTHROUGH_VALUE_LEN);
        let query = raw_query(&[
            ("a", &value),
            ("b", &value),
            ("c", &value),
            ("d", &value),
            ("e", "x"),
        ]);
        let result = append_passthrough("/app", &query, &allow);
        assert!(!result.contains("d="), "the oversized pair must be dropped");
        assert!(
            result.contains("e=x"),
            "a later pair that fits must still be appended, got: {result}"
        );
    }

    /// Open-redirect property: whatever hostile string an attacker puts into
    /// an allowlisted value, the composed result stays anchored to the
    /// original `return_to` path and carries none of the raw open-redirect
    /// primitives this crate defends against elsewhere
    /// (`validate_return_to` in `handlers/login.rs`).
    #[test]
    fn open_redirect_property_hostile_values_stay_contained() {
        let hostile_values = [
            "//evil.com",
            "\r\nSet-Cookie: x=y",
            "https://evil.com",
            "/\\evil.com",
            "#",
            "?",
            "%00",
        ];
        let allow = vec!["note".to_string()];
        for value in hostile_values {
            let query = raw_query(&[("note", value)]);
            let result = append_passthrough("/app", &query, &allow);
            assert!(
                result.starts_with("/app"),
                "result must stay anchored to return_to, got: {result:?} for input {value:?}"
            );
            assert!(!result.contains('\r'), "got: {result:?}");
            assert!(!result.contains('\n'), "got: {result:?}");
            assert!(!result.contains("//"), "got: {result:?}");
            assert!(!result.contains(":/"), "got: {result:?}");
            assert!(
                !result["/app".len()..].contains('/'),
                "no unencoded '/' beyond the return_to path, got: {result:?}"
            );
        }
    }

    // ── verify_auth_freshness ─────────────────────────────────────────────────

    /// A fixed reference point. Every one of these tests supplies both `now`
    /// and `started_at` explicitly rather than reading the clock twice — two
    /// independent `Utc::now()` calls can straddle a second boundary and make
    /// a boundary assertion off by one, which is exactly the sort of flake a
    /// timing test must not have.
    const T0: i64 = 1_700_000_000;

    /// An `auth_time` `offset_secs` before the authorization request.
    fn auth_before_request(offset_secs: i64) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::from_timestamp(T0 - offset_secs, 0)
    }

    /// `started_at = T0`, and the callback arrives `elapsed` seconds later.
    fn check(
        auth_time: Option<chrono::DateTime<chrono::Utc>>,
        max_age: i64,
        elapsed: i64,
    ) -> Result<(), BffError> {
        verify_auth_freshness(auth_time, max_age, T0, T0 + elapsed)
    }

    #[test]
    fn auth_freshness_accepts_a_recent_authentication() {
        assert!(check(auth_before_request(10), 300, 1).is_ok());
        assert!(check(auth_before_request(0), 300, 1).is_ok());
        assert!(check(auth_before_request(299), 300, 1).is_ok());
    }

    #[test]
    fn auth_freshness_rejects_a_stale_authentication() {
        let err = check(auth_before_request(3600), 300, 1)
            .expect_err("an hour-old auth_time must fail a 300s requirement");
        assert!(
            matches!(err, BffError::BadRequest(_)),
            "expected BadRequest, got: {err:?}"
        );
    }

    /// Fails **closed**: a provider that omits `auth_time` has not honoured
    /// `max_age`, which is the exact silent-downgrade case this check exists
    /// to catch. Accepting the token for lack of evidence would defeat the
    /// whole feature.
    #[test]
    fn auth_freshness_rejects_a_missing_auth_time_claim() {
        let err = check(None, 300, 1).expect_err("a missing auth_time must fail closed");
        assert!(
            matches!(err, BffError::BadRequest(_)),
            "expected BadRequest, got: {err:?}"
        );
    }

    /// The budget is measured from the **authorization request**, not from
    /// callback arrival — the provider's `max_age` clock stops when it receives
    /// the request, so whatever the user does at the provider afterwards (the
    /// consent screen, or the very Application-Initiated Action a step-up
    /// variant asked for) must not be charged against it.
    ///
    /// Without this, the crate's own worked example — "change your password,
    /// re-authenticated within 5 minutes" — rejects any user who takes more
    /// than five minutes to fill in the password form, despite the provider
    /// having honoured the request perfectly.
    #[test]
    fn auth_freshness_does_not_charge_time_spent_at_the_provider() {
        // Authenticated right at the request, callback arrives 9 minutes later
        // (well inside the 600s pre-auth slot TTL that bounds the flow).
        assert!(
            check(auth_before_request(0), 300, 540).is_ok(),
            "time spent at the provider after authenticating must not count \
             against the freshness budget"
        );
        // And a genuinely stale authentication is still caught regardless of
        // how quickly the callback came back.
        assert!(check(auth_before_request(1_000), 300, 0).is_err());
    }

    /// `Duration::ZERO` is meaningful — the provider enforces it strictly —
    /// and the skew allowance is what absorbs clock drift between the two
    /// machines rather than any elapsed time.
    #[test]
    fn auth_freshness_zero_max_age_tolerates_clock_drift() {
        assert!(
            check(auth_before_request(5), 0, 1).is_ok(),
            "5s of drift must satisfy max_age=0 within the skew allowance"
        );
        assert!(
            check(auth_before_request(AUTH_TIME_SKEW_SECS + 1), 0, 1).is_err(),
            "beyond the skew allowance it must still fail"
        );
    }

    /// The effective window is exactly `max_age + AUTH_TIME_SKEW_SECS`, pinned
    /// on both sides of the boundary so an off-by-one cannot pass.
    #[test]
    fn auth_freshness_applies_the_skew_allowance_at_the_boundary() {
        assert!(
            check(auth_before_request(300 + AUTH_TIME_SKEW_SECS), 300, 0).is_ok(),
            "exactly at the window must be accepted"
        );
        assert!(
            check(auth_before_request(300 + AUTH_TIME_SKEW_SECS + 1), 300, 0).is_err(),
            "one second past the window must be rejected"
        );
    }

    /// A slightly future `auth_time` is drift and is tolerated; a wildly
    /// future one is malformed or hostile and is not. Both sides of the
    /// boundary are pinned.
    #[test]
    fn auth_freshness_tolerates_small_clock_drift_but_not_large() {
        // `auth_time` ahead of the callback's clock by exactly the allowance.
        assert!(
            check(auth_before_request(-AUTH_TIME_SKEW_SECS), 300, 0).is_ok(),
            "exactly the skew allowance of forward drift must be tolerated"
        );
        assert!(
            check(auth_before_request(-(AUTH_TIME_SKEW_SECS + 1)), 300, 0).is_err(),
            "one second past the allowance must be rejected"
        );
    }

    // ── The final composed-redirect guard ─────────────────────────────────────

    /// The guard must accept what the normal path actually produces.
    #[test]
    fn composed_redirect_guard_accepts_normal_targets() {
        for ok in [
            "/",
            "/app",
            "/app/settings?kc_action_status=success",
            "/app?a=1&b=2#tab",
            "/app?v=a%2Fb",
        ] {
            assert!(
                is_safe_composed_redirect(ok),
                "{ok:?} must pass the composed-redirect guard"
            );
        }
    }

    /// The guard is unreachable through the normal path — `return_to` is
    /// validated at login and every appended value is percent-encoded — so it
    /// is tested directly. These are the shapes it exists to stop, and they
    /// mirror `validate_return_to`'s rules: `//`, `\` and `:/` are rejected
    /// **anywhere**, not just at the start.
    #[test]
    fn composed_redirect_guard_rejects_open_redirect_shapes() {
        for bad in [
            "//evil.com",
            "https://evil.com",
            "/app?next=https:/evil.com",
            "/app?next=//evil.com",
            "/app\\evil",
            "/app\r\nSet-Cookie: x=y",
            "/app\u{e9}",
            "app",
            "",
        ] {
            assert!(
                !is_safe_composed_redirect(bad),
                "{bad:?} must be rejected by the composed-redirect guard"
            );
        }
        let too_long = format!("/{}", "a".repeat(MAX_COMPOSED_REDIRECT_LEN));
        assert!(!is_safe_composed_redirect(&too_long));
    }

    // ── S4.2: handler error paths (network-free — return before token exchange) ─

    use crate::config::OidcBffConfig;
    use crate::oidc::{BffExtraProviderMetadata, OidcRp};
    use crate::session_state::PreAuthEntry;
    use actix_session::SessionExt;
    use actix_web::{test::TestRequest, web};

    fn test_cfg() -> OidcBffConfig {
        crate::config::test_config()
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
            max_age_secs: None,
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
            req.clone(),
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

    /// Passthrough is **success-path only**. An IdP `error=` response returns
    /// 400 and never redirects, so no attacker-suppliable value can ever be
    /// appended to a URL — even with a matching parameter present on the
    /// callback request and that name allowlisted.
    ///
    /// Today this holds structurally (the error branch returns `Err` long
    /// before step 14), but "unify the two paths so errors redirect too" is an
    /// obvious-looking refactor, and it would turn the passthrough into an
    /// open redirect gadget driven by the error path. This test is what fails
    /// if anyone tries it.
    #[actix_web::test]
    async fn error_path_never_appends_passthrough_params() {
        let req = TestRequest::with_uri(
            "/auth/callback?error=access_denied&state=state_a&kc_action_status=evil",
        )
        .to_http_request();
        let session = req.get_session();
        let now = chrono::Utc::now().timestamp();
        session
            .insert(PRE_AUTH, vec![seed_entry("state_a", now)])
            .unwrap();

        let cfg = crate::config::test_config_builder()
            .callback_passthrough_params(["kc_action_status"])
            .build()
            .unwrap();

        let result = callback(
            req.clone(),
            session.clone(),
            query(None, Some("state_a"), Some("access_denied")),
            test_rp(),
            web::Data::new(cfg),
        )
        .await;

        let err = result.expect_err("an IdP error must not produce a redirect");
        assert!(
            matches!(err, BffError::BadRequest(_)),
            "expected BadRequest, got: {err:?}"
        );
        // `BffError` renders as problem+json with no Location header at all —
        // there is no redirect for a passthrough value to ride on.
        let resp = actix_web::ResponseError::error_response(&err);
        assert!(
            resp.headers().get("Location").is_none(),
            "the error path must not emit a Location header"
        );
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
            req.clone(),
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
            req.clone(),
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
                req.clone(),
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
            req.clone(),
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
            req.clone(),
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

    // ── Full success path against a local mock IdP (LOGIN_AT stamping) ─────────
    //
    // Unlike the error-path tests above, exercising a successful callback
    // requires an actual token exchange and a signature-verifiable ID token.
    // We stand up a throwaway actix-web server on a random local port to play
    // the IdP's token endpoint, and sign a real ID token with a locally
    // generated (test-only, never used anywhere else) RSA key whose public
    // half is embedded directly into the provider metadata — no JWKS fetch
    // needed.

    use crate::oidc::BffProviderMetadata;
    use openidconnect::core::{
        CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    };
    use openidconnect::{
        Audience, IdToken, IssuerUrl, JsonWebKeyId, PrivateSigningKey, StandardClaims,
        SubjectIdentifier,
    };

    /// Test-only RSA private key (PKCS#1 PEM), generated solely for signing
    /// mock ID tokens in this test module. Never used outside `#[cfg(test)]`.
    const TEST_RSA_PRIV_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsz4+Sdz8g9PKOq0EVcEdOcJsrera0dwKK+Bijsp5TkSH9BtO
2r8MvovVUlKhmS4zLqI/J2Ls4F0hs2YIQczOG/YhOBTTi9aSewtTmmpFgTjzKnT5
guDyS32YBAiawUB0pFDmCk6TcQGtGORqafj0e2rkHO0iyjCIreFvMO2mNmom0NcR
j4XqGaX8Vah75J0edLyAFC+McJNiehYm/wh4DZ4ekAcicblbWHxZlDazNyXoELlI
/tVQvEvecygJo2wmHZ7vE5UAoIXLFzYKj6jtSk13LtJOX1Z2KqKJxKapFWLfy+NV
wM1d2IAcytNj3dFuKpnPSdPlYNQ1AhAmmR3lPQIDAQABAoIBAA7mdbceL7+ls4H9
MAcQ7qUGjJJIm7gmWpIbLRZBrqPa/pJEUuHMT/rnFOyrAdQCCy8tPaLAjoB4PXz0
Vmth4yBf7ZMD6DIPvE2OO3zyqKR9X3mAD93ZZUrxPdnX/UVjXk7qirUAozEZupH/
Kvl0QJ6h3CSrceDs9++8dcnTd6W+OX8BwG/0+jhwzLf3PVaCcvHOXGWHBMkcBRCw
Axy6a2yb4FNEsU1PIBWRQ4e5COPkuK6sJSWoL54HiTunLnGbFq8PAkbFt/YilAVD
+7/71jJKJx4olcRDjo6SRHFYUIg5YA5KN0tSpZLsyRw7PX5Z9Rl9AyFjQu/TlZ9G
XMIwqQECgYEA7TbN563DGhzEGqlskPupWf7dBkZOJnuR0lWqZ5JW8/ZCd/19uFGd
XfaBQXfumdk+k+NoLWyty9cP6sjY/wOdLu0jXBWf1/uRNLBsrLtBd+sUvp7agypg
fsWjE1L6whXJRtRpUdiITlskrRk1dExZXD2lM5PFaL0XL+Dp0YH29XUCgYEAwXAo
A9V6KHMnj0+SgWIB++V1jStS0RZsyQ+Bv5PnpBcD1Hl9i90tB0/fmcF4kE0ZfJ3d
hX67YgTZ3zdCKWmaswwgihMCYBle3vYC1Y+hb3IARGOfpQLmzBBgrwmx1C1fUS6h
OWc9H8SrsW5/yAWnRgQpxYNiHQLqQAOkE0dkD6kCgYEA1mdZllTM6jYj3cFSunxs
pkYgugIjss6vj4AUZEa1xw3HKDL7RfSmmv4p9+WRyIa98+dwCtaXA43f+iMNVvmK
QZbfBeUZs5rStN/dagZadywIdP6ZnEJaM1spOVcgBPqyEQ3+H5bqJIBm1vnZAcPc
ZO3m+oZOwItggMr2K4Ifl90CgYAh1ABbc0jSrBi9+jdvwvj/2UfucSYhhJ9vpfOV
0kLPMmssDDcFb5+BSNmcpPX1nlYXse/ceaZBZQHJBHvgjCROrY8/NkXTEnzB1xn1
yRF9UN11GEsB63j7NN4Dnlln9qtVoib1x/UrihRQijd0fnCbUP0RGoHc+vaGTVyz
NmfsSQKBgQCh6J8neOGXDyQlOQpw/EOJr98IsQgXoFAuKsxGcdFLb4QRJDMgqPL1
xIT9GuH/OOSm+Ic7emF7/ZxN5kMlbZAHMBzlbHxImfVeJeXJwx++AvJUM5obtU2l
bE8H4uDeKnYSVMjktEb+/QCQ0Q0hS5Qkv916Ur9vaLCzFZllE/e49w==
-----END RSA PRIVATE KEY-----";

    fn test_signing_key() -> CoreRsaPrivateSigningKey {
        CoreRsaPrivateSigningKey::from_pem(
            TEST_RSA_PRIV_KEY_PEM,
            Some(JsonWebKeyId::new("test-key".to_string())),
        )
        .expect("test RSA key must parse")
    }

    /// Build provider metadata pointing at a local mock token endpoint, with
    /// the test signing key's public half embedded directly (bypassing a
    /// JWKS-URI fetch entirely).
    fn metadata_for_mock_idp(token_endpoint: &str) -> BffProviderMetadata {
        let raw = json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
            "token_endpoint": token_endpoint,
            "jwks_uri": "https://idp.example.com/oauth2/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        });
        let metadata: BffProviderMetadata =
            serde_json::from_value(raw).expect("mock IdP metadata must be valid");
        metadata.set_jwks(CoreJsonWebKeySet::new(vec![
            test_signing_key().as_verification_key()
        ]))
    }

    /// Sign a minimal, valid ID token matching `OidcRp::for_tests`' client
    /// ("test-client") and the mock IdP's issuer, carrying `nonce` and,
    /// optionally, `auth_time` — the claim an IdP emits when the consumer
    /// sent `prompt=login`.
    fn sign_id_token_with_auth_time(
        nonce: &str,
        auth_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> String {
        let now = chrono::Utc::now();
        let mut claims = IdTokenClaims::<BffAdditionalClaims, CoreGenderClaim>::new(
            IssuerUrl::new("https://idp.example.com".to_string()).unwrap(),
            vec![Audience::new("test-client".to_string())],
            now + chrono::Duration::hours(1),
            now,
            StandardClaims::new(SubjectIdentifier::new("test-user".to_string())),
            BffAdditionalClaims::default(),
        )
        .set_nonce(Some(Nonce::new(nonce.to_string())));
        if let Some(auth_time) = auth_time {
            claims = claims.set_auth_time(Some(auth_time));
        }

        let id_token: IdToken<
            BffAdditionalClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        > = IdToken::new(
            claims,
            &test_signing_key(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("id token must sign");
        id_token.to_string()
    }

    /// Sign a minimal, valid ID token matching `OidcRp::for_tests`' client
    /// ("test-client") and the mock IdP's issuer, carrying `nonce`.
    fn sign_id_token(nonce: &str) -> String {
        sign_id_token_with_auth_time(nonce, None)
    }

    /// Start a throwaway HTTP server on a random local port that always
    /// answers `POST /token` with a fixed token response body. Returns the
    /// server's base URL.
    async fn start_mock_token_endpoint(id_token_jwt: String) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind must succeed");
        let addr = listener.local_addr().expect("local_addr must succeed");
        let body = json!({
            "access_token": "test-access-token",
            "token_type": "bearer",
            "id_token": id_token_jwt,
        });
        let server = actix_web::HttpServer::new(move || {
            let body = body.clone();
            actix_web::App::new().route(
                "/token",
                web::post().to(move || {
                    let body = body.clone();
                    async move { HttpResponse::Ok().json(body) }
                }),
            )
        })
        .listen(listener)
        .expect("listen must succeed")
        .run();
        actix_web::rt::spawn(server);
        format!("http://{addr}")
    }

    /// After a full, successful callback (real token exchange + ID-token
    /// signature verification against the mock IdP) the session must contain
    /// `LOGIN_AT` stamped with a timestamp taken during the call.
    #[actix_web::test]
    async fn successful_callback_stamps_login_at() {
        let nonce = "mock-nonce";
        let jwt = sign_id_token(nonce);
        let base_url = start_mock_token_endpoint(jwt).await;
        let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let started_at = chrono::Utc::now().timestamp();
        session
            .insert(
                PRE_AUTH,
                vec![PreAuthEntry {
                    state: "state-1".to_string(),
                    pkce_verifier: "verifier".to_string(),
                    nonce: nonce.to_string(),
                    return_to: "/".to_string(),
                    started_at,
                    max_age_secs: None,
                }],
            )
            .unwrap();

        let before = chrono::Utc::now().timestamp();
        let result = callback(
            req.clone(),
            session.clone(),
            query(Some("test-code"), Some("state-1"), None),
            rp,
            web::Data::new(test_cfg()),
        )
        .await;
        let after = chrono::Utc::now().timestamp();

        result.expect("callback must succeed against the mock IdP");

        let login_at: i64 = session
            .get(LOGIN_AT)
            .expect("session read must not error")
            .expect("LOGIN_AT must be present after a successful callback");
        assert!(
            (before..=after).contains(&login_at),
            "login_at {login_at} must fall within the call window [{before}, {after}]"
        );
    }

    /// Extract the `Location` header of a callback response as a `&str`.
    fn location_of(resp: &HttpResponse) -> &str {
        resp.headers()
            .get("Location")
            .expect("Location header must be present")
            .to_str()
            .expect("Location header must be a valid string")
    }

    /// With an allowlisted `callback_passthrough_params` entry configured,
    /// a successful callback must carry that parameter through onto the
    /// post-login redirect's `Location`.
    #[actix_web::test]
    async fn successful_callback_appends_allowlisted_passthrough_params() {
        let nonce = "mock-nonce-passthrough";
        let jwt = sign_id_token(nonce);
        let base_url = start_mock_token_endpoint(jwt).await;
        let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let cfg = crate::config::test_config_builder()
            .callback_passthrough_params(["kc_action_status"])
            .build()
            .unwrap();

        let req = TestRequest::get()
            .uri("/auth/callback?code=test-code&state=state-1&kc_action_status=success")
            .to_http_request();
        let session = req.get_session();
        let started_at = chrono::Utc::now().timestamp();
        session
            .insert(
                PRE_AUTH,
                vec![PreAuthEntry {
                    state: "state-1".to_string(),
                    pkce_verifier: "verifier".to_string(),
                    nonce: nonce.to_string(),
                    return_to: "/dashboard".to_string(),
                    started_at,
                    max_age_secs: None,
                }],
            )
            .unwrap();

        let result = callback(
            req.clone(),
            session.clone(),
            web::Query::from_query(req.query_string()).expect("query must parse"),
            rp,
            web::Data::new(cfg),
        )
        .await
        .expect("callback must succeed against the mock IdP");

        assert_eq!(location_of(&result), "/dashboard?kc_action_status=success");
    }

    /// No-regression pin: with the default (empty) allowlist, the `Location`
    /// must be exactly `return_to`, byte for byte — existing consumers who
    /// have not opted into passthrough must see zero change in behaviour,
    /// even when the request happens to carry query parameters that would
    /// otherwise be eligible.
    #[actix_web::test]
    async fn successful_callback_empty_allowlist_location_is_exactly_return_to() {
        let nonce = "mock-nonce-no-passthrough";
        let jwt = sign_id_token(nonce);
        let base_url = start_mock_token_endpoint(jwt).await;
        let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let req = TestRequest::get()
            .uri("/auth/callback?code=test-code&state=state-1&kc_action_status=success")
            .to_http_request();
        let session = req.get_session();
        let started_at = chrono::Utc::now().timestamp();
        let return_to = "/dashboard?already=here";
        session
            .insert(
                PRE_AUTH,
                vec![PreAuthEntry {
                    state: "state-1".to_string(),
                    pkce_verifier: "verifier".to_string(),
                    nonce: nonce.to_string(),
                    return_to: return_to.to_string(),
                    started_at,
                    max_age_secs: None,
                }],
            )
            .unwrap();

        let result = callback(
            req.clone(),
            session.clone(),
            web::Query::from_query(req.query_string()).expect("query must parse"),
            rp,
            web::Data::new(test_cfg()),
        )
        .await
        .expect("callback must succeed against the mock IdP");

        assert_eq!(location_of(&result), return_to);
    }

    /// An ID token carrying an `auth_time` claim — what an IdP emits when the
    /// consumer sent `prompt=login` — validates and the callback succeeds when
    /// the slot carries **no** freshness requirement. `auth_time` on its own is
    /// informational; it only becomes a gate when a variant asked for one via
    /// `ExtraAuthParams::require_auth_within`.
    #[actix_web::test]
    async fn successful_callback_with_auth_time_claim_still_succeeds() {
        let nonce = "mock-nonce-auth-time";
        let jwt = sign_id_token_with_auth_time(nonce, Some(chrono::Utc::now()));
        let base_url = start_mock_token_endpoint(jwt).await;
        let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        let started_at = chrono::Utc::now().timestamp();
        session
            .insert(
                PRE_AUTH,
                vec![PreAuthEntry {
                    state: "state-1".to_string(),
                    pkce_verifier: "verifier".to_string(),
                    nonce: nonce.to_string(),
                    return_to: "/".to_string(),
                    started_at,
                    max_age_secs: None,
                }],
            )
            .unwrap();

        let result = callback(
            req.clone(),
            session.clone(),
            query(Some("test-code"), Some("state-1"), None),
            rp,
            web::Data::new(test_cfg()),
        )
        .await;

        result.expect("callback with an auth_time claim must still succeed");
    }

    /// Seed a pre-auth slot carrying a freshness requirement and run a full
    /// callback against the mock IdP with a signed `auth_time`.
    async fn callback_with_requirement(
        nonce: &str,
        auth_time: Option<chrono::DateTime<chrono::Utc>>,
        max_age_secs: i64,
    ) -> (Session, Result<HttpResponse, BffError>) {
        let jwt = sign_id_token_with_auth_time(nonce, auth_time);
        let base_url = start_mock_token_endpoint(jwt).await;
        let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        session
            .insert(
                PRE_AUTH,
                vec![PreAuthEntry {
                    state: "state-1".to_string(),
                    pkce_verifier: "verifier".to_string(),
                    nonce: nonce.to_string(),
                    return_to: "/".to_string(),
                    started_at: chrono::Utc::now().timestamp(),
                    max_age_secs: Some(max_age_secs),
                }],
            )
            .unwrap();

        let result = callback(
            req.clone(),
            session.clone(),
            query(Some("test-code"), Some("state-1"), None),
            rp,
            web::Data::new(test_cfg()),
        )
        .await;
        (session, result)
    }

    /// The happy path for a step-up variant: the provider re-authenticated the
    /// user, `auth_time` is fresh, the login completes.
    #[actix_web::test]
    async fn callback_accepts_a_fresh_authentication_when_required() {
        let (session, result) =
            callback_with_requirement("nonce-fresh", Some(chrono::Utc::now()), 300).await;

        result.expect("a fresh auth_time must satisfy the requirement");
        let sub: Option<String> = session.get(SUB).unwrap();
        assert_eq!(sub.as_deref(), Some("test-user"));
    }

    /// The case the whole feature exists for: the provider returned a valid,
    /// correctly-signed ID token, but for an authentication that happened
    /// hours ago — i.e. it did not honour `max_age`. The login must fail, and
    /// critically must leave **no session behind**.
    #[actix_web::test]
    async fn callback_rejects_a_stale_authentication_and_establishes_no_session() {
        let stale = chrono::Utc::now() - chrono::Duration::hours(4);
        let (session, result) = callback_with_requirement("nonce-stale", Some(stale), 300).await;

        let err = result.expect_err("a stale auth_time must fail the requirement");
        assert!(
            matches!(err, BffError::BadRequest(_)),
            "expected BadRequest, got: {err:?}"
        );

        // The security-relevant half: a rejected step-up must not hand back a
        // usable session. Every one of these is written after the check.
        for key in [SUB, ISS, ACCESS_TOKEN, ID_TOKEN, LOGIN_AT] {
            assert!(
                session.get::<serde_json::Value>(key).unwrap().is_none(),
                "{key:?} must not be set after a failed re-authentication check"
            );
        }

        // The absence assertions above would still pass if the check merely
        // moved to *after* `renew()`. This pins the documented ordering
        // itself: `Renewed` means the session key was rotated, which must not
        // happen for a login that is about to be rejected. (`Changed` is
        // expected — step (4) writes the remaining pre-auth slots back.)
        assert!(
            !matches!(session.status(), actix_session::SessionStatus::Renewed),
            "the freshness check must run before session.renew()"
        );
    }

    /// The control for the gating itself: with **no** requirement in the slot,
    /// even a years-old `auth_time` must be accepted. Most providers emit
    /// `auth_time` on every login, so if the check ever stopped being
    /// conditional — or defaulted a missing requirement to `0` — this is the
    /// everyday plain-`/auth/login` case that would break for every consumer.
    #[actix_web::test]
    async fn callback_ignores_stale_auth_time_when_no_requirement_is_set() {
        let nonce = "nonce-ungated";
        let ancient = chrono::Utc::now() - chrono::Duration::days(400);
        let jwt = sign_id_token_with_auth_time(nonce, Some(ancient));
        let base_url = start_mock_token_endpoint(jwt).await;
        let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        session
            .insert(
                PRE_AUTH,
                vec![PreAuthEntry {
                    state: "state-1".to_string(),
                    pkce_verifier: "verifier".to_string(),
                    nonce: nonce.to_string(),
                    return_to: "/".to_string(),
                    started_at: chrono::Utc::now().timestamp(),
                    max_age_secs: None,
                }],
            )
            .unwrap();

        callback(
            req.clone(),
            session.clone(),
            query(Some("test-code"), Some("state-1"), None),
            rp,
            web::Data::new(test_cfg()),
        )
        .await
        .expect("a stale auth_time must be ignored when nothing required freshness");
        assert_eq!(
            session.get::<String>(SUB).unwrap().as_deref(),
            Some("test-user")
        );
    }

    /// A step-up must re-authenticate the *same* user. The provider's re-prompt
    /// commonly allows account switching, so a route that reads as "confirm
    /// it's you" must not silently turn the session into somebody else's.
    #[actix_web::test]
    async fn callback_rejects_a_step_up_completed_as_a_different_subject() {
        // The mock IdP always signs for subject "test-user"; the session
        // already belongs to someone else.
        let (session, result) = {
            let nonce = "nonce-switch";
            let jwt = sign_id_token_with_auth_time(nonce, Some(chrono::Utc::now()));
            let base_url = start_mock_token_endpoint(jwt).await;
            let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
            let rp = web::Data::new(OidcRp::for_tests(metadata));

            let req = TestRequest::default().to_http_request();
            let session = req.get_session();
            session.insert(SUB, "someone-else").unwrap();
            session
                .insert(
                    PRE_AUTH,
                    vec![PreAuthEntry {
                        state: "state-1".to_string(),
                        pkce_verifier: "verifier".to_string(),
                        nonce: nonce.to_string(),
                        return_to: "/".to_string(),
                        started_at: chrono::Utc::now().timestamp(),
                        max_age_secs: Some(300),
                    }],
                )
                .unwrap();

            let result = callback(
                req.clone(),
                session.clone(),
                query(Some("test-code"), Some("state-1"), None),
                rp,
                web::Data::new(test_cfg()),
            )
            .await;
            (session, result)
        };

        let err = result.expect_err("a step-up as a different subject must be rejected");
        assert!(
            matches!(err, BffError::BadRequest(_)),
            "expected BadRequest, got: {err:?}"
        );
        assert_eq!(
            session.get::<String>(SUB).unwrap().as_deref(),
            Some("someone-else"),
            "the original subject must not have been overwritten"
        );
    }

    /// The same check must not fire on a *plain* login: switching accounts by
    /// logging in again is ordinary behaviour, and only a step-up route
    /// promises that the subject stays put.
    #[actix_web::test]
    async fn callback_allows_a_subject_change_when_no_requirement_is_set() {
        let nonce = "nonce-plain-switch";
        let jwt = sign_id_token_with_auth_time(nonce, Some(chrono::Utc::now()));
        let base_url = start_mock_token_endpoint(jwt).await;
        let metadata = metadata_for_mock_idp(&format!("{base_url}/token"));
        let rp = web::Data::new(OidcRp::for_tests(metadata));

        let req = TestRequest::default().to_http_request();
        let session = req.get_session();
        session.insert(SUB, "someone-else").unwrap();
        session
            .insert(
                PRE_AUTH,
                vec![PreAuthEntry {
                    state: "state-1".to_string(),
                    pkce_verifier: "verifier".to_string(),
                    nonce: nonce.to_string(),
                    return_to: "/".to_string(),
                    started_at: chrono::Utc::now().timestamp(),
                    max_age_secs: None,
                }],
            )
            .unwrap();

        callback(
            req.clone(),
            session.clone(),
            query(Some("test-code"), Some("state-1"), None),
            rp,
            web::Data::new(test_cfg()),
        )
        .await
        .expect("a plain login must be free to establish a different subject");
        assert_eq!(
            session.get::<String>(SUB).unwrap().as_deref(),
            Some("test-user")
        );
    }

    /// A provider that drops `auth_time` entirely has not honoured `max_age`,
    /// and is indistinguishable from one that ignored the request — fail
    /// closed, and establish no session.
    #[actix_web::test]
    async fn callback_rejects_a_missing_auth_time_when_required() {
        let (session, result) = callback_with_requirement("nonce-absent", None, 300).await;

        let err = result.expect_err("a missing auth_time must fail the requirement");
        assert!(
            matches!(err, BffError::BadRequest(_)),
            "expected BadRequest, got: {err:?}"
        );
        assert!(session.get::<String>(SUB).unwrap().is_none());
    }
}
