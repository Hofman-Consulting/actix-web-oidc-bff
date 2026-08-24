//! Shared validation for OAuth/OIDC query-parameter *names*, plus the two
//! hand-maintained deny-lists that guard the crate's two consumer-supplied
//! parameter surfaces.
//!
//! Both surfaces — extra authorization-request parameters
//! ([`crate::ExtraAuthParams`]) and callback passthrough parameters
//! ([`crate::OidcBffConfig::callback_passthrough_params`]) — apply the same
//! charset and length rules and differ only in which names they refuse.
//! Keeping the rules in one function and the two lists side by side is
//! deliberate: they are reviewed together, and a name that is dangerous on one
//! surface is usually worth a second look on the other.
//!
//! **Both lists are hand-maintained.** `DENIED_AUTH_PARAMS` additionally has a
//! mechanical completeness test in `handlers/login.rs`
//! (`deny_list_covers_every_crate_set_authorize_param`) which builds a real
//! authorization URL and asserts every parameter name the crate itself emits
//! appears here.

/// Maximum accepted length, in bytes, for a parameter name on either surface —
/// both [`crate::ExtraAuthParams`] and
/// [`crate::OidcBffConfigBuilder::callback_passthrough_params`].
///
/// Re-exported at the crate root: it is named in the error messages both
/// surfaces produce, so a consumer diagnosing one needs to be able to reach it.
pub const MAX_PARAM_NAME_LEN: usize = 64;

/// Parameter names that must never be added to the authorization request as an
/// "extra" parameter.
///
/// This list is **load-bearing, not cosmetic**. `oauth2`'s authorization-URL
/// builder appends extra parameters onto the built-in ones with no dedup or
/// conflict check, and identity providers disagree on whether the first or the
/// last occurrence of a repeated parameter wins. A duplicated `redirect_uri`
/// that happens to win is authorization-code theft; a duplicated `scope`,
/// `state`, `nonce`, or PKCE parameter breaks or weakens the flow.
///
/// The entries fall into four groups:
/// - values the crate sets itself (`client_id`, `redirect_uri`,
///   `response_type`, `scope`, `state`, `nonce`, `code_challenge`,
///   `code_challenge_method`)
/// - `response_mode`, which would move the response off the query string and
///   break the `GET /auth/callback` handler
/// - `request` / `request_uri` (JAR), which replace the entire request with a
///   caller-supplied blob and thereby bypass every entry above
/// - credentials that must never appear in a front-channel URL
///   (`client_secret`, `client_assertion`, `client_assertion_type`,
///   `code_verifier`)
///
/// `max_age` is denied for a different reason than the rest: it is not
/// dangerous, it is *unverifiable in the hand-rolled form*. Sent as a bare
/// parameter, a provider that ignored it would be indistinguishable from one
/// that honoured it, and the caller would believe they had a re-authentication
/// guarantee they do not have. `ExtraAuthParams::require_auth_within` sends it
/// **and** checks the resulting `auth_time` claim, so denying the raw name
/// makes the verified path the only path.
pub(crate) const DENIED_AUTH_PARAMS: &[&str] = &[
    "client_assertion",
    "client_assertion_type",
    "client_id",
    "client_secret",
    "code_challenge",
    "code_challenge_method",
    "code_verifier",
    "max_age",
    "nonce",
    "redirect_uri",
    "request",
    "request_uri",
    "response_mode",
    "response_type",
    "scope",
    "state",
];

/// Parameter names that must never be forwarded from the callback request into
/// the post-login redirect URL.
///
/// Everything here would end up in the browser's address bar, its history, the
/// `Referer` header of the next outbound request, and the access logs of every
/// proxy in front of the app. For the credential-bearing names
/// (`code`, tokens, client credentials) that is a direct disclosure. For
/// `state` and `code_verifier` it undermines the flow's CSRF/PKCE binding. For
/// `iss` (RFC 9207) and `session_state` it hands an application a value that
/// looks authoritative but has been through an untrusted round trip, inviting
/// it to make authorization decisions on data this crate never validated.
///
/// `error` / `error_description` / `error_uri` are listed because the failure
/// path deliberately does not redirect at all — forwarding them would be a
/// contradiction, and they are attacker-suppliable strings.
/// `response` is the passthrough analogue of `request`/`request_uri` on the
/// authorize side: under JARM (JWT Secured Authorization Response Mode) it is a
/// single signed JWT carrying `code`, `state`, `iss` and — in some profiles —
/// tokens. Forwarding one blob would leak everything the individual entries
/// here exist to withhold. `sid` is `session_state`'s sibling from OIDC session
/// management and is denied for the same reason.
pub(crate) const DENIED_PASSTHROUGH_PARAMS: &[&str] = &[
    "access_token",
    "client_assertion",
    "client_assertion_type",
    "client_secret",
    "code",
    "code_verifier",
    "error",
    "error_description",
    "error_uri",
    "id_token",
    "id_token_hint",
    "iss",
    "refresh_token",
    "response",
    "session_state",
    "sid",
    "state",
    "token",
];

/// Whether `value` contains a character that must never reach a URL the crate
/// builds: a C0 control (`\u{0}`..=`\u{1f}`), DEL, or a C1 control
/// (`\u{80}`..=`\u{9f}`).
///
/// Shared by both consumer-supplied *value* surfaces — extra authorize
/// parameter values and callback passthrough values. They had independent
/// copies of this predicate, spelled differently, in the two files a reviewer
/// is least likely to diff against each other; one definition removes the drift
/// risk.
///
/// Note this is a URL-safety rule, not an "is safe to render" rule: `<`, `>`,
/// `&`, quotes and `javascript:` all pass, because percent-encoding neutralises
/// them for the `Location` header. Consumers must still escape these values
/// before putting them in HTML.
pub(crate) fn has_control_chars(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}' | '\u{80}'..='\u{9f}'))
}

/// Why [`validate_param_name`] rejected a name.
///
/// Deliberately crate-internal: each surface maps these into its own public
/// error type (`AuthParamError` / `ConfigError`) so neither leaks the other's
/// vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParamNameError {
    /// The name was empty. A whitespace-only name yields
    /// [`ParamNameError::InvalidCharset`], not this — both current callers
    /// trim before validating, so they never see the distinction.
    Empty,
    /// The name exceeded [`MAX_PARAM_NAME_LEN`] bytes.
    TooLong,
    /// The name contained a character outside `[A-Za-z0-9_.-]`.
    InvalidCharset,
    /// The name appeared on the surface's deny-list.
    Denied,
}

/// Validate a parameter name against the shared rules and one deny-list.
///
/// The name must be non-empty, at most [`MAX_PARAM_NAME_LEN`] bytes, and made
/// up only of ASCII alphanumerics, `_`, `.`, or `-`. That charset is narrower
/// than what RFC 6749 permits, and intentionally so: it excludes everything
/// that could need percent-encoding, so a name can never smuggle a `&`, `=`,
/// or control character into a query string regardless of how it is later
/// serialised.
///
/// Deny-list matching is ASCII-case-insensitive. Parameter names are
/// case-sensitive to identity providers, so `Redirect_Uri` would not actually
/// collide with the crate's own `redirect_uri` — but a caller who writes it
/// has made a mistake worth surfacing either way, and over-blocking here costs
/// nothing.
pub(crate) fn validate_param_name(name: &str, denied: &[&str]) -> Result<(), ParamNameError> {
    if name.is_empty() {
        return Err(ParamNameError::Empty);
    }
    if name.len() > MAX_PARAM_NAME_LEN {
        return Err(ParamNameError::TooLong);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    {
        return Err(ParamNameError::InvalidCharset);
    }
    if denied.iter().any(|d| d.eq_ignore_ascii_case(name)) {
        return Err(ParamNameError::Denied);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        validate_param_name, ParamNameError, DENIED_AUTH_PARAMS, DENIED_PASSTHROUGH_PARAMS,
        MAX_PARAM_NAME_LEN,
    };

    #[test]
    fn accepts_ordinary_names() {
        for name in [
            "prompt",
            "kc_action",
            "acr_values",
            "ui.locale",
            "x-y",
            "a1",
        ] {
            assert!(
                validate_param_name(name, DENIED_AUTH_PARAMS).is_ok(),
                "{name:?} must be accepted"
            );
        }
    }

    #[test]
    fn rejects_empty_and_overlong_names() {
        assert_eq!(
            validate_param_name("", DENIED_AUTH_PARAMS),
            Err(ParamNameError::Empty)
        );
        let long = "a".repeat(MAX_PARAM_NAME_LEN + 1);
        assert_eq!(
            validate_param_name(&long, DENIED_AUTH_PARAMS),
            Err(ParamNameError::TooLong)
        );
        // Exactly at the cap is fine.
        let max = "a".repeat(MAX_PARAM_NAME_LEN);
        assert!(validate_param_name(&max, DENIED_AUTH_PARAMS).is_ok());
    }

    /// Anything that could need percent-encoding — or split a query string —
    /// must be refused outright rather than escaped later.
    #[test]
    fn rejects_names_outside_the_charset() {
        for name in [
            "kc action",
            "a&b",
            "a=b",
            "a?b",
            "a#b",
            "a%20b",
            "a/b",
            "a\nb",
            "a\u{e9}b",
            "a+b",
        ] {
            assert_eq!(
                validate_param_name(name, DENIED_AUTH_PARAMS),
                Err(ParamNameError::InvalidCharset),
                "{name:?} must be rejected by the charset rule"
            );
        }
    }

    #[test]
    fn rejects_every_denied_auth_param_case_insensitively() {
        for denied in DENIED_AUTH_PARAMS {
            assert_eq!(
                validate_param_name(denied, DENIED_AUTH_PARAMS),
                Err(ParamNameError::Denied),
                "{denied:?} must be denied"
            );
            assert_eq!(
                validate_param_name(&denied.to_ascii_uppercase(), DENIED_AUTH_PARAMS),
                Err(ParamNameError::Denied),
                "{denied:?} must be denied case-insensitively"
            );
        }
    }

    #[test]
    fn rejects_every_denied_passthrough_param_case_insensitively() {
        for denied in DENIED_PASSTHROUGH_PARAMS {
            assert_eq!(
                validate_param_name(denied, DENIED_PASSTHROUGH_PARAMS),
                Err(ParamNameError::Denied),
                "{denied:?} must be denied"
            );
            assert_eq!(
                validate_param_name(&denied.to_ascii_uppercase(), DENIED_PASSTHROUGH_PARAMS),
                Err(ParamNameError::Denied),
                "{denied:?} must be denied case-insensitively"
            );
        }
    }

    /// The two lists are independent: a name denied on one surface is not
    /// automatically denied on the other. `prompt` is the motivating case —
    /// it must be settable as an extra authorize parameter.
    #[test]
    fn lists_are_independent() {
        assert!(validate_param_name("code", DENIED_AUTH_PARAMS).is_ok());
        assert!(validate_param_name("prompt", DENIED_AUTH_PARAMS).is_ok());
        assert!(validate_param_name("prompt", DENIED_PASSTHROUGH_PARAMS).is_ok());
        assert!(validate_param_name("kc_action_status", DENIED_PASSTHROUGH_PARAMS).is_ok());
    }

    /// The mechanical completeness test in `handlers/login.rs` asserts
    /// *emitted ⊆ deny-list*, so it can only catch a parameter the crate
    /// starts emitting without a matching entry here. It is structurally blind
    /// to the **deletion** of an entry the crate never emits — and those are
    /// precisely the entries most likely to look like dead weight to someone
    /// tidying up.
    ///
    /// `request_uri` is the sharp one: a JAR request object replaces the entire
    /// authorization request with a caller-supplied blob, bypassing every other
    /// entry on this list including `redirect_uri`.
    #[test]
    fn policy_only_denied_auth_params_are_still_present() {
        for (name, why) in [
            ("request", "JAR: replaces the whole authorization request"),
            (
                "request_uri",
                "JAR by reference: replaces the whole authorization request",
            ),
            (
                "response_mode",
                "would move the response off the query string and break GET /auth/callback",
            ),
            ("client_secret", "credential, never in a front-channel URL"),
            (
                "client_assertion",
                "credential, never in a front-channel URL",
            ),
            (
                "client_assertion_type",
                "credential companion, never in a front-channel URL",
            ),
            ("code_verifier", "PKCE secret, never in a front-channel URL"),
            // Not policy-only any more — `require_auth_within` emits it, and
            // `deny_list_covers_every_crate_set_authorize_param` covers that
            // path. Kept here because the *reason* it is denied is unusual:
            // it is unverifiable in the hand-rolled form, not dangerous.
            (
                "max_age",
                "only ExtraAuthParams::require_auth_within may send it, because that is \
                 the path that also verifies the resulting auth_time claim",
            ),
        ] {
            assert!(
                DENIED_AUTH_PARAMS.contains(&name),
                "{name:?} must stay on DENIED_AUTH_PARAMS — {why}. The crate never emits it, \
                 so no mechanical test would notice its removal."
            );
        }
    }

    /// `DENIED_PASSTHROUGH_PARAMS` has no mechanical source of truth at all —
    /// there is no way to enumerate "names that must never appear in a
    /// browser-visible URL". This test is the whole safety net, so the reason
    /// for each entry lives in the assertion message.
    #[test]
    fn credential_bearing_passthrough_params_are_still_denied() {
        for (name, why) in [
            ("code", "the authorization code itself"),
            ("state", "CSRF binding for the pre-auth slot"),
            ("code_verifier", "PKCE secret"),
            ("access_token", "bearer credential"),
            ("refresh_token", "long-lived bearer credential"),
            ("id_token", "identity assertion"),
            ("token", "generic credential name"),
            ("client_secret", "client credential"),
            (
                "response",
                "JARM: one signed JWT carrying code/state/iss and possibly tokens",
            ),
            ("iss", "RFC 9207 issuer — an app may wrongly trust it"),
            ("session_state", "OP session identifier"),
            ("sid", "OP session identifier (session-management sibling)"),
        ] {
            assert!(
                DENIED_PASSTHROUGH_PARAMS.contains(&name),
                "{name:?} must stay on DENIED_PASSTHROUGH_PARAMS — {why}. Forwarding it would \
                 expose it in browser history, the Referer header, and access logs."
            );
        }
    }

    #[test]
    fn has_control_chars_detects_c0_del_and_c1() {
        for bad in ["a\rb", "a\nb", "a\u{0}b", "a\u{7f}b", "a\u{9f}b", "\t"] {
            assert!(
                super::has_control_chars(bad),
                "{bad:?} must be flagged as containing a control character"
            );
        }
        // Ordinary text — including characters that matter for HTML but not
        // for URL safety — must not be flagged.
        for ok in ["", "success", "a b", "<script>", "caf\u{e9}", "a&b=c"] {
            assert!(
                !super::has_control_chars(ok),
                "{ok:?} must not be flagged as containing a control character"
            );
        }
    }

    /// Both lists are hand-maintained; keeping them sorted and duplicate-free
    /// is what makes review of an added entry cheap.
    #[test]
    fn deny_lists_are_sorted_and_deduplicated() {
        for (label, list) in [
            ("DENIED_AUTH_PARAMS", DENIED_AUTH_PARAMS),
            ("DENIED_PASSTHROUGH_PARAMS", DENIED_PASSTHROUGH_PARAMS),
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.as_slice(),
                list,
                "{label} must be sorted and free of duplicates"
            );
        }
    }
}
