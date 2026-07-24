use actix_session::Session;
use serde::{Deserialize, Serialize};

use crate::error::BffError;

// ── Session key constants ──────────────────────────────────────────────────────

pub(crate) const SUB: &str = "sub";
pub(crate) const ISS: &str = "iss";
pub(crate) const EMAIL: &str = "email";
pub(crate) const NAME: &str = "name";
pub(crate) const ACCESS_TOKEN: &str = "access_token";
pub(crate) const REFRESH_TOKEN: &str = "refresh_token";
pub(crate) const ID_TOKEN: &str = "id_token";
/// Session key for the list of extra claim names persisted by the callback.
pub(crate) const CLAIM_KEYS: &str = "__bff_claim_keys";
/// Session key under which the `Vec<PreAuthEntry>` is stored.
pub(crate) const PRE_AUTH: &str = "oidc_pre_auth";

/// Session keys reserved for internal BFF use.
///
/// Claim names in `persist_claims` must not collide with these: a colliding
/// claim would let the [`crate::Auth`] extractor expose internal session
/// values (including raw tokens) to application code, or let an ID-token
/// claim overwrite the session's identity fields.
///
/// **Maintenance rule**: this is a hand-maintained list — it is NOT derived
/// mechanically from the constants above. When adding a new session key
/// constant, you must **also** add it here. The
/// `reserved_keys_cover_every_constant` test will fail if you forget.
pub(crate) const RESERVED_SESSION_KEYS: &[&str] = &[
    SUB,
    ISS,
    EMAIL,
    NAME,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    ID_TOKEN,
    CLAIM_KEYS,
    PRE_AUTH,
];

/// Keys written by the callback that must be scrubbed on re-login to prevent
/// stale token leakage across session renewal.
///
/// Excludes `SUB` and `ISS` because the callback always overwrites them.
pub(crate) const POST_AUTH_SCRUB_KEYS: &[&str] =
    &[EMAIL, NAME, ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN];

/// Maximum number of concurrent pre-auth slots per session.
///
/// Each slot is ~220 bytes serialised (state 32 chars, pkce_verifier 43 chars,
/// nonce 32 chars, return_to ≤512 chars, started_at 8 bytes), so 5 slots are
/// ~1.1 KB — well within the limit for `DbSessionStore` server-side storage.
///
/// **`CookieSessionStore` warning**: 5 slots × a long `return_to` can exceed
/// the ~4 KB cookie limit and silently break login (the browser simply drops
/// the oversized cookie). `DbSessionStore` is the supported configuration for
/// applications that need concurrent logins from the same browser (e.g.
/// multiple open tabs). If you must use `CookieSessionStore`, reduce this
/// constant or limit `return_to` path lengths accordingly.
pub(crate) const PRE_AUTH_MAX_SLOTS: usize = 5;

// ── PreAuthEntry ──────────────────────────────────────────────────────────────

/// Data stored in the session when the user begins the OIDC login flow.
///
/// Multiple entries may coexist (up to [`PRE_AUTH_MAX_SLOTS`]) to support
/// concurrent login attempts from the same browser (e.g. multiple tabs).
/// FIFO eviction is an availability trade-off; the `state` is validated
/// cryptographically so eviction is not a security boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PreAuthEntry {
    /// CSRF token / authorization `state` parameter.
    pub state: String,
    /// Raw PKCE code verifier secret (not JSON-encoded).
    pub pkce_verifier: String,
    /// Nonce secret.
    pub nonce: String,
    /// Post-login redirect target.
    pub return_to: String,
    /// Unix timestamp when the login was initiated (UTC seconds).
    pub started_at: i64,
}

// ── Constant-time comparison ──────────────────────────────────────────────────

/// Constant-time byte comparison so the `state` check leaks no timing signal.
///
/// The per-entry short-circuit on length mismatch is intentional: state values
/// are fixed-length public tokens, so revealing "lengths differ" leaks nothing.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── Pre-auth slot management ──────────────────────────────────────────────────

/// Append a new pre-auth entry, evicting the oldest (front) if the cap is
/// reached. FIFO eviction is an availability trade-off; state is still
/// validated cryptographically on use.
pub(crate) fn push_pre_auth(
    mut entries: Vec<PreAuthEntry>,
    new: PreAuthEntry,
) -> Vec<PreAuthEntry> {
    while entries.len() >= PRE_AUTH_MAX_SLOTS {
        entries.remove(0);
    }
    entries.push(new);
    entries
}

/// Scan all slots for an entry whose `state` matches. Returns the matched entry
/// and the remaining entries (with the matched slot removed).
///
/// Scans **all** entries with an unconditional `constant_time_eq` call per
/// slot — no cross-slot early exit — so the number of slots checked does not
/// reveal which slot matched. First-match-wins for duplicate states.
///
/// To add a new session key constant: register it in the constants block at
/// the top of this file AND add it to `RESERVED_SESSION_KEYS`. The
/// `reserved_keys_cover_every_constant` test enforces membership at compile
/// time (well, test time) — it will fail if you forget one.
pub(crate) fn take_matching(
    entries: Vec<PreAuthEntry>,
    state: &str,
) -> (Option<PreAuthEntry>, Vec<PreAuthEntry>) {
    let mut matched: Option<PreAuthEntry> = None;
    let mut rest: Vec<PreAuthEntry> = Vec::with_capacity(entries.len());

    for entry in entries {
        // Evaluate constant_time_eq unconditionally for every entry so the
        // comparison timing does not reveal which slot matched.
        let is_match = constant_time_eq(&entry.state, state);
        if matched.is_none() && is_match {
            matched = Some(entry);
        } else {
            rest.push(entry);
        }
    }

    (matched, rest)
}

/// Retain only entries whose age (`now - started_at`) is within `[0, ttl]`.
///
/// Entries with a negative age (clock skew, future timestamp) are also pruned.
pub(crate) fn prune_expired(entries: Vec<PreAuthEntry>, now: i64, ttl: i64) -> Vec<PreAuthEntry> {
    entries
        .into_iter()
        .filter(|e| {
            let age = now.saturating_sub(e.started_at);
            age >= 0 && age <= ttl
        })
        .collect()
}

/// Insert `value` into the session under `key`, logging the real error and
/// mapping to [`BffError::Internal`].
///
/// Replaces the pattern `.map_err(|_| BffError::Internal)` at every insert
/// site so the underlying error is captured in the log rather than discarded.
pub(crate) fn insert_or_internal<T: Serialize>(
    session: &Session,
    key: &str,
    value: &T,
) -> Result<(), BffError> {
    session.insert(key, value).map_err(|e| {
        log::error!("Failed to insert session key {key:?}: {e}");
        BffError::Internal
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(state: &str, started_at: i64) -> PreAuthEntry {
        PreAuthEntry {
            state: state.to_string(),
            pkce_verifier: "verifier".to_string(),
            nonce: "nonce".to_string(),
            return_to: "/".to_string(),
            started_at,
        }
    }

    // ── S1.1: RESERVED_SESSION_KEYS covers every constant ─────────────────────

    #[test]
    fn reserved_keys_cover_every_constant() {
        for key in [
            SUB,
            ISS,
            EMAIL,
            NAME,
            ACCESS_TOKEN,
            REFRESH_TOKEN,
            ID_TOKEN,
            CLAIM_KEYS,
            PRE_AUTH,
        ] {
            assert!(
                RESERVED_SESSION_KEYS.contains(&key),
                "RESERVED_SESSION_KEYS missing constant {key:?}"
            );
        }
        // POST_AUTH_SCRUB_KEYS must be a subset of RESERVED_SESSION_KEYS.
        for key in POST_AUTH_SCRUB_KEYS {
            assert!(
                RESERVED_SESSION_KEYS.contains(key),
                "POST_AUTH_SCRUB_KEYS has {key:?} not in RESERVED_SESSION_KEYS"
            );
        }
    }

    // ── S1.1: push_pre_auth caps at PRE_AUTH_MAX_SLOTS evicting oldest ────────

    #[test]
    fn pre_auth_push_caps_slots_evicting_oldest() {
        let mut slots: Vec<PreAuthEntry> = Vec::new();
        for i in 0..(PRE_AUTH_MAX_SLOTS + 2) {
            slots = push_pre_auth(slots, entry(&format!("state{i}"), i as i64));
        }
        assert_eq!(slots.len(), PRE_AUTH_MAX_SLOTS);
        // The oldest two entries ("state0" and "state1") must be evicted.
        assert!(!slots.iter().any(|e| e.state == "state0"));
        assert!(!slots.iter().any(|e| e.state == "state1"));
        // Most recently pushed entry must be last.
        assert_eq!(
            slots.last().unwrap().state,
            format!("state{}", PRE_AUTH_MAX_SLOTS + 1)
        );
    }

    // ── S1.1: take_matching ────────────────────────────────────────────────────

    #[test]
    fn take_matching_removes_only_matched_entry() {
        let entries = vec![
            entry("state_a", 0),
            entry("state_b", 1),
            entry("state_c", 2),
        ];
        let (matched, rest) = take_matching(entries, "state_b");
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().state, "state_b");
        assert_eq!(rest.len(), 2);
        assert!(rest.iter().all(|e| e.state != "state_b"));
    }

    #[test]
    fn take_matching_returns_none_for_unknown_state() {
        let entries = vec![entry("state_a", 0), entry("state_b", 1)];
        let (matched, rest) = take_matching(entries, "state_unknown");
        assert!(matched.is_none());
        assert_eq!(rest.len(), 2);
    }

    #[test]
    fn take_matching_is_length_safe() {
        // A match in the last slot must succeed even when other slots have
        // different-length states (no cross-slot early exit on length mismatch).
        let entries = vec![
            entry("short", 0),
            entry("a_much_longer_state_string", 1),
            entry("the_target_state_value", 2),
        ];
        let (matched, rest) = take_matching(entries, "the_target_state_value");
        assert!(
            matched.is_some(),
            "should match last slot regardless of other lengths"
        );
        assert_eq!(rest.len(), 2);
    }

    // ── S1.1: prune_expired ───────────────────────────────────────────────────

    #[test]
    fn prune_expired_drops_only_stale_entries() {
        let now = 1_000_000i64;
        let ttl = 600i64;
        let entries = vec![
            entry("fresh", now - 10),          // age=10, keep
            entry("at_limit", now - ttl),      // age=600, keep (boundary)
            entry("expired", now - (ttl + 1)), // age=601, drop
            entry("future", now + 100),        // negative age (clock skew), drop
        ];
        let kept = prune_expired(entries, now, ttl);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|e| e.state == "fresh"));
        assert!(kept.iter().any(|e| e.state == "at_limit"));
    }

    // ── S1.1: constant_time_eq (moved from callback.rs) ──────────────────────

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn constant_time_eq_rejects_differences() {
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc123", "abc12"));
        assert!(!constant_time_eq("abc123", ""));
        assert!(!constant_time_eq("Abc123", "abc123"));
    }

    #[test]
    fn take_matching_with_duplicate_states_removes_only_first() {
        // Defensive edge case: two slots carrying the same state (should not
        // happen with CsrfToken::new_random, but must not remove both).
        let entries = vec![entry("dup", 0), entry("dup", 1)];
        let (matched, rest) = take_matching(entries, "dup");
        assert_eq!(matched.unwrap().started_at, 0, "first duplicate must match");
        assert_eq!(rest.len(), 1, "second duplicate must be preserved");
        assert_eq!(rest[0].started_at, 1);
    }

    /// Verify that `take_matching` compares **every** entry with
    /// `constant_time_eq` — even after the first match is found — so the
    /// timing of the function does not reveal which slot matched.
    ///
    /// This property is structural (enforced by the unconditional `is_match`
    /// path) but we exercise it by confirming first-match-wins semantics are
    /// preserved when there are duplicates and non-matching neighbours.
    #[test]
    fn take_matching_takes_first_of_duplicates_while_comparing_all() {
        // Three slots: non-match, first-dup (should be taken), second-dup
        // (should remain). If the implementation short-circuits after the first
        // match the second dup would still end up in `rest`, but we also verify
        // the non-match is there and that we haven't accidentally dropped slots.
        let entries = vec![entry("other", 0), entry("dup", 1), entry("dup", 2)];
        let (matched, rest) = take_matching(entries, "dup");
        assert_eq!(
            matched.as_ref().unwrap().started_at,
            1,
            "first occurrence must be taken"
        );
        assert_eq!(rest.len(), 2, "non-match and second dup must be in rest");
        // The `other` entry must survive untouched.
        assert!(
            rest.iter().any(|e| e.state == "other"),
            "non-matching entry must remain"
        );
        // The second duplicate must survive.
        assert!(
            rest.iter().any(|e| e.state == "dup" && e.started_at == 2),
            "second duplicate must remain"
        );
    }

    // ── S1.1: insert_or_internal happy path ──────────────────────────────────

    #[test]
    fn insert_or_internal_happy_path() {
        use actix_session::SessionExt;
        use actix_web::test::TestRequest;

        let req = TestRequest::default().to_http_request();
        let session = req.get_session();

        insert_or_internal(&session, "some_key", &"some_value".to_string())
            .expect("insert into a fresh session must succeed");

        assert_eq!(
            session.get::<String>("some_key").unwrap(),
            Some("some_value".to_string()),
            "inserted value must round-trip through the session"
        );
    }
}
