//! Persistent, revocable session storage.
//!
//! `actix-session`'s built-in cookie store keeps all session state in an
//! encrypted client cookie, which means sessions cannot be revoked server-side
//! before they expire. For a BFF that holds identity claims, a server-side
//! store is usually preferable: the cookie carries only an opaque key.
//!
//! This module provides [`DbSessionStore`], an `actix_session::storage::
//! SessionStore` adapter that delegates all persistence to a consumer-supplied
//! [`SessionRepository`]. The consumer owns the actual storage (Postgres,
//! Redis, etc.); this crate stays free of any database dependency.
//!
//! ## Pre-auth TTL cap
//!
//! [`DbSessionStore`] automatically caps the TTL for anonymous / pre-auth rows
//! (those that do not contain the `sub` session key) to
//! [`DbSessionStore::with_pre_auth_ttl_secs`] (default `600 s`). This prevents
//! an unauthenticated attacker from flooding `/auth/login` and filling the
//! session table with rows that live as long as authenticated sessions. Use
//! [`DbSessionStore::from_config`] when constructing the store to keep both
//! values in sync with [`crate::OidcBffConfig`]. Rate-limiting `/auth/login`
//! at the deployment level (reverse proxy / WAF) is still recommended.
//!
//! ## Absolute session lifetime (hard cap)
//!
//! Authenticated rows (those containing `sub`) are additionally bounded by
//! [`DbSessionStore::with_max_lifetime_secs`] (default
//! [`crate::config::DEFAULT_MAX_SESSION_LIFETIME_SECS`], 7 days), counted from
//! the `__bff_login_at` session key written at login. This matters most under
//! [`crate::config::SessionExpiry::Sliding`], where the idle TTL alone would
//! otherwise permit an unbounded session lifetime as long as the user keeps
//! making requests. The cap is enforced in three places:
//!
//! - [`load()`][actix_session::storage::SessionStore::load] — the authoritative
//!   check; it runs on every request carrying a session cookie and deletes +
//!   returns `None` for a row past its cap.
//! - [`update()`][actix_session::storage::SessionStore::update] — a write past
//!   the cap is dropped in favour of deleting the row, so a session cannot be
//!   kept alive by an authenticated request racing its own expiry.
//! - [`update_ttl()`][actix_session::storage::SessionStore::update_ttl] — a sliding-expiry renewal
//!   (see [`crate::session_middleware`]) is clamped to the cap rather than
//!   extending past it. This is also where the defect this module fixes lived:
//!   `update_ttl` previously received no session state and therefore could not
//!   distinguish an anonymous pre-auth row from an authenticated one,
//!   silently bypassing the pre-auth TTL cap above.
//!
//! A row missing `__bff_login_at` (e.g. state written by a version of this
//! crate predating this field, or a caller that removed the key directly —
//! it is a plain string key, and `RESERVED_SESSION_KEYS` only guards
//! `persist_claims`, not direct `session.remove`) is treated as dead by
//! [`load()`][actix_session::storage::SessionStore::load],
//! [`update()`][actix_session::storage::SessionStore::update], and
//! [`update_ttl()`][actix_session::storage::SessionStore::update_ttl]. Only
//! [`save()`][actix_session::storage::SessionStore::save] heals it, by
//! injecting `__bff_login_at = now()` when `sub` is present without it —
//! `save()` is the one path where `now()` is unambiguously the correct login
//! time (a genuinely new session). Injecting it in `update()` too would let
//! anything that strips `__bff_login_at` from an otherwise-live session
//! silently restart the absolute-lifetime clock on its next write. See the
//! injection logic in `save()` below.
//!
//! One consequence: the store can never *shorten* a live session. Lowering
//! `post_auth_ttl_secs` (or `max_session_lifetime_secs`) at deploy time does
//! not retroactively affect rows already persisted with a longer expiry —
//! they simply lapse on their own schedule, bounded by whichever cap was in
//! effect when they were last written.
//!
//! ## `update()` missing-row contract
//!
//! [`SessionRepository::update`] returns `Ok(true)` when a row was updated and
//! `Ok(false)` when the key is absent (e.g. the session was purged by a
//! concurrent logout). The adapter handles the `false` case in two branches:
//!
//! - **Token-bearing state** (state contains `access_token`, `refresh_token`,
//!   or `id_token`): the write is **dropped** and the stale key is returned.
//!   This ensures that a request racing a logout cannot recreate a
//!   token-bearing row after the session was purged — logout remains
//!   authoritative.
//! - **Token-free state** (pre-auth / anonymous): the adapter generates a new
//!   session key and inserts the state, mirroring actix-session's Redis
//!   semantics to preserve multi-tab login ergonomics. The pre-auth TTL cap
//!   is applied here too so the fallback cannot reopen the DoS.
//!
//! This missing-row fallback is only reached once the write has already
//! cleared the absolute-lifetime check above — a session past its cap never
//! reaches `repo.update()` in the first place.
//!
//! ## Storage guidance
//!
//! Sliding expiry (`touch()`, driven by [`crate::config::SessionExpiry::Sliding`])
//! makes `expires_at` a high-churn column — every authenticated request
//! would otherwise write it. The coalescing window in `update_ttl()` below
//! mitigates this by collapsing repeated renewals into roughly one write per
//! [`DbSessionStore::with_touch_coalesce_secs`]. When implementing
//! [`SessionRepository`] against a relational database:
//!
//! - Do **not** index `expires_at` on its own (beyond what's needed for a
//!   periodic cleanup sweep) — an index on a column updated on nearly every
//!   authenticated request turns every `touch()` into an index write, not
//!   just a row write.
//! - Consider a lower `fillfactor` and more aggressive `autovacuum` settings
//!   for this table so that an `UPDATE ... SET expires_at = $1` can be
//!   satisfied as a Postgres HOT (Heap-Only Tuple) update — i.e. reuse the
//!   existing page slot instead of writing a new row version — which avoids
//!   touching secondary indexes at all.
//! - Concurrent XHRs from the same browser tab (or multiple tabs) share one
//!   session key, so expect them to serialize on that row's lock under load;
//!   the coalescing window in `update_ttl()` (see
//!   [`DbSessionStore::with_touch_coalesce_secs`]) exists specifically to
//!   reduce how often that lock is taken.
//!
//! ## NOTE on `anyhow`
//! This is the only place in the crate that uses `anyhow`. It exists here
//! because `actix-session 0.10`'s `SessionStore` trait API forces
//! `anyhow::Error` into its signature — `LoadError::Other`, `SaveError::Other`,
//! `UpdateError::Other`, and the `update_ttl`/`delete` return types all take
//! `anyhow::Error` directly. The trait cannot be satisfied without constructing
//! `anyhow::Error` values. Everything else uses [`crate::BffError`] /
//! [`RepoError`].

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::time::Duration as CookieDuration;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use std::{collections::HashMap, future::Future, sync::Arc};

use crate::config::{DEFAULT_MAX_SESSION_LIFETIME_SECS, DEFAULT_PRE_AUTH_TTL_SECS, MAX_TTL_SECS};
use crate::session_state;

/// Error type returned by [`SessionRepository`] implementations.
///
/// Boxed so consumers can return their own error type without this crate
/// depending on it.
pub type RepoError = Box<dyn std::error::Error + Send + Sync>;

/// A persisted session row.
///
/// `state` is the JSON-serialized `HashMap<String, String>` of session
/// entries. The repository stores and returns it verbatim.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// The opaque session key stored in the browser's cookie.
    pub session_key: String,
    /// JSON-serialized `HashMap<String, String>` of session entries.
    pub state: String,
    /// When this row should be treated as expired.
    pub expires_at: DateTime<Utc>,
}

/// Storage backend for sessions, implemented by the consuming application.
///
/// All methods are keyed by the opaque session key. Implementations *should*
/// filter expired rows on the database side (e.g. a SQL `WHERE expires_at >
/// NOW()`), but must not rely solely on that: [`DbSessionStore`] enforces
/// expiry in its `load()` path regardless, as a defense-in-depth measure for
/// repositories that return stale rows. When `load()` finds an expired record
/// it calls `delete()` as a best-effort cleanup (a failure there is only
/// logged; it does not turn the load into an error).
#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    /// Fetch a session by key. Returns `None` if missing or expired.
    ///
    /// Called twice per unchanged request under
    /// [`crate::config::SessionExpiry::Sliding`] — once via `load()`, once
    /// via `update_ttl()` (the adapter needs the row's current `state` to
    /// decide whether the caller is authenticated and its current
    /// `expires_at` to apply the write-skip/coalescing guard). Keep this
    /// cheap and indexed on the primary key.
    async fn get(&self, session_key: &str) -> Result<Option<SessionRecord>, RepoError>;
    /// Insert a new session record.
    async fn insert(&self, record: &SessionRecord) -> Result<(), RepoError>;
    /// Update an existing session's state and expiry.
    ///
    /// Returns `Ok(true)` when the row was found and updated. Returns
    /// `Ok(false)` — **not** an error — when no row with that key exists.
    /// This allows the adapter to distinguish a missing session (e.g. purged
    /// by a concurrent logout) from a storage failure, and apply the
    /// appropriate fallback (see module-level docs).
    async fn update(
        &self,
        session_key: &str,
        state: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, RepoError>;
    /// Extend an existing session's expiry without changing its state.
    ///
    /// Called under [`crate::config::SessionExpiry::Sliding`] (set via
    /// [`crate::config::OidcBffConfigBuilder::session_expiry`]) — see
    /// [`crate::session_middleware`] for the mode this maps to at the
    /// `actix-session` level. The adapter only
    /// calls this for authenticated rows that have moved forward by at least
    /// the coalescing window (see
    /// [`DbSessionStore::with_touch_coalesce_secs`]); anonymous/pre-auth rows
    /// never reach this method.
    ///
    /// **Contract — implementations MUST honour this exactly:**
    /// `UPDATE ... SET expires_at = $1 WHERE session_key = $2 AND expires_at >
    /// NOW()`. This method **must not** insert a row that does not already
    /// exist. The adapter cannot detect an upsert implementation from the
    /// return value, and an upsert would reopen a TOCTOU window between its
    /// `get()` and this call: a token-bearing row purged by a concurrent
    /// logout in that window would be silently resurrected by `touch()`,
    /// violating the invariant that logout is authoritative. Implementations
    /// should keep this cheap (e.g. an indexed `UPDATE`); see the "Storage
    /// guidance" section of the module docs for schema-level advice.
    async fn touch(&self, session_key: &str, expires_at: DateTime<Utc>) -> Result<(), RepoError>;
    /// Delete a session by key.
    async fn delete(&self, session_key: &str) -> Result<(), RepoError>;
}

/// `actix-session` store adapter over a [`SessionRepository`].
///
/// Pass directly to `SessionMiddleware::new(store, key)`.
///
/// See the [module-level docs](self) for details on the pre-auth TTL cap, the
/// absolute session lifetime, and the `update()` missing-row contract.
pub struct DbSessionStore<R>
where
    R: SessionRepository,
{
    repo: Arc<R>,
    /// Maximum TTL applied to anonymous / pre-auth rows (rows without `sub`).
    pre_auth_ttl_secs: i64,
    /// Absolute ceiling on an authenticated row's life, counted from
    /// `__bff_login_at`.
    max_lifetime_secs: i64,
    /// Minimum forward movement (seconds) required before `update_ttl()`
    /// issues a `touch()` write.
    touch_coalesce_secs: i64,
}

impl<R> DbSessionStore<R>
where
    R: SessionRepository,
{
    /// Create a new store with the default pre-auth TTL cap (600 s), default
    /// absolute lifetime (7 days), and default touch-coalescing window
    /// (60 s).
    ///
    /// **These defaults are independent of any [`crate::OidcBffConfig`] a
    /// consumer may have built** — `new()` keeps the crate's own hard-coded
    /// defaults *regardless of what the config says*. A consumer who
    /// configures, say, a 1-hour [`crate::OidcBffConfig::max_session_lifetime`]
    /// and then calls `new()` still gets 7-day rows: the two are simply never
    /// compared. [`Self::from_config`] is the correct default path for
    /// deriving the store's TTLs from an `OidcBffConfig`; `new()` plus the
    /// `with_*` builders below remain for consumers who deliberately want the
    /// store tuned independently of the OIDC config.
    pub fn new(repo: R) -> Self {
        Self {
            repo: Arc::new(repo),
            pre_auth_ttl_secs: DEFAULT_PRE_AUTH_TTL_SECS,
            max_lifetime_secs: DEFAULT_MAX_SESSION_LIFETIME_SECS,
            touch_coalesce_secs: DEFAULT_TOUCH_COALESCE_SECS,
        }
    }

    /// Create a new store from an existing `Arc<R>` with the default pre-auth
    /// TTL cap (600 s), default absolute lifetime (7 days), and default
    /// touch-coalescing window (60 s).
    ///
    /// See [`Self::new`] for why these defaults do not automatically track a
    /// [`crate::OidcBffConfig`]; use [`Self::from_arc_with_config`] to derive
    /// them from one instead.
    pub fn from_arc(repo: Arc<R>) -> Self {
        Self {
            repo,
            pre_auth_ttl_secs: DEFAULT_PRE_AUTH_TTL_SECS,
            max_lifetime_secs: DEFAULT_MAX_SESSION_LIFETIME_SECS,
            touch_coalesce_secs: DEFAULT_TOUCH_COALESCE_SECS,
        }
    }

    /// Create a new store whose pre-auth TTL cap and absolute session
    /// lifetime are derived from `cfg`, leaving the touch-coalescing window
    /// at its default (60 s).
    ///
    /// This is the correct default construction path: [`Self::new`] silently
    /// keeps the crate's own built-in defaults (600 s pre-auth, 7 days max
    /// lifetime) regardless of what `cfg` says, so a consumer who configures
    /// a 1-hour [`crate::OidcBffConfig::max_session_lifetime`] and calls
    /// `new()` would still get 7-day rows. `from_config` wires both values
    /// from `cfg` so the store and the OIDC config never drift apart.
    ///
    /// ```rust,ignore
    /// let cfg = OidcBffConfig::builder()
    ///     // ...
    ///     .build()?;
    /// let store = DbSessionStore::from_config(repo, &cfg);
    /// ```
    #[must_use]
    pub fn from_config(repo: R, cfg: &crate::OidcBffConfig) -> Self {
        Self::from_arc_with_config(Arc::new(repo), cfg)
    }

    /// Like [`Self::from_config`], but takes an existing `Arc<R>` rather than
    /// constructing a new one — for consumers who already share the
    /// repository elsewhere.
    #[must_use]
    pub fn from_arc_with_config(repo: Arc<R>, cfg: &crate::OidcBffConfig) -> Self {
        Self {
            repo,
            pre_auth_ttl_secs: cfg.pre_auth_ttl_secs(),
            max_lifetime_secs: cfg.max_session_lifetime_secs(),
            touch_coalesce_secs: DEFAULT_TOUCH_COALESCE_SECS,
        }
    }

    /// Override the maximum TTL applied to anonymous / pre-auth session rows.
    ///
    /// Pre-auth rows are those that do not contain the `sub` session key.
    /// Capping their TTL limits how long an unauthenticated flood of
    /// `/auth/login` requests can fill the session table.
    ///
    /// Prefer [`Self::from_config`] to keep this in sync with
    /// [`crate::OidcBffConfig::pre_auth_ttl`] automatically; use this setter
    /// directly only when the store's pre-auth TTL should diverge from the
    /// OIDC config.
    ///
    /// ```rust,ignore
    /// let store = DbSessionStore::new(repo).with_pre_auth_ttl_secs(120);
    /// ```
    pub fn with_pre_auth_ttl_secs(mut self, secs: i64) -> Self {
        self.pre_auth_ttl_secs =
            clamp_positive_ttl("pre_auth_ttl_secs", secs, DEFAULT_PRE_AUTH_TTL_SECS);
        self
    }

    /// Override the absolute ceiling (in seconds) on an authenticated
    /// session's total life, counted from `__bff_login_at`.
    ///
    /// Prefer [`Self::from_config`] to keep this in sync with
    /// [`crate::OidcBffConfig::max_session_lifetime`] automatically; use this
    /// setter directly only when the store's absolute lifetime should
    /// diverge from the OIDC config.
    ///
    /// ```rust,ignore
    /// let store = DbSessionStore::new(repo).with_max_lifetime_secs(3600);
    /// ```
    pub fn with_max_lifetime_secs(mut self, secs: i64) -> Self {
        self.max_lifetime_secs =
            clamp_positive_ttl("max_lifetime_secs", secs, DEFAULT_MAX_SESSION_LIFETIME_SECS);
        self
    }

    /// Override the minimum forward movement (seconds) required before
    /// `update_ttl()` issues a `touch()` write.
    ///
    /// Under [`crate::config::SessionExpiry::Sliding`], every authenticated
    /// request would otherwise trigger a write to extend the expiry by a
    /// handful of seconds. Coalescing collapses that into roughly one write
    /// per `touch_coalesce_secs` of active use, which is irrelevant against
    /// an idle window measured in hours. Defaults to 60 s.
    pub fn with_touch_coalesce_secs(mut self, secs: i64) -> Self {
        self.touch_coalesce_secs = clamp_touch_coalesce_secs(secs);
        self
    }

    /// Compute the expiry to persist for `state`, or `None` when the session
    /// must be treated as dead.
    ///
    /// - **Anonymous** (no `sub`): `now + min(ttl_secs, pre_auth_ttl_secs)`.
    /// - **Authenticated** (has `sub`): bounded by the absolute lifetime
    ///   computed from `__bff_login_at`; see [`hard_cap_expiry`] for the exact
    ///   conditions under which this returns `None` (missing/unparsable/
    ///   future-skewed `__bff_login_at`, or an expired/overflowing hard cap).
    fn effective_expiry(
        &self,
        state: &HashMap<String, String>,
        ttl_secs: i64,
    ) -> Option<DateTime<Utc>> {
        compute_effective_expiry(
            state,
            ttl_secs,
            self.pre_auth_ttl_secs,
            self.max_lifetime_secs,
        )
    }

    /// Returns `true` if the state contains any token key that must not be
    /// re-inserted after a session has been purged (do-not-resurrect guard).
    fn state_has_tokens(session_state: &HashMap<String, String>) -> bool {
        session_state.contains_key(session_state::ACCESS_TOKEN)
            || session_state.contains_key(session_state::REFRESH_TOKEN)
            || session_state.contains_key(session_state::ID_TOKEN)
    }

    /// Inject `__bff_login_at = now()` into `state` when it is authenticated
    /// (`sub` present) but missing the login-time marker.
    ///
    /// Called only from `save()` — a genuinely new session, where `now()` is
    /// unambiguously the correct login time. This makes "every row inserted
    /// by `save()` carries `__bff_login_at`" a store-side invariant by
    /// construction, healing state from callers that forgot to set it (or a
    /// predecessor crate version that didn't have the field). Logged at
    /// `warn` because it should not normally happen — the callback sets this
    /// immediately after `session.renew()`. **Must not** be called from
    /// `update()`: an existing row missing `__bff_login_at` is dead (see
    /// module docs), and injecting `now()` there would silently restart its
    /// absolute-lifetime clock.
    fn inject_login_at_if_missing(state: &mut HashMap<String, String>) {
        if state.contains_key(session_state::SUB) && !state.contains_key(session_state::LOGIN_AT) {
            log::warn!(
                "store: authenticated session state is missing {:?}; injecting now() so the \
                 absolute session lifetime can still be enforced",
                session_state::LOGIN_AT
            );
            let ts = Utc::now().timestamp();
            // MUST be the JSON encoding of an i64 (bare digits, not a quoted
            // string): the read side (`Session::get` in the `Auth`
            // extractor) deserializes this value as JSON via
            // `session_state::login_at_from_json`. `i64` serialization is
            // infallible, but the fallback keeps this call site panic-free.
            let encoded = serde_json::to_string(&ts).unwrap_or_else(|_| ts.to_string());
            state.insert(session_state::LOGIN_AT.to_string(), encoded);
        }
    }
}

/// Default value (seconds) for [`DbSessionStore::with_touch_coalesce_secs`].
const DEFAULT_TOUCH_COALESCE_SECS: i64 = 60;

/// Clamp a builder-supplied TTL-like value (seconds) into `(0, MAX_TTL_SECS]`,
/// logging a warning and substituting `default` when out of range.
///
/// Mirrors the bounds `duration_to_ttl_secs` enforces for the builder's TTL
/// setters in `config.rs`, but the builders (`DbSessionStore::with_*`) are
/// infallible (`self -> Self`), so an out-of-range input is clamped rather
/// than rejected. Without this, e.g. `with_max_lifetime_secs(i64::MAX)` would
/// overflow `hard_cap_expiry`'s arithmetic and fail *closed* — treating every
/// authenticated session as already past its absolute lifetime.
fn clamp_positive_ttl(name: &str, secs: i64, default: i64) -> i64 {
    if secs <= 0 {
        log::warn!("store: {name} must be greater than 0, got {secs}; using default {default}s");
        default
    } else if secs > MAX_TTL_SECS {
        log::warn!(
            "store: {name} must not exceed {MAX_TTL_SECS} seconds (365 days), got {secs}; \
             clamping to the maximum"
        );
        MAX_TTL_SECS
    } else {
        secs
    }
}

/// Clamp a builder-supplied `touch_coalesce_secs` value into
/// `[0, MAX_TTL_SECS]`, logging a warning when out of range.
///
/// Unlike [`clamp_positive_ttl`], `0` is a valid coalescing window (it simply
/// disables coalescing — every forward movement is touched). A negative value
/// is rejected because it would make the `update_ttl()` write-skip guard
/// (`new_expiry - s.expires_at < window`) trivially always pass, silently
/// disabling coalescing in the opposite, unbounded-write-amplification
/// direction.
fn clamp_touch_coalesce_secs(secs: i64) -> i64 {
    if secs < 0 {
        log::warn!(
            "store: touch_coalesce_secs must not be negative, got {secs}; clamping to 0 \
             (coalescing disabled)"
        );
        0
    } else if secs > MAX_TTL_SECS {
        log::warn!(
            "store: touch_coalesce_secs must not exceed {MAX_TTL_SECS} seconds (365 days), got \
             {secs}; clamping to the maximum"
        );
        MAX_TTL_SECS
    } else {
        secs
    }
}

/// Parse `__bff_login_at` from a session state map.
///
/// Deserializes the raw stored value as JSON and delegates the encoding
/// decision to [`session_state::login_at_from_json`] — the single shared
/// definition of the `LOGIN_AT` encoding contract, also used by the `Auth`
/// extractor. Returns `None` if the key is absent or its value is neither
/// valid JSON nor one of the two accepted encodings.
fn parse_login_at(state: &HashMap<String, String>) -> Option<i64> {
    let raw = state.get(session_state::LOGIN_AT)?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    session_state::login_at_from_json(&value)
}

/// Compute the absolute (hard-cap) expiry for an authenticated row, or `None`
/// when the row must be treated as dead:
///
/// - `__bff_login_at` missing or unparsable by [`parse_login_at`];
/// - `__bff_login_at` more than [`session_state::LOGIN_AT_FUTURE_SKEW_SECS`]
///   in the future;
/// - `login_at + max_lifetime_secs` overflows; or
/// - the computed hard cap has already passed (`hard <= now`).
fn hard_cap_expiry(
    state: &HashMap<String, String>,
    now: DateTime<Utc>,
    max_lifetime_secs: i64,
) -> Option<DateTime<Utc>> {
    let login_at = parse_login_at(state)?;
    let login_at_dt = DateTime::<Utc>::from_timestamp(login_at, 0)?;

    if login_at_dt > now + chrono::Duration::seconds(session_state::LOGIN_AT_FUTURE_SKEW_SECS) {
        return None;
    }

    let max_dur = chrono::Duration::try_seconds(max_lifetime_secs)?;
    let hard = login_at_dt.checked_add_signed(max_dur)?;

    if hard <= now {
        None
    } else {
        Some(hard)
    }
}

/// Compute the expiry to persist for `state` given the requested `ttl_secs`,
/// or `None` when the session must be treated as dead. See
/// [`DbSessionStore::effective_expiry`] for the field-level summary and
/// [`hard_cap_expiry`] for the authenticated dead-session conditions.
fn compute_effective_expiry(
    state: &HashMap<String, String>,
    ttl_secs: i64,
    pre_auth_ttl_secs: i64,
    max_lifetime_secs: i64,
) -> Option<DateTime<Utc>> {
    let now = Utc::now();

    if !state.contains_key(session_state::SUB) {
        let capped = ttl_secs.min(pre_auth_ttl_secs);
        let dur = chrono::Duration::try_seconds(capped)?;
        return now.checked_add_signed(dur);
    }

    let hard = hard_cap_expiry(state, now, max_lifetime_secs)?;
    let ttl_dur = chrono::Duration::try_seconds(ttl_secs)?;
    let candidate = now.checked_add_signed(ttl_dur)?;
    Some(candidate.min(hard))
}

fn generate_session_key() -> Result<SessionKey, anyhow::Error> {
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    SessionKey::try_from(key).map_err(|e| anyhow::anyhow!("Invalid session key: {e}"))
}

/// `now + ttl_secs`, falling back to a 12-hour expiry on overflow (i.e. an
/// absurd `ttl_secs` input) rather than panicking.
///
/// Used only by the missing-row fallback insert in `update()` — the primary
/// save/update/update_ttl paths use [`compute_effective_expiry`], which
/// applies the pre-auth cap and absolute lifetime and returns `None` (rather
/// than silently falling back) on overflow.
fn expiry_from_ttl(ttl_secs: i64) -> DateTime<Utc> {
    Utc::now()
        + chrono::Duration::try_seconds(ttl_secs).unwrap_or_else(|| chrono::Duration::hours(12))
}

impl<R> SessionStore for DbSessionStore<R>
where
    R: SessionRepository,
{
    fn load(
        &self,
        session_key: &SessionKey,
    ) -> impl Future<Output = Result<Option<HashMap<String, String>>, LoadError>> {
        let repo = self.repo.clone();
        let key = session_key.as_ref().to_owned();
        let max_lifetime_secs = self.max_lifetime_secs;

        async move {
            let session = repo
                .get(&key)
                .await
                .map_err(|e| LoadError::Other(anyhow::anyhow!("get session failed: {e}")))?;

            match session {
                None => Ok(None),
                Some(s) => {
                    let now = Utc::now();

                    // Enforce expiry regardless of whether the repository already
                    // filtered the row (defense-in-depth for non-compliant repos).
                    if s.expires_at <= now {
                        if let Err(e) = repo.delete(&key).await {
                            log::warn!(
                                "store::load: best-effort delete of expired session {key:?} failed: {e}"
                            );
                        }
                        return Ok(None);
                    }

                    let state: HashMap<String, String> = serde_json::from_str(&s.state)
                        .map_err(|e| LoadError::Deserialization(anyhow::anyhow!("{e}")))?;

                    // Authoritative absolute-lifetime check: runs on every
                    // request carrying a cookie. A `sub`-bearing row whose
                    // hard cap has passed (or whose __bff_login_at is
                    // missing/unparsable/future-skewed) is dead.
                    if state.contains_key(session_state::SUB)
                        && hard_cap_expiry(&state, now, max_lifetime_secs).is_none()
                    {
                        if let Err(e) = repo.delete(&key).await {
                            log::warn!(
                                "store::load: best-effort delete of session {key:?} past its \
                                 absolute lifetime failed: {e}"
                            );
                        }
                        return Ok(None);
                    }

                    Ok(Some(state))
                }
            }
        }
    }

    fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &CookieDuration,
    ) -> impl Future<Output = Result<SessionKey, SaveError>> {
        let repo = self.repo.clone();
        let mut session_state = session_state;
        Self::inject_login_at_if_missing(&mut session_state);

        let ttl_secs = ttl.whole_seconds();
        let expires_at = self
            .effective_expiry(&session_state, ttl_secs)
            .ok_or_else(|| {
                SaveError::Other(anyhow::anyhow!(
                    "computed session expiry is invalid (overflow or dead session)"
                ))
            });

        async move {
            let expires_at = expires_at?;

            let session_key = generate_session_key()
                .map_err(|e| SaveError::Other(anyhow::anyhow!("Key generation failed: {e}")))?;

            let state = serde_json::to_string(&session_state)
                .map_err(|e| SaveError::Serialization(anyhow::anyhow!("{e}")))?;

            let record = SessionRecord {
                session_key: session_key.as_ref().to_owned(),
                state,
                expires_at,
            };

            repo.insert(&record)
                .await
                .map_err(|e| SaveError::Other(anyhow::anyhow!("insert session failed: {e}")))?;

            Ok(session_key)
        }
    }

    fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &CookieDuration,
    ) -> impl Future<Output = Result<SessionKey, UpdateError>> {
        let repo = self.repo.clone();

        let ttl_secs = ttl.whole_seconds();
        // Computed synchronously (before any I/O) from the state as it will
        // be persisted, so a session past its absolute lifetime never reaches
        // repo.update() — see the module-level "Absolute session lifetime"
        // docs for why this ordering matters. Deliberately does NOT call
        // `inject_login_at_if_missing` (only `save()` does): a `sub`-bearing
        // row with no `__bff_login_at` here is an *existing* session that
        // lost its marker, not a new one, so `effective_expiry` correctly
        // treats it as dead (`None`) below rather than minting a fresh
        // absolute-lifetime clock for it.
        let expiry = self.effective_expiry(&session_state, ttl_secs);
        let pre_auth_ttl_secs = self.pre_auth_ttl_secs;

        async move {
            let state = serde_json::to_string(&session_state)
                .map_err(|e| UpdateError::Serialization(anyhow::anyhow!("{e}")))?;

            let Some(expires_at) = expiry else {
                // Dead session (past the absolute lifetime, or an
                // unparsable/missing __bff_login_at): delete and return the
                // stale key. Returning early here — before repo.update() is
                // ever called — is what stops the missing-row fallback below
                // from minting a fresh row for a session that has exceeded
                // its cap, AND what stops a request that stripped
                // `__bff_login_at` from an otherwise-live session from
                // restarting its absolute-lifetime clock.
                if let Err(e) = repo.delete(session_key.as_ref()).await {
                    log::warn!(
                        "store::update: best-effort delete of dead session {:?} failed: {e}",
                        session_key.as_ref()
                    );
                }
                return Ok(session_key);
            };

            let row_existed = repo
                .update(session_key.as_ref(), &state, expires_at)
                .await
                .map_err(|e| UpdateError::Other(anyhow::anyhow!("update session failed: {e}")))?;

            if row_existed {
                return Ok(session_key);
            }

            // Missing-row fallback: the session was purged (logout) or expired
            // between load and update.

            // Do-not-resurrect guard: if the state carries any token key, drop
            // the write and return the stale key. A request racing a logout must
            // not be able to recreate a token-bearing row — logout is
            // authoritative. The stale key resolves to nothing on the next load.
            if Self::state_has_tokens(&session_state) {
                log::warn!(
                    "store::update: session key {:?} is missing and state contains tokens — \
                     dropping write to honour purge",
                    session_key.as_ref()
                );
                return Ok(session_key);
            }

            // Token-free state (pre-auth / anonymous): mirror actix-session's
            // Redis semantics by generating a new key and inserting. Apply the
            // pre-auth TTL cap so this fallback cannot reopen the DoS window.
            let new_key = generate_session_key()
                .map_err(|e| UpdateError::Other(anyhow::anyhow!("Key generation failed: {e}")))?;

            let capped_ttl = ttl_secs.min(pre_auth_ttl_secs);
            let record = SessionRecord {
                session_key: new_key.as_ref().to_owned(),
                state,
                expires_at: expiry_from_ttl(capped_ttl),
            };

            repo.insert(&record)
                .await
                .map_err(|e| UpdateError::Other(anyhow::anyhow!("insert session failed: {e}")))?;

            Ok(new_key)
        }
    }

    fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &CookieDuration,
    ) -> impl Future<Output = Result<(), anyhow::Error>> {
        let repo = self.repo.clone();
        let key = session_key.as_ref().to_owned();
        let ttl_secs = ttl.whole_seconds();
        let pre_auth_ttl_secs = self.pre_auth_ttl_secs;
        let max_lifetime_secs = self.max_lifetime_secs;
        let touch_coalesce_secs = self.touch_coalesce_secs;

        async move {
            // (1) Missing row: never insert. A TTL refresh must not resurrect
            // a session purged by a concurrent logout.
            let Some(s) = repo
                .get(&key)
                .await
                .map_err(|e| anyhow::anyhow!("get session failed: {e}"))?
            else {
                return Ok(());
            };

            let now = Utc::now();

            // (2) Defense-in-depth, mirroring the check in load(): a row the
            // repository failed to filter server-side is dead regardless of
            // what follows.
            if s.expires_at <= now {
                if let Err(e) = repo.delete(&key).await {
                    log::warn!(
                        "store::update_ttl: best-effort delete of expired session {key:?} \
                         failed: {e}"
                    );
                }
                return Ok(());
            }

            let state: HashMap<String, String> = match serde_json::from_str(&s.state) {
                Ok(state) => state,
                Err(e) => {
                    log::warn!(
                        "store::update_ttl: undeserializable state for session {key:?}, \
                         deleting: {e}"
                    );
                    if let Err(e) = repo.delete(&key).await {
                        log::warn!(
                            "store::update_ttl: best-effort delete of undeserializable session \
                             {key:?} failed: {e}"
                        );
                    }
                    return Ok(());
                }
            };

            // (3) Anonymous/pre-auth rows are never renewed here — this is
            // the fix for the defect this module addresses. `update_ttl`
            // fires for ANY unchanged session under sliding expiry,
            // authenticated or not (see vendored actix-session
            // middleware.rs). Pre-auth state completes in seconds and has no
            // legitimate need for sliding renewal — renewing it here would
            // only widen the flood window for free, letting an attacker keep
            // flood rows alive indefinitely by pinging once per coalescing
            // window instead of re-authenticating every `pre_auth_ttl_secs`.
            if !state.contains_key(session_state::SUB) {
                return Ok(());
            }

            // (4) Absolute-lifetime clamp for authenticated rows.
            let Some(new_expiry) =
                compute_effective_expiry(&state, ttl_secs, pre_auth_ttl_secs, max_lifetime_secs)
            else {
                if let Err(e) = repo.delete(&key).await {
                    log::warn!(
                        "store::update_ttl: best-effort delete of session {key:?} past its \
                         absolute lifetime failed: {e}"
                    );
                }
                return Ok(());
            };

            // (5) Write-skip guard — applied AFTER the hard-cap clamp above.
            // This ordering is the whole security property fixed here: if a
            // future refactor moved this comparison before the clamp, an
            // attacker could keep renewing an authenticated row up to
            // `ttl_secs` at a time regardless of the absolute cap, silently
            // reopening a bypass equivalent to the one this module fixes for
            // anonymous rows. Do not reorder without also updating
            // `update_ttl_clamp_applied_before_write_skip_guard`.
            if new_expiry <= s.expires_at {
                // Would not move the expiry forward at all (e.g. already
                // clamped to the hard cap on a previous call).
                return Ok(());
            }
            // `try_seconds` (rather than `seconds`, which panics for
            // |secs| > i64::MAX / 1000) as defence in depth: `with_touch_coalesce_secs`
            // already clamps to `[0, MAX_TTL_SECS]`, so this can't actually
            // fail, but a fallback to "no coalescing window" (0s) is a safe,
            // fail-open default if that invariant is ever broken — it can
            // only cause an extra write, never bypass a security check.
            let coalesce_window = chrono::Duration::try_seconds(touch_coalesce_secs)
                .unwrap_or_else(|| chrono::Duration::seconds(0));
            if new_expiry - s.expires_at < coalesce_window {
                // Moves forward, but by less than the coalescing window —
                // skip to bound write amplification from chatty clients.
                return Ok(());
            }

            // (6)
            repo.touch(&key, new_expiry)
                .await
                .map_err(|e| anyhow::anyhow!("touch session failed: {e}"))?;
            Ok(())
        }
    }

    fn delete(&self, session_key: &SessionKey) -> impl Future<Output = Result<(), anyhow::Error>> {
        let repo = self.repo.clone();
        let key = session_key.as_ref().to_owned();

        async move {
            repo.delete(&key)
                .await
                .map_err(|e| anyhow::anyhow!("delete session failed: {e}"))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    // ---------------------------------------------------------------------------
    // InMemoryRepo — test double
    // ---------------------------------------------------------------------------

    /// A simple in-memory [`SessionRepository`] that records every `delete`,
    /// `touch`, and `insert` call so tests can assert best-effort cleanup and
    /// write-skip behaviour.
    ///
    /// `update()` returns `Ok(true)` when the key exists and `Ok(false)` when it
    /// does not, matching the [`SessionRepository`] contract. `touch()` follows
    /// the documented contract: it only updates a row that already exists and
    /// never inserts.
    struct InMemoryRepo {
        rows: Mutex<HashMap<String, SessionRecord>>,
        deletes: Mutex<Vec<String>>,
        touches: Mutex<Vec<String>>,
        inserts: Mutex<Vec<String>>,
        /// When set, `get()` returns this error instead of consulting `rows`.
        get_error: Mutex<Option<String>>,
    }

    impl InMemoryRepo {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                deletes: Mutex::new(Vec::new()),
                touches: Mutex::new(Vec::new()),
                inserts: Mutex::new(Vec::new()),
                get_error: Mutex::new(None),
            }
        }

        fn seed(&self, record: SessionRecord) {
            self.rows
                .lock()
                .unwrap()
                .insert(record.session_key.clone(), record);
        }

        fn deleted_keys(&self) -> Vec<String> {
            self.deletes.lock().unwrap().clone()
        }

        fn touch_count(&self) -> usize {
            self.touches.lock().unwrap().len()
        }

        fn insert_count(&self) -> usize {
            self.inserts.lock().unwrap().len()
        }

        fn row_count(&self) -> usize {
            self.rows.lock().unwrap().len()
        }

        fn get_row(&self, key: &str) -> Option<SessionRecord> {
            self.rows.lock().unwrap().get(key).cloned()
        }

        fn fail_get_with(&self, msg: &str) {
            *self.get_error.lock().unwrap() = Some(msg.to_string());
        }
    }

    #[async_trait]
    impl SessionRepository for InMemoryRepo {
        async fn get(&self, session_key: &str) -> Result<Option<SessionRecord>, RepoError> {
            if let Some(msg) = self.get_error.lock().unwrap().clone() {
                return Err(msg.into());
            }
            Ok(self.rows.lock().unwrap().get(session_key).cloned())
        }

        async fn insert(&self, record: &SessionRecord) -> Result<(), RepoError> {
            self.inserts
                .lock()
                .unwrap()
                .push(record.session_key.clone());
            self.rows
                .lock()
                .unwrap()
                .insert(record.session_key.clone(), record.clone());
            Ok(())
        }

        async fn update(
            &self,
            session_key: &str,
            state: &str,
            expires_at: DateTime<Utc>,
        ) -> Result<bool, RepoError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(rec) = rows.get_mut(session_key) {
                rec.state = state.to_owned();
                rec.expires_at = expires_at;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn touch(
            &self,
            session_key: &str,
            expires_at: DateTime<Utc>,
        ) -> Result<(), RepoError> {
            self.touches.lock().unwrap().push(session_key.to_owned());
            let mut rows = self.rows.lock().unwrap();
            if let Some(rec) = rows.get_mut(session_key) {
                rec.expires_at = expires_at;
            }
            Ok(())
        }

        async fn delete(&self, session_key: &str) -> Result<(), RepoError> {
            self.rows.lock().unwrap().remove(session_key);
            self.deletes.lock().unwrap().push(session_key.to_owned());
            Ok(())
        }
    }

    /// Variant that always fails `delete()` — used to verify that a failing
    /// best-effort delete does not propagate as an error.
    ///
    /// `update()` delegates to the inner repo and returns `Ok(true)`/`Ok(false)`
    /// per the [`SessionRepository`] contract.
    struct FailingDeleteRepo {
        inner: InMemoryRepo,
    }

    impl FailingDeleteRepo {
        fn new() -> Self {
            Self {
                inner: InMemoryRepo::new(),
            }
        }

        fn seed(&self, record: SessionRecord) {
            self.inner.seed(record);
        }
    }

    #[async_trait]
    impl SessionRepository for FailingDeleteRepo {
        async fn get(&self, session_key: &str) -> Result<Option<SessionRecord>, RepoError> {
            self.inner.get(session_key).await
        }

        async fn insert(&self, record: &SessionRecord) -> Result<(), RepoError> {
            self.inner.insert(record).await
        }

        async fn update(
            &self,
            session_key: &str,
            state: &str,
            expires_at: DateTime<Utc>,
        ) -> Result<bool, RepoError> {
            self.inner.update(session_key, state, expires_at).await
        }

        async fn touch(
            &self,
            session_key: &str,
            expires_at: DateTime<Utc>,
        ) -> Result<(), RepoError> {
            self.inner.touch(session_key, expires_at).await
        }

        async fn delete(&self, _session_key: &str) -> Result<(), RepoError> {
            Err("simulated delete failure".into())
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    fn make_state(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn past_expiry() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::seconds(1)
    }

    fn ttl_one_hour() -> CookieDuration {
        CookieDuration::hours(1)
    }

    fn ttl_twelve_hours() -> CookieDuration {
        CookieDuration::hours(12)
    }

    fn random_key_str() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

    fn pre_auth_state() -> HashMap<String, String> {
        make_state(&[("oidc_state", "abc123"), ("nonce", "xyz")])
    }

    /// State with `LOGIN_AT` set to `now`, JSON-encoded as `Session::insert`
    /// would encode an `i64` (bare digits, no quotes).
    fn authenticated_state() -> HashMap<String, String> {
        let mut state = make_state(&[
            (session_state::SUB, "user-42"),
            ("email", "user@example.com"),
        ]);
        state.insert(
            session_state::LOGIN_AT.to_string(),
            Utc::now().timestamp().to_string(),
        );
        state
    }

    fn token_bearing_state() -> HashMap<String, String> {
        let mut state = make_state(&[
            (session_state::SUB, "user-42"),
            (session_state::ACCESS_TOKEN, "at-secret"),
            (session_state::REFRESH_TOKEN, "rt-secret"),
            (session_state::ID_TOKEN, "idt-secret"),
        ]);
        state.insert(
            session_state::LOGIN_AT.to_string(),
            Utc::now().timestamp().to_string(),
        );
        state
    }

    fn seed_authenticated_row(repo: &InMemoryRepo, key_str: &str, expires_in: chrono::Duration) {
        repo.seed(SessionRecord {
            session_key: key_str.to_owned(),
            state: serde_json::to_string(&authenticated_state()).unwrap(),
            expires_at: Utc::now() + expires_in,
        });
    }

    // ---------------------------------------------------------------------------
    // A-1: Pre-auth TTL cap tests
    // ---------------------------------------------------------------------------

    /// A-1 — save caps TTL for pre-auth state (no `sub` key).
    ///
    /// The row's `expires_at` must be within ±2 s of `now + 600 s` even though
    /// a 12-hour TTL was passed.
    #[actix_web::test]
    async fn save_caps_ttl_for_pre_auth_state() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let before = Utc::now();
        let key = store
            .save(pre_auth_state(), &ttl_twelve_hours())
            .await
            .unwrap();
        let after = Utc::now();

        let row = repo.get_row(key.as_ref()).unwrap();
        let lower = before + chrono::Duration::seconds(598);
        let upper = after + chrono::Duration::seconds(602);
        assert!(
            row.expires_at >= lower && row.expires_at <= upper,
            "pre-auth save: expected expires_at ≈ now+600s, got {:?}",
            row.expires_at
        );
    }

    /// A-1 — save keeps full TTL for authenticated state (has `sub` key).
    #[actix_web::test]
    async fn save_keeps_full_ttl_for_authenticated_state() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let before = Utc::now();
        let key = store
            .save(authenticated_state(), &ttl_twelve_hours())
            .await
            .unwrap();
        let after = Utc::now();

        let row = repo.get_row(key.as_ref()).unwrap();
        let lower = before + chrono::Duration::hours(11);
        let upper = after + chrono::Duration::hours(13);
        assert!(
            row.expires_at >= lower && row.expires_at <= upper,
            "auth save: expected expires_at ≈ now+12h, got {:?}",
            row.expires_at
        );
    }

    /// A-1 — update caps TTL for pre-auth state.
    #[actix_web::test]
    async fn update_caps_ttl_for_pre_auth_state() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        // Seed a row so update() finds it.
        let key_str = random_key_str();
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: "{}".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        let before = Utc::now();
        store
            .update(session_key, pre_auth_state(), &ttl_twelve_hours())
            .await
            .unwrap();
        let after = Utc::now();

        let row = repo.get_row(&key_str).unwrap();
        let lower = before + chrono::Duration::seconds(598);
        let upper = after + chrono::Duration::seconds(602);
        assert!(
            row.expires_at >= lower && row.expires_at <= upper,
            "pre-auth update: expected expires_at ≈ now+600s, got {:?}",
            row.expires_at
        );
    }

    /// A-1 — update keeps full TTL for authenticated state.
    #[actix_web::test]
    async fn update_keeps_full_ttl_for_authenticated_state() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let key_str = random_key_str();
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: "{}".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        let before = Utc::now();
        store
            .update(session_key, authenticated_state(), &ttl_twelve_hours())
            .await
            .unwrap();
        let after = Utc::now();

        let row = repo.get_row(&key_str).unwrap();
        let lower = before + chrono::Duration::hours(11);
        let upper = after + chrono::Duration::hours(13);
        assert!(
            row.expires_at >= lower && row.expires_at <= upper,
            "auth update: expected expires_at ≈ now+12h, got {:?}",
            row.expires_at
        );
    }

    /// A-1 — custom pre-auth TTL override is respected in save().
    #[actix_web::test]
    async fn with_pre_auth_ttl_override_respected() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone()).with_pre_auth_ttl_secs(120);

        let before = Utc::now();
        let key = store
            .save(pre_auth_state(), &ttl_twelve_hours())
            .await
            .unwrap();
        let after = Utc::now();

        let row = repo.get_row(key.as_ref()).unwrap();
        let lower = before + chrono::Duration::seconds(118);
        let upper = after + chrono::Duration::seconds(122);
        assert!(
            row.expires_at >= lower && row.expires_at <= upper,
            "custom cap: expected expires_at ≈ now+120s, got {:?}",
            row.expires_at
        );
    }

    /// Superseded A-1 review amendment, now inverted by the CRITICAL fix:
    /// `update()` must NOT inject `LOGIN_AT` for a `sub`-bearing row that
    /// arrives without one — that would silently restart the absolute
    /// lifetime clock for anything that stripped the marker from an
    /// otherwise-live session (see module docs). Mixed state (both `sub`
    /// and pre-auth fields, no `LOGIN_AT`) is therefore treated as dead: the
    /// row is deleted, the stale key is returned, and no new row is
    /// created. See `update_on_sub_without_login_at_is_treated_as_dead`
    /// below for the full assertion set.
    #[actix_web::test]
    async fn update_mixed_state_without_login_at_is_treated_as_dead() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let key_str = random_key_str();
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: "{}".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // State has both `sub` (authenticated) and an oidc_pre_auth field,
        // but deliberately no LOGIN_AT.
        let mixed_state =
            make_state(&[(session_state::SUB, "user-42"), ("oidc_pre_auth", "[...]")]);

        let returned_key = store
            .update(session_key, mixed_state, &ttl_twelve_hours())
            .await
            .unwrap();

        assert_eq!(
            returned_key.as_ref(),
            key_str,
            "dead session: stale key must be returned"
        );
        assert!(
            repo.get_row(&key_str).is_none(),
            "row missing LOGIN_AT must be deleted, not healed with a fresh clock"
        );
    }

    // ---------------------------------------------------------------------------
    // A-2: update() missing-row contract
    // ---------------------------------------------------------------------------

    /// A-2 — when the row is absent and state is token-free (pre-auth), the
    /// adapter falls back to generating a new key and inserting the row, just as
    /// actix-session's Redis store does. The returned key must differ from the
    /// stale one, and the new row must exist in the repo with the A-1 capped TTL.
    #[actix_web::test]
    async fn update_missing_key_falls_back_to_save_for_pre_auth_state() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        // Use a key that was never inserted.
        let stale_key_str = random_key_str();
        let stale_key = SessionKey::try_from(stale_key_str.clone()).unwrap();

        let before = Utc::now();
        let returned_key = store
            .update(stale_key, pre_auth_state(), &ttl_twelve_hours())
            .await
            .unwrap();
        let after = Utc::now();

        // A new key must have been generated.
        assert_ne!(
            returned_key.as_ref(),
            stale_key_str,
            "fallback must return a new key"
        );

        // The new key must exist in the repo.
        let new_row = repo.get_row(returned_key.as_ref());
        assert!(
            new_row.is_some(),
            "fallback must insert a new row in the repo"
        );

        // The new row must have the capped TTL (≈ now+600s).
        let row = new_row.unwrap();
        let lower = before + chrono::Duration::seconds(598);
        let upper = after + chrono::Duration::seconds(602);
        assert!(
            row.expires_at >= lower && row.expires_at <= upper,
            "fallback insert: expected capped TTL ≈ now+600s, got {:?}",
            row.expires_at
        );

        // The stale key must NOT have been inserted.
        assert!(
            repo.get_row(&stale_key_str).is_none(),
            "stale key must not appear in repo"
        );
    }

    /// A-2 — do-not-resurrect guard: when the row is absent and state contains
    /// token keys, the write must be dropped and the stale key returned. No new
    /// row must be inserted.
    #[actix_web::test]
    async fn update_missing_key_with_tokens_is_not_resurrected() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let stale_key_str = random_key_str();
        let stale_key = SessionKey::try_from(stale_key_str.clone()).unwrap();

        let row_count_before = repo.row_count();

        let returned_key = store
            .update(stale_key, token_bearing_state(), &ttl_twelve_hours())
            .await
            .unwrap();

        // The stale key must be returned unchanged.
        assert_eq!(
            returned_key.as_ref(),
            stale_key_str,
            "do-not-resurrect: must return the stale key"
        );

        // No new row must have been inserted.
        assert_eq!(
            repo.row_count(),
            row_count_before,
            "do-not-resurrect: repo must remain unchanged"
        );
    }

    /// A-2 — when the key exists, the same key is returned (non-fallback path).
    #[actix_web::test]
    async fn update_existing_key_returns_same_key() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let initial_state = make_state(&[("v", "1")]);
        let key = store.save(initial_state, &ttl_one_hour()).await.unwrap();

        let key_str_before = key.as_ref().to_owned();
        let new_state = make_state(&[("v", "2")]);
        let returned_key = store.update(key, new_state, &ttl_one_hour()).await.unwrap();

        assert_eq!(
            returned_key.as_ref(),
            key_str_before,
            "existing key: returned key must be unchanged"
        );
    }

    // ---------------------------------------------------------------------------
    // Absolute session lifetime: effective_expiry table
    // ---------------------------------------------------------------------------

    /// Anonymous state is capped at `min(ttl_secs, pre_auth_ttl_secs)`
    /// regardless of `LOGIN_AT` / max lifetime.
    #[actix_web::test]
    async fn effective_expiry_anonymous_capped_at_pre_auth_ttl() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_pre_auth_ttl_secs(120);
        let before = Utc::now();
        let expiry = store
            .effective_expiry(&pre_auth_state(), 12 * 3600)
            .expect("anonymous state must always produce Some");
        let after = Utc::now();
        assert!(expiry >= before + chrono::Duration::seconds(118));
        assert!(expiry <= after + chrono::Duration::seconds(122));
    }

    /// Authenticated state well within its lifetime gets the requested TTL.
    #[actix_web::test]
    async fn effective_expiry_authenticated_normal() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let before = Utc::now();
        let expiry = store
            .effective_expiry(&authenticated_state(), 3600)
            .expect("normal authenticated state must produce Some");
        let after = Utc::now();
        assert!(expiry >= before + chrono::Duration::seconds(3598));
        assert!(expiry <= after + chrono::Duration::seconds(3602));
    }

    /// A TTL that would extend past the absolute lifetime is clamped to it.
    #[actix_web::test]
    async fn effective_expiry_clamped_at_hard_cap() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_max_lifetime_secs(3600);
        let login_at = Utc::now().timestamp() - 3000; // logged in 3000s ago
        let mut state = authenticated_state();
        state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());

        // Requesting an 8h TTL — far beyond the 1h max lifetime from login.
        let expiry = store
            .effective_expiry(&state, 8 * 3600)
            .expect("session within its lifetime must produce Some");

        let expected_hard =
            DateTime::<Utc>::from_timestamp(login_at, 0).unwrap() + chrono::Duration::seconds(3600);
        assert!(
            (expiry - expected_hard).num_seconds().abs() <= 1,
            "expected clamp to hard cap {expected_hard:?}, got {expiry:?}"
        );
    }

    /// A session whose absolute lifetime has already passed is dead.
    #[actix_web::test]
    async fn effective_expiry_past_hard_cap_is_none() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_max_lifetime_secs(3600);
        let login_at = Utc::now().timestamp() - 7200; // logged in 2h ago, max is 1h
        let mut state = authenticated_state();
        state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());

        assert!(store.effective_expiry(&state, 3600).is_none());
    }

    /// Authenticated state with no `LOGIN_AT` at all is dead.
    #[actix_web::test]
    async fn effective_expiry_missing_login_at_is_none() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let state = make_state(&[(session_state::SUB, "user-42")]);
        assert!(store.effective_expiry(&state, 3600).is_none());
    }

    /// Authenticated state with an unparsable `LOGIN_AT` is dead.
    #[actix_web::test]
    async fn effective_expiry_unparsable_login_at_is_none() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let mut state = make_state(&[(session_state::SUB, "user-42")]);
        state.insert(
            session_state::LOGIN_AT.to_string(),
            "not-a-number".to_string(),
        );
        assert!(store.effective_expiry(&state, 3600).is_none());
    }

    /// A `LOGIN_AT` far enough in the future (beyond the skew allowance) is
    /// dead — mirrors the negative-age rejection in `prune_expired`.
    #[actix_web::test]
    async fn effective_expiry_future_login_at_is_none() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let mut state = make_state(&[(session_state::SUB, "user-42")]);
        let future = Utc::now().timestamp() + 3600;
        state.insert(session_state::LOGIN_AT.to_string(), future.to_string());
        assert!(store.effective_expiry(&state, 3600).is_none());
    }

    /// A `LOGIN_AT` within the skew allowance is accepted.
    #[actix_web::test]
    async fn effective_expiry_login_at_within_skew_accepted() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let mut state = make_state(&[(session_state::SUB, "user-42")]);
        let slightly_future = Utc::now().timestamp() + 30;
        state.insert(
            session_state::LOGIN_AT.to_string(),
            slightly_future.to_string(),
        );
        assert!(store.effective_expiry(&state, 3600).is_some());
    }

    /// `login_at + max_lifetime_secs` overflowing i64 yields `None` rather
    /// than panicking.
    #[actix_web::test]
    async fn effective_expiry_overflow_is_none() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_max_lifetime_secs(i64::MAX);
        let mut state = make_state(&[(session_state::SUB, "user-42")]);
        state.insert(session_state::LOGIN_AT.to_string(), i64::MAX.to_string());
        assert!(store.effective_expiry(&state, 3600).is_none());
    }

    /// Both JSON encodings of `LOGIN_AT` that `Session::insert` can produce —
    /// a bare number (from an `i64`) and a quoted string (from a `String`) —
    /// parse identically.
    #[actix_web::test]
    async fn effective_expiry_accepts_both_login_at_encodings() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let now = Utc::now().timestamp();

        let mut bare_number_state = make_state(&[(session_state::SUB, "user-42")]);
        bare_number_state.insert(session_state::LOGIN_AT.to_string(), now.to_string());

        let mut quoted_string_state = make_state(&[(session_state::SUB, "user-42")]);
        quoted_string_state.insert(session_state::LOGIN_AT.to_string(), format!("\"{now}\""));

        let a = store
            .effective_expiry(&bare_number_state, 3600)
            .expect("bare number encoding must parse");
        let b = store
            .effective_expiry(&quoted_string_state, 3600)
            .expect("quoted string encoding must parse");

        assert!(
            (a - b).num_seconds().abs() <= 1,
            "both encodings must yield the same expiry: {a:?} vs {b:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // from_config / from_arc_with_config
    // ---------------------------------------------------------------------------

    /// `from_config` wires both `pre_auth_ttl_secs` and `max_lifetime_secs`
    /// from a non-default [`crate::OidcBffConfig`].
    #[actix_web::test]
    async fn from_config_picks_up_both_ttls_from_config() {
        let cfg = crate::config::test_config_builder()
            .pre_auth_ttl(Duration::from_secs(120))
            .post_auth_ttl(Duration::from_secs(1800))
            .max_session_lifetime(Duration::from_secs(3600))
            .build()
            .unwrap();

        let store = DbSessionStore::from_config(InMemoryRepo::new(), &cfg);

        assert_eq!(store.pre_auth_ttl_secs, 120);
        assert_eq!(store.max_lifetime_secs, 3600);
        // Untouched by from_config — stays at its own default.
        assert_eq!(store.touch_coalesce_secs, DEFAULT_TOUCH_COALESCE_SECS);
    }

    /// `from_arc_with_config` behaves identically to `from_config` when
    /// starting from an existing `Arc<R>`.
    #[actix_web::test]
    async fn from_arc_with_config_picks_up_both_ttls_from_config() {
        let cfg = crate::config::test_config_builder()
            .pre_auth_ttl(Duration::from_secs(90))
            .post_auth_ttl(Duration::from_secs(1800))
            .max_session_lifetime(Duration::from_secs(7200))
            .build()
            .unwrap();

        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc_with_config(repo, &cfg);

        assert_eq!(store.pre_auth_ttl_secs, 90);
        assert_eq!(store.max_lifetime_secs, 7200);
    }

    /// `from_config` must diverge from `new()`'s hard-coded defaults when the
    /// config carries non-default TTLs — this is the whole reason
    /// `from_config` exists: `new()` silently ignores the config entirely.
    #[actix_web::test]
    async fn from_config_differs_from_new_when_config_is_non_default() {
        let cfg = crate::config::test_config_builder()
            .pre_auth_ttl(Duration::from_secs(120))
            .post_auth_ttl(Duration::from_secs(1800))
            .max_session_lifetime(Duration::from_secs(3600))
            .build()
            .unwrap();

        let default_store = DbSessionStore::new(InMemoryRepo::new());
        let configured_store = DbSessionStore::from_config(InMemoryRepo::new(), &cfg);

        assert_ne!(
            default_store.pre_auth_ttl_secs,
            configured_store.pre_auth_ttl_secs
        );
        assert_ne!(
            default_store.max_lifetime_secs,
            configured_store.max_lifetime_secs
        );

        // And the behavioural effect actually differs: an anonymous row
        // requesting a 12h TTL is capped at the configured 120s under
        // from_config, but at the default 600s under new().
        let before = Utc::now();
        let default_expiry = default_store
            .effective_expiry(&pre_auth_state(), 12 * 3600)
            .unwrap();
        let configured_expiry = configured_store
            .effective_expiry(&pre_auth_state(), 12 * 3600)
            .unwrap();
        let after = Utc::now();

        assert!(configured_expiry < default_expiry);
        assert!(configured_expiry >= before + chrono::Duration::seconds(118));
        assert!(configured_expiry <= after + chrono::Duration::seconds(122));
    }

    // ---------------------------------------------------------------------------
    // Builder clamping (with_pre_auth_ttl_secs / with_max_lifetime_secs /
    // with_touch_coalesce_secs)
    // ---------------------------------------------------------------------------

    /// `with_pre_auth_ttl_secs` clamps a non-positive value to the default
    /// rather than persisting it (which would previously have panicked
    /// downstream at the `chrono::Duration::try_seconds` call site, or —
    /// for a negative value — computed an expiry in the past).
    #[actix_web::test]
    async fn with_pre_auth_ttl_secs_clamps_non_positive_to_default() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_pre_auth_ttl_secs(0);
        let before = Utc::now();
        let expiry = store
            .effective_expiry(&pre_auth_state(), 12 * 3600)
            .unwrap();
        let after = Utc::now();
        let lower = before + chrono::Duration::seconds(DEFAULT_PRE_AUTH_TTL_SECS - 2);
        let upper = after + chrono::Duration::seconds(DEFAULT_PRE_AUTH_TTL_SECS + 2);
        assert!(
            expiry >= lower && expiry <= upper,
            "expected fallback to the default pre-auth TTL, got {expiry:?}"
        );
    }

    /// `with_pre_auth_ttl_secs` clamps a value above `MAX_TTL_SECS` to the
    /// maximum rather than persisting it verbatim.
    #[actix_web::test]
    async fn with_pre_auth_ttl_secs_clamps_overflow_to_max() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_pre_auth_ttl_secs(i64::MAX);
        let before = Utc::now();
        let expiry = store.effective_expiry(&pre_auth_state(), i64::MAX).unwrap();
        let after = Utc::now();
        let lower = before + chrono::Duration::seconds(MAX_TTL_SECS - 2);
        let upper = after + chrono::Duration::seconds(MAX_TTL_SECS + 2);
        assert!(
            expiry >= lower && expiry <= upper,
            "expected clamp to MAX_TTL_SECS, got {expiry:?}"
        );
    }

    /// `with_max_lifetime_secs(i64::MAX)` must clamp to `MAX_TTL_SECS`
    /// rather than fail *closed* (previously: overflow in
    /// `hard_cap_expiry`'s arithmetic made every authenticated session look
    /// already dead).
    #[actix_web::test]
    async fn with_max_lifetime_secs_clamps_i64_max_instead_of_failing_closed() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_max_lifetime_secs(i64::MAX);
        let expiry = store.effective_expiry(&authenticated_state(), 3600);
        assert!(
            expiry.is_some(),
            "a freshly logged-in session must not be treated as dead just because \
             with_max_lifetime_secs(i64::MAX) was passed"
        );
    }

    /// `with_max_lifetime_secs` clamps a non-positive value to the default
    /// rather than failing every session closed.
    #[actix_web::test]
    async fn with_max_lifetime_secs_clamps_non_positive_to_default() {
        let store = DbSessionStore::new(InMemoryRepo::new()).with_max_lifetime_secs(-1);
        let expiry = store.effective_expiry(&authenticated_state(), 3600);
        assert!(
            expiry.is_some(),
            "a negative max_lifetime_secs must fall back to the default, not kill every session"
        );
    }

    /// `with_touch_coalesce_secs` accepts `0` (disables coalescing) rather
    /// than clamping it to the default — `0` is a valid value here, unlike
    /// the TTL builders.
    #[actix_web::test]
    async fn with_touch_coalesce_secs_accepts_zero() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        seed_authenticated_row(&repo, &key_str, chrono::Duration::minutes(1));

        let store = DbSessionStore::from_arc(repo.clone()).with_touch_coalesce_secs(0);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await
            .unwrap();

        assert_eq!(
            repo.touch_count(),
            1,
            "a 0s coalescing window must still touch on any forward movement"
        );
    }

    /// `with_touch_coalesce_secs` clamps a negative value to `0` rather than
    /// making the write-skip guard's coalescing check trivially always pass
    /// (which would silently disable coalescing rather than tightening it).
    #[actix_web::test]
    async fn with_touch_coalesce_secs_clamps_negative_to_zero() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        seed_authenticated_row(&repo, &key_str, chrono::Duration::minutes(1));

        let store = DbSessionStore::from_arc(repo.clone()).with_touch_coalesce_secs(-60);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await
            .unwrap();

        assert_eq!(
            repo.touch_count(),
            1,
            "a negative coalesce value must clamp to 0, not disable the touch"
        );
    }

    // ---------------------------------------------------------------------------
    // update_ttl
    // ---------------------------------------------------------------------------

    /// Authenticated row: update_ttl extends the expiry (regression test
    /// rewritten for the LOGIN_AT-aware store — see below for the anonymous
    /// regression test for the actual defect).
    #[actix_web::test]
    async fn update_ttl_extends_expiry_for_authenticated_row() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        seed_authenticated_row(&repo, &key_str, chrono::Duration::seconds(30));

        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(2))
            .await
            .unwrap();

        let row = repo.get_row(&key_str).unwrap();
        let remaining = row.expires_at - Utc::now();
        assert!(
            remaining > chrono::Duration::minutes(119),
            "expected expiry ~2h from now, got {remaining:?}"
        );
        assert_eq!(repo.touch_count(), 1);
    }

    /// THE REGRESSION TEST for the defect this module fixes: `update_ttl` on
    /// an anonymous/pre-auth row must NOT extend its expiry past the pre-auth
    /// cap — and, per the stricter fix, must not touch it at all.
    #[actix_web::test]
    async fn update_ttl_applies_pre_auth_cap_to_anonymous_row() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        let original_expiry = Utc::now() + chrono::Duration::seconds(30);
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&pre_auth_state()).unwrap(),
            expires_at: original_expiry,
        });

        let store = DbSessionStore::from_arc(repo.clone()).with_pre_auth_ttl_secs(600);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // Attempt to extend by 8 hours, as an attacker pinging an endpoint
        // with a flooded pre-auth cookie would.
        store
            .update_ttl(&session_key, &CookieDuration::hours(8))
            .await
            .unwrap();

        let row = repo.get_row(&key_str).unwrap();
        assert!(
            (row.expires_at - original_expiry).num_seconds().abs() <= 1,
            "anonymous row must not have been extended at all, got {:?} (was {:?})",
            row.expires_at,
            original_expiry
        );
    }

    /// Anonymous state must skip `touch()` entirely — not just clamp the
    /// value passed to it.
    #[actix_web::test]
    async fn update_ttl_skips_touch_entirely_for_anonymous_row() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&pre_auth_state()).unwrap(),
            expires_at: Utc::now() + chrono::Duration::seconds(30),
        });

        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(8))
            .await
            .unwrap();

        assert_eq!(
            repo.touch_count(),
            0,
            "touch() must never be called for anonymous/pre-auth state"
        );
    }

    /// An authenticated row is clamped to `login_at + max_lifetime_secs` even
    /// when the requested TTL would extend it further.
    #[actix_web::test]
    async fn update_ttl_clamps_authenticated_row_to_hard_cap() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        let login_at = Utc::now().timestamp() - 3000;
        let mut state = authenticated_state();
        state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&state).unwrap(),
            expires_at: Utc::now() + chrono::Duration::seconds(30),
        });

        let store = DbSessionStore::from_arc(repo.clone()).with_max_lifetime_secs(3600);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(8))
            .await
            .unwrap();

        let row = repo.get_row(&key_str).unwrap();
        let expected_hard =
            DateTime::<Utc>::from_timestamp(login_at, 0).unwrap() + chrono::Duration::seconds(3600);
        assert!(
            (row.expires_at - expected_hard).num_seconds().abs() <= 1,
            "expected clamp to {expected_hard:?}, got {:?}",
            row.expires_at
        );
    }

    /// A missing row is a no-op: no insert, no error, no touch.
    #[actix_web::test]
    async fn update_ttl_missing_row_is_noop() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());
        let key_str = random_key_str();
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await
            .unwrap();

        assert_eq!(repo.row_count(), 0);
        assert_eq!(repo.insert_count(), 0);
        assert_eq!(repo.touch_count(), 0);
    }

    /// A `get()` failure propagates as an `Err`, rather than being swallowed.
    #[actix_web::test]
    async fn update_ttl_propagates_get_failure() {
        let repo = Arc::new(InMemoryRepo::new());
        repo.fail_get_with("simulated get failure");
        let store = DbSessionStore::from_arc(repo);
        let key_str = random_key_str();
        let session_key = SessionKey::try_from(key_str).unwrap();

        let result = store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await;
        assert!(result.is_err(), "a get() failure must propagate as Err");
    }

    /// A row whose new expiry would not move forward at all is skipped.
    #[actix_web::test]
    async fn update_ttl_skips_when_not_moving_forward() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        // Already sitting exactly at (or effectively at) a 1h expiry.
        let login_at = Utc::now().timestamp() - 100;
        let mut state = authenticated_state();
        state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());
        let current_expiry =
            Utc::now() + chrono::Duration::hours(1) + chrono::Duration::seconds(200);
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&state).unwrap(),
            expires_at: current_expiry,
        });

        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // Requesting a 1h TTL from now would compute an expiry *behind* the
        // row's current expires_at.
        store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await
            .unwrap();

        assert_eq!(
            repo.touch_count(),
            0,
            "must not touch when the new expiry would not move forward"
        );
    }

    /// A row whose new expiry moves forward, but by less than the coalescing
    /// window, is skipped.
    #[actix_web::test]
    async fn update_ttl_skips_within_coalesce_window() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        seed_authenticated_row(
            &repo,
            &key_str,
            chrono::Duration::hours(1) - chrono::Duration::seconds(10),
        );

        let store = DbSessionStore::from_arc(repo.clone()).with_touch_coalesce_secs(60);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // Moves the expiry forward by ~10s — inside the 60s coalescing window.
        store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await
            .unwrap();

        assert_eq!(
            repo.touch_count(),
            0,
            "a sub-coalesce-window movement must be skipped"
        );
    }

    /// A row whose new expiry moves forward by at least the coalescing
    /// window is touched.
    #[actix_web::test]
    async fn update_ttl_touches_beyond_coalesce_window() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        seed_authenticated_row(&repo, &key_str, chrono::Duration::minutes(1));

        let store = DbSessionStore::from_arc(repo.clone()).with_touch_coalesce_secs(60);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await
            .unwrap();

        assert_eq!(repo.touch_count(), 1);
    }

    /// Undeserializable state is deleted rather than causing an error.
    #[actix_web::test]
    async fn update_ttl_deletes_on_undeserializable_state() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: "not valid json".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });

        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        let result = store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await;
        assert!(result.is_ok());
        assert!(repo.get_row(&key_str).is_none());
        assert!(repo.deleted_keys().contains(&key_str));
    }

    /// A session past its absolute lifetime is deleted by update_ttl, not
    /// touched.
    #[actix_web::test]
    async fn update_ttl_deletes_session_past_hard_cap() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        let login_at = Utc::now().timestamp() - 7200;
        let mut state = authenticated_state();
        state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&state).unwrap(),
            expires_at: Utc::now() + chrono::Duration::seconds(30),
        });

        let store = DbSessionStore::from_arc(repo.clone()).with_max_lifetime_secs(3600);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        store
            .update_ttl(&session_key, &CookieDuration::hours(1))
            .await
            .unwrap();

        assert_eq!(repo.touch_count(), 0);
        assert!(repo.get_row(&key_str).is_none());
        assert!(repo.deleted_keys().contains(&key_str));
    }

    /// Pins the clamp-before-write-skip-guard ordering: a row sitting exactly
    /// at the hard cap must be skipped (not touched) rather than repeatedly
    /// "extended" to the same clamped value forever. This is the property
    /// that would silently break if a refactor compared `ttl_secs`-derived
    /// expiry against `s.expires_at` before applying the hard-cap clamp.
    #[actix_web::test]
    async fn update_ttl_clamp_applied_before_write_skip_guard() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        let max_lifetime_secs = 3600i64;
        let login_at = Utc::now().timestamp() - 3000;
        let hard_cap = DateTime::<Utc>::from_timestamp(login_at, 0).unwrap()
            + chrono::Duration::seconds(max_lifetime_secs);

        let mut state = authenticated_state();
        state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());
        // Row is already sitting at the hard cap (as if a previous
        // update_ttl call already clamped it there).
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&state).unwrap(),
            expires_at: hard_cap,
        });

        let store =
            DbSessionStore::from_arc(repo.clone()).with_max_lifetime_secs(max_lifetime_secs);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // Request a huge TTL — if the clamp were applied AFTER the write-skip
        // comparison (the bug this test pins), the uncapped candidate
        // (now + 8h) would look like forward movement relative to
        // s.expires_at and would incorrectly touch() past the hard cap.
        store
            .update_ttl(&session_key, &CookieDuration::hours(8))
            .await
            .unwrap();

        assert_eq!(
            repo.touch_count(),
            0,
            "row already at the hard cap must not be touched again"
        );
        let row = repo.get_row(&key_str).unwrap();
        assert!(
            (row.expires_at - hard_cap).num_seconds().abs() <= 1,
            "row must remain at the hard cap, got {:?}",
            row.expires_at
        );
    }

    // ---------------------------------------------------------------------------
    // load(): absolute lifetime enforcement
    // ---------------------------------------------------------------------------

    /// A row past its absolute lifetime is deleted and `load()` returns
    /// `None`, even though `expires_at` on the row itself has not lapsed.
    #[actix_web::test]
    async fn load_deletes_and_returns_none_past_absolute_lifetime() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        let login_at = Utc::now().timestamp() - 7200;
        let mut state = authenticated_state();
        state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&state).unwrap(),
            // The row's own expiry has not lapsed yet...
            expires_at: Utc::now() + chrono::Duration::hours(6),
        });

        // ...but the absolute lifetime (1h from login, 2h ago) has.
        let store = DbSessionStore::from_arc(repo.clone()).with_max_lifetime_secs(3600);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        let result = store.load(&session_key).await.unwrap();
        assert_eq!(result, None);
        assert!(repo.deleted_keys().contains(&key_str));
    }

    /// A `sub`-bearing row with no `LOGIN_AT` at all is rejected by `load()`.
    #[actix_web::test]
    async fn load_rejects_sub_with_no_login_at() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        let state = make_state(&[(session_state::SUB, "user-42")]);
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&state).unwrap(),
            expires_at: Utc::now() + chrono::Duration::hours(6),
        });

        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        let result = store.load(&session_key).await.unwrap();
        assert_eq!(result, None);
        assert!(repo.deleted_keys().contains(&key_str));
    }

    /// An authenticated row within its lifetime loads normally.
    #[actix_web::test]
    async fn load_returns_state_within_absolute_lifetime() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        seed_authenticated_row(&repo, &key_str, chrono::Duration::hours(1));

        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        let result = store.load(&session_key).await.unwrap();
        assert!(result.is_some());
    }

    // ---------------------------------------------------------------------------
    // save()/update(): LOGIN_AT injection
    // ---------------------------------------------------------------------------

    /// `save()` injects `LOGIN_AT` when `sub` is present without it.
    #[actix_web::test]
    async fn save_injects_login_at_when_missing() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let state = make_state(&[(session_state::SUB, "user-42")]);
        let before = Utc::now().timestamp();
        let key = store.save(state, &ttl_one_hour()).await.unwrap();
        let after = Utc::now().timestamp();

        let row = repo.get_row(key.as_ref()).unwrap();
        let persisted: HashMap<String, String> = serde_json::from_str(&row.state).unwrap();
        let login_at = parse_login_at(&persisted).expect("LOGIN_AT must have been injected");
        assert!(login_at >= before && login_at <= after);
    }

    /// CRITICAL fix regression test: the value `inject_login_at_if_missing`
    /// writes must be the JSON encoding of an `i64` (bare digits), because
    /// the read side (`Session::get` in the `Auth` extractor) deserializes
    /// it as JSON. A plausible-looking regression — e.g. switching to
    /// `format!("\"{ts}\"")` or a bare `ts.to_string()` that happened to
    /// diverge from the JSON encoding — would compile and keep every other
    /// store test green while silently 401'ing every healed session. This
    /// asserts the persisted raw value round-trips through the exact same
    /// path the extractor uses: `serde_json::from_str` into a `Value`, then
    /// `session_state::login_at_from_json`.
    #[actix_web::test]
    async fn injected_login_at_parses_through_the_extractor_json_path() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let state = make_state(&[(session_state::SUB, "user-42")]);
        let before = Utc::now().timestamp();
        let key = store.save(state, &ttl_one_hour()).await.unwrap();
        let after = Utc::now().timestamp();

        let row = repo.get_row(key.as_ref()).unwrap();
        let persisted: HashMap<String, String> = serde_json::from_str(&row.state).unwrap();
        let raw = persisted
            .get(session_state::LOGIN_AT)
            .expect("LOGIN_AT must have been injected");

        // Exactly the path `Session::get` + the extractor's JSON decoding
        // would take, bypassing this module's own (more permissive)
        // `parse_login_at` entirely.
        let value: serde_json::Value =
            serde_json::from_str(raw).expect("injected LOGIN_AT must itself be valid JSON");
        let login_at = session_state::login_at_from_json(&value)
            .expect("injected LOGIN_AT must parse via the shared extractor contract");

        assert!(login_at >= before && login_at <= after);
    }

    /// CRITICAL fix regression test: `update()` on `sub`-bearing state with
    /// no `LOGIN_AT` must NOT inject one (unlike `save()`). It must be
    /// treated exactly like `load()` treats a `sub`-without-`LOGIN_AT` row —
    /// dead: the row is deleted, no new row is created (via the missing-row
    /// fallback or otherwise), and the stale key is returned. Before this
    /// fix, injecting `now()` here would silently restart the absolute
    /// session lifetime on every write.
    #[actix_web::test]
    async fn update_on_sub_without_login_at_is_treated_as_dead() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: "{}".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });
        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        let state = make_state(&[(session_state::SUB, "user-42")]);
        let row_count_before = repo.row_count();
        let returned_key = store
            .update(session_key, state, &ttl_one_hour())
            .await
            .unwrap();

        assert_eq!(
            returned_key.as_ref(),
            key_str,
            "dead session: stale key must be returned"
        );
        assert!(
            repo.get_row(&key_str).is_none(),
            "row missing LOGIN_AT must be deleted, not healed"
        );
        assert_eq!(
            repo.insert_count(),
            0,
            "no new row may be minted by the missing-row fallback for this state"
        );
        assert_eq!(repo.row_count(), row_count_before - 1);
        // No lifetime can have been extended: the row no longer exists at all.
    }

    /// `update()` on a session past its absolute lifetime deletes the row and
    /// does NOT create a new one via the missing-row fallback.
    #[actix_web::test]
    async fn update_on_dead_session_creates_no_new_row() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();
        let login_at = Utc::now().timestamp() - 7200;
        let mut seeded_state = authenticated_state();
        seeded_state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&seeded_state).unwrap(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });

        let store = DbSessionStore::from_arc(repo.clone()).with_max_lifetime_secs(3600);
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // Caller submits state carrying the same (now-expired-by-hard-cap)
        // LOGIN_AT — as would happen for a request racing its own expiry.
        let mut submitted_state = make_state(&[(session_state::SUB, "user-42")]);
        submitted_state.insert(session_state::LOGIN_AT.to_string(), login_at.to_string());

        let row_count_before = repo.row_count();
        let returned_key = store
            .update(session_key, submitted_state, &ttl_one_hour())
            .await
            .unwrap();

        assert_eq!(returned_key.as_ref(), key_str, "stale key must be returned");
        assert!(
            repo.get_row(&key_str).is_none(),
            "dead session's row must be deleted"
        );
        assert_eq!(
            repo.insert_count(),
            0,
            "no new row may be minted for a session past its absolute lifetime"
        );
        assert!(repo.row_count() <= row_count_before);
    }

    // ---------------------------------------------------------------------------
    // Original tests (baseline — must stay green)
    // ---------------------------------------------------------------------------

    #[actix_web::test]
    async fn save_then_load_round_trips_state() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let state = make_state(&[("user", "alice"), ("role", "admin")]);

        let key = store.save(state.clone(), &ttl_one_hour()).await.unwrap();
        let loaded = store.load(&key).await.unwrap();

        assert_eq!(loaded, Some(state));
    }

    #[actix_web::test]
    async fn load_missing_key_returns_none() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        // Generate a valid-format key that was never saved.
        let key = generate_session_key().unwrap();
        let result = store.load(&key).await.unwrap();
        assert_eq!(result, None);
    }

    /// A3 — red first: before the expiry check was added, this test would have
    /// returned `Some(state)` instead of `None`.
    #[actix_web::test]
    async fn load_expired_record_returns_none() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str = random_key_str();

        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&make_state(&[("x", "1")])).unwrap(),
            expires_at: past_expiry(),
        });

        let store = DbSessionStore::from_arc(repo);
        let session_key = SessionKey::try_from(key_str).unwrap();
        let result = store.load(&session_key).await.unwrap();

        assert_eq!(result, None);
    }

    /// A3 — best-effort delete: loading an expired record must attempt a delete,
    /// log the key, and a failing delete must NOT turn the load into an Err.
    #[actix_web::test]
    async fn load_expired_record_best_effort_deletes() {
        let key_str = random_key_str();

        // Part 1: successful delete — key appears in the delete log.
        let good_repo = Arc::new(InMemoryRepo::new());
        good_repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&make_state(&[("x", "1")])).unwrap(),
            expires_at: past_expiry(),
        });
        let store = DbSessionStore::from_arc(good_repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();
        let result = store.load(&session_key).await.unwrap();
        assert_eq!(result, None);
        assert!(
            good_repo.deleted_keys().contains(&key_str),
            "expected key to appear in delete log"
        );

        // Part 2: failing delete — load still returns Ok(None), not Err.
        let fail_repo = Arc::new(FailingDeleteRepo::new());
        fail_repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&make_state(&[("x", "1")])).unwrap(),
            expires_at: past_expiry(),
        });
        let store2 = DbSessionStore::from_arc(fail_repo);
        let session_key2 = SessionKey::try_from(key_str).unwrap();
        let result2 = store2.load(&session_key2).await;
        // Must be Ok(None), not Err.
        assert!(result2.is_ok(), "failing delete must not propagate as Err");
        assert_eq!(result2.unwrap(), None);
    }

    #[actix_web::test]
    async fn update_replaces_state_and_key_is_stable() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let initial_state = make_state(&[("v", "1")]);
        let key = store.save(initial_state, &ttl_one_hour()).await.unwrap();

        let key_str_before = key.as_ref().to_owned();
        let new_state = make_state(&[("v", "2"), ("extra", "yes")]);
        let returned_key = store
            .update(key, new_state.clone(), &ttl_one_hour())
            .await
            .unwrap();

        // The session key must not change on update.
        assert_eq!(returned_key.as_ref(), key_str_before);

        let loaded = store.load(&returned_key).await.unwrap();
        assert_eq!(loaded, Some(new_state));
    }

    #[actix_web::test]
    async fn delete_removes_record() {
        let store = DbSessionStore::new(InMemoryRepo::new());
        let state = make_state(&[("a", "b")]);
        let key = store.save(state, &ttl_one_hour()).await.unwrap();

        // Verify it exists.
        assert!(store.load(&key).await.unwrap().is_some());

        store.delete(&key).await.unwrap();

        assert_eq!(store.load(&key).await.unwrap(), None);
    }

    #[test]
    fn generate_session_key_is_64_alphanumeric() {
        let k1 = generate_session_key().unwrap();
        let k2 = generate_session_key().unwrap();

        let s1 = k1.as_ref();
        let s2 = k2.as_ref();

        assert_eq!(s1.len(), 64, "session key must be 64 characters");
        assert!(
            s1.chars().all(|c| c.is_ascii_alphanumeric()),
            "session key must be ASCII alphanumeric"
        );
        assert_ne!(s1, s2, "two generated keys must differ");
    }

    #[test]
    fn expiry_from_ttl_is_now_plus_ttl() {
        let before = Utc::now();
        let expiry = expiry_from_ttl(3600);
        let after = Utc::now();

        let lower = before + chrono::Duration::seconds(3598);
        let upper = after + chrono::Duration::seconds(3602);
        assert!(
            expiry >= lower && expiry <= upper,
            "expiry {expiry} not within ±2s of now+3600s"
        );
    }

    /// Overflow input (i64::MAX seconds) must fall back to ~12 hours without panicking.
    #[test]
    fn expiry_from_ttl_overflow_falls_back_to_12h() {
        let before = Utc::now();
        let expiry = expiry_from_ttl(i64::MAX);
        let after = Utc::now();

        let lower = before + chrono::Duration::hours(11);
        let upper = after + chrono::Duration::hours(13);
        assert!(
            expiry >= lower && expiry <= upper,
            "overflow expiry {expiry} not within the expected 12h fallback window"
        );
    }
}
