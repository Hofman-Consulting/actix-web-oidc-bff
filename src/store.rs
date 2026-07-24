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
//! session table with rows that live as long as authenticated sessions. Pass
//! `cfg.pre_auth_ttl_secs` when constructing the store to keep both values in
//! sync. Rate-limiting `/auth/login` at the deployment level (reverse proxy /
//! WAF) is still recommended.
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
//!   (A-1) is applied here too so the fallback cannot reopen the DoS.
//!
//! ## NOTE on `anyhow`
//! This is the only place in the crate that uses `anyhow`. It exists here
//! because `actix-session 0.10`'s `SessionStore` trait API forces
//! `anyhow::Error` into its signature — `LoadError::Other`, `SaveError::Other`,
//! `UpdateError::Other`, and the `update_ttl`/`delete` return types all take
//! `anyhow::Error` directly. The trait cannot be satisfied without constructing
//! `anyhow::Error` values. Everything else uses [`crate::BffError`] /
//! [`RepoError`].

use actix_session::storage::{LoadError, SaveError, SessionKey, UpdateError};
use actix_web::cookie::time::Duration as CookieDuration;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use std::{collections::HashMap, future::Future, sync::Arc};

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
    async fn touch(&self, session_key: &str, expires_at: DateTime<Utc>) -> Result<(), RepoError>;
    /// Delete a session by key.
    async fn delete(&self, session_key: &str) -> Result<(), RepoError>;
}

/// Default maximum TTL (in seconds) for pre-auth / anonymous session rows.
///
/// Matches the config default for `pre_auth_ttl_secs`. Pass
/// `cfg.pre_auth_ttl_secs` to [`DbSessionStore::with_pre_auth_ttl_secs`] to
/// keep both in sync.
const DEFAULT_PRE_AUTH_TTL_SECS: i64 = 600;

/// `actix-session` store adapter over a [`SessionRepository`].
///
/// Pass directly to `SessionMiddleware::new(store, key)`.
///
/// See the [module-level docs](self) for details on the pre-auth TTL cap and
/// the `update()` missing-row contract.
pub struct DbSessionStore<R>
where
    R: SessionRepository,
{
    repo: Arc<R>,
    /// Maximum TTL applied to anonymous / pre-auth rows (rows without `sub`).
    pre_auth_ttl_secs: i64,
}

impl<R> DbSessionStore<R>
where
    R: SessionRepository,
{
    /// Create a new store with the default pre-auth TTL cap (600 s).
    ///
    /// Pass `cfg.pre_auth_ttl_secs` via [`Self::with_pre_auth_ttl_secs`] to
    /// keep the cap in sync with the OIDC config.
    pub fn new(repo: R) -> Self {
        Self {
            repo: Arc::new(repo),
            pre_auth_ttl_secs: DEFAULT_PRE_AUTH_TTL_SECS,
        }
    }

    /// Create a new store from an existing `Arc<R>` with the default pre-auth
    /// TTL cap (600 s).
    pub fn from_arc(repo: Arc<R>) -> Self {
        Self {
            repo,
            pre_auth_ttl_secs: DEFAULT_PRE_AUTH_TTL_SECS,
        }
    }

    /// Override the maximum TTL applied to anonymous / pre-auth session rows.
    ///
    /// Pre-auth rows are those that do not contain the `sub` session key.
    /// Capping their TTL limits how long an unauthenticated flood of
    /// `/auth/login` requests can fill the session table.
    ///
    /// ```rust,ignore
    /// let store = DbSessionStore::new(repo)
    ///     .with_pre_auth_ttl_secs(cfg.pre_auth_ttl_secs);
    /// ```
    pub fn with_pre_auth_ttl_secs(mut self, secs: i64) -> Self {
        self.pre_auth_ttl_secs = secs;
        self
    }

    /// Compute the effective TTL for a session, capping it for pre-auth rows.
    ///
    /// Authenticated rows (those containing `sub`) receive the full `ttl_secs`.
    /// All other rows are capped at `self.pre_auth_ttl_secs` to limit exposure
    /// from unauthenticated session flooding.
    fn effective_ttl(&self, session_state: &HashMap<String, String>, ttl_secs: i64) -> i64 {
        if session_state.contains_key(session_state::SUB) {
            ttl_secs
        } else {
            ttl_secs.min(self.pre_auth_ttl_secs)
        }
    }

    /// Returns `true` if the state contains any token key that must not be
    /// re-inserted after a session has been purged (do-not-resurrect guard).
    fn state_has_tokens(session_state: &HashMap<String, String>) -> bool {
        session_state.contains_key(session_state::ACCESS_TOKEN)
            || session_state.contains_key(session_state::REFRESH_TOKEN)
            || session_state.contains_key(session_state::ID_TOKEN)
    }
}

fn generate_session_key() -> Result<SessionKey, anyhow::Error> {
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    SessionKey::try_from(key).map_err(|e| anyhow::anyhow!("Invalid session key: {e}"))
}

fn expiry_from_ttl(ttl_secs: i64) -> DateTime<Utc> {
    Utc::now()
        + chrono::Duration::try_seconds(ttl_secs).unwrap_or_else(|| chrono::Duration::hours(12))
}

impl<R> actix_session::storage::SessionStore for DbSessionStore<R>
where
    R: SessionRepository,
{
    fn load(
        &self,
        session_key: &SessionKey,
    ) -> impl Future<Output = Result<Option<HashMap<String, String>>, LoadError>> {
        let repo = self.repo.clone();
        let key = session_key.as_ref().to_owned();

        async move {
            let session = repo
                .get(&key)
                .await
                .map_err(|e| LoadError::Other(anyhow::anyhow!("get session failed: {e}")))?;

            match session {
                None => Ok(None),
                Some(s) => {
                    // Enforce expiry regardless of whether the repository already
                    // filtered the row (defense-in-depth for non-compliant repos).
                    if s.expires_at <= Utc::now() {
                        if let Err(e) = repo.delete(&key).await {
                            log::warn!(
                                "store::load: best-effort delete of expired session {key:?} failed: {e}"
                            );
                        }
                        return Ok(None);
                    }

                    let state: HashMap<String, String> = serde_json::from_str(&s.state)
                        .map_err(|e| LoadError::Deserialization(anyhow::anyhow!("{e}")))?;
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
        let ttl_secs = self.effective_ttl(&session_state, ttl.whole_seconds());

        async move {
            let session_key = generate_session_key()
                .map_err(|e| SaveError::Other(anyhow::anyhow!("Key generation failed: {e}")))?;

            let state = serde_json::to_string(&session_state)
                .map_err(|e| SaveError::Serialization(anyhow::anyhow!("{e}")))?;

            let record = SessionRecord {
                session_key: session_key.as_ref().to_owned(),
                state,
                expires_at: expiry_from_ttl(ttl_secs),
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
        let ttl_secs = self.effective_ttl(&session_state, ttl.whole_seconds());
        let pre_auth_ttl_secs = self.pre_auth_ttl_secs;

        async move {
            let state = serde_json::to_string(&session_state)
                .map_err(|e| UpdateError::Serialization(anyhow::anyhow!("{e}")))?;

            let row_existed = repo
                .update(session_key.as_ref(), &state, expiry_from_ttl(ttl_secs))
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

        async move {
            repo.touch(&key, expiry_from_ttl(ttl_secs))
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
    use actix_session::storage::SessionStore as _;
    use actix_web::cookie::time::Duration as CookieDuration;
    use std::sync::Mutex;

    // ---------------------------------------------------------------------------
    // InMemoryRepo — test double
    // ---------------------------------------------------------------------------

    /// A simple in-memory [`SessionRepository`] that records every `delete` call
    /// so tests can assert best-effort cleanup behaviour.
    ///
    /// `update()` returns `Ok(true)` when the key exists and `Ok(false)` when it
    /// does not, matching the [`SessionRepository`] contract.
    struct InMemoryRepo {
        rows: Mutex<HashMap<String, SessionRecord>>,
        deletes: Mutex<Vec<String>>,
    }

    impl InMemoryRepo {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                deletes: Mutex::new(Vec::new()),
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

        fn row_count(&self) -> usize {
            self.rows.lock().unwrap().len()
        }

        fn get_row(&self, key: &str) -> Option<SessionRecord> {
            self.rows.lock().unwrap().get(key).cloned()
        }
    }

    #[async_trait]
    impl SessionRepository for InMemoryRepo {
        async fn get(&self, session_key: &str) -> Result<Option<SessionRecord>, RepoError> {
            Ok(self.rows.lock().unwrap().get(session_key).cloned())
        }

        async fn insert(&self, record: &SessionRecord) -> Result<(), RepoError> {
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

    fn ttl_ten_minutes() -> CookieDuration {
        CookieDuration::minutes(10)
    }

    fn pre_auth_state() -> HashMap<String, String> {
        make_state(&[("oidc_state", "abc123"), ("nonce", "xyz")])
    }

    fn authenticated_state() -> HashMap<String, String> {
        make_state(&[
            (session_state::SUB, "user-42"),
            ("email", "user@example.com"),
        ])
    }

    fn token_bearing_state() -> HashMap<String, String> {
        make_state(&[
            (session_state::SUB, "user-42"),
            (session_state::ACCESS_TOKEN, "at-secret"),
            (session_state::REFRESH_TOKEN, "rt-secret"),
            (session_state::ID_TOKEN, "idt-secret"),
        ])
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
        let key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
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

        let key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
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

    /// A-1 review amendment — an authenticated user opening a new login tab
    /// produces state with BOTH `sub` (from existing session) and pre-auth
    /// fields. The TTL must be the FULL authenticated TTL — the cap must only
    /// trigger when `sub` is absent.
    #[actix_web::test]
    async fn update_full_ttl_for_authenticated_user_starting_new_login() {
        let repo = Arc::new(InMemoryRepo::new());
        let store = DbSessionStore::from_arc(repo.clone());

        let key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: "{}".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // State has both `sub` (authenticated) and an oidc_pre_auth field.
        let mixed_state =
            make_state(&[(session_state::SUB, "user-42"), ("oidc_pre_auth", "[...]")]);

        let before = Utc::now();
        store
            .update(session_key, mixed_state, &ttl_twelve_hours())
            .await
            .unwrap();
        let after = Utc::now();

        let row = repo.get_row(&key_str).unwrap();
        let lower = before + chrono::Duration::hours(11);
        let upper = after + chrono::Duration::hours(13);
        assert!(
            row.expires_at >= lower && row.expires_at <= upper,
            "mixed-state update: expected full TTL (~12h), got {:?}",
            row.expires_at
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
        let stale_key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
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

        let stale_key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
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
        let key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

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
        let key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

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
    async fn update_ttl_extends_expiry() {
        let repo = Arc::new(InMemoryRepo::new());
        let key_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        repo.seed(SessionRecord {
            session_key: key_str.clone(),
            state: serde_json::to_string(&make_state(&[("k", "v")])).unwrap(),
            // Start with an expiry 30 seconds in the future.
            expires_at: Utc::now() + chrono::Duration::seconds(30),
        });

        let store = DbSessionStore::from_arc(repo.clone());
        let session_key = SessionKey::try_from(key_str.clone()).unwrap();

        // Touch with a 2-hour TTL.
        store
            .update_ttl(&session_key, &CookieDuration::hours(2))
            .await
            .unwrap();

        // The row's expiry should now be ~2 hours from now.
        let row = repo.rows.lock().unwrap();
        let rec = row.get(&key_str).unwrap();
        let remaining = rec.expires_at - Utc::now();
        assert!(
            remaining > chrono::Duration::minutes(119),
            "expected expiry ~2h from now, got {remaining:?}"
        );
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

    // Suppress unused-variable warning for helpers that exist for clarity.
    #[allow(dead_code)]
    fn _use_ttl_helpers() {
        let _ = ttl_ten_minutes();
    }
}
