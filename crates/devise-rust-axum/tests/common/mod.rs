//! Shared fixture for the 09-02 route/flow suites: a full-module
//! `FixtureUser` over the `MemoryAdapter` oracle, scope registry bootstrap,
//! and the wired axum test app (`SessionManagerLayer` outermost +
//! `DeviseLayer` + `devise_for_router`).

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use axum::Router;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use devise_rust::adapter::{DeviseKey, OrmAdapter, memory::MemoryAdapter};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::hooks::HookRegistry;
use devise_rust::mailer::TestMailer;
use devise_rust::model::{
    AdapterBridge, DatabaseAuthenticatable, ModelFinder, PasswordVerifiable, Recoverable,
    Registerable, Validatable,
};
use devise_rust::rememberable::Rememberable;
use devise_rust::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};
use devise_rust::time::Clock;
use devise_rust_axum::{DeviseLayer, DeviseWebState, devise_for_router, session_manager_layer};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tower_sessions::service::SessionManagerLayer;
use tower_sessions::service::SignedCookie;
use tower_sessions::session::{Id, Record};
use tower_sessions::session_store::SessionStore;
use tower_sessions::{MemoryStore, Session, session_store};

pub use devise_rust::adapter::OrmAdapter as OrmAdapterTrait;
pub use devise_rust::time::SystemClock;

/// `SystemClock` instant as RFC3339 (helper for lock/timestamp fixtures).
pub fn now_rfc3339() -> String {
    <SystemClock as Clock>::now(&SystemClock).to_rfc3339()
}

/// [`MemoryAdapter`] wrapper assigning surrogate ids **before** delegating.
///
/// The memory oracle keys storage by an internal counter without writing
/// the id back onto the model, so controller-created records (whose id is
/// 0) would never resolve back through `to_key`. This wrapper assigns the
/// id first (start at 1, matching the oracle's counter — every create
/// flows through this wrapper, keeping the two counters in lockstep),
/// preserving `#[serde(skip)]` fields because the oracle stores typed
/// clones.
#[derive(Debug, Clone)]
pub struct IdAssigningAdapter {
    inner: MemoryAdapter<FixtureUser>,
    counter: Arc<std::sync::atomic::AtomicI64>,
}

impl IdAssigningAdapter {
    pub fn new() -> Self {
        Self {
            inner: MemoryAdapter::new(),
            counter: Arc::new(std::sync::atomic::AtomicI64::new(1)),
        }
    }
}

impl Default for IdAssigningAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl OrmAdapter<FixtureUser> for IdAssigningAdapter {
    type New = FixtureUser;

    async fn get(
        &self,
        id: &DeviseKey,
    ) -> Result<Option<FixtureUser>, devise_rust::adapter::OrmError> {
        OrmAdapter::get(&self.inner, id).await
    }

    async fn find_first(
        &self,
        conditions: &devise_rust::adapter::Conditions,
    ) -> Result<Option<FixtureUser>, devise_rust::adapter::OrmError> {
        OrmAdapter::find_first(&self.inner, conditions).await
    }

    async fn create(
        &self,
        mut model: FixtureUser,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        model.id = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        OrmAdapter::create(&self.inner, model).await
    }

    async fn update(
        &self,
        key: &DeviseKey,
        changes: &devise_rust::adapter::ChangeSet,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        OrmAdapter::update(&self.inner, key, changes).await
    }

    async fn update_columns(
        &self,
        key: &DeviseKey,
        fields: &std::collections::HashMap<String, devise_rust::adapter::Value>,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        OrmAdapter::update_columns(&self.inner, key, fields).await
    }

    async fn increment_counter(
        &self,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        OrmAdapter::increment_counter(&self.inner, key, column).await
    }

    async fn delete(&self, id: &DeviseKey) -> Result<(), devise_rust::adapter::OrmError> {
        OrmAdapter::delete(&self.inner, id).await
    }
}

/// DBAU-07 observability: emails whose sign-in fired
/// `after_database_authentication`. Keyed by email so concurrent tests with
/// fresh fixtures never race on one shared flag.
pub static AFTER_DB_AUTH_SEEN: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// Record one `after_database_authentication` firing (see
/// [`AFTER_DB_AUTH_SEEN`]).
pub fn record_after_db_auth(email: &str) {
    if let Ok(mut seen) = AFTER_DB_AUTH_SEEN.lock() {
        seen.insert(email.to_string());
    }
}

/// Whether `after_database_authentication` fired for `email` since the last
/// reset.
pub fn after_db_auth_fired(email: &str) -> bool {
    AFTER_DB_AUTH_SEEN
        .lock()
        .is_ok_and(|seen| seen.contains(email))
}

/// Full-module fixture user: every Devise module trait implemented so the
/// route matrix can exercise all five controllers against one model.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FixtureUser {
    pub id: i64,
    pub email: String,
    pub encrypted_password: String,
    #[serde(skip)]
    pub password: Option<String>,
    #[serde(skip)]
    pub password_confirmation: Option<String>,
    pub reset_password_token: Option<String>,
    pub reset_password_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    pub remember_created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub remember_token: Option<String>,
    pub sign_in_count: u64,
    pub current_sign_in_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sign_in_at: Option<chrono::DateTime<chrono::Utc>>,
    pub current_sign_in_ip: Option<String>,
    pub last_sign_in_ip: Option<String>,
    pub confirmation_token: Option<String>,
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub confirmation_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    pub unconfirmed_email: Option<String>,
    pub failed_attempts: u32,
    pub unlock_token: Option<String>,
    pub locked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Sign-in identity under a non-default `authentication_keys` config
    /// (the M-fix matrix: `authentication_keys = ["username"]`).
    pub username: Option<String>,
    /// Omniauthable identity pair (D-11): the provider name + uid the
    /// default linking policy reads and writes.
    pub provider: Option<String>,
    pub uid: Option<String>,
    /// Display name asserted by an OAuth provider profile.
    pub name: Option<String>,
    #[serde(skip)]
    pub raw_reset_token: Option<String>,
    #[serde(skip)]
    pub raw_confirmation_token: Option<String>,
    #[serde(skip)]
    pub raw_unlock_token: Option<String>,
    #[serde(skip)]
    pub remember_me_flag: Option<bool>,
    /// Devise `skip_confirmation_notification!` fixture seam: the app
    /// model's create-time opt-out (confirmable.rb:286-288). The flow
    /// suite opts in through an address marker in `new_with_session`
    /// because no request param may carry it (S7 sanitizer).
    #[serde(skip)]
    pub skip_confirmation_notification: bool,
    /// Window stamp: the app config this record was BUILT under never expires
    /// unconfirmed access (`allow_unconfirmed_access_for: nil`, Devise's
    /// "unconfirmed access never expires"). `new_with_session` stamps it from
    /// the controller's config because the fixture's
    /// `active_for_authentication` has no other channel to the app config;
    /// without it a controller-built record could never compose the
    /// never-expiring window and no app config could reach the sign-up
    /// sign-in branch. A REAL (serialized) column, because the memory oracle
    /// round-trips every record through JSON on `update_columns` and a
    /// `serde(skip)` stamp would be dropped by the sign-in bookkeeping.
    pub unconfirmed_access_never_expires: bool,
}

impl FixtureUser {
    /// New record with a hashed password (stretches from `config`).
    pub fn new_with_password(email: &str, password: &str, config: &DeviseConfig) -> Self {
        let mut user = Self {
            email: email.to_string(),
            ..Self::default()
        };
        user.set_password(Some(password.to_string()), config);
        user
    }

    /// Fixture branch: mark confirmed in memory (adapter write done by caller).
    pub fn confirmed_now(mut self, clock: &dyn Clock) -> Self {
        self.confirmed_at = Some(clock.now());
        self
    }

    /// Fixture branch: pre-stamp `remember_created_at` in the past so a
    /// cookie minted at sign-in satisfies the strict `generated_at >
    /// remember_created_at` window (the two-cookie-jar regression needs a
    /// remember cookie that is genuinely ALIVE before the password change).
    pub fn remembered_since(mut self, at: chrono::DateTime<chrono::Utc>) -> Self {
        self.remember_created_at = Some(at);
        self
    }
}

impl std::fmt::Debug for FixtureUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // CONCERNS #6: Devise's inspect never prints credentials; the
        // redaction wrapper is the port's single home for that on owned models.
        devise_rust::error::Redacted(self).fmt(f)
    }
}

impl AnyDeviseModel for FixtureUser {
    fn redacted_hash(&self) -> serde_json::Value {
        <Self as devise_rust::model::Authenticatable>::serializable_hash(self)
    }

    fn as_activatable(&self) -> Option<&dyn devise_rust::model::Activatable> {
        Some(self)
    }
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password.get(..29).map(str::to_string)
    }

    fn as_password_verifiable(&self) -> Option<&dyn PasswordVerifiable> {
        Some(self)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// DBAU-07 observability: record that the sign-in path fired Devise's
    /// `after_database_authentication` hook for this record's email.
    fn after_database_authentication(&self) {
        record_after_db_auth(&self.email);
    }

    fn rememberable_value_opt(&self) -> Option<String> {
        self.remember_token
            .clone()
            .filter(|token| !token.is_empty())
            .or_else(|| self.authenticatable_salt())
    }

    fn remember_created_at_opt(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.remember_created_at
    }

    fn remember_me_flag_opt(&self) -> Option<bool> {
        self.remember_me_flag
    }

    fn set_remember_me_flag(&mut self, flag: bool) {
        self.remember_me_flag = Some(flag);
    }
}

impl PasswordVerifiable for FixtureUser {
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
        if self.encrypted_password.is_empty() {
            return false;
        }
        devise_rust::crypto::encryptor::compare(password, &self.encrypted_password, config)
    }
}

#[async_trait::async_trait]
impl devise_rust::model::Authenticatable for FixtureUser {
    fn active_for_authentication(&self) -> bool {
        // The confirmable gate composes on the window the record was BUILT
        // under (see the field doc): a controller-built record carries the
        // app's `allow_unconfirmed_access_for`, every other fixture record
        // keeps the hardcoded test window.
        let config = if self.unconfirmed_access_never_expires {
            DeviseConfig {
                allow_unconfirmed_access_for: None,
                ..test_config()
            }
        } else {
            test_config()
        };
        devise_rust::model::compose_active_for_authentication(
            self,
            &config,
            &devise_rust::time::SystemClock,
        )
    }

    fn inactive_message(&self) -> &'static str {
        devise_rust::model::compose_inactive_message(
            self,
            &test_config(),
            &devise_rust::time::SystemClock,
        )
    }

    fn serializable_hash(&self) -> JsonValue {
        serde_json::json!({ "id": self.id, "email": self.email })
    }
}

#[async_trait::async_trait]
impl DatabaseAuthenticatable for FixtureUser {
    fn encrypted_password(&self) -> Option<&str> {
        if self.encrypted_password.is_empty() {
            None
        } else {
            Some(&self.encrypted_password)
        }
    }

    fn set_encrypted_password(&mut self, value: Option<String>) {
        self.encrypted_password = value.unwrap_or_default();
    }

    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn set_password_virtual(&mut self, password: Option<String>) {
        self.password = password;
    }

    fn password_confirmation(&self) -> Option<&str> {
        self.password_confirmation.as_deref()
    }

    fn set_password_confirmation(&mut self, value: Option<String>) {
        self.password_confirmation = value;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }

    fn assign_attributes(&mut self, attrs: &serde_json::Map<String, JsonValue>) {
        if let Some(JsonValue::String(email)) = attrs.get("email") {
            email.clone_into(&mut self.email);
        }
        // Mass-assignment probes (S7): a model whose assign_attributes
        // persists these columns must never see them from a Devise
        // controller — the ParameterSanitizer drops them first.
        if let Some(JsonValue::String(unconfirmed)) = attrs.get("unconfirmed_email") {
            self.unconfirmed_email = Some(unconfirmed.clone());
        }
        if let Some(JsonValue::Number(attempts)) = attrs.get("failed_attempts") {
            self.failed_attempts =
                u32::try_from(attempts.as_u64().unwrap_or_default()).unwrap_or_default();
        }
    }
}

impl Registerable for FixtureUser {
    /// Core's default `new_with_session` body (`model.rs`), plus the window
    /// stamp the activity gate above reads.
    fn new_with_session(
        params: &serde_json::Map<String, serde_json::Value>,
        session: &serde_json::Value,
        config: &DeviseConfig,
    ) -> Self {
        let _ = session;
        let params = devise_rust::model::normalize_attribute_map(params, config);
        let mut record = Self::default();
        record.assign_attributes(&params);
        if let Some(password) = params.get("password").and_then(serde_json::Value::as_str) {
            record.set_password(Some(password.to_string()), config);
        }
        if let Some(confirmation) = params
            .get("password_confirmation")
            .and_then(serde_json::Value::as_str)
        {
            record.set_password_confirmation(Some(confirmation.to_string()));
        }
        // Fixture seam for the confirmable create-time gate
        // (confirmable.rb:286-288): an app model may suppress the sign-up
        // confirmation mail from its own code (Devise
        // `skip_confirmation_notification!`); the fixture opts in by
        // address marker because no request param may carry it (S7).
        record.skip_confirmation_notification = record.email.contains("skip-notify");
        record.unconfirmed_access_never_expires = config.allow_unconfirmed_access_for.is_none();
        record
    }
}

#[async_trait::async_trait]
impl Validatable for FixtureUser {
    fn email_value(&self) -> Option<&str> {
        Some(&self.email)
    }

    fn uniqueness_scope_id(&self) -> Option<String> {
        DatabaseAuthenticatable::persisted(self).then(|| self.id.to_string())
    }
}

#[async_trait::async_trait]
impl Recoverable for FixtureUser {
    fn reset_password_token(&self) -> Option<&str> {
        self.reset_password_token.as_deref()
    }

    fn reset_password_sent_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.reset_password_sent_at
    }

    fn set_reset_password_token_fields(
        &mut self,
        token: Option<String>,
        sent_at: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        self.reset_password_token = token;
        self.reset_password_sent_at = sent_at;
    }

    fn raw_reset_password_token(&self) -> Option<&str> {
        self.raw_reset_token.as_deref()
    }

    fn set_raw_reset_password_token(&mut self, raw: Option<String>) {
        self.raw_reset_token = raw;
    }
}

#[async_trait::async_trait]
impl devise_rust::confirmable::Confirmable for FixtureUser {
    fn confirmation_token(&self) -> Option<&str> {
        self.confirmation_token.as_deref()
    }

    fn set_confirmation_token(&mut self, token: Option<String>) {
        self.confirmation_token = token;
    }

    fn confirmed_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.confirmed_at
    }

    fn set_confirmed_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.confirmed_at = at;
    }

    fn confirmation_sent_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.confirmation_sent_at
    }

    fn set_confirmation_sent_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.confirmation_sent_at = at;
    }

    fn unconfirmed_email(&self) -> Option<&str> {
        self.unconfirmed_email.as_deref()
    }

    fn set_unconfirmed_email(&mut self, email: Option<String>) {
        self.unconfirmed_email = email;
    }

    fn set_email_address(&mut self, email: String) {
        self.email = email;
    }

    fn raw_confirmation_token(&self) -> Option<&str> {
        self.raw_confirmation_token.as_deref()
    }

    fn set_raw_confirmation_token(&mut self, raw: Option<String>) {
        self.raw_confirmation_token = raw;
    }

    fn confirmation_notification_skipped(&self) -> bool {
        self.skip_confirmation_notification
    }

    fn skip_confirmation_notification(&mut self) {
        self.skip_confirmation_notification = true;
    }
}

#[async_trait::async_trait]
impl devise_rust::lockable::Lockable for FixtureUser {
    fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    fn set_failed_attempts(&mut self, count: u32) {
        self.failed_attempts = count;
    }

    fn locked_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.locked_at
    }

    fn set_locked_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.locked_at = at;
    }

    fn unlock_token(&self) -> Option<&str> {
        self.unlock_token.as_deref()
    }

    fn set_unlock_token(&mut self, token: Option<String>) {
        self.unlock_token = token;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }

    fn raw_unlock_token(&self) -> Option<&str> {
        self.raw_unlock_token.as_deref()
    }

    fn set_raw_unlock_token(&mut self, raw: Option<String>) {
        self.raw_unlock_token = raw;
    }
}

impl Rememberable for FixtureUser {
    fn remember_created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.remember_created_at
    }

    fn set_remember_created_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.remember_created_at = at;
    }

    fn remember_token(&self) -> Option<&str> {
        self.remember_token.as_deref()
    }

    fn set_remember_token(&mut self, token: Option<String>) {
        self.remember_token = token;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }
}

impl devise_rust::trackable::Trackable for FixtureUser {
    fn sign_in_count(&self) -> u64 {
        self.sign_in_count
    }

    fn set_sign_in_count(&mut self, count: u64) {
        self.sign_in_count = count;
    }

    fn current_sign_in_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.current_sign_in_at
    }

    fn set_current_sign_in_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.current_sign_in_at = at;
    }

    fn last_sign_in_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_sign_in_at
    }

    fn set_last_sign_in_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.last_sign_in_at = at;
    }

    fn current_sign_in_ip(&self) -> Option<&str> {
        self.current_sign_in_ip.as_deref()
    }

    fn set_current_sign_in_ip(&mut self, ip: Option<String>) {
        self.current_sign_in_ip = ip;
    }

    fn last_sign_in_ip(&self) -> Option<&str> {
        self.last_sign_in_ip.as_deref()
    }

    fn set_last_sign_in_ip(&mut self, ip: Option<String>) {
        self.last_sign_in_ip = ip;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }
}

impl devise_rust::mailer::HasEmail for FixtureUser {
    fn email(&self) -> &str {
        &self.email
    }
}

/// The omniauthable seam over the fixture (09-04 flow matrix): delegates
/// to the core default find-link-create policy behind the verified
/// email gate (D-08/D-09/D-10).
#[async_trait::async_trait]
impl devise_rust::omniauthable::Omniauthable for FixtureUser {
    type New = FixtureUser;

    async fn from_omniauth<A>(
        profile: devise_rust::omniauthable::ProviderProfile,
        adapter: &A,
        clock: &dyn Clock,
    ) -> devise_rust::error::ResourceWithErrors<Self>
    where
        Self: Sized,
        A: devise_rust::adapter::OrmAdapter<Self, New = Self::New> + Send + Sync,
    {
        let mut outcome = devise_rust::omniauthable::default_from_omniauth(
            adapter,
            &profile,
            &devise_rust::config::DeviseConfig::default(),
            clock,
        )
        .await;
        // Devise's canonical from_omniauth pattern: a provider-verified
        // identity is confirmed on creation (one home: core helper).
        if outcome.is_valid() {
            let _ = devise_rust::omniauthable::confirm_verified_identity(
                &mut outcome.record,
                &profile,
                adapter,
                clock,
            )
            .await;
        }
        outcome
    }

    fn new_from_profile(
        profile: &devise_rust::omniauthable::ProviderProfile,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Self::New {
        // A real bcrypt hash keeps the warden salt-in-session fetch valid
        // (omniauth-created rows carry no usable password — like Devise —
        // but the salt prefix must exist for the signed-in probe refetch).
        let mut user = FixtureUser::new_with_password(
            &profile.email.clone().unwrap_or_default(),
            "omniauth-no-password-login",
            &test_config(),
        );
        user.provider = Some(profile.provider.clone());
        user.uid = Some(profile.uid.clone());
        user.name.clone_from(&profile.name);
        user
    }
}

/// Verify every signed `devise.flash` cookie value among captured
/// `Set-Cookie` pairs, returning the bare flash keys that verified (S11:
/// the cookie value is a MAC-prefixed signed envelope over the bare I18n
/// key — exactly the core `devise.*` message stems, never rendered copy).
pub fn flash_keys_from_cookies(cookies: &[String], config: &DeviseConfig) -> Vec<String> {
    let key = devise_rust_axum::callbacks::derive_session_key(&config.secret_key)
        .expect("flash key derives");
    cookies
        .iter()
        .filter_map(|pair| {
            let value = pair.strip_prefix("devise.flash=")?;
            let value = value.split(';').next()?;
            let mut jar = cookie::CookieJar::new();
            jar.add_original(cookie::Cookie::new("devise.flash", value.to_string()));
            jar.signed(&key)
                .get("devise.flash")
                .map(|cookie| cookie.value().to_string())
        })
        .collect()
}

/// Verify the signed `devise.flash.timedout` marker cookie among captured
/// `Set-Cookie` pairs: Devise stages the marker BESIDE the timeout alert
/// (`failure_app.rb:137`: `flash[:timedout] = true`), so the pair must ride
/// the failure response together.
pub fn timedout_marker_from_cookies(cookies: &[String], config: &DeviseConfig) -> bool {
    let key = devise_rust_axum::callbacks::derive_session_key(&config.secret_key)
        .expect("flash key derives");
    cookies
        .iter()
        .filter_map(|pair| {
            let value = pair.strip_prefix("devise.flash.timedout=")?;
            let value = value.split(';').next()?;
            let mut jar = cookie::CookieJar::new();
            jar.add_original(cookie::Cookie::new(
                "devise.flash.timedout",
                value.to_string(),
            ));
            jar.signed(&key)
                .get("devise.flash.timedout")
                .map(|cookie| cookie.value().to_string())
        })
        .any(|value| value == "true")
}

/// The test configuration with fast `stretches` (4) and a fixed 32-byte secret.
pub fn test_config() -> DeviseConfig {
    DeviseConfig {
        secret_key: "test-secret-key-for-testing-only-32-bytes-min".to_string(),
        stretches: 4,
        ..DeviseConfig::default()
    }
}

/// The default mapping plus `Module::Timeoutable`: core registers the
/// per-request timeout tick hook only when the module is on the mapping,
/// so the timeoutable flow fixtures need the module present.
pub fn timeout_mapping() -> Mapping {
    let mut mapping = default_mapping();
    mapping.modules.push(Module::Timeoutable);
    mapping
}

/// Default mapping builder (full module matrix), with overrides applied.
pub fn default_mapping() -> Mapping {
    Mapping {
        name: "user".to_string(),
        class_name: "FixtureUser".to_string(),
        path: "users".to_string(),
        path_prefix: None,
        singular: "user".to_string(),
        path_names: PathNames::default(),
        controllers: std::collections::HashMap::new(),
        modules: vec![
            Module::DatabaseAuthenticatable,
            Module::Registerable,
            Module::Recoverable,
            Module::Rememberable,
            Module::Validatable,
            Module::Confirmable,
            Module::Lockable,
            Module::Trackable,
        ],
        only: vec![],
        skip: vec![],
        constraints: std::collections::HashMap::new(),
        defaults: std::collections::HashMap::new(),
        format: None,
        router_name: None,
        sign_out_via: SignOutVia::Delete,
        failure_app: None,
    }
}

/// Registry holding the given mappings.
pub fn registry_with(mappings: &[Mapping]) -> Arc<ScopeRegistry> {
    let mut registry = ScopeRegistry::new();
    for mapping in mappings {
        registry.register(mapping.clone());
    }
    Arc::new(registry)
}

/// Shared app state over the fixture user on the memory-adapter oracle.
pub type TestState = DeviseWebState<FixtureUser, IdAssigningAdapter, TestMailer>;

/// Build a fresh [`TestState`]: adapter + mailer + config + mapping + clock.
pub fn test_state(mapping: Mapping) -> TestState {
    test_state_with_config(mapping, test_config())
}

/// Same as [`test_state`] with an explicit config.
pub fn test_state_with_config(mapping: Mapping, config: DeviseConfig) -> TestState {
    let registry = registry_with(std::slice::from_ref(&mapping));
    DeviseWebState::new(
        mapping,
        registry,
        Arc::new(config),
        Arc::new(IdAssigningAdapter::new()),
        Arc::new(TestMailer::default()),
        Arc::new(SystemClock),
    )
    .expect("test state builds (secret is 32+ bytes)")
}

/// Probe route under the scope: 200 with the layer-resolved user email;
/// unauthenticated requests fail through `RequireAuth` (→ 302 + flash for
/// navigational, 401 for API) with stored-location support on GET.
async fn private_probe(user: devise_rust_axum::RequireAuth<FixtureUser>) -> impl IntoResponse {
    let (email, sign_in_count) = user
        .user()
        .map(|user| (user.email.clone(), user.sign_in_count))
        .unwrap_or_default();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "email": email, "sign_in_count": sign_in_count })),
    )
}

/// Bypass call-site probe (`test_helpers::bypass_sign_in`): signs the
/// email's record into the REQUEST'S OWN session without any password
/// post — Devise `IntegrationHelpers#sign_in` parity. The response
/// `Set-Cookie` carries the rotated id for jar replay into protected
/// routes (the actix suite drives the same shape from extractors.rs).
async fn bypass_sign_in_probe(
    adapter: Arc<IdAssigningAdapter>,
    session: Session,
    email: String,
) -> StatusCode {
    let mut conditions = devise_rust::adapter::Conditions::new();
    conditions.insert("email", devise_rust::adapter::Value::String(email));
    let Some(user) = OrmAdapter::find_first(adapter.as_ref(), &conditions)
        .await
        .expect("lookup")
    else {
        return StatusCode::NOT_FOUND;
    };
    devise_rust_axum::test_helpers::bypass_sign_in(&session, "user", &user)
        .await
        .expect("bypass");
    StatusCode::OK
}

/// Bypass sign-out call-site probe (`test_helpers::sign_out_with_forget`):
/// clears the `user` scope with the remember-cookie delete intent; the
/// drained op's scope + key ride the JSON body for assertion
/// (T-09-07: logout never leaves a live remember login).
async fn bypass_sign_out_probe(
    config: Arc<DeviseConfig>,
    session: Session,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    let op = devise_rust_axum::test_helpers::sign_out_with_forget(&session, "user", &config)
        .await
        .expect("sign out");
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "scope": op.scope(),
            "key": op.key(),
        })),
    )
}

/// Wired axum test app: `SessionManagerLayer` outermost, then `DeviseLayer`
/// (with the fixture finder + the core Devise hooks registered), then the
/// `devise_for_router` mount. Returns the state alongside the router so
/// tests can seed users and read sent mail.
///
/// The probe route lives OUTSIDE the devise router (axum routes claim their
/// exact path) but still prefix-matches the registry's `find_by_path`, so
/// the layer resolves the `user` scope for it.
///
/// The two `/devise-test/bypass-*` probes mount the `IntegrationHelpers`
/// call sites under the SAME session store as the devise routes (the
/// store lives inside the session layer, so the probes must share the
/// app's layers — the actix suite could build a standalone mini-app
/// because actix sessions are cookie-carried).
pub fn build_app(state: TestState) -> (TestState, Router) {
    let session_layer = session_manager_layer(&state.config).expect("session layer builds");
    devise_app(state, session_layer)
}

/// [`build_app`] over a caller-chosen mailer: the failing-mailer fixtures
/// need the full standard stack with delivery errors, so only the mailer
/// type differs from [`TestState`].
pub fn build_app_with_mailer<L>(
    state: DeviseWebState<FixtureUser, IdAssigningAdapter, L>,
) -> (DeviseWebState<FixtureUser, IdAssigningAdapter, L>, Router)
where
    L: devise_rust::mailer::Mailer<FixtureUser> + Send + Sync + 'static,
{
    let session_layer = session_manager_layer(&state.config).expect("session layer builds");
    devise_app(state, session_layer)
}

/// [`build_app`] over an EXPLICIT session layer: the failure-path fixtures
/// drive the renewal gates through a store whose `cycle_id` budget is spent
/// (SESS-05 / D-04 propagation assertions).
fn devise_app<S, L>(
    state: DeviseWebState<FixtureUser, IdAssigningAdapter, L>,
    session_layer: SessionManagerLayer<S, SignedCookie>,
) -> (DeviseWebState<FixtureUser, IdAssigningAdapter, L>, Router)
where
    S: SessionStore + Clone,
    L: devise_rust::mailer::Mailer<FixtureUser> + Send + Sync + 'static,
{
    let mut hooks = HookRegistry::new();
    devise_rust::hooks::register_devise_hooks(&mut hooks, &state.mapping);

    let mapping = state.mapping.clone();
    let scope_name = mapping.name.clone();
    let finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(state.adapter.as_ref().clone()));
    let devise_layer = DeviseLayer::new(
        registry_with(std::slice::from_ref(&mapping)),
        state.config.clone(),
    )
    .with_hooks(Arc::new(hooks))
    .with_finder(&scope_name, finder);

    // The bypass probes capture the shared Arcs (the devise router already
    // consumed the typed state into `Router<()>`).
    let probe_adapter = state.adapter.clone();
    let probe_config = state.config.clone();

    let app = Router::new()
        .merge(devise_for_router(state.clone()))
        .route(
            "/users_dashboard",
            axum::routing::get(private_probe).post(private_probe),
        )
        .route(
            "/devise-test/bypass-sign-in",
            axum::routing::get(
                move |session: Session,
                      Query(query): Query<std::collections::HashMap<String, String>>| {
                    let adapter = probe_adapter.clone();
                    async move {
                        bypass_sign_in_probe(
                            adapter,
                            session,
                            query.get("email").cloned().unwrap_or_default(),
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/devise-test/bypass-sign-out",
            axum::routing::get(move |session: Session| {
                let config = probe_config.clone();
                async move { bypass_sign_out_probe(config, session).await }
            }),
        )
        .route(
            "/devise-test/age-tick",
            axum::routing::get(
                |session: Session,
                 Query(query): Query<std::collections::HashMap<String, String>>| async move {
                    age_tick_probe(session, &query).await
                },
            ),
        )
        .layer(devise_layer)
        .layer(session_layer);
    (state, app)
}

/// Age the scope's timeoutable `last_request_at` tick far past the default
/// 30-minute `timeout_in` (the timeoutable flow fixtures sign in normally,
/// then stale the tick through this probe so the NEXT request times out).
async fn age_tick_probe(
    session: Session,
    query: &std::collections::HashMap<String, String>,
) -> StatusCode {
    let scope = query
        .get("scope")
        .cloned()
        .unwrap_or_else(|| "user".to_string());
    let stale = SystemClock.now().timestamp() - 7200;
    session
        .insert_value(
            &devise_rust::timeoutable::last_request_at_key(&scope),
            serde_json::json!(stale),
        )
        .await
        .expect("tick ages");
    StatusCode::OK
}

// ============================================================================
// Failure-path fixture: a session store whose id-rotation budget is spent.
// The D-04 renewal gates must answer 500 (not a flashed success) when the
// cycle fails, so the propagation needs a store that can actually fail.
// ============================================================================

/// Wire a [`CycleFailStore`] into the same app [`build_app`] builds, driven
/// by a shared switch the fixture flips when the NEXT session-id rotation
/// must fail.
///
/// The cookie attributes mirror [`session_manager_layer`] (`SameSite=Lax`,
/// signed over the Devise-derived key, `HttpOnly`, `Secure`) so the only
/// difference from the default app is the store's failure switch.
pub fn build_app_with_cycle_switch(
    state: TestState,
    closed: Arc<std::sync::atomic::AtomicBool>,
) -> (TestState, Router) {
    let key = devise_rust_axum::callbacks::derive_session_key(&state.config.secret_key)
        .expect("session key derives");
    let session_layer = SessionManagerLayer::new(CycleFailStore::new(closed))
        .with_same_site(cookie::SameSite::Lax)
        .with_http_only(true)
        .with_secure(true)
        .with_signed(key);
    devise_app(state, session_layer)
}

/// `MemoryStore` whose `delete` (the store call `Session::cycle_id` makes
/// when rotating the session id) fails once the shared switch closes.
///
/// tower-sessions rotates the id by deleting the old record and re-creating
/// it under a fresh id, so a failing `delete` IS a failed session-id
/// renewal. The switch lets a fixture sign in normally and then watch the
/// NEXT transition's cycle fail: every renewal helper must propagate that
/// failure as a 500 instead of flashing success (D-04 renewal gates).
#[derive(Debug)]
pub struct CycleFailStore {
    inner: MemoryStore,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl CycleFailStore {
    /// A store that refuses rotations once `closed` flips to `true`.
    pub fn new(closed: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            inner: MemoryStore::default(),
            closed,
        }
    }

    /// A fresh open switch paired with the store that watches it.
    pub fn pair() -> (Self, Arc<std::sync::atomic::AtomicBool>) {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (Self::new(closed.clone()), closed)
    }
}

impl Clone for CycleFailStore {
    fn clone(&self) -> Self {
        Self::new(self.closed.clone())
    }
}

#[async_trait::async_trait]
impl SessionStore for CycleFailStore {
    async fn create(&self, session_record: &mut Record) -> session_store::Result<()> {
        self.inner.create(session_record).await
    }

    async fn save(&self, session_record: &Record) -> session_store::Result<()> {
        self.inner.save(session_record).await
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        self.inner.load(session_id).await
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(session_store::Error::Backend(
                "session-id renewal refused: cycle switch closed".to_string(),
            ));
        }
        self.inner.delete(session_id).await
    }
}

// ============================================================================
// Two-scope app (S2 / M-fix matrix): sibling `admin` mapping over the SAME
// FixtureUser model + adapter, for the registry-derived sign-out-all and
// the all-scopes `verify_signed_out_user` behavior.
// ============================================================================

/// The sibling `admin` mapping over the fixture user.
pub fn admin_mapping() -> Mapping {
    Mapping {
        name: "admin".to_string(),
        class_name: "FixtureUser".to_string(),
        path: "admins".to_string(),
        singular: "admin".to_string(),
        ..default_mapping()
    }
}

/// Wired TWO-scope app: `user` + `admin` devise mounts sharing one adapter
/// and config, both behind the same `DeviseLayer` (registry carries both).
pub fn build_two_scope_app() -> (TestState, Router) {
    let user_mapping = default_mapping();
    let admin_mapping = admin_mapping();
    let config = Arc::new(test_config());
    let adapter = Arc::new(IdAssigningAdapter::new());
    let mailer = Arc::new(TestMailer::default());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

    let registry = registry_with(&[user_mapping.clone(), admin_mapping.clone()]);
    let state_user = DeviseWebState::new(
        user_mapping.clone(),
        registry.clone(),
        config.clone(),
        adapter.clone(),
        mailer.clone(),
        clock.clone(),
    )
    .expect("user state builds");
    let state_admin = DeviseWebState::new(
        admin_mapping.clone(),
        registry.clone(),
        config.clone(),
        adapter.clone(),
        mailer.clone(),
        clock.clone(),
    )
    .expect("admin state builds");

    let mut hooks = HookRegistry::new();
    devise_rust::hooks::register_devise_hooks(&mut hooks, &state_user.mapping);

    let finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(adapter.as_ref().clone()));
    let devise_layer = DeviseLayer::new(registry, config.clone())
        .with_hooks(Arc::new(hooks))
        .with_finder("user", finder.clone())
        .with_finder("admin", finder.clone());
    let session_layer = session_manager_layer(&config).expect("session layer builds");

    let app = Router::new()
        .merge(devise_for_router(state_user.clone()))
        .merge(devise_for_router(state_admin.clone()))
        .layer(devise_layer)
        .layer(session_layer);
    (state_user, app)
}

// ============================================================================
// Omniauth flow fixtures (09-04): the omniauthable mapping variant, the
// provider-allowlist config, and the omniauth-aware wired app.
// ============================================================================

/// Omniauthable mapping variant: the full module matrix plus
/// `Module::Omniauthable` (the route-table amendment's consumer).
pub fn omniauth_mapping() -> Mapping {
    let mut mapping = default_mapping();
    mapping.modules.push(Module::Omniauthable);
    mapping
}

/// Test config with the request-time provider allowlist populated.
pub fn omniauth_test_config(providers: &[&str]) -> DeviseConfig {
    DeviseConfig {
        omniauth_providers: providers.iter().map(ToString::to_string).collect(),
        ..test_config()
    }
}

/// Wired omniauth test app: the full devise router plus the omniauth
/// router (from the shared spec data) under the same session layers as
/// [`build_app`], with the dashboard probe mounted for post-sign-in
/// jar-replay assertions.
///
/// The app carries an explicit `omniauth_origin` so the redirect URIs
/// derive from a stable origin — the flow tests set the same `Host`
/// header on every oneshot request (the jar replay across the
/// authorize POST -> callback GET IS the Lax cookie assertion).
pub fn build_omniauth_app(
    mapping: Mapping,
    config: DeviseConfig,
    providers: std::collections::HashMap<String, devise_rust::omniauthable::OAuthProviderConfig>,
) -> (TestState, Router) {
    let registry = registry_with(std::slice::from_ref(&mapping));
    let state = DeviseWebState::new(
        mapping,
        registry,
        Arc::new(config),
        Arc::new(IdAssigningAdapter::new()),
        Arc::new(TestMailer::default()),
        Arc::new(SystemClock),
    )
    .expect("test state builds (secret is 32+ bytes)");

    let mut hooks = HookRegistry::new();
    devise_rust::hooks::register_devise_hooks(&mut hooks, &state.mapping);

    let mapping = state.mapping.clone();
    let scope_name = mapping.name.clone();
    let finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(state.adapter.as_ref().clone()));
    let devise_layer = DeviseLayer::new(
        registry_with(std::slice::from_ref(&mapping)),
        state.config.clone(),
    )
    .with_hooks(Arc::new(hooks))
    .with_finder(&scope_name, finder);
    let session_layer = session_manager_layer(&state.config).expect("session layer builds");

    let omniauth_state = devise_rust_axum::OmniauthWebState::new(state.clone(), providers);
    let app = Router::new()
        .merge(devise_for_router(state.clone()))
        .merge(devise_rust_axum::omniauth_router(omniauth_state).expect("omniauth router"))
        .route(
            "/users_dashboard",
            axum::routing::get(private_probe).post(private_probe),
        )
        .layer(devise_layer)
        .layer(session_layer);
    (state, app)
}
