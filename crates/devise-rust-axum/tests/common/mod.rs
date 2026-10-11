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
use tower_sessions::Session;

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

/// Full-module fixture user: every Devise module trait implemented so the
/// route matrix can exercise all five controllers against one model.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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
    #[serde(skip)]
    pub raw_reset_token: Option<String>,
    #[serde(skip)]
    pub raw_confirmation_token: Option<String>,
    #[serde(skip)]
    pub raw_unlock_token: Option<String>,
    #[serde(skip)]
    pub remember_me_flag: Option<bool>,
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

impl AnyDeviseModel for FixtureUser {
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
        use devise_rust::confirmable::Confirmable;
        use devise_rust::lockable::Lockable;
        // Devise super-chain: base(true) → confirmable → lockable order.
        let config = test_config();
        let clock = SystemClock;
        let base = self.locked_at.is_none() || !self.access_locked(&config, &clock);
        let confirmable_active = self.confirmed() || !self.confirmation_required();
        devise_rust::model::chain_active_for_authentication(confirmable_active, base)
    }

    fn inactive_message(&self) -> &'static str {
        if self.locked_at.is_some() {
            "locked"
        } else if self.confirmed_at.is_none() {
            "unconfirmed"
        } else {
            "inactive"
        }
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
    }
}

impl Registerable for FixtureUser {}

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

/// Test configuration: fast `stretches`, fixed 32-byte secret.
pub fn test_config() -> DeviseConfig {
    DeviseConfig {
        secret_key: "test-secret-key-for-testing-only-32-bytes-min".to_string(),
        stretches: 4,
        ..DeviseConfig::default()
    }
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
    DeviseWebState::new(
        mapping,
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
    let email = user
        .user()
        .map(|user| user.email.clone())
        .unwrap_or_default();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "email": email })),
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
        .layer(devise_layer)
        .layer(session_layer);
    (state, app)
}
