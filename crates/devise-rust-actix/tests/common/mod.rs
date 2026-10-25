//! Shared fixture for the 08-03 route/flow suites: a full-module
//! `FixtureUser` over `MemoryAdapter`, scope registry bootstrap, and the
//! wired actix test service (`SessionMiddleware` outermost + `DeviseMiddleware`
//! + `devise_for` scope).

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpResponse, web};
use devise_rust::{
    adapter::{DeviseKey, memory::MemoryAdapter},
    config::DeviseConfig,
    failure::AnyDeviseModel,
    mailer::TestMailer,
    model::{
        AdapterBridge, DatabaseAuthenticatable, PasswordVerifiable, Recoverable, Registerable,
        Validatable,
    },
    rememberable::Rememberable,
    scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia},
    time::Clock,
};
use devise_rust_actix::{ActixSessionStore, DeviseMiddleware, routes::DeviseWebState};

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
/// id first (start at 1, matching the oracle's counter — every create flows
/// through this wrapper, keeping the two counters in lockstep), preserving
/// `#[serde(skip)]` fields because the oracle stores typed clones.
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
impl devise_rust::adapter::OrmAdapter<FixtureUser> for IdAssigningAdapter {
    type New = FixtureUser;

    async fn get(
        &self,
        id: &DeviseKey,
    ) -> Result<Option<FixtureUser>, devise_rust::adapter::OrmError> {
        devise_rust::adapter::OrmAdapter::get(&self.inner, id).await
    }

    async fn find_first(
        &self,
        conditions: &devise_rust::adapter::Conditions,
    ) -> Result<Option<FixtureUser>, devise_rust::adapter::OrmError> {
        devise_rust::adapter::OrmAdapter::find_first(&self.inner, conditions).await
    }

    async fn create(
        &self,
        mut model: FixtureUser,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        model.id = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        devise_rust::adapter::OrmAdapter::create(&self.inner, model).await
    }

    async fn update(
        &self,
        key: &DeviseKey,
        changes: &devise_rust::adapter::ChangeSet,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        devise_rust::adapter::OrmAdapter::update(&self.inner, key, changes).await
    }

    async fn update_columns(
        &self,
        key: &DeviseKey,
        fields: &std::collections::HashMap<String, devise_rust::adapter::Value>,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        devise_rust::adapter::OrmAdapter::update_columns(&self.inner, key, fields).await
    }

    async fn increment_counter(
        &self,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<FixtureUser, devise_rust::adapter::OrmError> {
        devise_rust::adapter::OrmAdapter::increment_counter(&self.inner, key, column).await
    }

    async fn delete(&self, id: &DeviseKey) -> Result<(), devise_rust::adapter::OrmError> {
        devise_rust::adapter::OrmAdapter::delete(&self.inner, id).await
    }
}
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

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
}

impl AnyDeviseModel for FixtureUser {
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
        devise_rust::model::compose_active_for_authentication(
            self,
            &test_config(),
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

impl FixtureUser {
    /// Confirmable-aware lock check used by the fixture's activity gate:
    /// a record whose lock EXPIRED counts as active (Devise's own flow
    /// auto-unlocks expired locks before the gate is read).
    fn access_locked_now(&self, config: &DeviseConfig, clock: &dyn Clock) -> bool {
        use devise_rust::lockable::Lockable;
        self.access_locked(config, clock)
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
        devise_rust::model::DatabaseAuthenticatable::persisted(self).then(|| self.id.to_string())
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
        let mut outcome =
            devise_rust::omniauthable::default_from_omniauth(adapter, &profile, clock).await;
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

/// Registry holding the default user mapping.
pub fn registry_with(mapping: Mapping) -> Arc<ScopeRegistry> {
    let mut registry = ScopeRegistry::new();
    registry.register(mapping);
    Arc::new(registry)
}

/// Shared app state over the fixture user on the memory adapter.
pub type TestState = DeviseWebState<FixtureUser, IdAssigningAdapter, TestMailer>;

/// Build a fresh [`TestState`]: adapter + mailer + config + mapping + clock.
pub fn test_state(mapping: Mapping) -> TestState {
    test_state_with_config(mapping, test_config())
}

/// Same as [`test_state`] with an explicit config.
pub fn test_state_with_config(mapping: Mapping, config: DeviseConfig) -> TestState {
    let all_scopes = vec![mapping.name.clone()];
    TestState {
        mapping,
        config: Arc::new(config),
        adapter: Arc::new(IdAssigningAdapter::new()),
        mailer: Arc::new(TestMailer::default()),
        clock: Arc::new(SystemClock),
        all_scopes,
        marker: std::marker::PhantomData,
    }
}

/// Probe route under the scope: 200 with the middleware-resolved user
/// email; unauthenticated requests fail through `RequireAuth` (-> 302 + flash
/// for navigational, 401 for API) with stored-location support on GET.
async fn private_probe(user: devise_rust_actix::RequireAuth<FixtureUser>) -> HttpResponse {
    let email = user.user().map(|u| u.email.clone()).unwrap_or_default();
    HttpResponse::Ok().json(serde_json::json!({ "email": email }))
}

/// Wired actix test service: `SessionMiddleware` outermost, then
/// `DeviseMiddleware` (with the fixture finder registered), then the
/// `devise_for` scope. `actix_web::wrap` order is reverse-execution, so
/// wrapping Devise first puts the session middleware outermost.
///
/// Returns the service alongside the shared state so tests can seed users
/// and read sent mail.
pub async fn build_app(
    state: TestState,
) -> (
    TestState,
    impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
) {
    let key =
        devise_rust_actix::derive_actix_key(&state.config.secret_key).expect("derive actix key");
    let store = ActixSessionStore::new(key.clone());
    let scope_name = state.mapping.name.clone();
    let finder: Arc<dyn devise_rust::model::ModelFinder> =
        Arc::new(AdapterBridge::new(state.adapter.as_ref().clone()));
    let middleware = DeviseMiddleware::new(
        Arc::new(store),
        registry_with(state.mapping.clone()),
        state.config.clone(),
    )
    .with_finder(&scope_name, finder);

    let data_state = state.clone();
    let service = actix_web::test::init_service(
        App::new()
            .wrap(middleware)
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key)
                    .cookie_secure(false)
                    .build(),
            )
            .service(devise_rust_actix::routes::devise_for_users(web::Data::new(
                data_state.clone(),
            )))
            // Probe route OUTSIDE the devise scope (actix scopes claim their
            // prefix) but still prefix-matching the registry's find_by_path.
            .route("/users_dashboard", web::get().to(private_probe))
            .route("/users_dashboard", web::post().to(private_probe)),
    )
    .await;
    (state, service)
}

// ============================================================================
// Omniauth flow fixtures (09-04): the omniauthable mapping variant, the
// provider-allowlist config, and the omniauth-aware wired service.
// ============================================================================

/// Omniauthable mapping variant: the full module matrix plus
/// `Module::Omniauthable` (the route-table amendment's consumer).
pub fn omniauth_mapping() -> Mapping {
    let mut mapping = default_mapping();
    mapping
        .modules
        .push(devise_rust::scope::Module::Omniauthable);
    mapping
}

/// Test config with the request-time provider allowlist populated.
pub fn omniauth_test_config(providers: &[&str]) -> DeviseConfig {
    DeviseConfig {
        omniauth_providers: providers.iter().map(ToString::to_string).collect(),
        ..test_config()
    }
}

/// Wired omniauth test service: the omniauth scope (mounted FIRST —
/// actix matches top-level services in registration order and the
/// omniauth base is the longer prefix), the full devise scope, and the
/// dashboard probe for post-sign-in cookie-replay assertions.
pub async fn build_omniauth_service(
    mapping: Mapping,
    config: DeviseConfig,
    providers: std::collections::HashMap<String, devise_rust::omniauthable::OAuthProviderConfig>,
) -> (
    TestState,
    impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
) {
    let all_scopes = vec![mapping.name.clone()];
    let state = TestState {
        mapping,
        config: Arc::new(config),
        adapter: Arc::new(IdAssigningAdapter::new()),
        mailer: Arc::new(TestMailer::default()),
        clock: Arc::new(SystemClock),
        all_scopes,
        marker: std::marker::PhantomData,
    };

    let key =
        devise_rust_actix::derive_actix_key(&state.config.secret_key).expect("derive actix key");
    let store = ActixSessionStore::new(key.clone());
    let scope_name = state.mapping.name.clone();
    let finder: Arc<dyn devise_rust::model::ModelFinder> =
        Arc::new(AdapterBridge::new(state.adapter.as_ref().clone()));
    let middleware = DeviseMiddleware::new(
        Arc::new(store),
        registry_with(state.mapping.clone()),
        state.config.clone(),
    )
    .with_finder(&scope_name, finder);

    let omniauth_state = devise_rust_actix::OmniauthWebState::new(state.clone(), providers);
    let data_state = state.clone();
    let service = actix_web::test::init_service(
        App::new()
            .wrap(middleware)
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key)
                    .cookie_secure(false)
                    .build(),
            )
            // The omniauth scope FIRST (longest-prefix match wins in
            // registration order).
            .service(
                devise_rust_actix::devise_omniauth_scope(web::Data::new(omniauth_state))
                    .expect("omniauth scope"),
            )
            .service(devise_rust_actix::routes::devise_for_users(web::Data::new(
                data_state.clone(),
            )))
            .route("/users_dashboard", web::get().to(private_probe))
            .route("/users_dashboard", web::post().to(private_probe)),
    )
    .await;
    (state, service)
}
