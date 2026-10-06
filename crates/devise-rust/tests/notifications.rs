//! Notification integration tests (Task 3): `after_database_authentication`
//! fires from the password strategies, and email/password change
//! notifications dispatch through the Mailer with Devise parity (original vs
//! current recipient).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use devise_rust::adapter::memory::MemoryAdapter;
use devise_rust::adapter::{ChangeSet, DeviseKey, OrmAdapter, Value};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::hooks::HookRegistry;
use devise_rust::mailer::{HasEmail, Mailer, MailerContext, TestMailer};
use devise_rust::model::{Authenticatable, DatabaseAuthenticatable, PasswordVerifiable};
use devise_rust::proxy::AuthProxy;
use devise_rust::request::{AuthRequest, HttpMethod};
use devise_rust::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};
use devise_rust::session::SessionStore;
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct User {
    id: i64,
    email: String,
    encrypted_password: String,
    #[serde(skip)]
    password: Option<String>,
    #[serde(skip)]
    password_confirmation: Option<String>,
    #[serde(skip)]
    after_auth_count: Arc<AtomicUsize>,
}

impl AnyDeviseModel for User {
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        DatabaseAuthenticatable::database_authenticatable_salt(self)
    }

    fn as_password_verifiable(&self) -> Option<&dyn PasswordVerifiable> {
        Some(self)
    }

    fn after_database_authentication(&self) {
        self.after_auth_count.fetch_add(1, Ordering::SeqCst);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PasswordVerifiable for User {
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
        DatabaseAuthenticatable::valid_password(self, password, config)
    }
}

impl Authenticatable for User {
    fn serializable_hash(&self) -> JsonValue {
        serde_json::json!({ "id": self.id, "email": self.email })
    }
}

impl HasEmail for User {
    fn email(&self) -> &str {
        &self.email
    }
}

#[async_trait::async_trait]
impl DatabaseAuthenticatable for User {
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
            self.email.clone_from(email);
        }
    }
}

#[derive(Default)]
struct NotificationStore {
    data: Arc<std::sync::RwLock<HashMap<String, JsonValue>>>,
}

#[async_trait::async_trait]
impl SessionStore for NotificationStore {
    async fn get_value(&self, key: &str) -> Option<JsonValue> {
        self.data.read().unwrap().get(key).cloned()
    }

    async fn insert_value(&self, key: &str, value: JsonValue) {
        self.data.write().unwrap().insert(key.to_string(), value);
    }

    async fn remove(&self, key: &str) {
        self.data.write().unwrap().remove(key);
    }

    async fn remove_prefix(&self, prefix: &str) {
        self.data
            .write()
            .unwrap()
            .retain(|k, _| !k.starts_with(prefix));
    }

    async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        self.data
            .read()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }

    async fn renew(&self) -> Result<(), devise_rust::error::DeviseError> {
        Ok(())
    }

    async fn reset(&self) -> Result<(), devise_rust::error::DeviseError> {
        self.data.write().unwrap().clear();
        Ok(())
    }
}

fn test_config() -> DeviseConfig {
    DeviseConfig {
        stretches: 4,
        send_email_changed_notification: true,
        send_password_change_notification: true,
        ..DeviseConfig::default()
    }
}

fn proxy_with_store(config: &DeviseConfig) -> (AuthProxy, MemoryAdapter<User>) {
    let mut registry = ScopeRegistry::new();
    registry.register(Mapping {
        name: "user".to_string(),
        class_name: "User".to_string(),
        path: "users".to_string(),
        path_prefix: None,
        singular: "user".to_string(),
        path_names: PathNames::default(),
        controllers: HashMap::new(),
        modules: vec![Module::DatabaseAuthenticatable],
        only: vec![],
        skip: vec![],
        constraints: HashMap::new(),
        defaults: HashMap::new(),
        format: None,
        router_name: None,
        sign_out_via: SignOutVia::Delete,
        failure_app: None,
    });
    let mut proxy = AuthProxy::new(
        Arc::new(NotificationStore::default()),
        Arc::new(registry),
        Arc::new(HookRegistry::new()),
        Arc::new(config.clone()),
    );
    let adapter = MemoryAdapter::<User>::new();
    proxy.register_finder(
        "user",
        Arc::new(devise_rust::model::AdapterBridge::new(adapter.clone())),
    );
    (proxy, adapter)
}

#[tokio::test]
async fn after_database_authentication_fires_on_password_strategies() {
    let config = test_config();
    let counter = Arc::new(AtomicUsize::new(0));
    let (mut proxy, adapter) = proxy_with_store(&config);

    // Seed the record and authenticate via the params strategy.
    let user = User {
        id: 1,
        email: "notify@example.com".to_string(),
        encrypted_password: devise_rust::crypto::encryptor::digest("secret123", &config),
        after_auth_count: Arc::clone(&counter),
        ..User::default()
    };
    adapter.create(user).await.unwrap();

    let mut request = AuthRequest::new(HttpMethod::Post, "/users/sign_in".to_string());
    request
        .params
        .insert("user_email".to_string(), "notify@example.com".to_string());
    request
        .params
        .insert("user_password".to_string(), "secret123".to_string());
    request.flags.allow_params_authentication = true;

    let authenticated = proxy.authenticate("user", &request).await;
    assert!(authenticated.is_some(), "params auth succeeds");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "after_database_authentication fired exactly once (DBAU-07)"
    );

    // Wrong password: no hook fire (fresh proxy same adapter).
    let (mut proxy2, _) = proxy_with_store(&config);
    proxy2.register_finder(
        "user",
        Arc::new(devise_rust::model::AdapterBridge::new(adapter.clone())),
    );
    let mut bad = AuthRequest::new(HttpMethod::Post, "/users/sign_in".to_string());
    bad.params
        .insert("user_email".to_string(), "notify@example.com".to_string());
    bad.params
        .insert("user_password".to_string(), "wrong".to_string());
    bad.flags.allow_params_authentication = true;
    assert!(proxy2.authenticate("user", &bad).await.is_none());
    assert_eq!(counter.load(Ordering::SeqCst), 1, "no fire on failure");
}

#[tokio::test]
async fn email_change_notification_goes_to_original_address() {
    let config = test_config();
    let mailer = TestMailer::default();
    let user = User {
        id: 1,
        email: "new@example.com".to_string(),
        encrypted_password: devise_rust::crypto::encryptor::digest("secret123", &config),
        ..User::default()
    };

    // Direct change (no unconfirmed_email): body names the NEW address.
    let changes = ChangeSet::new(
        HashMap::from([(
            "email".to_string(),
            Value::String("old@example.com".to_string()),
        )]),
        HashMap::from([(
            "email".to_string(),
            Value::String("new@example.com".to_string()),
        )]),
    );
    DatabaseAuthenticatable::send_email_changed_notification(&user, &changes, &mailer, &config)
        .expect("notification sends");
    let sent = mailer.sent_mails();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].to, "old@example.com",
        "recipient is the ORIGINAL email (DBAU-08)"
    );
    assert_eq!(sent[0].subject, "Email Changed");
    assert!(sent[0].body.contains("has been changed to new@example.com"));

    // No email change -> no notification.
    let steady = ChangeSet::new(
        HashMap::from([("email".to_string(), Value::String("a@x.com".to_string()))]),
        HashMap::from([("email".to_string(), Value::String("a@x.com".to_string()))]),
    );
    DatabaseAuthenticatable::send_email_changed_notification(&user, &steady, &mailer, &config)
        .expect("no-op");
    assert_eq!(mailer.sent_mails().len(), 1, "no email without a change");
}

#[tokio::test]
async fn password_change_notification_goes_to_current_address() {
    let config = test_config();
    let mailer = TestMailer::default();
    let user = User {
        id: 1,
        email: "notify@example.com".to_string(),
        encrypted_password: devise_rust::crypto::encryptor::digest("rotated123", &config),
        ..User::default()
    };

    let changes = ChangeSet::new(
        HashMap::from([(
            "encrypted_password".to_string(),
            Value::String("old-hash".to_string()),
        )]),
        HashMap::from([(
            "encrypted_password".to_string(),
            Value::String("new-hash".to_string()),
        )]),
    );
    DatabaseAuthenticatable::send_password_change_notification(&user, &changes, &mailer, &config)
        .expect("notification sends");

    let sent = mailer.sent_mails();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "notify@example.com", "current email (DBAU-09)");
    assert_eq!(sent[0].subject, "Password Changed");
    assert!(sent[0].body.contains("your password has been changed"));

    // Untouched password -> no notification.
    let steady = ChangeSet::new(
        HashMap::from([("email".to_string(), Value::String("a@x.com".to_string()))]),
        HashMap::from([("email".to_string(), Value::String("b@x.com".to_string()))]),
    );
    DatabaseAuthenticatable::send_password_change_notification(&user, &steady, &mailer, &config)
        .expect("no-op");
    assert_eq!(mailer.sent_mails().len(), 1);
}

#[test]
fn mailer_context_carries_template_vars() {
    let user = User {
        id: 1,
        email: "ctx@example.com".to_string(),
        ..User::default()
    };
    let mailer = TestMailer::default();
    let ctx = MailerContext::from_record(&user)
        .with_token("tok-9")
        .with_url("https://example.com/users/password/edit?reset_password_token=tok-9");
    let body = mailer
        .reset_password_instructions(&user, Some("tok-9"), &ctx)
        .expect("reset mail renders");
    assert!(body.contains("Change my password"));
    assert!(body.contains("reset_password_token=tok-9"));
    let sent = mailer.sent_mails();
    assert_eq!(sent[0].template_vars.token.as_deref(), Some("tok-9"));
}
