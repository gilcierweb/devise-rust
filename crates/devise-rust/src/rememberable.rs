//! Rememberable module - persistent sessions via the signed cookie triple (RMB-01..05).
//!
//! Mirrors `devise/lib/devise/models/rememberable.rb`: `remember_me` stamping
//! `remember_created_at` (plus minting the `remember_token` when the model
//! carries the column) with validation-free persistence, `forget_me` clearing
//! per `expire_all_remember_me_on_sign_out`, the five-condition
//! `remember_me` validity check, the `[key, value, timestamp]` cookie codec,
//! and the `RememberableCookieAttrs` D-16 hardened attributes with a
//! plain-HTTP development opt-out for `Secure`.
//!
//! The DB stores the remember token RAW in its column (Devise keeps
//! `remember_token` unhashed, unlike confirmation and unlock tokens); the
//! salt fallback covers models without the column. Cookie signing and
//! verification stay bridge concerns (Phase 7/8): the core codec is
//! signer-agnostic and works over the already-verified triple delivered in
//! `AuthRequest.cookies`.
//!
//! == Options
//!
//! * `remember_for` - cookie validity window (default 2 weeks, D-13)
//! * `extend_remember_period` - re-issue the cookie on remember-hit
//!   (default false, fixed expiry, D-14)
//! * `rememberable_options` - cookie overrides: `key` renames the cookie,
//!   `secure = "false"` opts out of `Secure` for plain-HTTP development,
//!   `path` and `domain` pass through (D-16)
//! * `expire_all_remember_me_on_sign_out` - `forget_me` clears
//!   `remember_created_at` (default true, D-15)
//!
//! == Examples
//!
//! ```ignore
//! // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
//! user.remember_me(&adapter, &clock).await?;
//! let (key, value, generated_at) = user.serialize_into_cookie(&clock)?;
//! let encoded = devise_rust::rememberable::encode_cookie_value(&key, &value, &generated_at);
//! ```

use crate::adapter::{DeviseKey, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::DeviseError;
use crate::model::Authenticatable;
use crate::request::AuthRequest;
use crate::time::Clock;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::str::FromStr;

/// Column holding the raw remember token on models that carry one.
///
/// Mirrors the optional `remember_token` column, which Devise keeps unhashed unlike confirmation and unlock tokens.
pub const REMEMBER_TOKEN_COLUMN: &str = "remember_token";

/// Column holding the remember creation timestamp (required field).
///
/// Mirrors the required `remember_created_at` column.
pub const REMEMBER_CREATED_AT_COLUMN: &str = "remember_created_at";

/// Virtual sign-in flag name (`remember_me` form param and accessor).
///
/// Mirrors the virtual `remember_me` accessor the sign-in form posts (`attr_accessor :remember_me`).
pub const REMEMBER_ME_FLAG: &str = "remember_me";

/// Required model fields for Rememberable, mirroring Devise's
/// `Rememberable.required_fields`.
///
/// == Examples
///
/// ```
/// use devise_rust::rememberable::required_fields;
///
/// assert_eq!(required_fields(), vec!["remember_created_at"]);
/// ```
#[must_use]
pub fn required_fields() -> Vec<&'static str> {
    vec![REMEMBER_CREATED_AT_COLUMN]
}

/// Error when a model offers neither a remember token column nor a usable
/// authenticatable salt.
///
/// Mirrors Devise's `rememberable_value` raise, but as an explicit value:
/// core never panics on user data, so cookie creation reports this instead
/// of raising.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingRememberableValue;

impl std::fmt::Display for MissingRememberableValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "rememberable_value has no token column and authenticatable_salt is empty: \
             add a remember_token column or ensure a password is always set"
        )
    }
}

impl std::error::Error for MissingRememberableValue {}

/// `SameSite` attribute for the remember cookie (D-16 defaults to `Lax`).
///
/// Cookie attribute vocabulary for the remember cookie; mirrors devise's Rails cookie options, hardened per D-16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Strict first-party-only cookies.
    Strict,
    /// Lax top-level-get cookies (the D-16 default).
    Lax,
    /// Cross-site cookies (requires `Secure`).
    None,
}

impl SameSite {
    /// Header token for `Set-Cookie`.
    ///
    /// == Examples
    ///
    /// ```
    /// use devise_rust::rememberable::SameSite;
    ///
    /// assert_eq!(SameSite::Lax.header_value(), "Lax");
    /// ```
    ///
    /// Renders the `SameSite` attribute value; part of the `rememberable_options` surface mirroring devise's cookie option pass-through.
    #[must_use]
    pub fn header_value(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.header_value())
    }
}

/// Hardened `Set-Cookie` attributes for the remember cookie (D-16).
///
/// Devise sets `httponly` plus `expires` only. This port also sets `Secure`
/// and `SameSite=Lax`, with a per-scope plain-HTTP development opt-out that
/// disables `Secure` alone: set `rememberable_options["secure"]` to
/// `"false"` (also accepted: `"0"`, `"no"`, `"off"`). Everything else stays
/// hardened, and the default without the flag is secure.
///
/// Mirrors devise's Rails cookie defaults for the remember cookie, hardened per D-16: `HttpOnly`, `SameSite=Lax`, `Secure` with the documented plain-HTTP development opt-out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberableCookieAttrs {
    /// Cookie name: `rememberable_options["key"]` else `remember_{scope}_token`.
    pub key: String,
    /// Always true (D-16).
    pub httponly: bool,
    /// True unless the per-scope development opt-out disables it (D-16).
    pub secure: bool,
    /// Always `Lax` in this port (D-16).
    pub same_site: SameSite,
    /// `remember_for` after the issuing instant (D-13).
    pub expires: DateTime<Utc>,
    /// Optional `Path` passthrough from `rememberable_options["path"]`.
    pub path: Option<String>,
    /// Optional `Domain` passthrough from `rememberable_options["domain"]`.
    pub domain: Option<String>,
}

impl RememberableCookieAttrs {
    /// Build the hardened attributes for `scope` from config at `clock.now()`.
    ///
    /// == Examples
    ///
    /// ```ignore
    /// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
    /// let attrs = RememberableCookieAttrs::for_scope("user", &config, &clock);
    /// assert!(attrs.httponly && attrs.secure);
    /// ```
    ///
    /// Resolves `rememberable_options` for one scope; mirrors the per-model option cascade devise reads through `Devise::Models.config`.
    #[must_use]
    pub fn for_scope(scope: &str, config: &DeviseConfig, clock: &dyn Clock) -> Self {
        Self {
            key: remember_cookie_key(scope, config),
            httponly: true,
            secure: cookie_secure_flag(config),
            same_site: SameSite::Lax,
            expires: clock.now() + config.remember_for,
            path: config.rememberable_options.get("path").cloned(),
            domain: config.rememberable_options.get("domain").cloned(),
        }
    }

    /// Render a `Set-Cookie` header value carrying `cookie_value`.
    ///
    /// The value travels verbatim; bridges apply transport encoding when
    /// their cookie jar requires it.
    ///
    /// == Examples
    ///
    /// ```
    /// use devise_rust::rememberable::RememberableCookieAttrs;
    /// use devise_rust::config::DeviseConfig;
    /// use devise_rust::time::{Clock, FixedClock};
    /// use chrono::DateTime;
    ///
    /// let clock = FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"));
    /// let attrs = RememberableCookieAttrs::for_scope("user", &DeviseConfig::default(), &clock);
    /// let header = attrs.to_set_cookie_header("v");
    /// assert!(header.starts_with("remember_user_token=v;"));
    /// assert!(header.contains("; HttpOnly; Secure; SameSite=Lax"));
    /// ```
    ///
    /// Renders the remember cookie as a `Set-Cookie` header value; the transport mirroring how devise's controllers set the `serialize_into_cookie` triple.
    #[must_use]
    pub fn to_set_cookie_header(&self, cookie_value: &str) -> String {
        let mut parts = vec![
            format!("{}={cookie_value}", self.key),
            format!(
                "Expires={}",
                self.expires.format("%a, %d %b %Y %H:%M:%S GMT")
            ),
        ];
        if let Some(path) = &self.path {
            parts.push(format!("Path={path}"));
        }
        if let Some(domain) = &self.domain {
            parts.push(format!("Domain={domain}"));
        }
        if self.httponly {
            parts.push("HttpOnly".to_string());
        }
        if self.secure {
            parts.push("Secure".to_string());
        }
        parts.push(format!("SameSite={}", self.same_site.header_value()));
        parts.join("; ")
    }
}

/// Resolve the remember cookie name for `scope`.
///
/// Honors the `rememberable_options["key"]` override (blank values fall back
/// to the default); otherwise `remember_{scope}_token`.
///
/// == Examples
///
/// ```
/// use devise_rust::config::DeviseConfig;
/// use devise_rust::rememberable::remember_cookie_key;
///
/// assert_eq!(remember_cookie_key("user", &DeviseConfig::default()), "remember_user_token");
/// ```
///
/// Mirrors the `remember_#{scope}_token` cookie name with the `rememberable_options[:key]` override (`devise/lib/devise/controllers/rememberable.rb`).
#[must_use]
pub fn remember_cookie_key(scope: &str, config: &DeviseConfig) -> String {
    config
        .rememberable_options
        .get("key")
        .map(String::as_str)
        .filter(|key| !key.trim().is_empty())
        .map_or_else(
            || crate::session::keys::remember_token_key(scope),
            str::to_string,
        )
}

/// Whether the `Secure` attribute stays on (D-16).
///
/// True unless `rememberable_options["secure"]` carries a falsy value
/// (`"false"`, `"0"`, `"no"`, `"off"`, case-insensitive). Any other value,
/// including absence, keeps `Secure`.
///
/// Resolves the `Secure` attribute from `rememberable_options`; mirrors devise's cookie option read, hardened per D-16.
#[must_use]
pub fn cookie_secure_flag(config: &DeviseConfig) -> bool {
    !matches!(
        config
            .rememberable_options
            .get("secure")
            .map(|value| value.to_ascii_lowercase())
            .as_deref(),
        Some("false" | "0" | "no" | "off")
    )
}

/// Whether a sign-in param value requests persistence.
///
/// Ports Devise's `TRUE_VALUES` membership for the string params our flat map
/// carries (`'1'`, `'on'`/`'ON'`, `'t'`/`'T'`, `'true'`/`'TRUE'`). Anything
/// else, including absence, means a session-only sign-in.
///
/// == Examples
///
/// ```
/// use devise_rust::rememberable::is_true_value;
///
/// assert!(is_true_value("1"));
/// assert!(is_true_value("on"));
/// assert!(!is_true_value("yes"));
/// assert!(!is_true_value(""));
/// ```
///
/// `TRUE_VALUES` parsing for `rememberable_options` booleans; mirrors devise's `ActiveSupport` type coercion in `Controllers::Rememberable`.
#[must_use]
pub fn is_true_value(value: &str) -> bool {
    matches!(value, "1" | "on" | "ON" | "t" | "T" | "true" | "TRUE")
}

/// Whether `request` carries a truthy `remember_me` flag for `scope`.
///
/// Checks the three flat param shapes (`{scope}[remember_me]`,
/// `{scope}_remember_me`, bare `remember_me`), mirroring how the params
/// strategy resolves credentials. Used by the params strategy to stamp the
/// model's virtual flag (Devise `Authenticatable#remember_me`) and by the
/// rememberable-set hook as a fallback.
#[must_use]
pub fn remember_flag_set(request: &AuthRequest, scope: &str) -> bool {
    let scoped_bracket = format!("{scope}[{REMEMBER_ME_FLAG}]");
    let scoped_flat = format!("{scope}_{REMEMBER_ME_FLAG}");
    request
        .params
        .get(&scoped_bracket)
        .or_else(|| request.params.get(&scoped_flat))
        .or_else(|| request.params.get(REMEMBER_ME_FLAG))
        .is_some_and(|value| is_true_value(value.as_str()))
}

/// Parse the cookie timestamp: strict integer epoch seconds only.
///
/// Devise carries an open TODO on the JSON type coercion (`time_from_json`
/// accepts float strings and falls back to `Time.parse`). This port resolves
/// it by accepting epoch seconds alone; float strings, free-form dates, and
/// blank input are rejected outright (`None`), so unparseable cookies fail
/// closed instead of rescuing toward valid.
///
/// == Examples
///
/// ```
/// use devise_rust::rememberable::parse_generated_at;
///
/// assert!(parse_generated_at("1700000000").is_some());
/// assert!(parse_generated_at("1700000000.5").is_none());
/// assert!(parse_generated_at("2013").is_some());
/// assert!(parse_generated_at("not-a-time").is_none());
/// ```
///
/// Strict integer-epoch parse of the cookie timestamp; mirrors devise's `time_from_json` read, resolving its TODO by failing closed on malformed values.
#[must_use]
pub fn parse_generated_at(raw: &str) -> Option<DateTime<Utc>> {
    let epoch: i64 = raw.trim().parse().ok()?;
    DateTime::from_timestamp(epoch, 0)
}

/// The five-condition remember check (RMB-03), in Devise's numbered order.
///
/// 1. A parseable generation instant is present.
/// 2. The instant sits inside the `remember_for` window (`ago < generated`).
/// 3. The record carries a `remember_created_at` timestamp.
/// 4. The generation instant is STRICTLY greater than `remember_created_at`,
///    so refreshing `remember_created_at` (credential rotation) kills older
///    cookies (RMB-05). Equal timestamps are invalid.
/// 5. The presented token matches the stored value in constant time
///    (T-05-07: always through `secure_compare`, never `==`).
///
/// Condition 3 is an explicit presence check rather than Devise's
/// `|| Time.now` fallback: a missing `remember_created_at` fails closed even
/// for future-dated cookies, which the fallback would accept. All other
/// boundaries are Devise-exact.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// assert!(remember_cookie_valid(&stored, &token, Some(generated), Some(created), &config, &clock));
/// ```
///
/// Mirrors the five-condition `remember_me?` check (`devise/lib/devise/models/rememberable.rb`): token compare, timestamp, expiry, extend period, and `created_at` ordering.
#[must_use]
pub fn remember_cookie_valid(
    stored_value: &str,
    presented_token: &str,
    generated_at: Option<DateTime<Utc>>,
    remember_created_at: Option<DateTime<Utc>>,
    config: &DeviseConfig,
    clock: &dyn Clock,
) -> bool {
    let Some(generated_at) = generated_at else {
        return false;
    };
    if clock.ago(config.remember_for) >= generated_at {
        return false;
    }
    let Some(created_at) = remember_created_at else {
        return false;
    };
    if generated_at <= created_at {
        return false;
    }
    crate::crypto::secure_compare(stored_value, presented_token)
}

/// Encode the cookie triple as the string the cookie jar carries.
///
/// The jar holds one string per cookie; the triple travels as a JSON array
/// `[key, value, generated_at]`, with the timestamp in integer-epoch-seconds
/// form.
///
/// == Examples
///
/// ```
/// use devise_rust::rememberable::{decode_cookie_value, encode_cookie_value};
///
/// let encoded = encode_cookie_value("1", "tok", "1700000000");
/// assert_eq!(
///     decode_cookie_value(&encoded),
///     Some(("1".to_string(), "tok".to_string(), "1700000000".to_string()))
/// );
/// ```
///
/// The wire half of the `[key, value, timestamp]` codec mirroring devise's `serialize_into_cookie` output format.
#[must_use]
pub fn encode_cookie_value(key: &str, value: &str, generated_at: &str) -> String {
    serde_json::json!([key, value, generated_at]).to_string()
}

/// Decode the jar string back into the triple.
///
/// Returns `None` for malformed JSON, non-array payloads, short arrays (the
/// Devise "no timestamp" miss), and non-string elements. Every `None` is a
/// stale-cookie miss: delete the cookie and pass through, never fail.
///
/// == Examples
///
/// ```
/// use devise_rust::rememberable::decode_cookie_value;
///
/// assert!(decode_cookie_value("not json").is_none());
/// assert!(decode_cookie_value("[\"1\",\"tok\"]").is_none());
/// ```
///
/// The parse half of the `[key, value, timestamp]` codec mirroring devise's `serialize_from_cookie` input format.
#[must_use]
pub fn decode_cookie_value(raw: &str) -> Option<(String, String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    let parts = parsed.as_array()?;
    if parts.len() < 3 {
        return None;
    }
    Some((
        parts[0].as_str()?.to_string(),
        parts[1].as_str()?.to_string(),
        parts[2].as_str()?.to_string(),
    ))
}

/// Build a fresh cookie triple stamping `clock.now()` as integer epoch seconds.
///
/// Timestamps share the epoch-second granularity with `remember_created_at`,
/// so a cookie minted in the same second as `remember_me` compares equal and
/// is invalid under the strict greater-than rule; callers minting and
/// validating in one step advance the clock past the creation second first.
///
/// Builds the cookie triple from the record; mirrors the model-side half of devise's `serialize_into_cookie`.
#[must_use]
/// Mint the cookie triple `[key, value, generated_at]` (RMB-02).
///
/// `generated_at` is the integer-epoch cookie timestamp (Devise's
/// `Time.now.utc.to_f.to_s` at whole-second resolution). It is guaranteed to
/// be STRICTLY NEWER than `remember_created_at`: with epoch-second
/// resolution, the same second would otherwise mint a cookie that fails
/// condition 4 of the five-condition check until the clock ticks (a
/// self-healing but real false-negative right after sign-in). Devise gets
/// this for free from float microseconds; the port nudges by one second.
pub fn build_cookie_triple(key: &str, value: &str, clock: &dyn Clock) -> (String, String, String) {
    (
        key.to_string(),
        value.to_string(),
        clock.now().timestamp().to_string(),
    )
}

/// Same-contract mint, but `generated_at` is forced strictly newer than
/// `remember_created_at` (see [`build_cookie_triple`]). Use this whenever
/// both timestamps can land in the same epoch second (the sign-in set hook
/// and any durable mint right after stamping `remember_created_at`).
pub fn build_cookie_triple_after_created_at(
    key: &str,
    value: &str,
    clock: &dyn Clock,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
) -> (String, String, String) {
    let mut generated = clock.now();
    if let Some(created) = created_at {
        let floor = created + chrono::TimeDelta::seconds(1);
        if generated <= created {
            generated = floor;
        }
    }
    (
        key.to_string(),
        value.to_string(),
        generated.timestamp().to_string(),
    )
}

/// `Rememberable` module - persistent sessions over `remember_created_at`
/// plus an optional `remember_token` column.
///
/// The DB stores the remember token RAW (Devise keeps this column unhashed);
/// models without the column fall back to `authenticatable_salt`, and models
/// with neither report [`MissingRememberableValue`] instead of panicking.
/// Every time read takes `&dyn Clock`.
///
/// == Options
///
/// See the module-level docs: `remember_for`, `extend_remember_period`,
/// `rememberable_options`, `expire_all_remember_me_on_sign_out`.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// impl Rememberable for User {
///     fn remember_created_at(&self) -> Option<DateTime<Utc>> { self.remember_created_at }
///     // ... column accessors ...
/// }
/// ```
///
/// Mirrors `Devise::Models::Rememberable` (`devise/lib/devise/models/rememberable.rb`) as the trait surface: `remember_me`, `forget_me`, cookie serialization, and the validity check.
#[async_trait]
pub trait Rememberable: Authenticatable {
    /// Stored `remember_created_at` column.
    fn remember_created_at(&self) -> Option<DateTime<Utc>>;
    /// Write the `remember_created_at` column.
    fn set_remember_created_at(&mut self, at: Option<DateTime<Utc>>);
    /// Stored `remember_token` column (`None` when the model has no column).
    fn remember_token(&self) -> Option<&str>;
    /// Write the `remember_token` column (no-op when the model has no column).
    fn set_remember_token(&mut self, token: Option<String>);
    /// Whether the model carries the `remember_token` column.
    ///
    /// Column-less models keep the default `false` and resolve their value
    /// from `authenticatable_salt`.
    fn has_remember_token_column(&self) -> bool {
        false
    }
    /// Whether the record is persisted (Devise `persisted?`). Unpersisted
    /// records never write remember state.
    fn persisted(&self) -> bool;

    /// `rememberable_value`: the token column when the model carries one
    /// (even when empty, mirroring Devise returning the column as-is), else
    /// the `authenticatable_salt`, else [`MissingRememberableValue`].
    ///
    /// # Errors
    ///
    /// Returns [`MissingRememberableValue`] when no token column exists and
    /// the salt is missing or empty. Never panics on user data.
    fn rememberable_value(&self) -> Result<String, MissingRememberableValue> {
        if self.has_remember_token_column() {
            return Ok(self.remember_token().unwrap_or_default().to_string());
        }
        if let Some(salt) = self.authenticatable_salt() {
            if !salt.is_empty() {
                return Ok(salt);
            }
        }
        Err(MissingRememberableValue)
    }

    /// Extension hook run after a successful remember-hit (Devise
    /// `after_remembered`). Default no-op; override for custom logic.
    fn after_remembered(&self) {}

    /// `extend_remember_period` for this record (default: global config).
    fn extend_remember_period(&self, config: &DeviseConfig) -> bool {
        config.extend_remember_period
    }

    /// `rememberable_options` for this record (default: global config map).
    fn rememberable_options(&self, config: &DeviseConfig) -> HashMap<String, String> {
        config.rememberable_options.clone()
    }

    /// `remember_expires_at`: `remember_for` after now (D-13).
    fn remember_expires_at(&self, config: &DeviseConfig, clock: &dyn Clock) -> DateTime<Utc> {
        clock.now() + config.remember_for
    }

    /// `serialize_into_cookie`: the `[key, value, timestamp]` triple with an
    /// integer-epoch-seconds timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`MissingRememberableValue`] when the record offers no value.
    fn serialize_into_cookie(
        &self,
        clock: &dyn Clock,
    ) -> Result<(String, String, String), MissingRememberableValue>
    where
        Self: Sized,
    {
        let value = self.rememberable_value()?;
        Ok(build_cookie_triple_after_created_at(
            &self.to_key().to_string(),
            &value,
            clock,
            self.remember_created_at(),
        ))
    }

    /// `serialize_from_cookie`: fetch by key, then enforce the five
    /// conditions. Any miss (bad key, unknown record, valueless record, failed
    /// check) yields `None`; callers translate `None` into cookie deletion
    /// plus pass-through, never failure.
    async fn serialize_from_cookie<A>(
        key: &str,
        token: &str,
        generated_at: &str,
        adapter: &A,
        config: &DeviseConfig,
        clock: &dyn Clock,
    ) -> Option<Self>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let key = DeviseKey::from_str(key).ok()?;
        let record = adapter.get(&key).await.ok()??;
        let stored = record.rememberable_value().ok()?;
        let generated = parse_generated_at(generated_at);
        if remember_cookie_valid(
            &stored,
            token,
            generated,
            record.remember_created_at(),
            config,
            clock,
        ) {
            Some(record)
        } else {
            None
        }
    }

    /// Instance five-condition check over a presented cookie pair.
    ///
    /// A valueless record reports invalid rather than panicking.
    fn remember_me_valid(
        &self,
        token: &str,
        generated_at: &str,
        config: &DeviseConfig,
        clock: &dyn Clock,
    ) -> bool
    where
        Self: Sized,
    {
        let stored = self.rememberable_value().unwrap_or_default();
        remember_cookie_valid(
            &stored,
            token,
            parse_generated_at(generated_at),
            self.remember_created_at(),
            config,
            clock,
        )
    }

    /// `remember_me!` (RMB-01): mint the token when the column exists and is
    /// empty (looping until unused, Devise `remember_token`), stamp
    /// `remember_created_at` when unset, and persist validation-free through
    /// `update_columns`. Writes only when something changed (Devise
    /// `save if changed?`), so reuse never slides state under fixed expiry.
    ///
    /// The virtual `remember_me` flag survives persistence: `update_columns`
    /// returns a fresh row that would reset skipped fields, so the flag is
    /// restored afterwards.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` when the uniqueness probe or persistence fails.
    async fn remember_me<A>(&mut self, adapter: &A, clock: &dyn Clock) -> Result<(), DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let mut fields = HashMap::new();
        if self.has_remember_token_column() && self.remember_token().is_none() {
            let raw = loop {
                let candidate = crate::crypto::friendly_token(20);
                if adapter
                    .column_value_unused(REMEMBER_TOKEN_COLUMN, &Value::String(candidate.clone()))
                    .await
                    .map_err(DeviseError::Adapter)?
                {
                    break candidate;
                }
            };
            self.set_remember_token(Some(raw.clone()));
            fields.insert(REMEMBER_TOKEN_COLUMN.to_string(), Value::String(raw));
        }
        if self.remember_created_at().is_none() {
            let now = clock.now();
            self.set_remember_created_at(Some(now));
            fields.insert(
                REMEMBER_CREATED_AT_COLUMN.to_string(),
                Value::String(now.to_rfc3339()),
            );
        }
        if fields.is_empty() {
            return Ok(());
        }
        let flag = self.remember_me_flag_opt();
        let updated = adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        *self = updated;
        self.set_remember_me_flag(flag.unwrap_or(false));
        Ok(())
    }

    /// `forget_me!` (RMB-01): return early for unpersisted records (zero
    /// adapter calls), always clear the token column when present, and clear
    /// `remember_created_at` only when `expire_all_remember_me_on_sign_out`
    /// holds (D-15). Persists validation-free through `update_columns`.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` when persistence fails.
    async fn forget_me<A>(&mut self, adapter: &A, config: &DeviseConfig) -> Result<(), DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if !self.persisted() {
            return Ok(());
        }
        let mut fields = HashMap::new();
        if self.has_remember_token_column() {
            self.set_remember_token(None);
            fields.insert(REMEMBER_TOKEN_COLUMN.to_string(), Value::Null);
        }
        if config.expire_all_remember_me_on_sign_out {
            self.set_remember_created_at(None);
            fields.insert(REMEMBER_CREATED_AT_COLUMN.to_string(), Value::Null);
        }
        if fields.is_empty() {
            return Ok(());
        }
        let flag = self.remember_me_flag_opt();
        let updated = adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        *self = updated;
        self.set_remember_me_flag(flag.unwrap_or(false));
        Ok(())
    }
}

/// Cookie intent the core hands to bridges (Phase 7/8).
///
/// Core never touches the jar: strategies and hooks push these ops onto the
/// proxy outbox, and bridges drain them after authentication, executing `Set`
/// through `RememberableBridge::set_cookie` (rendering
/// [`RememberableCookieAttrs::to_set_cookie_header`]) and `Clear` through
/// `RememberableBridge::clear_cookie` (the Devise `cookies.delete`
/// equivalent).
///
/// Set/Clear op vocabulary the remember hooks fill and the framework transport drains; mirrors the cookie writes and deletions devise performs inline in warden hooks.
#[derive(Debug, Clone, PartialEq)]
pub enum RememberCookieOp {
    /// Set (or re-issue) the remember cookie for `scope`.
    Set {
        /// Scope the cookie belongs to.
        scope: String,
        /// Cookie name (key override aware).
        key: String,
        /// Jar string (encoded triple).
        value: String,
        /// Hardened attributes to render.
        attrs: RememberableCookieAttrs,
    },
    /// Delete the remember cookie for `scope` (stale-cookie miss, logout).
    Clear {
        /// Scope the cookie belongs to.
        scope: String,
        /// Cookie name to delete.
        key: String,
    },
}

impl RememberCookieOp {
    /// Scope this op applies to.
    ///
    /// The scope a remember op targets; mirrors the `#{scope}` interpolation in devise's cookie names.
    #[must_use]
    pub fn scope(&self) -> &str {
        match self {
            RememberCookieOp::Set { scope, .. } | RememberCookieOp::Clear { scope, .. } => scope,
        }
    }

    /// Cookie name this op applies to.
    ///
    /// The cookie name a remember op targets; mirrors `rememberable_options[:key]`, devise's cookie-name override.
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            RememberCookieOp::Set { key, .. } | RememberCookieOp::Clear { key, .. } => key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::memory::MemoryAdapter;
    use crate::failure::AnyDeviseModel;
    use crate::time::FixedClock;
    use chrono::TimeDelta;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
        encrypted_password: String,
        remember_token: Option<String>,
        remember_created_at: Option<DateTime<Utc>>,
        #[serde(skip)]
        remember_flag: Option<bool>,
    }

    impl TestUser {
        fn fresh(id: i64, email: &str) -> Self {
            Self {
                id,
                email: email.to_string(),
                encrypted_password: "$2a$12$01234567890123456789012345678901234567890123456789012"
                    .to_string(),
                ..Self::default()
            }
        }
    }

    impl AnyDeviseModel for TestUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            self.encrypted_password.get(..29).map(str::to_string)
        }

        fn rememberable_value_opt(&self) -> Option<String> {
            if self.has_remember_token_column() {
                return Some(self.remember_token.clone().unwrap_or_default());
            }
            self.authenticatable_salt().filter(|salt| !salt.is_empty())
        }

        fn remember_created_at_opt(&self) -> Option<DateTime<Utc>> {
            self.remember_created_at
        }

        fn remember_me_flag_opt(&self) -> Option<bool> {
            self.remember_flag
        }

        fn set_remember_me_flag(&mut self, flag: bool) {
            self.remember_flag = Some(flag);
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait]
    impl Authenticatable for TestUser {
        fn serializable_hash(&self) -> serde_json::Value {
            serde_json::json!({ "id": self.id, "email": self.email })
        }
    }

    #[async_trait]
    impl Rememberable for TestUser {
        fn remember_created_at(&self) -> Option<DateTime<Utc>> {
            self.remember_created_at
        }

        fn set_remember_created_at(&mut self, at: Option<DateTime<Utc>>) {
            self.remember_created_at = at;
        }

        fn remember_token(&self) -> Option<&str> {
            self.remember_token.as_deref()
        }

        fn set_remember_token(&mut self, token: Option<String>) {
            self.remember_token = token;
        }

        fn has_remember_token_column(&self) -> bool {
            true
        }

        fn persisted(&self) -> bool {
            self.id != 0
        }
    }

    fn test_config() -> DeviseConfig {
        DeviseConfig::default()
    }

    fn fixed_clock() -> FixedClock {
        FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"))
    }

    #[tokio::test]
    async fn rememberable_tracer_remember_then_cookie_round_trip_valid() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1, "tracer@example.com");
        adapter.create(user.clone()).await.unwrap();

        user.remember_me(&adapter, &clock).await.unwrap();
        let created_at = user.remember_created_at().expect("created_at is stamped");
        assert!(user.remember_token().is_some_and(|token| !token.is_empty()));

        // Epoch-second granularity plus strict greater-than: the cookie must
        // postdate the creation second to validate.
        clock.advance(TimeDelta::seconds(2));
        let (key, value, generated) = user.serialize_into_cookie(&clock).unwrap();
        assert_eq!(key, user.to_key().to_string());
        assert_eq!(value, user.rememberable_value().unwrap());

        let encoded = encode_cookie_value(&key, &value, &generated);
        let decoded = decode_cookie_value(&encoded).expect("codec round-trips");
        assert_eq!(decoded, (key.clone(), value.clone(), generated.clone()));

        assert!(user.remember_me_valid(&decoded.1, &decoded.2, &config, &clock));

        let found =
            TestUser::serialize_from_cookie(&key, &value, &generated, &adapter, &config, &clock)
                .await;
        assert!(found.is_some_and(|record| record.to_key() == user.to_key()));

        let attrs = RememberableCookieAttrs::for_scope("user", &config, &clock);
        assert_eq!(attrs.key, "remember_user_token");
        assert!(attrs.httponly);
        assert!(attrs.secure);
        assert_eq!(attrs.same_site, SameSite::Lax);
        assert_eq!(attrs.expires, clock.now() + config.remember_for);

        let header = attrs.to_set_cookie_header(&encoded);
        assert!(header.contains("remember_user_token="));
        assert!(header.contains("; HttpOnly"));
        assert!(header.contains("; Secure"));
        assert!(header.contains("; SameSite=Lax"));
        assert!(header.contains("; Expires="));

        // Strict greater-than is observable: the cookie second postdates creation.
        let generated_epoch: i64 = generated.parse().expect("epoch timestamp");
        assert!(generated_epoch > created_at.timestamp());
    }

    #[test]
    fn rememberable_tracer_dev_opt_out_disables_secure_only() {
        let clock = fixed_clock();
        let plain = RememberableCookieAttrs::for_scope("user", &test_config(), &clock);
        let mut dev_config = test_config();
        dev_config
            .rememberable_options
            .insert("secure".to_string(), "false".to_string());
        let dev = RememberableCookieAttrs::for_scope("user", &dev_config, &clock);

        assert!(plain.secure);
        assert!(!dev.secure);
        assert_eq!(dev.httponly, plain.httponly);
        assert_eq!(dev.same_site, plain.same_site);
        assert_eq!(dev.expires, plain.expires);
        assert_eq!(dev.key, plain.key);

        let header = dev.to_set_cookie_header("v");
        assert!(!header.contains("; Secure"));
        assert!(header.contains("; HttpOnly"));
    }

    /// Salt-column-less model: value resolves from `authenticatable_salt`,
    /// never from a token column it does not carry.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct SaltUser {
        id: i64,
        email: String,
        encrypted_password: String,
        remember_created_at: Option<DateTime<Utc>>,
        #[serde(skip)]
        remember_flag: Option<bool>,
    }

    impl SaltUser {
        fn fresh(id: i64, email: &str) -> Self {
            Self {
                id,
                email: email.to_string(),
                encrypted_password: "$2a$12$01234567890123456789012345678901234567890123456789012"
                    .to_string(),
                ..Self::default()
            }
        }

        fn barren(id: i64) -> Self {
            Self {
                id,
                email: "barren@example.com".to_string(),
                encrypted_password: String::new(),
                ..Self::default()
            }
        }
    }

    impl AnyDeviseModel for SaltUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            self.encrypted_password.get(..29).map(str::to_string)
        }

        fn rememberable_value_opt(&self) -> Option<String> {
            self.authenticatable_salt().filter(|salt| !salt.is_empty())
        }

        fn remember_created_at_opt(&self) -> Option<DateTime<Utc>> {
            self.remember_created_at
        }

        fn remember_me_flag_opt(&self) -> Option<bool> {
            self.remember_flag
        }

        fn set_remember_me_flag(&mut self, flag: bool) {
            self.remember_flag = Some(flag);
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait]
    impl Authenticatable for SaltUser {
        fn serializable_hash(&self) -> serde_json::Value {
            serde_json::json!({ "id": self.id, "email": self.email })
        }
    }

    #[async_trait]
    impl Rememberable for SaltUser {
        fn remember_created_at(&self) -> Option<DateTime<Utc>> {
            self.remember_created_at
        }

        fn set_remember_created_at(&mut self, at: Option<DateTime<Utc>>) {
            self.remember_created_at = at;
        }

        fn remember_token(&self) -> Option<&str> {
            None
        }

        fn set_remember_token(&mut self, _token: Option<String>) {}

        fn persisted(&self) -> bool {
            self.id != 0
        }
    }

    /// Adapter wrapper counting writes, proving guarded paths stay silent.
    struct CountingAdapter<'a> {
        inner: &'a MemoryAdapter<TestUser>,
        writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl crate::adapter::OrmAdapter<TestUser> for CountingAdapter<'_> {
        type New = TestUser;

        async fn get(&self, id: &DeviseKey) -> Result<Option<TestUser>, crate::adapter::OrmError> {
            self.inner.get(id).await
        }

        async fn find_first(
            &self,
            conditions: &crate::adapter::Conditions,
        ) -> Result<Option<TestUser>, crate::adapter::OrmError> {
            self.inner.find_first(conditions).await
        }

        async fn create(&self, model: TestUser) -> Result<TestUser, crate::adapter::OrmError> {
            self.inner.create(model).await
        }

        async fn update(
            &self,
            key: &DeviseKey,
            changes: &crate::adapter::ChangeSet,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.inner.update(key, changes).await
        }

        async fn update_columns(
            &self,
            key: &DeviseKey,
            fields: &HashMap<String, Value>,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.update_columns(key, fields).await
        }

        async fn increment_counter(
            &self,
            key: &DeviseKey,
            column: &'static str,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.increment_counter(key, column).await
        }

        async fn delete(&self, id: &DeviseKey) -> Result<(), crate::adapter::OrmError> {
            self.inner.delete(id).await
        }
    }

    fn write_count(counter: &std::sync::Arc<std::sync::atomic::AtomicUsize>) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Seed a persisted user remembered at the clock instant, returning the
    /// record plus its cookie triple minted two seconds later.
    async fn remembered_cookie(
        adapter: &MemoryAdapter<TestUser>,
        clock: &mut FixedClock,
        id: i64,
    ) -> (TestUser, String, String, String) {
        let mut user = TestUser::fresh(id, "matrix@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.remember_me(adapter, &*clock).await.unwrap();
        clock.advance(TimeDelta::seconds(2));
        let (key, value, generated) = user.serialize_into_cookie(&*clock).unwrap();
        (user, key, value, generated)
    }

    /// Regression (S6.3): a cookie minted in the SAME epoch second as
    /// `remember_created_at` still validates — the mint is forced strictly
    /// newer than the creation stamp, so condition 4 of the five-condition
    /// check cannot false-negative right after sign-in.
    #[tokio::test]
    async fn rememberable_same_second_mint_stays_valid() {
        let config = test_config();
        let clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1, "matrix@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.remember_me(&adapter, &clock).await.unwrap();

        // No clock advance: same second as the creation stamp.
        let (key, value, generated) = user.serialize_into_cookie(&clock).unwrap();
        assert_eq!(key, user.to_key().to_string());
        assert!(
            generated.parse::<i64>().expect("epoch")
                > user.remember_created_at().expect("created").timestamp(),
            "cookie timestamp must be strictly newer than remember_created_at"
        );
        assert!(
            user.remember_me_valid(&value, &generated, &config, &clock),
            "same-second mint must validate"
        );
    }

    #[tokio::test]
    async fn rememberable_nil_case_invalid_datetime() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (user, key, value, _) = remembered_cookie(&adapter, &mut clock, 1).await;

        assert!(
            TestUser::serialize_from_cookie(&key, &value, "not-a-time", &adapter, &config, &clock)
                .await
                .is_none()
        );
        assert!(!user.remember_me_valid(&value, "1700000000.5", &config, &clock));
        assert!(!user.remember_me_valid(&value, "", &config, &clock));
    }

    #[tokio::test]
    async fn rememberable_nil_case_unknown_resource() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (_, _, value, generated) = remembered_cookie(&adapter, &mut clock, 1).await;

        assert!(
            TestUser::serialize_from_cookie("999", &value, &generated, &adapter, &config, &clock)
                .await
                .is_none()
        );
        assert!(
            TestUser::serialize_from_cookie("nope", &value, &generated, &adapter, &config, &clock)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn rememberable_nil_case_missing_timestamp() {
        let config = test_config();
        let clock = fixed_clock();

        assert!(decode_cookie_value("[\"1\",\"tok\"]").is_none());
        assert!(decode_cookie_value("[]").is_none());
        assert!(decode_cookie_value("not json").is_none());
        assert!(decode_cookie_value("[\"1\",7,8]").is_none());
        assert!(!remember_cookie_valid(
            "tok",
            "tok",
            None,
            Some(clock.now()),
            &config,
            &clock
        ));
    }

    #[tokio::test]
    async fn rememberable_nil_case_timestamp_at_or_before_creation() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (user, key, value, _) = remembered_cookie(&adapter, &mut clock, 1).await;
        let created = user.remember_created_at().expect("created is set");

        let earlier = (created - TimeDelta::seconds(60)).timestamp().to_string();
        assert!(
            TestUser::serialize_from_cookie(&key, &value, &earlier, &adapter, &config, &clock)
                .await
                .is_none()
        );
        assert!(!user.remember_me_valid(&value, &earlier, &config, &clock));
    }

    #[tokio::test]
    async fn rememberable_equal_timestamps_are_invalid() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (user, key, value, _) = remembered_cookie(&adapter, &mut clock, 1).await;
        let created = user.remember_created_at().expect("created is set");
        let same = created.timestamp().to_string();

        assert!(!user.remember_me_valid(&value, &same, &config, &clock));
        assert!(
            TestUser::serialize_from_cookie(&key, &value, &same, &adapter, &config, &clock)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn rememberable_nil_case_older_than_remember_for() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (user, key, value, _) = remembered_cookie(&adapter, &mut clock, 1).await;

        clock.advance(TimeDelta::weeks(3));
        let stale_generated = (fixed_clock().now() + TimeDelta::seconds(10))
            .timestamp()
            .to_string();
        assert!(
            TestUser::serialize_from_cookie(
                &key,
                &value,
                &stale_generated,
                &adapter,
                &config,
                &clock
            )
            .await
            .is_none()
        );
        assert!(!user.remember_me_valid(&value, &stale_generated, &config, &clock));
    }

    #[tokio::test]
    async fn rememberable_nil_case_wrong_token() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (user, key, _, generated) = remembered_cookie(&adapter, &mut clock, 1).await;

        assert!(
            TestUser::serialize_from_cookie(&key, "wrong", &generated, &adapter, &config, &clock)
                .await
                .is_none()
        );
        assert!(!user.remember_me_valid("wrong", &generated, &config, &clock));
    }

    #[tokio::test]
    async fn rememberable_missing_created_at_is_invalid() {
        let config = test_config();
        let clock = fixed_clock();
        let user = SaltUser::fresh(1, "salt@example.com");
        let value = user.rememberable_value().expect("salt resolves");
        let generated = clock.now().timestamp().to_string();

        assert!(!user.remember_me_valid(&value, &generated, &config, &clock));
    }

    #[tokio::test]
    async fn rememberable_forget_clears_per_expire_all() {
        let clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();

        let mut forgetting = TestUser::fresh(1, "forget@example.com");
        adapter.create(forgetting.clone()).await.unwrap();
        forgetting.remember_me(&adapter, &clock).await.unwrap();
        assert!(forgetting.remember_token().is_some());
        assert!(forgetting.remember_created_at().is_some());

        forgetting
            .forget_me(&adapter, &test_config())
            .await
            .unwrap();
        assert!(forgetting.remember_token().is_none());
        assert!(forgetting.remember_created_at().is_none());
        let stored = adapter.get(&forgetting.to_key()).await.unwrap().unwrap();
        assert!(stored.remember_token.is_none());
        assert!(stored.remember_created_at.is_none());

        let mut keeping = TestUser::fresh(2, "keep@example.com");
        adapter.create(keeping.clone()).await.unwrap();
        keeping.remember_me(&adapter, &clock).await.unwrap();
        let mut partial = test_config();
        partial.expire_all_remember_me_on_sign_out = false;
        keeping.forget_me(&adapter, &partial).await.unwrap();
        assert!(keeping.remember_token().is_none());
        assert!(keeping.remember_created_at().is_some());
        let stored = adapter.get(&keeping.to_key()).await.unwrap().unwrap();
        assert!(stored.remember_token.is_none());
        assert!(stored.remember_created_at.is_some());
    }

    #[tokio::test]
    async fn rememberable_forget_unpersisted_touches_no_adapter() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            writes: writes.clone(),
        };

        let mut ghost = TestUser::fresh(0, "ghost@example.com");
        ghost.forget_me(&adapter, &config).await.unwrap();
        assert_eq!(write_count(&writes), 0);
    }

    #[tokio::test]
    async fn rememberable_remember_reuse_keeps_token_without_write() {
        let clock = fixed_clock();
        let inner = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1, "reuse@example.com");
        inner.create(user.clone()).await.unwrap();
        user.remember_me(&inner, &clock).await.unwrap();
        let token = user.remember_token().map(str::to_string);
        let created = user.remember_created_at();

        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            writes: writes.clone(),
        };
        user.remember_me(&adapter, &clock).await.unwrap();
        assert_eq!(write_count(&writes), 0);
        assert_eq!(user.remember_token().map(str::to_string), token);
        assert_eq!(user.remember_created_at(), created);
    }

    #[tokio::test]
    async fn rememberable_fixed_expiry_never_slides() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (user, key, value, generated) = remembered_cookie(&adapter, &mut clock, 1).await;
        let created = user.remember_created_at().expect("created is set");

        // Reuse a week later: the same value validates, and the stored
        // creation instant never moves, so the window stays fixed.
        clock.advance(TimeDelta::weeks(1));
        let (fresh_key, fresh_value, fresh_generated) = user.serialize_into_cookie(&clock).unwrap();
        assert_eq!(fresh_key, key);
        assert_eq!(fresh_value, value);
        let fresh_epoch: i64 = fresh_generated.parse().expect("epoch timestamp");
        let old_epoch: i64 = generated.parse().expect("epoch timestamp");
        assert!(fresh_epoch > old_epoch);
        assert!(user.remember_me_valid(&fresh_value, &fresh_generated, &config, &clock));

        let stored = adapter.get(&user.to_key()).await.unwrap().unwrap();
        assert_eq!(stored.remember_created_at, Some(created));

        let expires_at = user.remember_expires_at(&config, &fixed_clock());
        assert_eq!(expires_at, fixed_clock().now() + config.remember_for);
    }

    #[tokio::test]
    async fn rememberable_password_rotation_kills_older_cookies() {
        let config = test_config();
        let mut clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let (user, key, value, generated) = remembered_cookie(&adapter, &mut clock, 1).await;
        assert!(user.remember_me_valid(&value, &generated, &config, &clock));

        clock.advance(TimeDelta::seconds(3600));
        let rotated_at = clock.now();
        adapter
            .update_columns(
                &user.to_key(),
                &HashMap::from([(
                    REMEMBER_CREATED_AT_COLUMN.to_string(),
                    Value::String(rotated_at.to_rfc3339()),
                )]),
            )
            .await
            .unwrap();

        // Reload: the in-memory copy still carries the pre-rotation instant.
        let rotated = adapter.get(&user.to_key()).await.unwrap().unwrap();
        assert_eq!(rotated.remember_created_at, Some(rotated_at));
        assert!(!rotated.remember_me_valid(&value, &generated, &config, &clock));
        assert!(
            TestUser::serialize_from_cookie(&key, &value, &generated, &adapter, &config, &clock)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn rememberable_value_resolution() {
        let clock = fixed_clock();

        let mut token_user = TestUser::fresh(1, "token@example.com");
        token_user.set_remember_token(Some("raw-token".to_string()));
        assert_eq!(token_user.rememberable_value().unwrap(), "raw-token");

        let salt_user = SaltUser::fresh(2, "salt@example.com");
        let salt = salt_user.authenticatable_salt().expect("salt is set");
        assert_eq!(salt_user.rememberable_value().unwrap(), salt);

        let empty_token_user = TestUser::fresh(3, "empty@example.com");
        assert_eq!(
            empty_token_user.rememberable_value().unwrap(),
            String::new()
        );

        let barren = SaltUser::barren(4);
        assert_eq!(barren.rememberable_value(), Err(MissingRememberableValue));
        assert!(barren.serialize_into_cookie(&clock).is_err());
    }

    #[tokio::test]
    async fn rememberable_remember_unpersisted_errors_without_panic() {
        let clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut ghost = TestUser::fresh(0, "ghost@example.com");

        let result = ghost.remember_me(&adapter, &clock).await;
        assert!(matches!(
            result,
            Err(DeviseError::Adapter(crate::adapter::OrmError::NotFound))
        ));
    }

    #[tokio::test]
    async fn rememberable_forget_salt_model_clears_created_only() {
        let config = test_config();
        let clock = fixed_clock();
        let adapter = MemoryAdapter::<SaltUser>::new();
        let mut user = SaltUser::fresh(1, "salt@example.com");
        adapter.create(user.clone()).await.unwrap();

        user.remember_me(&adapter, &clock).await.unwrap();
        assert!(user.remember_created_at().is_some());
        assert!(user.remember_token().is_none());

        user.forget_me(&adapter, &config).await.unwrap();
        assert!(user.remember_created_at().is_none());
        let stored = adapter.get(&user.to_key()).await.unwrap().unwrap();
        assert!(stored.remember_created_at.is_none());
    }

    /// Minimal session store for hook dispatch tests.
    #[derive(Debug, Default)]
    struct HookTestStore {
        data: std::sync::Arc<std::sync::RwLock<HashMap<String, serde_json::Value>>>,
    }

    #[async_trait]
    impl crate::session::SessionStore for HookTestStore {
        async fn get_value(&self, key: &str) -> Option<serde_json::Value> {
            self.data.read().unwrap().get(key).cloned()
        }

        async fn insert_value(&self, key: &str, value: serde_json::Value) {
            self.data.write().unwrap().insert(key.to_string(), value);
        }

        async fn remove(&self, key: &str) {
            self.data.write().unwrap().remove(key);
        }

        async fn remove_prefix(&self, prefix: &str) {
            let mut data = self.data.write().unwrap();
            let doomed: Vec<String> = data
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect();
            for key in doomed {
                data.remove(&key);
            }
        }

        async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
            self.data
                .read()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect()
        }

        async fn renew(&self) -> Result<(), crate::error::DeviseError> {
            Ok(())
        }

        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            self.data.write().unwrap().clear();
            Ok(())
        }
    }

    fn hook_test_proxy(
        config: DeviseConfig,
    ) -> (crate::proxy::AuthProxy, std::sync::Arc<HookTestStore>) {
        let store = std::sync::Arc::new(HookTestStore::default());
        let mut registry = crate::scope::ScopeRegistry::new();
        registry.register(crate::scope::Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: crate::scope::PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![
                crate::scope::Module::DatabaseAuthenticatable,
                crate::scope::Module::Rememberable,
            ],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: crate::scope::SignOutVia::Delete,
            failure_app: None,
        });
        let mut hooks = crate::hooks::HookRegistry::new();
        crate::hooks::register_devise_hooks(
            &mut hooks,
            registry.get("user").expect("mapping is registered"),
        );
        let proxy = crate::proxy::AuthProxy::new(
            store.clone(),
            std::sync::Arc::new(registry),
            std::sync::Arc::new(hooks),
            std::sync::Arc::new(config),
        );
        (proxy, store)
    }

    #[tokio::test]
    async fn rememberable_set_hook_emits_hardened_cookie() {
        let (mut proxy, _) = hook_test_proxy(test_config());
        let mut user = TestUser::fresh(1, "hook@example.com");
        user.set_remember_token(Some("hook-token".to_string()));
        user.set_remember_created_at(Some(fixed_clock().now()));
        user.set_remember_me_flag(true);
        assert!(proxy.sign_in("user", Box::new(user), false).await);

        let ops = proxy.take_remember_cookie_ops();
        assert_eq!(ops.len(), 1);
        let RememberCookieOp::Set {
            scope,
            key,
            value,
            attrs,
        } = &ops[0]
        else {
            panic!("set hook queues a Set op, got {:?}", ops[0]);
        };
        assert_eq!(scope, "user");
        assert_eq!(key, "remember_user_token");
        let triple = decode_cookie_value(value).expect("jar carries the triple");
        assert_eq!(triple.0, "1");
        assert_eq!(triple.1, "hook-token");
        assert!(attrs.httponly && attrs.secure);
        assert_eq!(attrs.same_site, SameSite::Lax);
        let header = attrs.to_set_cookie_header(value);
        assert!(header.contains("; HttpOnly"));
        assert!(header.contains("; Secure"));
        assert!(header.contains("; SameSite=Lax"));
    }

    #[tokio::test]
    async fn rememberable_set_hook_skips_without_flag_or_value() {
        let (mut proxy, _) = hook_test_proxy(test_config());

        // Flag unset: session-only sign-in leaves no cookie intent.
        let mut plain = TestUser::fresh(1, "plain@example.com");
        plain.set_remember_token(Some("hook-token".to_string()));
        plain.set_remember_created_at(Some(fixed_clock().now()));
        assert!(proxy.sign_in("user", Box::new(plain), false).await);
        assert!(proxy.take_remember_cookie_ops().is_empty());
        assert!(proxy.sign_out("user").await);
        // The sign-out above queues its own delete; drain before continuing.
        let leftovers = proxy.take_remember_cookie_ops();
        assert_eq!(leftovers.len(), 1);

        // Flag set but no value minted yet: fail closed, no junk cookie.
        let mut empty = TestUser::fresh(1, "empty@example.com");
        empty.set_remember_me_flag(true);
        assert!(proxy.sign_in("user", Box::new(empty), false).await);
        assert!(proxy.take_remember_cookie_ops().is_empty());
        assert!(proxy.sign_out("user").await);
        let ops = proxy.take_remember_cookie_ops();
        assert_eq!(ops.len(), 1);
        assert!(
            ops.iter()
                .all(|op| matches!(op, RememberCookieOp::Clear { .. }))
        );
    }

    #[tokio::test]
    async fn rememberable_logout_hook_clears_cookie() {
        let (mut proxy, _) = hook_test_proxy(test_config());
        let user = TestUser::fresh(1, "bye@example.com");
        assert!(proxy.sign_in("user", Box::new(user), false).await);
        assert!(proxy.take_remember_cookie_ops().is_empty());

        assert!(proxy.sign_out("user").await);
        let ops = proxy.take_remember_cookie_ops();
        assert_eq!(ops.len(), 1);
        assert!(matches!(
            &ops[0],
            RememberCookieOp::Clear { scope, key }
            if scope == "user" && key == "remember_user_token"
        ));
    }
}
