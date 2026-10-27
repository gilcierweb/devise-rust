//! `AuthRequest` snapshot - bridges carry this structured snapshot instead of raw HTTP
//!
//! Mirrors the Rack request surface devise's strategies and failure app read: method, path, headers, params, and the warden env flags.
//!
//! Normalizes untrusted HTTP input (headers, params, cookies, path) before crossing
//! into core. Core trusts snapshot fields; bridges MUST sanitize before building.

use crate::config::DeviseConfig;
use std::collections::HashMap;

/// HTTP method for request classification
///
/// Mirrors the HTTP verb dispatch of devise's router: the `sign_out_via` matching vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl HttpMethod {
    /// Parse from string (case-insensitive)
    ///
    /// Returns `None` for unknown methods. Kept as an inherent method
    /// returning `Option` (instead of `std::str::FromStr`) to preserve the
    /// existing bridge/test call sites that match on `Option`.
    ///
    /// Parses the verb, mirroring the router dispatch devise's route generation relies on; unknown verbs fail closed to a non-matching value.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(HttpMethod::Get),
            "POST" => Some(HttpMethod::Post),
            "PUT" => Some(HttpMethod::Put),
            "PATCH" => Some(HttpMethod::Patch),
            "DELETE" => Some(HttpMethod::Delete),
            "HEAD" => Some(HttpMethod::Head),
            "OPTIONS" => Some(HttpMethod::Options),
            _ => None,
        }
    }

    /// Check if this is a safe/idempotent method
    ///
    /// GET and HEAD safety, mirroring devise's method checks in the failure and timeout hooks.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            HttpMethod::Get | HttpMethod::Head | HttpMethod::Options
        )
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
        }
    }
}

/// Request flags - control authentication behavior per request
///
/// Five independent Devise-mandated toggles (`skip_storage`, `skip_timeout`,
/// `skip_timeoutable`, `skip_trackable`, `allow_params_authentication`).
/// Kept as plain bools for readability and struct-literal construction in
/// bridges/tests; a state machine would be over-engineering here.
///
/// Mirrors the env flags devise sets: `devise.skip_trackable`, `devise.skip_timeoutable`, and the XHR marker.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct RequestFlags {
    /// Skip session storage for this request (`http_auth` strategy)
    pub skip_storage: bool,
    /// Skip timeout check for this request
    pub skip_timeout: bool,
    /// Skip timeoutable module check
    pub skip_timeoutable: bool,
    /// Skip trackable module update
    pub skip_trackable: bool,
    /// Allow params authentication (`devise.allow_params_authentication`)
    pub allow_params_authentication: bool,
}

/// `AuthRequest` - normalized snapshot of HTTP request for authentication decisions
///
/// Bridges (actix, axum) build this from their request types, applying:
/// - `ParameterFilter` normalization (case-insensitive keys, whitespace stripping)
/// - Devise config gating (`http_authenticatable`, `params_authenticatable`, etc.)
/// - Stored location parsing (`parse_uri` semantics)
///
/// The framework-neutral request snapshot strategies read; the typed mirror of devise's Rack env, params, and headers access.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthRequest {
    /// HTTP method
    pub method: HttpMethod,
    /// Request path (relative, no scheme/authority)
    pub path: String,
    /// Request headers (lowercase keys)
    pub headers: HashMap<String, String>,
    /// Request params (body params for POST, query for GET)
    pub params: HashMap<String, String>,
    /// Request cookies
    pub cookies: HashMap<String, String>,
    /// Query string parameters
    pub query: HashMap<String, String>,
    /// Behavioral flags
    pub flags: RequestFlags,
    /// Socket peer address (`request.remote_ip` equivalent, e.g. `"127.0.0.1"`).
    ///
    /// Bridges MUST fill this from the socket peer only. `X-Forwarded-For`
    /// and every other proxy header are attacker-controlled and are NEVER
    /// trusted in v1 (D-20): core reads no header for IP purposes, so a
    /// forged header can never reach `update_tracked_fields`. Proxy-aware
    /// IP resolution is a future opt-in, not this phase.
    pub peer_addr: Option<String>,
    /// Request-derived values keyed by name, for Devise's `request_keys`
    /// lookup conditions.
    ///
    /// Devise (`strategies/authenticatable.rb:151-155`) reads each configured
    /// request key off the request object itself (`request.send(key)`, for
    /// example `request.host` or `request.subdomain`), then merges the result
    /// into the authentication hash AFTER the params keys
    /// (`parse_authentication_key_values(auth_values, authentication_keys) &&
    /// parse_authentication_key_values(request_values, request_keys)`), so a
    /// same-named request value overwrites the param value.
    ///
    /// Rust request types carry no arbitrary `send(key)` methods, so the
    /// port's translation is a bridge-populated map. The two bridges populate
    /// exactly two keys with their Devise request-object mappings: `host`
    /// from the `Host` header (`request.host`) and `remote_ip` from the socket
    /// peer (`request.remote_ip`, the D-20 rule: never a proxy header).
    ///
    /// The values are used strictly as DB lookup conditions, never for
    /// redirects or authorization. They are `#[serde(default)]` so a
    /// previously recorded snapshot without the field keeps deserializing
    /// with an empty map, which makes every configured request key fail
    /// closed exactly as a request that never carried it would.
    #[serde(default)]
    pub request_values: HashMap<String, String>,
}

impl AuthRequest {
    /// Create a new `AuthRequest` with minimal required fields
    ///
    /// Assembles the snapshot from method, path, headers, and params; mirrors the Rack env devise's strategies read.
    #[must_use]
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            params: HashMap::new(),
            cookies: HashMap::new(),
            query: HashMap::new(),
            flags: RequestFlags::default(),
            peer_addr: None,
            request_values: HashMap::new(),
        }
    }

    /// Attach the socket peer address (bridge-supplied, never a proxy header).
    ///
    /// == Examples
    ///
    /// ```
    /// use devise_rust::request::{AuthRequest, HttpMethod};
    ///
    /// let request = AuthRequest::new(HttpMethod::Get, "/users/sign_in")
    ///     .peer_addr("127.0.0.1".to_string());
    /// assert_eq!(request.peer_addr.as_deref(), Some("127.0.0.1"));
    /// ```
    ///
    /// Mirrors `request.remote_ip`: the socket peer address only; proxy headers are never trusted here (D-20).
    #[must_use]
    pub fn peer_addr(mut self, addr: String) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    /// Resolve the winning media range of an `Accept` header.
    ///
    /// Picks the entry with the highest quality (`q=`); on equal quality the
    /// first listed entry wins, matching how browsers order their preferences.
    /// An empty or unparsable header yields `*/*` (the browser default).
    fn best_media_range(accept: &str) -> &str {
        let mut best: Option<(&str, f32)> = None;
        for entry in accept.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (mime, quality) = match entry.split_once(';') {
                Some((mime, params)) => {
                    let quality = params
                        .split(';')
                        .find_map(|param| {
                            let param = param.trim();
                            param
                                .strip_prefix("q=")
                                .and_then(|value| value.parse::<f32>().ok())
                        })
                        .unwrap_or(1.0);
                    (mime.trim(), quality)
                }
                None => (entry, 1.0),
            };
            if mime.is_empty() {
                continue;
            }
            match best {
                Some((_, best_quality)) if quality <= best_quality => {}
                _ => best = Some((mime, quality)),
            }
        }
        best.map_or("*/*", |(mime, _)| mime)
    }

    /// Check if request is a navigational format (HTML/Turbo Stream)
    ///
    /// Mirrors Devise's `is_navigational_format?` - Rails resolves
    /// `request.format.ref` from the Accept header and asks whether it is in
    /// `config.navigational_formats` (default: `["*/*", "html", "turbo_stream"]`).
    /// The winning media range (highest `q`, first listed on ties) decides:
    /// `*/*` resolves to `:html` (browsers, bare curl), an explicit
    /// `application/json` resolves to `:json` and is NOT navigational, so an
    /// API failure answers 401 rather than a 302 to the sign-in page.
    #[must_use]
    pub fn is_navigational_format(&self, config: &DeviseConfig) -> bool {
        let accept = self.headers.get("accept").map_or("*/*", |s| s.as_str());
        let negotiated = Self::best_media_range(accept);

        // `*/*` (or no parsable entry) resolves to the browser format.
        if negotiated.contains("*/*") {
            return true;
        }
        if negotiated.contains("html") || negotiated.contains("turbo") {
            return true;
        }
        // Honor custom navigational_formats entries ("json" makes json
        // navigational for that app); "*/*" never forces a redirect on its
        // own once a concrete type won.
        config.navigational_formats.iter().any(|format| {
            let format = format.trim();
            !format.is_empty() && format != "*/*" && negotiated.contains(format)
        })
    }

    /// Check if request is XHR (AJAX)
    ///
    /// Mirrors the XHR check behind `Devise.http_authenticatable_on_xhr`.
    #[must_use]
    pub fn is_xhr(&self) -> bool {
        self.headers
            .get("x-requested-with")
            .is_some_and(|v| v.eq_ignore_ascii_case("xmlhttprequest"))
    }

    /// Check if request has HTTP Basic Authorization header
    ///
    /// Detects the Authorization header, mirroring the env check in `Devise::Strategies::Authenticatable`.
    #[must_use]
    pub fn has_http_basic(&self) -> bool {
        self.headers
            .get("authorization")
            .is_some_and(|v| v.starts_with("Basic "))
    }

    /// Extract HTTP Basic credentials (username, optional password)
    ///
    /// Returns `None` when the header is missing, malformed, or not Basic.
    /// The password half mirrors `decode_credentials`
    /// (`strategies/authenticatable.rb:122-125`): the decoded value splits
    /// on the first colon with limit 2, so a colonless payload yields a
    /// username with no password at all (`None`) while an empty password
    /// after the colon stays a present-but-empty slot (`Some("")`).
    ///
    /// Parses HTTP Basic credentials, mirroring warden's basic-auth decoding.
    #[must_use]
    pub fn http_basic_credentials(&self) -> Option<(String, Option<String>)> {
        let auth = self.headers.get("authorization")?;
        let encoded = auth.strip_prefix("Basic ")?;
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let mut parts = decoded.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next().map(str::to_string);
        Some((username, password))
    }

    /// Get recall target (controller, action) from params
    ///
    /// Used for `Failure::Recall` - custom sign-in forms that need original params.
    ///
    /// Mirrors the failure app's `recall` target resolution from the request.
    #[must_use]
    pub fn recall_target(&self) -> Option<(String, String)> {
        let controller = self.params.get("recall_controller")?.clone();
        let action = self.params.get("recall_action")?.clone();
        Some((controller, action))
    }

    /// Get the scope-specific params hash (`params[scope]`)
    ///
    /// Devise strategies extract credentials from `params[scope]` (e.g., `params[:user]`).
    ///
    /// Mirrors `params[scope]`: the scope credential hash devise's params strategy extracts.
    #[must_use]
    pub fn scope_params(&self, _scope: &str) -> Option<&HashMap<String, String>> {
        // This is a simplified version - real implementation would parse nested params
        // For now, we check if any param keys start with "scope."
        None
    }

    /// Parse stored location URI - Devise's `parse_uri` semantics
    ///
    /// Strips scheme+authority, keeps path+query+fragment. Invalid → None.
    ///
    /// Mirrors devise's `stored_location` read with the open-redirect guard: same-host validation of the stored location.
    ///
    /// The guard rejects every shape a browser could resolve off-host:
    /// absolute schemes (`http://`, `https://`), protocol-relative `//host`,
    /// and - because browsers normalize `\` to `/` and strip raw control
    /// whitespace - any target containing a backslash, tab, CR, or LF. A
    /// leading `/` alone is not evidence of same-hostness (`/\evil.com` and
    /// `/\/evil.com` both travel off-host once the browser rewrites them).
    #[must_use]
    pub fn parse_stored_uri(input: &str) -> Option<String> {
        // Reject absolute URLs, accept relative paths
        if input.starts_with("http://") || input.starts_with("https://") {
            return None;
        }
        if input.starts_with("//") {
            return None;
        }
        // A backslash or raw control whitespace makes the target unsafe after
        // browser normalization (path confusion, open redirect, header folding).
        if input
            .chars()
            .any(|c| matches!(c, '\\' | '\t' | '\r' | '\n'))
        {
            return None;
        }
        // Must start with / for a valid path
        if !input.starts_with('/') {
            return None;
        }
        Some(input.to_string())
    }

    /// Get params for a specific scope (e.g., `params[:user][:email]`)
    ///
    /// Handles both flat and nested param structures.
    ///
    /// Reads one param from the scope hash; the `params[scope][key]` mirror.
    #[must_use]
    pub fn get_scope_param(&self, scope: &str, key: &str) -> Option<&String> {
        // Try nested: params["scope"]["key"]
        let _nested = self.params.get(scope);
        // This is simplified - real implementation needs nested HashMap
        // Try flat: params["scope_key"]
        let flat_key = format!("{scope}_{key}");
        self.params.get(&flat_key)
    }
}

/// Build `AuthRequest` from raw parts (bridge helper)
///
/// Takes standard `HashMap` maps; generalizing over hashers would add
/// generic noise for zero benefit since bridges always pass `RandomState`.
///
/// Builds the snapshot from parts; mirrors the Rack request assembly for tests over the framework adapters.
#[allow(clippy::implicit_hasher)]
#[must_use]
pub fn build_auth_request(
    method: HttpMethod,
    path: String,
    headers: HashMap<String, String>,
    params: HashMap<String, String>,
    cookies: HashMap<String, String>,
    query: HashMap<String, String>,
    flags: RequestFlags,
) -> AuthRequest {
    build_auth_request_with_peer(method, path, headers, params, cookies, query, flags, None)
}

/// Build `AuthRequest` from raw parts plus the socket peer address.
///
/// `peer_addr` is the framework-supplied socket peer (`request.remote_ip`
/// equivalent). Bridges pass `Some` here and MUST never substitute an
/// `X-Forwarded-For` or other proxy header value (D-20).
///
/// Builds the snapshot with an explicit socket peer; mirrors `request.remote_ip` for tests replaying recorded requests.
#[allow(clippy::implicit_hasher, clippy::too_many_arguments)]
#[must_use]
pub fn build_auth_request_with_peer(
    method: HttpMethod,
    path: String,
    headers: HashMap<String, String>,
    params: HashMap<String, String>,
    cookies: HashMap<String, String>,
    query: HashMap<String, String>,
    flags: RequestFlags,
    peer_addr: Option<String>,
) -> AuthRequest {
    AuthRequest {
        method,
        path,
        headers,
        params,
        cookies,
        query,
        flags,
        peer_addr,
        request_values: HashMap::new(),
    }
}

/// Builder methods for `AuthRequest`
impl AuthRequest {
    /// Add headers to the request
    ///
    /// Header map accessor; mirrors the Rack header hash devise's strategies read.
    #[must_use]
    pub fn headers(mut self, headers: impl IntoIterator<Item = (String, String)>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Add params to the request
    ///
    /// Params map accessor; mirrors the Rack params hash devise's strategies read.
    #[must_use]
    pub fn params(mut self, params: impl IntoIterator<Item = (String, String)>) -> Self {
        self.params.extend(params);
        self
    }

    /// Attach the request-derived values the `request_keys` conditions read.
    ///
    /// The bridge populates this map from the framework's request object
    /// (`request.send(key)` parity, `strategies/authenticatable.rb:151-155`):
    /// `host` from the Host header and `remote_ip` from the socket peer only.
    /// Values are stored RAW: Devise routes params through the
    /// `ParameterFilter` but request-derived values enter the authentication
    /// hash unnormalized.
    ///
    /// == Examples
    ///
    /// ```
    /// use devise_rust::request::{AuthRequest, HttpMethod};
    ///
    /// let request = AuthRequest::new(HttpMethod::Get, "/users/sign_in")
    ///     .request_values([("host".to_string(), "app.example.com".to_string())]);
    /// assert_eq!(request.request_values.get("host").map(String::as_str), Some("app.example.com"));
    /// ```
    #[must_use]
    pub fn request_values(mut self, values: impl IntoIterator<Item = (String, String)>) -> Self {
        self.request_values.extend(values);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeviseConfig;

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_str("GET"), Some(HttpMethod::Get));
        assert_eq!(HttpMethod::from_str("post"), Some(HttpMethod::Post));
        assert_eq!(HttpMethod::from_str("PuT"), Some(HttpMethod::Put));
        assert_eq!(HttpMethod::from_str("delete"), Some(HttpMethod::Delete));
        assert_eq!(HttpMethod::from_str("INVALID"), None);
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
    }

    /// The `request_values` builder fills the map the `request_keys`
    /// conditions read (`strategies/authenticatable.rb:151-155`), and the
    /// field is `#[serde(default)]` so a snapshot recorded before the field
    /// existed still deserializes (with an empty map, which makes every
    /// configured request key fail closed rather than panic).
    #[test]
    fn test_request_values_builder_and_serde_default() {
        let request = AuthRequest::new(HttpMethod::Get, "/users/sign_in").request_values([
            ("host".to_string(), "app.example.com".to_string()),
            ("remote_ip".to_string(), "203.0.113.7".to_string()),
        ]);
        assert_eq!(
            request.request_values.get("host").map(String::as_str),
            Some("app.example.com")
        );
        assert_eq!(
            request.request_values.get("remote_ip").map(String::as_str),
            Some("203.0.113.7")
        );

        // A hand-written snapshot lacking the field: serde fills the empty map.
        let snapshot = r#"{"method":"Post","path":"/users/sign_in","headers":{},"params":{},"cookies":{},"query":{},"flags":{"skip_storage":false,"skip_timeout":false,"skip_timeoutable":false,"skip_trackable":false,"allow_params_authentication":true},"peer_addr":null}"#;
        let restored: AuthRequest = serde_json::from_str(snapshot).expect("snapshot deserializes");
        assert!(
            restored.request_values.is_empty(),
            "the serde default must be an empty map"
        );
    }

    #[test]
    fn test_is_navigational_format() {
        let config = DeviseConfig::default();

        // */* matches everything (browsers, bare curl): Rails resolves it
        // to :html, which IS in navigational_formats.
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("accept".to_string(), "*/*".to_string())]);
        assert!(req.is_navigational_format(&config));

        // A missing Accept header behaves like a browser (*/*).
        let req = AuthRequest::new(HttpMethod::Get, "/");
        assert!(req.is_navigational_format(&config));

        // Browser header: html (q=1) beats */* (q=0.8).
        let req = AuthRequest::new(HttpMethod::Get, "/").headers([(
            "accept".to_string(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        )]);
        assert!(req.is_navigational_format(&config));

        // text/html matches
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("accept".to_string(), "text/html".to_string())]);
        assert!(req.is_navigational_format(&config));

        // turbo_stream matches
        let req = AuthRequest::new(HttpMethod::Get, "/").headers([(
            "accept".to_string(),
            "text/vnd.turbo-stream.html".to_string(),
        )]);
        assert!(req.is_navigational_format(&config));

        // An explicit application/json (no */*) is an API request: Rails
        // resolves request.format.ref to :json, which is NOT navigational,
        // so the failure app must answer 401 - never a 302 to sign_in.
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("accept".to_string(), "application/json".to_string())]);
        assert!(!req.is_navigational_format(&config));

        // axios-style header: json (q=1) beats */* (q=0.01).
        let req = AuthRequest::new(HttpMethod::Get, "/").headers([(
            "accept".to_string(),
            "application/json, text/javascript, */*; q=0.01".to_string(),
        )]);
        assert!(!req.is_navigational_format(&config));

        // Test with config that excludes */*
        let config_no_star = DeviseConfig {
            navigational_formats: vec!["html".to_string(), "turbo_stream".to_string()],
            ..config
        };
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("accept".to_string(), "application/json".to_string())]);
        assert!(!req.is_navigational_format(&config_no_star));
    }

    #[test]
    fn test_is_xhr() {
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("x-requested-with".to_string(), "XMLHttpRequest".to_string())]);
        assert!(req.is_xhr());

        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("x-requested-with".to_string(), "xmlhttprequest".to_string())]);
        assert!(req.is_xhr());

        let req = AuthRequest::new(HttpMethod::Get, "/");
        assert!(!req.is_xhr());
    }

    #[test]
    fn test_has_http_basic() {
        let req = AuthRequest::new(HttpMethod::Get, "/").headers([(
            "authorization".to_string(),
            "Basic dXNlcjpwYXNz".to_string(),
        )]);
        assert!(req.has_http_basic());

        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("authorization".to_string(), "Bearer token".to_string())]);
        assert!(!req.has_http_basic());

        let req = AuthRequest::new(HttpMethod::Get, "/");
        assert!(!req.has_http_basic());
    }

    #[test]
    fn test_http_basic_credentials() {
        // user:pass -> dXNlcjpwYXNz
        let req = AuthRequest::new(HttpMethod::Get, "/").headers([(
            "authorization".to_string(),
            "Basic dXNlcjpwYXNz".to_string(),
        )]);
        let creds = req.http_basic_credentials();
        assert_eq!(creds, Some(("user".to_string(), Some("pass".to_string()))));

        // Malformed
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("authorization".to_string(), "Basic not-base64!".to_string())]);
        assert!(req.http_basic_credentials().is_none());
    }

    /// `authenticatable.rb:122-125` (`decode_credentials`): the decoded value
    /// splits on the first colon with limit 2, so a colonless payload yields a
    /// username with NO password while an empty password after the colon
    /// stays a present-but-empty slot.
    #[test]
    fn test_http_basic_credentials_split_shape() {
        // "user" with no colon: the password slot is missing, not empty.
        let colonless = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "user");
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("authorization".to_string(), format!("Basic {colonless}"))]);
        assert_eq!(
            req.http_basic_credentials(),
            Some(("user".to_string(), None))
        );

        // "user:" with an empty password: the slot exists and is empty.
        let empty_pass =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "user:");
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("authorization".to_string(), format!("Basic {empty_pass}"))]);
        assert_eq!(
            req.http_basic_credentials(),
            Some(("user".to_string(), Some(String::new())))
        );

        // A password carrying its own colons keeps everything after the first.
        let with_colons = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "user:pa:ss:word",
        );
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("authorization".to_string(), format!("Basic {with_colons}"))]);
        assert_eq!(
            req.http_basic_credentials(),
            Some(("user".to_string(), Some("pa:ss:word".to_string())))
        );

        // Missing header still aborts the whole call.
        let req = AuthRequest::new(HttpMethod::Get, "/");
        assert!(req.http_basic_credentials().is_none());
    }

    #[test]
    fn test_recall_target() {
        let req = AuthRequest::new(HttpMethod::Get, "/").params([
            ("recall_controller".to_string(), "sessions".to_string()),
            ("recall_action".to_string(), "new".to_string()),
        ]);
        assert_eq!(
            req.recall_target(),
            Some(("sessions".to_string(), "new".to_string()))
        );

        let req = AuthRequest::new(HttpMethod::Get, "/");
        assert!(req.recall_target().is_none());
    }

    #[test]
    fn test_parse_stored_uri() {
        // Valid relative paths
        assert_eq!(
            AuthRequest::parse_stored_uri("/protected"),
            Some("/protected".to_string())
        );
        assert_eq!(
            AuthRequest::parse_stored_uri("/path?query=1"),
            Some("/path?query=1".to_string())
        );
        assert_eq!(
            AuthRequest::parse_stored_uri("/path#fragment"),
            Some("/path#fragment".to_string())
        );

        // Invalid: absolute URLs
        assert!(AuthRequest::parse_stored_uri("http://example.com/path").is_none());
        assert!(AuthRequest::parse_stored_uri("https://example.com/path").is_none());
        assert!(AuthRequest::parse_stored_uri("//example.com/path").is_none());

        // Invalid: no leading slash
        assert!(AuthRequest::parse_stored_uri("path").is_none());
        assert!(AuthRequest::parse_stored_uri("").is_none());
    }

    /// S1: the open-redirect guard must also reject protocol-relative
    /// backslash targets. Browsers normalize `\` to `/`, so a stored
    /// `/\evil.com` would resolve `Location: /\evil.com` off-host even though
    /// it starts with a slash. Raw tab/CR/LF are rejected for the same
    /// reason (header folding and browser normalization).
    #[test]
    fn test_parse_stored_uri_rejects_backslash_targets() {
        // Protocol-relative backslash forms (Ruby's `parse_uri` equivalent
        // rejects them; a naive `starts_with("//")` does not).
        assert!(AuthRequest::parse_stored_uri("/\\evil.com").is_none());
        assert!(AuthRequest::parse_stored_uri("/\\t//evil.com").is_none());
        assert!(AuthRequest::parse_stored_uri("/\\/evil.com").is_none());

        // Already-rejected shapes stay rejected.
        assert!(AuthRequest::parse_stored_uri("//evil.com").is_none());
        assert!(AuthRequest::parse_stored_uri("http://evil.com").is_none());
        assert!(AuthRequest::parse_stored_uri("https://evil.com").is_none());

        // A well-formed relative path still lands.
        assert_eq!(
            AuthRequest::parse_stored_uri("/good/path?q=1"),
            Some("/good/path?q=1".to_string())
        );
    }
}
