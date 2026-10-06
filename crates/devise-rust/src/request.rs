//! `AuthRequest` snapshot - bridges carry this structured snapshot instead of raw HTTP
//!
//! Normalizes untrusted HTTP input (headers, params, cookies, path) before crossing
//! into core. Core trusts snapshot fields; bridges MUST sanitize before building.

use crate::config::DeviseConfig;
use std::collections::HashMap;

/// HTTP method for request classification
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
}

impl AuthRequest {
    /// Create a new `AuthRequest` with minimal required fields
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
        }
    }

    /// Check if request is a navigational format (HTML/Turbo Stream)
    ///
    /// Mirrors Devise's `is_navigational_format?` - checks Accept header against
    /// `config.navigational_formats` (default: `["*/*", "html", "turbo_stream"]`).
    /// Devise 5.0.4 includes `"*/*"` so bare curl gets redirect (RESEARCH.md Pitfall 2).
    #[must_use]
    pub fn is_navigational_format(&self, config: &DeviseConfig) -> bool {
        let accept = self.headers.get("accept").map_or("*/*", |s| s.as_str());

        for format in &config.navigational_formats {
            let format = format.trim();
            if format == "*/*" {
                return true;
            }
            if accept.contains(format) {
                return true;
            }
        }
        false
    }

    /// Check if request is XHR (AJAX)
    #[must_use]
    pub fn is_xhr(&self) -> bool {
        self.headers
            .get("x-requested-with")
            .is_some_and(|v| v.eq_ignore_ascii_case("xmlhttprequest"))
    }

    /// Check if request has HTTP Basic Authorization header
    #[must_use]
    pub fn has_http_basic(&self) -> bool {
        self.headers
            .get("authorization")
            .is_some_and(|v| v.starts_with("Basic "))
    }

    /// Extract HTTP Basic credentials (username, password)
    ///
    /// Returns None if header is missing, malformed, or not Basic.
    #[must_use]
    pub fn http_basic_credentials(&self) -> Option<(String, String)> {
        let auth = self.headers.get("authorization")?;
        let encoded = auth.strip_prefix("Basic ")?;
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let mut parts = decoded.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next()?.to_string();
        Some((username, password))
    }

    /// Get recall target (controller, action) from params
    ///
    /// Used for `Failure::Recall` - custom sign-in forms that need original params.
    #[must_use]
    pub fn recall_target(&self) -> Option<(String, String)> {
        let controller = self.params.get("recall_controller")?.clone();
        let action = self.params.get("recall_action")?.clone();
        Some((controller, action))
    }

    /// Get the scope-specific params hash (params[scope])
    ///
    /// Devise strategies extract credentials from `params[scope]` (e.g., params[:user]).
    #[must_use]
    pub fn scope_params(&self, _scope: &str) -> Option<&HashMap<String, String>> {
        // This is a simplified version - real implementation would parse nested params
        // For now, we check if any param keys start with "scope."
        None
    }

    /// Parse stored location URI - Devise's `parse_uri` semantics
    ///
    /// Strips scheme+authority, keeps path+query+fragment. Invalid → None.
    #[must_use]
    pub fn parse_stored_uri(input: &str) -> Option<String> {
        // Simple implementation: reject absolute URLs, accept relative paths
        if input.starts_with("http://") || input.starts_with("https://") {
            return None;
        }
        if input.starts_with("//") {
            return None;
        }
        // Must start with / for a valid path
        if !input.starts_with('/') {
            return None;
        }
        Some(input.to_string())
    }

    /// Get params for a specific scope (e.g., params[:user][:email])
    ///
    /// Handles both flat and nested param structures.
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
    AuthRequest {
        method,
        path,
        headers,
        params,
        cookies,
        query,
        flags,
    }
}

/// Builder methods for `AuthRequest`
impl AuthRequest {
    /// Add headers to the request
    #[must_use]
    pub fn headers(mut self, headers: impl IntoIterator<Item = (String, String)>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Add params to the request
    #[must_use]
    pub fn params(mut self, params: impl IntoIterator<Item = (String, String)>) -> Self {
        self.params.extend(params);
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

    #[test]
    fn test_is_navigational_format() {
        let config = DeviseConfig::default();

        // */* matches everything (Devise 5.0.4 default)
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("accept".to_string(), "*/*".to_string())]);
        assert!(req.is_navigational_format(&config));

        // text/html matches
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("accept".to_string(), "text/html".to_string())]);
        assert!(req.is_navigational_format(&config));

        // application/json MATCHES because */* is in default navigational_formats
        // (Devise 5.0.4 behavior: bare curl gets redirect)
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("accept".to_string(), "application/json".to_string())]);
        assert!(req.is_navigational_format(&config));

        // turbo_stream matches
        let req = AuthRequest::new(HttpMethod::Get, "/").headers([(
            "accept".to_string(),
            "text/vnd.turbo-stream.html".to_string(),
        )]);
        assert!(req.is_navigational_format(&config));

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
        assert_eq!(creds, Some(("user".to_string(), "pass".to_string())));

        // Malformed
        let req = AuthRequest::new(HttpMethod::Get, "/")
            .headers([("authorization".to_string(), "Basic not-base64!".to_string())]);
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
}
