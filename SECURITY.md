# Security Policy

## Built-in protections

devise-rust ports Devise's security-critical behaviors exactly. The
protections below are enforced by the core crate and verified by the
security regression suite:

| Protection | Implementation |
|------------|----------------|
| **Timing-safe compare** | `subtle::ConstantTimeEq` for all token/password comparisons |
| **Digest-only token storage** | HMAC-SHA256 digests in DB; raw tokens only in emails |
| **Session salt invalidation** | Password change → salt mismatch → old sessions rejected |
| **Paranoid mode** | Uniform `:invalid` error; dummy bcrypt for unknown accounts |
| **Secret filtering** | `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` excluded from `Debug`/`Serialize` |
| **Bcrypt cost** | Configurable `stretches` (default 12); runs in `spawn_blocking` |
| **CSRF protection** | Framework bridge callbacks (`handle_unverified_request`); token rotation on sign in |
| **Blank-token guards** | Token lookups fail closed on blank input |
| **Remember cookie integrity** | Signed cookie with the five-condition validity check and hardened attributes (`HttpOnly`, `SameSite=Lax`, `Secure`) |

## Security configuration for production

```rust
let config = DeviseConfig {
    secret_key: std::env::var("DEVISE_SECRET_KEY").expect("DEVISE_SECRET_KEY"), // 32+ bytes
    paranoid: true,                    // uniform errors, dummy bcrypt on unknown accounts
    pepper: Some(std::env::var("DEVISE_PEPPER").expect("DEVISE_PEPPER")),
    stretches: 14,                     // higher cost for production
    skip_session_storage: vec!["http_auth".to_string()],
    expire_all_remember_me_on_sign_out: true,
    sign_out_all_scopes: true,
    ..DeviseConfig::default()
};
```

Operational notes:

- Keep the `Secure` cookie attribute on in production (the example apps'
  plain-HTTP opt-out is for local development only).
- Load `DEVISE_SECRET_KEY` and `DEVISE_PEPPER` from your secret store;
  never commit them.
- Session cookies are signed with a key derived from `secret_key`; rotate
  the secret to invalidate all sessions.

## Reporting a vulnerability

Email security at gilcierweb.dev (security@gilcierweb.dev) with details.
Please include the devise-rust version, a description of the issue, and
steps or a proof of concept when possible. Report security issues only
to this address; use the public issue tracker for everything else.
