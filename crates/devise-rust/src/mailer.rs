//! Mailer - Devise mailer actions for the 5 built-in notifications (MAIL-01..03).
//!
//! Mirrors `Devise::Mailer` / `Devise::Mailers::Helpers`
//! (`devise/lib/devise/mailers/helpers.rb`): five actions
//! (`confirmation_instructions`, `reset_password_instructions`,
//! `unlock_instructions`, `email_changed`, `password_change`), each rendering
//! a compile-time-embedded Tera template with a [`MailerContext`].
//!
//! == Options
//!
//! Subjects come from the embedded I18n catalog
//! (`devise.mailer.<action>.subject`, matching `devise/config/locales/en.yml`).
//!
//! == Examples
//!
//! ```
//! use devise_rust::mailer::{HasEmail, Mailer, MailerContext, TestMailer};
//!
//! struct User { email: String }
//! impl HasEmail for User {
//!     fn email(&self) -> &str { &self.email }
//! }
//!
//! let user = User { email: "user@example.com".to_string() };
//! let mailer = TestMailer::default();
//! let ctx = MailerContext::from_record(&user)
//!     .with_token("raw-token")
//!     .with_url("https://example.com/users/confirmation?confirmation_token=raw-token");
//! let body = mailer.confirmation_instructions(&user, Some("raw-token"), &ctx)?;
//! assert!(body.contains("Confirm my account"));
//! assert_eq!(mailer.sent_mails().len(), 1);
//! # Ok::<(), devise_rust::error::DeviseError>(())
//! ```

use crate::error::DeviseError;
use crate::i18n::translate_simple;
use std::sync::Mutex;

/// Embedded Devise mailer templates (`devise/app/views/devise/mailer/*.html.erb`
/// converted ERB `<%= %>` -> Tera `{{ }}`). Embedded at compile time (MAIL-02).
pub mod templates {
    /// `confirmation_instructions` - welcome + confirmation link.
    pub const CONFIRMATION_INSTRUCTIONS: &str =
        include_str!("../templates/devise/mailer/confirmation_instructions.email.tera");
    /// `reset_password_instructions` - reset-password link.
    pub const RESET_PASSWORD_INSTRUCTIONS: &str =
        include_str!("../templates/devise/mailer/reset_password_instructions.email.tera");
    /// `unlock_instructions` - unlock link.
    pub const UNLOCK_INSTRUCTIONS: &str =
        include_str!("../templates/devise/mailer/unlock_instructions.email.tera");
    /// `email_changed` - change notification to the original address.
    pub const EMAIL_CHANGED: &str =
        include_str!("../templates/devise/mailer/email_changed.email.tera");
    /// `password_change` - change notification.
    pub const PASSWORD_CHANGE: &str =
        include_str!("../templates/devise/mailer/password_change.email.tera");
}

/// Template variables shared by all 5 mailer actions (MAIL-02).
///
/// `resource` carries the record's serializable fields so templates can use
/// Devise's `@resource.<field>` expressions (e.g. `{{ resource.email }}`,
/// `{% if resource.unconfirmed_email %}`).
#[derive(Debug, Clone)]
pub struct MailerContext {
    /// Delivery address (Devise `headers[:to]`). For `email_changed` this is
    /// the ORIGINAL email; the new address rides inside `resource`.
    pub email: String,
    /// Raw token (confirmation / reset password / unlock actions).
    pub token: Option<String>,
    /// Absolute action URL built by the host app (routes are app-side).
    ///
    /// Inserted into templates with `| safe` (Devise's `link_to` does not escape
    /// `/`, and Tera's HTML escaper would render it `&#x2F;`). User-controlled
    /// fields (`email`, `resource.*`) remain autoescaped, so the URL must be
    /// application-constructed - which it always is (route helper + raw token).
    pub url: Option<String>,
    /// Serializable record fields available to templates (`@resource`).
    pub resource: serde_json::Value,
}

impl MailerContext {
    /// Build a context extracting the email from the record (MAIL-03).
    pub fn from_record<M: HasEmail + ?Sized>(record: &M) -> Self {
        let email = record.email().to_string();
        Self {
            resource: serde_json::json!({ "email": email }),
            email,
            token: None,
            url: None,
        }
    }

    /// Attach the raw token emailed to the user (never the digest).
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Attach the action URL (`confirmation_url`/`edit_password_url`/`unlock_url`).
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Attach the record's serializable fields (`@resource` in templates).
    #[must_use]
    pub fn with_resource(mut self, resource: serde_json::Value) -> Self {
        self.resource = resource;
        self
    }

    fn to_tera_context(&self) -> tera::Context {
        let mut ctx = tera::Context::new();
        ctx.insert("email", &self.email);
        ctx.insert("token", self.token.as_deref().unwrap_or(""));
        ctx.insert("url", self.url.as_deref().unwrap_or(""));
        ctx.insert("resource", &self.resource);
        ctx
    }
}

/// Supplies the delivery email for [`MailerContext::from_record`].
pub trait HasEmail {
    /// The record's primary email address (Devise `email` column).
    fn email(&self) -> &str;
}

/// Devise mailer actions (MAIL-01). Generic over the record type `M`; trait
/// is `Send + Sync` so implementations can deliver asynchronously.
///
/// Each action takes the record, the raw token when the action carries one,
/// and the extracted [`MailerContext`], returning the rendered body.
pub trait Mailer<M>: Send + Sync {
    /// `confirmation_instructions` - welcome mail with confirmation link.
    ///
    /// # Errors
    /// Returns `DeviseError::Mailer` when the template fails to render.
    fn confirmation_instructions(
        &self,
        record: &M,
        token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError>;

    /// `reset_password_instructions` - password reset link mail.
    ///
    /// # Errors
    /// Returns `DeviseError::Mailer` when the template fails to render.
    fn reset_password_instructions(
        &self,
        record: &M,
        token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError>;

    /// `unlock_instructions` - account-unlock link mail.
    ///
    /// # Errors
    /// Returns `DeviseError::Mailer` when the template fails to render.
    fn unlock_instructions(
        &self,
        record: &M,
        token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError>;

    /// `email_changed` - notification to the ORIGINAL address.
    ///
    /// # Errors
    /// Returns `DeviseError::Mailer` when the template fails to render.
    fn email_changed(
        &self,
        record: &M,
        token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError>;

    /// `password_change` - notification that the password changed.
    ///
    /// # Errors
    /// Returns `DeviseError::Mailer` when the template fails to render.
    fn password_change(
        &self,
        record: &M,
        token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError>;
}

/// One email captured by [`TestMailer`] for assertions (MAIL-03).
#[derive(Debug, Clone)]
pub struct SentMail {
    /// Recipient (`headers[:to]`).
    pub to: String,
    /// Sender (`headers[:from]` = `config.mailer_sender`, `None` when unset).
    pub from: Option<String>,
    /// Subject line from the I18n catalog (`devise.mailer.<action>.subject`).
    pub subject: String,
    /// Rendered template body.
    pub body: String,
    /// Template variables the body was rendered with.
    pub template_vars: MailerContext,
}

/// Test mailer: renders the real embedded templates and captures deliveries
/// to an in-memory vector for assertions (MAIL-03).
#[derive(Debug, Default)]
pub struct TestMailer {
    sent: Mutex<Vec<SentMail>>,
    mailer_sender: Option<String>,
}

impl TestMailer {
    /// Snapshot of captured deliveries, oldest first.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn sent_mails(&self) -> Vec<SentMail> {
        self.sent.lock().expect("TestMailer mutex poisoned").clone()
    }

    /// Set the sender (`Devise.mailer_sender` - per-scope variants resolve
    /// through the config cascade before reaching the mailer).
    #[must_use]
    pub fn with_sender(mut self, mailer_sender: Option<String>) -> Self {
        self.mailer_sender = mailer_sender;
        self
    }

    fn deliver(
        &self,
        action: &str,
        template: &str,
        context: &MailerContext,
    ) -> Result<String, DeviseError> {
        let body = tera::Tera::one_off(template, &context.to_tera_context(), true)
            .map_err(|e| DeviseError::Mailer(format!("{action} template render failed: {e}")))?;
        let mail = SentMail {
            to: context.email.clone(),
            from: self.mailer_sender.clone(),
            subject: translate_simple(&format!("devise.mailer.{action}.subject")),
            body,
            template_vars: context.clone(),
        };
        let body = mail.body.clone();
        self.sent
            .lock()
            .expect("TestMailer mutex poisoned")
            .push(mail);
        Ok(body)
    }
}

impl<M> Mailer<M> for TestMailer {
    fn confirmation_instructions(
        &self,
        _record: &M,
        _token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError> {
        self.deliver(
            "confirmation_instructions",
            templates::CONFIRMATION_INSTRUCTIONS,
            context,
        )
    }

    fn reset_password_instructions(
        &self,
        _record: &M,
        _token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError> {
        self.deliver(
            "reset_password_instructions",
            templates::RESET_PASSWORD_INSTRUCTIONS,
            context,
        )
    }

    fn unlock_instructions(
        &self,
        _record: &M,
        _token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError> {
        self.deliver(
            "unlock_instructions",
            templates::UNLOCK_INSTRUCTIONS,
            context,
        )
    }

    fn email_changed(
        &self,
        _record: &M,
        _token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError> {
        self.deliver("email_changed", templates::EMAIL_CHANGED, context)
    }

    fn password_change(
        &self,
        _record: &M,
        _token: Option<&str>,
        context: &MailerContext,
    ) -> Result<String, DeviseError> {
        self.deliver("password_change", templates::PASSWORD_CHANGE, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct User {
        email: String,
    }

    impl HasEmail for User {
        fn email(&self) -> &str {
            &self.email
        }
    }

    #[test]
    fn mailer_trait_compiles() {
        // Generic bound proof: any `Mailer<M>` exposes all 5 Devise actions
        // taking (&M, Option<&str>, &MailerContext) -> Result<String, DeviseError>.
        fn send_all<M, T: Mailer<M>>(
            mailer: &T,
            record: &M,
            ctx: &MailerContext,
        ) -> Result<Vec<String>, DeviseError> {
            Ok(vec![
                mailer.confirmation_instructions(record, ctx.token.as_deref(), ctx)?,
                mailer.reset_password_instructions(record, ctx.token.as_deref(), ctx)?,
                mailer.unlock_instructions(record, ctx.token.as_deref(), ctx)?,
                mailer.email_changed(record, ctx.token.as_deref(), ctx)?,
                mailer.password_change(record, ctx.token.as_deref(), ctx)?,
            ])
        }

        let user = User {
            email: "user@example.com".to_string(),
        };
        let mailer = TestMailer::default();
        let ctx = MailerContext::from_record(&user)
            .with_token("tok")
            .with_url("https://example.com/action?token=tok");

        let bodies = send_all(&mailer, &user, &ctx).expect("all 5 actions deliver");
        assert_eq!(bodies.len(), 5);

        let sent = mailer.sent_mails();
        assert_eq!(sent.len(), 5);
        let subjects: Vec<&str> = sent.iter().map(|m| m.subject.as_str()).collect();
        // Subjects from the vendored Devise catalog (config/locales/en.yml).
        assert_eq!(
            subjects,
            [
                "Confirmation instructions",
                "Reset password instructions",
                "Unlock instructions",
                "Email Changed",
                "Password Changed"
            ]
        );
        assert!(sent.iter().all(|m| m.to == "user@example.com"));
    }

    #[test]
    fn mailer_templates_compile() {
        // All 5 embedded templates compile and render the Devise content with
        // Tera syntax (MAIL-02).
        let user = User {
            email: "user@example.com".to_string(),
        };
        let mailer = TestMailer::default();
        let ctx = MailerContext::from_record(&user)
            .with_token("tok-1")
            .with_url("https://example.com/action?token=tok-1");

        let confirm = mailer
            .confirmation_instructions(&user, Some("tok-1"), &ctx)
            .expect("confirmation renders");
        assert!(confirm.contains("Welcome user@example.com!"));
        assert!(confirm.contains("Confirm my account"));

        let reset = mailer
            .reset_password_instructions(&user, Some("tok-1"), &ctx)
            .expect("reset renders");
        assert!(reset.contains("Hello user@example.com!"));
        assert!(reset.contains("Change my password"));
        assert!(reset.contains("If you didn't request this, please ignore this email."));

        let unlock = mailer
            .unlock_instructions(&user, Some("tok-1"), &ctx)
            .expect("unlock renders");
        assert!(unlock.contains("excessive number of unsuccessful sign in attempts"));
        assert!(unlock.contains("Unlock my account"));

        let password = mailer
            .password_change(&user, None, &ctx)
            .expect("password_change renders");
        assert!(password.contains("your password has been changed"));

        // email_changed: both Devise branches (reconfirmable vs direct change).
        let reconfirm_ctx = MailerContext::from_record(&user).with_resource(serde_json::json!({
            "email": "new@example.com",
            "unconfirmed_email": "new@example.com"
        }));
        let reconfirm = mailer
            .email_changed(&user, None, &reconfirm_ctx)
            .expect("email_changed (reconfirm) renders");
        assert!(reconfirm.contains("being changed to new@example.com"));

        let direct_ctx = MailerContext::from_record(&user).with_resource(serde_json::json!({
            "email": "new@example.com"
        }));
        let direct = mailer
            .email_changed(&user, None, &direct_ctx)
            .expect("email_changed (direct) renders");
        assert!(direct.contains("has been changed to new@example.com"));
    }

    #[test]
    fn mailer_sender_config_flows_to_from_header() {
        // MAIL-02 parity: from = config.mailer_sender (unset -> None).
        let user = User {
            email: "user@example.com".to_string(),
        };
        let ctx = MailerContext::from_record(&user);

        let plain = TestMailer::default();
        plain
            .confirmation_instructions(&user, Some("t"), &ctx)
            .expect("renders");
        assert_eq!(plain.sent_mails()[0].from, None);

        let configured =
            TestMailer::default().with_sender(Some("no-reply@example.com".to_string()));
        configured
            .confirmation_instructions(&user, Some("t"), &ctx)
            .expect("renders");
        assert_eq!(
            configured.sent_mails()[0].from.as_deref(),
            Some("no-reply@example.com")
        );
    }

    #[test]
    fn test_mailer_confirmation() {
        let user = User {
            email: "user@example.com".to_string(),
        };
        let mailer = TestMailer::default();
        let ctx = MailerContext::from_record(&user)
            .with_token("raw-token-123")
            .with_url("https://example.com/users/confirmation?confirmation_token=raw-token-123");

        let body = mailer
            .confirmation_instructions(&user, Some("raw-token-123"), &ctx)
            .expect("confirmation email renders");

        assert!(body.contains("Welcome user@example.com!"));
        assert!(
            body.contains(
                r#"<a href="https://example.com/users/confirmation?confirmation_token=raw-token-123">Confirm my account</a>"#
            ),
            "rendered body was: {body}"
        );

        let sent = mailer.sent_mails();
        assert_eq!(sent.len(), 1);
        let mail = &sent[0];
        assert_eq!(mail.to, "user@example.com");
        assert_eq!(mail.subject, "Confirmation instructions");
        assert_eq!(mail.body, body);
        assert_eq!(mail.template_vars.token.as_deref(), Some("raw-token-123"));
    }
}
