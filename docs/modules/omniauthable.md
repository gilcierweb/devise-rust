# `omniauthable`

Mirrors `Devise::Models::Omniauthable`
(`devise/lib/devise/models/omniauthable.rb` and
`devise/lib/devise/omniauth/config.rb`, untracked upstream reference).
Generic `OAuth2` provider wiring with always-on PKCE and CSRF state, the
`ProviderProfile` handoff, and the required `from_omniauth` model seam.
Phase 9 shipped this module in core plus route pairs in both framework
crates.

The trait lives at
[`devise_rust::omniauthable::Omniauthable`](https://docs.rs/devise-rust/latest/devise_rust/omniauthable/trait.Omniauthable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `omniauth_providers` | `DeviseConfig.omniauth_providers` | `[]` | provider-name allowlist checked at request time by the framework handlers |
| `omniauth_path_prefix` | `DeviseConfig.omniauth_path_prefix` | nil | global prefix override; the default base is `{scope_path}/auth` |

Providers are registered by name with generic endpoint configuration
(`OAuthProviderConfig`); core ships no vendor presets, matching the
generic OAuth2 client. PKCE (S256) and a random CSRF `state` are
generated for every authorize attempt with no opt-out anywhere on the
path, and the `state` comparison runs through `secure_compare` only.
OAuth access and refresh tokens stay in the session for the duration of
the flow and never reach the database; only the identity pair
(`provider` + `uid`) persists.

## Examples

The model seam is the Devise convention `User.from_omniauth(auth)` where
the app owns the handoff. The trait method is required (no default body)
and returns `ResourceWithErrors`, never an `Option`; an empty error set
means the record is ready to sign in. Apps that want the Devise-style
default policy delegate to `default_from_omniauth`, which implements
find-by-identity, link on verified email only, else create:

<!-- text fence: adapter and clock parameters; the same shape is the
     compiled ignore-fenced example on the Omniauthable trait -->
```text
#[async_trait]
impl Omniauthable for User {
    type New = NewUser;

    async fn from_omniauth<A>(
        profile: ProviderProfile,
        adapter: &A,
        clock: &dyn Clock,
    ) -> ResourceWithErrors<Self>
    where
        Self: Sized,
        A: OrmAdapter<Self, New = Self::New> + Send + Sync,
    {
        default_from_omniauth(adapter, &profile, clock).await
    }

    fn new_from_profile(profile: &ProviderProfile, now: DateTime<Utc>) -> Self::New {
        NewUser {
            email: profile.email.clone().unwrap_or_default(),
            provider: Some(profile.provider.clone()),
            uid: Some(profile.uid.clone()),
            name: profile.name.clone(),
            created_at: Some(now),
        }
    }
}
```

## Chaining note

`omniauthable` is third in the Devise module super-chain (after
`rememberable`). It adds no `active_for_authentication` or
`inactive_message` condition: the module contributes configuration, the
authorize and callback routes (POST-only authorize, GET-or-POST
callback), and the model seam, mirroring Devise where omniauthable wires
routes and leaves `from_omniauth` to the app.
