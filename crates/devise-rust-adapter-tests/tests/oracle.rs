//! `MemoryAdapter` oracle leg (D-29): the identical shared contract cases
//! against the in-memory adapter, with zero backend-conditional assertions
//! (D-30). Both fixture ID shapes (integer and uuid column) run the same
//! suite: the oracle assigns external `DeviseKey`s, so the model's own id
//! field is inert fixture data.

use chrono::NaiveDateTime;
use devise_rust::adapter::{DeviseKey, memory::MemoryAdapter};
use devise_rust_adapter_tests::{ContractFactory, ContractModel, run_contract_suite};
use rstest::rstest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// Oracle fixture: the full sample-row contract (see the adapter-tests
/// crate docs) over an inert `$id_ty` id field.
macro_rules! oracle_fixture {
    ($name:ident, $id_ty:ty, $id_expr:expr) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct $name {
            id: $id_ty,
            email: String,
            encrypted_password: String,
            reset_password_token: Option<String>,
            reset_password_sent_at: Option<NaiveDateTime>,
            confirmation_token: Option<String>,
            confirmation_sent_at: Option<NaiveDateTime>,
            unconfirmed_email: Option<String>,
            failed_attempts: i64,
            sign_in_count: i64,
            current_sign_in_ip: Option<String>,
            last_sign_in_ip: Option<String>,
            unlock_token: Option<String>,
            locked_at: Option<NaiveDateTime>,
            created_at: NaiveDateTime,
            updated_at: NaiveDateTime,
        }

        impl $name {
            fn sample(email: &str, now: NaiveDateTime) -> Self {
                Self {
                    id: $id_expr,
                    email: email.to_owned(),
                    encrypted_password: "bcrypt-digest".to_owned(),
                    reset_password_token: Some(format!("enc-reset-{email}")),
                    reset_password_sent_at: Some(now),
                    confirmation_token: Some(format!("enc-confirm-{email}")),
                    confirmation_sent_at: Some(now),
                    unconfirmed_email: None,
                    failed_attempts: 0,
                    sign_in_count: 0,
                    current_sign_in_ip: None,
                    last_sign_in_ip: None,
                    unlock_token: Some(format!("enc-unlock-{email}")),
                    locked_at: None,
                    created_at: now,
                    updated_at: now,
                }
            }
        }

        impl ContractModel for $name {
            type New = Self;

            fn sample_new(email: &str, now: NaiveDateTime) -> Self {
                Self::sample(email, now)
            }

            fn contract_email(&self) -> &str {
                &self.email
            }

            fn contract_encrypted_password(&self) -> &str {
                &self.encrypted_password
            }

            fn contract_reset_password_token(&self) -> Option<&str> {
                self.reset_password_token.as_deref()
            }

            fn contract_reset_password_sent_at(&self) -> Option<NaiveDateTime> {
                self.reset_password_sent_at
            }

            fn contract_confirmation_token(&self) -> Option<&str> {
                self.confirmation_token.as_deref()
            }

            fn contract_confirmation_sent_at(&self) -> Option<NaiveDateTime> {
                self.confirmation_sent_at
            }

            fn contract_unconfirmed_email(&self) -> Option<&str> {
                self.unconfirmed_email.as_deref()
            }

            fn contract_failed_attempts(&self) -> i64 {
                self.failed_attempts
            }

            fn contract_sign_in_count(&self) -> i64 {
                self.sign_in_count
            }

            fn contract_current_sign_in_ip(&self) -> Option<&str> {
                self.current_sign_in_ip.as_deref()
            }

            fn contract_last_sign_in_ip(&self) -> Option<&str> {
                self.last_sign_in_ip.as_deref()
            }

            fn contract_unlock_token(&self) -> Option<&str> {
                self.unlock_token.as_deref()
            }

            fn contract_locked_at(&self) -> Option<NaiveDateTime> {
                self.locked_at
            }

            fn contract_created_at(&self) -> NaiveDateTime {
                self.created_at
            }

            fn contract_updated_at(&self) -> NaiveDateTime {
                self.updated_at
            }
        }
    };
}

oracle_fixture!(IntOracleUser, i64, 0);
oracle_fixture!(
    UuidOracleUser,
    String,
    uuid::Uuid::new_v4().hyphenated().to_string()
);

/// Oracle leg factory: a fresh empty store per case; the first created
/// row lands under sequential integer key 1.
struct OracleFactory<M> {
    _model: PhantomData<M>,
}

impl<M> OracleFactory<M> {
    fn new() -> Self {
        Self {
            _model: PhantomData,
        }
    }
}

impl<M> ContractFactory for OracleFactory<M>
where
    M: ContractModel<New = M> + Clone + Serialize + DeserializeOwned,
{
    type Model = M;
    type Adapter = MemoryAdapter<M>;

    async fn adapter(&self) -> MemoryAdapter<M> {
        std::future::ready(MemoryAdapter::new()).await
    }

    fn key_of_created(&self, _row: &M) -> DeviseKey {
        // A fresh oracle store assigns sequential integer keys from 1; a
        // case's tracked row is always the first create in its store.
        DeviseKey::from_i64(1)
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_i64(999_999)
    }
}

#[rstest]
#[case::integer_pk(OracleFactory::<IntOracleUser>::new())]
#[case::uuid_pk(OracleFactory::<UuidOracleUser>::new())]
#[tokio::test]
async fn oracle_contract_suite<M>(#[case] factory: OracleFactory<M>)
where
    M: ContractModel<New = M> + Clone + Serialize + DeserializeOwned,
{
    run_contract_suite(&factory).await;
}
