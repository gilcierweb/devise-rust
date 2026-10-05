//! Postgres contract suite entry (e2e-pg feature): invokes the exact same
//! contract steps as the sqlite leg against a testcontainers Postgres
//! instance with native UUID + INET columns from emitted DDL.

#![cfg(feature = "e2e-pg")]

#[path = "common/mod.rs"]
mod common;

#[path = "models.rs"]
mod models;

use std::collections::HashMap;

use common::pg::{bootstrap_pg, PgRig};
use devise_rust::adapter::{ChangeSet, Conditions, DeviseKey, OrmAdapter, OrmError, Value};
use models::{FixtureUser, NewFixtureUser};

const TRACER_EMAIL: &str = "tracer@example.com";

/// `create` plus the `insert` alias; asserts every devise column round-trips
/// (fixture parity with the emitted DDL). Returns the first row's key.
async fn create_and_alias_step(rig: &PgRig) -> DeviseKey {
    let now = common::sample_time();
    let created: FixtureUser = rig
        .users
        .create(NewFixtureUser::sample(TRACER_EMAIL, now))
        .await
        .expect("create stores the row");
    assert_eq!(created.email, TRACER_EMAIL);
    assert_eq!(
        created.reset_password_token.as_deref(),
        Some("enc-reset-tracer@example.com")
    );
    assert_eq!(created.reset_password_sent_at, Some(now));
    assert_eq!(created.sign_in_count, 0);
    assert_eq!(
        created.confirmation_token.as_deref(),
        Some("enc-confirm-tracer@example.com")
    );
    assert_eq!(created.confirmation_sent_at, Some(now));
    assert_eq!(created.unconfirmed_email, None);
    assert_eq!(created.failed_attempts, 0);
    assert_eq!(
        created.unlock_token.as_deref(),
        Some("enc-unlock-tracer@example.com")
    );
    assert_eq!(created.locked_at, None);
    assert_eq!(created.created_at, now);
    assert_eq!(created.updated_at, now);

    let second: FixtureUser = rig
        .users
        .insert(NewFixtureUser::sample("second@example.com", now))
        .await
        .expect("insert alias stores the row");
    assert_eq!(second.id, created.id + 1);

    DeviseKey::from_i64(created.id)
}

/// `get`/`get_strict` hit and miss legs.
async fn get_steps(rig: &PgRig, key: &DeviseKey) {
    let found = rig.users.get(key).await.expect("get works");
    assert_eq!(found.as_ref().map(|u| u.email.as_str()), Some(TRACER_EMAIL));

    let strict = rig.users.get_strict(key).await.expect("get_strict hits");
    assert_eq!(strict, found.expect("get hit matches strict hit"));

    let missing = DeviseKey::from_i64(999_999);
    assert_eq!(rig.users.get(&missing).await.expect("get miss works"), None);
    assert!(
        matches!(
            rig.users.get_strict(&missing).await.unwrap_err(),
            OrmError::NotFound
        ),
        "get_strict must refuse absence"
    );
}

/// `find_first` by authentication key and by token digest, plus the strict miss.
async fn finder_steps(rig: &PgRig) {
    let mut by_email = Conditions::new();
    by_email.insert("email", TRACER_EMAIL);
    let found = rig
        .users
        .find_first(&by_email)
        .await
        .expect("email finder works");
    assert_eq!(found.as_ref().map(|u| u.email.as_str()), Some(TRACER_EMAIL));
    assert_eq!(
        rig.users
            .find_first_strict(&by_email)
            .await
            .expect("strict email finder hits"),
        found.expect("strict hit matches finder hit")
    );

    let mut by_token = Conditions::new();
    by_token.insert("reset_password_token", "enc-reset-tracer@example.com");
    assert_eq!(
        rig.users
            .find_first(&by_token)
            .await
            .expect("token finder works")
            .map(|u| u.email),
        Some(TRACER_EMAIL.to_owned()),
        "token-digest lookup resolves the row"
    );

    let mut missing = Conditions::new();
    missing.insert("email", "nobody@example.com");
    assert_eq!(
        rig.users.find_first(&missing).await.expect("miss works"),
        None
    );
    assert!(
        matches!(
            rig.users.find_first_strict(&missing).await.unwrap_err(),
            OrmError::NotFound
        ),
        "find_first_strict must refuse absence"
    );
}

/// Diff-scoped `update` (untouched columns preserved) and tristate `NULL`
/// clearing through the same verb.
async fn update_steps(rig: &PgRig, key: &DeviseKey) {
    let before = rig.users.get_strict(key).await.expect("row exists");
    let token = before
        .reset_password_token
        .clone()
        .expect("sample sets a token");

    let changes = ChangeSet::new(
        HashMap::from([
            ("email".to_owned(), Value::from(TRACER_EMAIL)),
            (
                "reset_password_token".to_owned(),
                Value::from(token.as_str()),
            ),
        ]),
        HashMap::from([
            ("email".to_owned(), Value::from("renamed@example.com")),
            (
                "reset_password_token".to_owned(),
                Value::from(token.as_str()),
            ),
        ]),
    );
    let updated = rig.users.update(key, &changes).await.expect("update works");
    assert_eq!(updated.email, "renamed@example.com");
    assert_eq!(
        updated.reset_password_token.as_deref(),
        Some(token.as_str()),
        "untouched token column is preserved by a diff-scoped update"
    );

    let clearing = ChangeSet::new(
        HashMap::from([(
            "reset_password_token".to_owned(),
            Value::from(token.as_str()),
        )]),
        HashMap::from([("reset_password_token".to_owned(), Value::Null)]),
    );
    let cleared = rig
        .users
        .update(key, &clearing)
        .await
        .expect("clearing works");
    assert_eq!(cleared.reset_password_token, None);
    let reread = rig.users.get_strict(key).await.expect("row exists");
    assert_eq!(
        reread.reset_password_token, None,
        "Value::Null through update SETs NULL (devise clearing)"
    );
}

/// `update_columns`: force-writes an unchanged value (#5783) without moving
/// `updated_at`, writes it when named, and NULLs a named token column.
async fn update_columns_steps(rig: &PgRig, key: &DeviseKey) {
    let before = rig.users.get_strict(key).await.expect("row exists");

    let force = HashMap::from([("email".to_owned(), Value::from("renamed@example.com"))]);
    let forced = rig
        .users
        .update_columns(key, &force)
        .await
        .expect("force-write works");
    assert_eq!(forced.email, "renamed@example.com");
    assert_eq!(
        forced.updated_at, before.updated_at,
        "update_columns leaves updated_at alone unless named"
    );

    let stamp = common::later_time();
    let stamped = rig
        .users
        .update_columns(
            key,
            &HashMap::from([("updated_at".to_owned(), Value::from("2026-06-07 08:09:10"))]),
        )
        .await
        .expect("naming updated_at writes it");
    assert_eq!(stamped.updated_at, stamp);

    let nulling = HashMap::from([("unlock_token".to_owned(), Value::Null)]);
    let nulled = rig
        .users
        .update_columns(key, &nulling)
        .await
        .expect("named NULL writes NULL");
    assert_eq!(nulled.unlock_token, None);
    let reread = rig.users.get_strict(key).await.expect("row exists");
    assert_eq!(reread.unlock_token, None);
}

/// Uniqueness discrimination with a value-free Display, the
/// `column_value_unused` probe across a create, and `delete`.
async fn uniqueness_and_delete_steps(rig: &PgRig, key: &DeviseKey) {
    assert!(
        rig.users
            .column_value_unused("email", &Value::from("probe@example.com"))
            .await
            .expect("probe works"),
        "unused value reports true"
    );
    rig.users
        .create(NewFixtureUser::sample("probe@example.com", common::sample_time()))
        .await
        .expect("probe row stores");
    assert!(
        !rig.users
            .column_value_unused("email", &Value::from("probe@example.com"))
            .await
            .expect("probe works"),
        "taken value reports false"
    );

    let dupe = rig
        .users
        .create(NewFixtureUser::sample("probe@example.com", common::sample_time()))
        .await
        .unwrap_err();
    assert!(
        matches!(dupe, OrmError::UniqueViolation { .. }),
        "duplicate email must discriminate UniqueViolation, got {dupe:?}"
    );
    let rendered = dupe.to_string();
    assert!(
        !rendered.contains("probe@example.com"),
        "error Display must not leak the value: {rendered}"
    );

    rig.users.delete(key).await.expect("delete works");
    assert_eq!(
        rig.users.get(key).await.expect("get works"),
        None,
        "deleted row reads back None"
    );
    rig.users
        .delete(key)
        .await
        .expect("deleting a missing row is a no-op");
}

#[tokio::test]
async fn pg_full_op_roundtrip_integer_pk() {
    let rig = bootstrap_pg().await;
    let key = create_and_alias_step(&rig).await;
    get_steps(&rig, &key).await;
    finder_steps(&rig).await;
    update_steps(&rig, &key).await;
    update_columns_steps(&rig, &key).await;
    uniqueness_and_delete_steps(&rig, &key).await;
}