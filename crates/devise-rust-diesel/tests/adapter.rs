//! SQLite contract suite entry: the end-to-end tracer plus (from Task 2)
//! the shared contract cases. Thin `#[tokio::test]` wrappers here invoke
//! rig-backed steps; parameterized behavior groups live in `common/contract`.

#[path = "common/mod.rs"]
mod common;

#[path = "models.rs"]
mod models;

use std::collections::HashMap;

use common::{SqliteRig, bootstrap_sqlite_memory, later_time, sample_time};
use devise_rust::adapter::{ChangeSet, Conditions, DeviseKey, OrmAdapter, OrmError, Value};
use models::{FixtureUser, NewFixtureUser};

const TRACER_EMAIL: &str = "tracer@example.com";

/// `create` plus the `insert` alias; asserts every devise column round-trips
/// (fixture parity with the emitted DDL). Returns the first row's key.
async fn create_and_alias_step(rig: &SqliteRig) -> DeviseKey {
    let now = sample_time();
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
async fn get_steps(rig: &SqliteRig, key: &DeviseKey) {
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
async fn finder_steps(rig: &SqliteRig) {
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
async fn update_steps(rig: &SqliteRig, key: &DeviseKey) {
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
async fn update_columns_steps(rig: &SqliteRig, key: &DeviseKey) {
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

    let stamp = later_time();
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
async fn uniqueness_and_delete_steps(rig: &SqliteRig, key: &DeviseKey) {
    assert!(
        rig.users
            .column_value_unused("email", &Value::from("probe@example.com"))
            .await
            .expect("probe works"),
        "unused value reports true"
    );
    rig.users
        .create(NewFixtureUser::sample("probe@example.com", sample_time()))
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
        .create(NewFixtureUser::sample("probe@example.com", sample_time()))
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
async fn sqlite_full_op_roundtrip() {
    let rig = bootstrap_sqlite_memory().await;
    let key = create_and_alias_step(&rig).await;
    get_steps(&rig, &key).await;
    finder_steps(&rig).await;
    update_steps(&rig, &key).await;
    update_columns_steps(&rig, &key).await;
    uniqueness_and_delete_steps(&rig, &key).await;
}

/// D-11 tracer slice: two sequential `increment_counter` calls raise the
/// stored `failed_attempts` by exactly 2 on the live sqlite adapter - the
/// single-statement `SET col = col + 1` plus re-read, end to end.
#[tokio::test]
async fn sqlite_counter_two_increments_raise_by_exactly_two() {
    let rig = bootstrap_sqlite_memory().await;
    let now = sample_time();
    let created: FixtureUser = rig
        .users
        .create(NewFixtureUser::sample("counter@example.com", now))
        .await
        .expect("create stores the row");
    assert_eq!(created.failed_attempts, 0);
    let key = DeviseKey::from_i64(created.id);

    let first = rig
        .users
        .increment_counter(&key, "failed_attempts")
        .await
        .expect("first increment works");
    assert_eq!(first.failed_attempts, 1);
    let second = rig
        .users
        .increment_counter(&key, "failed_attempts")
        .await
        .expect("second increment works");
    assert_eq!(
        second.failed_attempts, 2,
        "two sequential increments raise the stored value by exactly 2"
    );

    // The returned row is the stored row (Devise's increment + reload).
    let reread = rig.users.get(&key).await.expect("get works");
    assert_eq!(reread.expect("row exists").failed_attempts, 2);
}

#[tokio::test]
async fn test_pool_basic() {
    use devise_rust_diesel::pool::sqlite_memory_pool;
    use diesel_async::SimpleAsyncConnection;

    let pool = sqlite_memory_pool().expect("pool");
    let mut conn = pool.get().await.expect("conn");
    conn.batch_execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, encrypted_password TEXT NOT NULL);").await.expect("ddl");
    drop(conn);
    println!("Pool basic test passed!");
}

#[tokio::test]
async fn test_adapter_basic() {
    use common::bootstrap_sqlite_memory;
    use common::sample_time;
    use devise_rust::adapter::{DeviseKey, OrmAdapter};
    use models::NewFixtureUser;

    let rig = bootstrap_sqlite_memory().await;
    let now = sample_time();
    let created = rig
        .users
        .create(NewFixtureUser::sample("test@example.com", now))
        .await
        .expect("create");
    assert_eq!(created.email, "test@example.com");

    let found = rig
        .users
        .get(&DeviseKey::from_i64(created.id))
        .await
        .expect("get")
        .expect("found");
    assert_eq!(found.email, "test@example.com");
    println!("Adapter basic test passed!");
}

#[tokio::test]
async fn test_adapter_update() {
    use common::bootstrap_sqlite_memory;
    use common::sample_time;
    use devise_rust::adapter::{ChangeSet, DeviseKey, OrmAdapter, Value};
    use models::NewFixtureUser;
    use std::collections::HashMap;

    let rig = bootstrap_sqlite_memory().await;
    let now = sample_time();
    let created = rig
        .users
        .create(NewFixtureUser::sample("test@example.com", now))
        .await
        .expect("create");

    let changes = ChangeSet::new(
        HashMap::from([("email".to_owned(), Value::from("test@example.com"))]),
        HashMap::from([("email".to_owned(), Value::from("updated@example.com"))]),
    );
    let updated = rig
        .users
        .update(&DeviseKey::from_i64(created.id), &changes)
        .await
        .expect("update");
    assert_eq!(updated.email, "updated@example.com");
    println!("Adapter update test passed!");
}

#[tokio::test]
async fn test_adapter_update_columns() {
    use common::bootstrap_sqlite_memory;
    use common::sample_time;
    use devise_rust::adapter::{DeviseKey, OrmAdapter, Value};
    use models::NewFixtureUser;
    use std::collections::HashMap;

    let rig = bootstrap_sqlite_memory().await;
    let now = sample_time();
    let created = rig
        .users
        .create(NewFixtureUser::sample("test@example.com", now))
        .await
        .expect("create");

    let fields = HashMap::from([("email".to_owned(), Value::from("updated2@example.com"))]);
    let updated = rig
        .users
        .update_columns(&DeviseKey::from_i64(created.id), &fields)
        .await
        .expect("update_columns");
    assert_eq!(updated.email, "updated2@example.com");
    println!("Adapter update_columns test passed!");
}
