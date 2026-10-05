use devise_rust_diesel::pool::sqlite_memory_pool;
use devise_rust_diesel::DieselOrmAdapter;
use devise_rust::adapter::{OrmAdapter, DeviseKey, Value, Conditions};
use diesel::ExpressionMethods;
use diesel_async::SimpleAsyncConnection;

diesel::table! {
    users (id) {
        id -> BigInt,
        email -> Text,
        encrypted_password -> Text,
    }
}

#[derive(Debug, Clone, PartialEq, diesel::Queryable, diesel::Selectable, diesel::Insertable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct User {
    pub id: i64,
    pub email: String,
    pub encrypted_password: String,
}

#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct NewUser {
    pub email: String,
    pub encrypted_password: String,
}

use devise_rust_diesel::{BoxPred, DieselModel, DieselPredicates};
use diesel::sql_types::Nullable;
use diesel::sql_types::Bool;

impl DieselModel for User {
    type Table = users::table;
    type New = NewUser;
    type Changeset = (); // not used
    fn table() -> Self::Table { users::table }
    fn key_of(model: &Self) -> DeviseKey { DeviseKey::from_i64(model.id) }
    fn changeset_from_map(_fields: &std::collections::HashMap<String, Value>) -> Result<Self::Changeset, devise_rust::adapter::OrmError> {
        Err(devise_rust::adapter::OrmError::NotFound)
    }
}

impl DieselPredicates<diesel::sqlite::Sqlite> for User {
    fn pk_predicate(key: &DeviseKey) -> Result<BoxPred<Self::Table, diesel::sqlite::Sqlite>, devise_rust::adapter::OrmError> {
        match key {
            DeviseKey::Integer(id) => Ok(Box::new(users::id.eq(*id))),
            _ => Err(devise_rust::adapter::OrmError::InvalidKey("integer pk".into())),
        }
    }
    fn finder_predicate(column: &str, value: &Value) -> Option<BoxPred<Self::Table, diesel::sqlite::Sqlite>> {
        if column != "email" { return None; }
        let Value::String(s) = value else { return None; }
        Some(Box::new(users::email.eq(s.clone())))
    }
}

#[tokio::test]
async fn test_basic_create_and_get() {
    let pool = sqlite_memory_pool().expect("pool");
    let mut conn = pool.get().await.expect("conn");
    conn.batch_execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, encrypted_password TEXT NOT NULL);").await.expect("ddl");
    drop(conn);
    
    let adapter = DieselOrmAdapter::new(pool);
    let created = adapter.create(NewUser { email: "test@example.com".into(), encrypted_password: "hash".into() }).await.expect("create");
    assert_eq!(created.email, "test@example.com");
    
    let found = adapter.get(&DeviseKey::from_i64(1)).await.expect("get").expect("found");
    assert_eq!(found.email, "test@example.com");
    println!("Basic test passed!");
}
