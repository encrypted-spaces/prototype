use crate::{access_control::AuthContext, error::Result, query::Query, schema::Schema};
use serde::Deserialize;

#[async_trait::async_trait]
pub trait Storage: Send + Sync {
    async fn create_table(&self, schema: &Schema) -> Result<()>;

    /// Execute UPDATE or DELETE query with access control enforcement
    async fn update_or_delete(&self, query: Query, auth_context: &AuthContext) -> Result<usize>;

    /// Execute INSERT query with access control enforcement, returning the inserted ID
    async fn insert(&self, query: Query, auth_context: &AuthContext) -> Result<i64>;

    /// Execute SELECT query, returning a single row.
    async fn select_one<T>(&self, query: Query) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>;

    /// Execute SELECT query, returning multiple rows.
    async fn select_all<T>(&self, query: Query) -> Result<Vec<T>>
    where
        T: for<'de> Deserialize<'de>;
}
