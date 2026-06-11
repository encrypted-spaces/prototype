use crate::Space;
use base64::Engine;
use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_backend::internal_schemas::{lists_schema, LISTS_TABLE_NAME};
use encrypted_spaces_backend::query::QueryParam;
use encrypted_spaces_changelog_core::changelog::OpType;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::OnceCell;

// ---------------------------------------------------------------------------
// Thread-local for hydration during select deserialization
// ---------------------------------------------------------------------------

thread_local! {
    static LIST_SPACE_CTX: RefCell<Option<Arc<Space>>> = const { RefCell::new(None) };
}

fn set_list_space_ctx(ctx: Arc<Space>) {
    LIST_SPACE_CTX.with(|cell| {
        *cell.borrow_mut() = Some(ctx);
    });
}

fn clear_list_space_ctx() {
    LIST_SPACE_CTX.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Run `f` with the thread-local space context set for List/TextArea
/// deserialization. A Drop guard ensures cleanup even on panic.
pub(crate) fn with_list_space_ctx<F, R>(ctx: Arc<Space>, f: F) -> R
where
    F: FnOnce() -> R,
{
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            clear_list_space_ctx();
        }
    }
    set_list_space_ctx(ctx);
    let _guard = Guard;
    f()
}

pub(crate) fn take_list_space_ctx() -> Option<Arc<Space>> {
    LIST_SPACE_CTX.with(|cell| cell.borrow().clone())
}

// ---------------------------------------------------------------------------
// ListContext — address + space reference for a hydrated list
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ListContext {
    pub(crate) space: Arc<Space>,
    pub(crate) table: String,
    pub(crate) row_id: i64,
    pub(crate) column: String,
    resolved_list_number: Arc<OnceCell<i64>>,
}

impl ListContext {
    fn new(space: Arc<Space>, table: String, row_id: i64, column: String) -> Self {
        Self {
            space,
            table,
            row_id,
            column,
            resolved_list_number: Arc::new(OnceCell::new()),
        }
    }

    pub(crate) fn with_known_list_number(
        space: Arc<Space>,
        table: String,
        row_id: i64,
        column: String,
        list_number: i64,
    ) -> Self {
        let cell = OnceCell::new();
        cell.set(list_number).ok();
        Self {
            space,
            table,
            row_id,
            column,
            resolved_list_number: Arc::new(cell),
        }
    }

    /// Resolve the list_number by querying the parent row if not yet known.
    async fn resolve_list_number(&self) -> Result<i64> {
        self.resolved_list_number
            .get_or_try_init(|| async {
                #[derive(Deserialize)]
                struct ParentRow {
                    #[allow(dead_code)]
                    id: Option<i64>,
                    #[serde(flatten)]
                    extra: HashMap<String, serde_json::Value>,
                }

                let rows: Vec<ParentRow> = self
                    .space
                    .table::<ParentRow>(&self.table)
                    .select()
                    .where_eq("id", self.row_id)
                    .all()
                    .await?;

                let row = rows.into_iter().next().ok_or(SdkError::NotFound)?;

                let val = row.extra.get(&self.column).ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "Column '{}' not found on parent row",
                        self.column
                    ))
                })?;

                // Handle both plain integer and enriched hydration object
                let ln = if let Some(n) = val.as_i64() {
                    n
                } else if let Some(obj) = val.as_object() {
                    obj.get("_li").and_then(|v| v.as_i64()).ok_or_else(|| {
                        SdkError::ValidationError(format!(
                            "List column '{}' has unexpected format",
                            self.column
                        ))
                    })?
                } else {
                    return Err(SdkError::ValidationError(format!(
                        "List column '{}' is not an integer or enriched object",
                        self.column
                    )));
                };

                if ln <= 0 {
                    return Err(SdkError::ValidationError(
                        "List column has not been allocated (list_number <= 0)".into(),
                    ));
                }

                Ok(ln)
            })
            .await
            .copied()
    }
}

// ---------------------------------------------------------------------------
// ListEntry<T> — a single item from a list
// ---------------------------------------------------------------------------

/// A single list item with its key, position, and deserialized value.
pub struct ListEntry<T> {
    pub key: Vec<u8>,
    pub position: u64,
    pub value: T,
}

// ---------------------------------------------------------------------------
// List<T> — unified field type + operational API
// ---------------------------------------------------------------------------

/// A list reference for `ColumnType::List` columns.
///
/// Use this type in your row structs. When deserialized via a table select,
/// the list is automatically hydrated with the space reference and can be
/// used for operations immediately:
///
/// ```ignore
/// #[derive(Serialize, Deserialize)]
/// struct Document {
///     id: Option<i64>,
///     title: String,
///     comments: List<Comment>,
/// }
///
/// let doc: Document = table.select().first().await?.unwrap();
/// doc.comments.append(&Comment { text: "hi".into() }).await?;
/// ```
pub struct List<T = ()> {
    pub(crate) list_number: i64,
    pub(crate) ctx: Option<ListContext>,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T> std::fmt::Debug for List<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("List")
            .field("list_number", &self.list_number)
            .field("hydrated", &self.ctx.is_some())
            .finish()
    }
}

impl<T> Clone for List<T> {
    fn clone(&self) -> Self {
        Self {
            list_number: self.list_number,
            ctx: self.ctx.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T> List<T> {
    /// Create an empty list reference (for use when inserting rows).
    ///
    /// The server will auto-allocate a `list_number` when the row is inserted.
    pub fn empty() -> Self {
        Self {
            list_number: 0,
            ctx: None,
            _phantom: PhantomData,
        }
    }

    /// Get the list_number (allocated by the server on parent row insert).
    /// Returns the resolved value from the OnceCell if available (for manual
    /// handles after lazy resolution), otherwise returns the struct field.
    /// Returns 0 for unallocated lists.
    pub fn list_number(&self) -> i64 {
        if let Some(ctx) = &self.ctx {
            if let Some(&resolved) = ctx.resolved_list_number.get() {
                return resolved;
            }
        }
        self.list_number
    }

    /// Returns true if this list has been hydrated with a space context.
    pub fn is_hydrated(&self) -> bool {
        self.ctx.is_some()
    }

    /// Hydrate this list with a space context. Called internally during select
    /// deserialization, or can be called manually via `Space::list()`.
    pub(crate) fn hydrate(
        &mut self,
        space: Arc<Space>,
        table: String,
        row_id: i64,
        column: String,
    ) {
        self.ctx = Some(ListContext::new(space, table, row_id, column));
    }

    fn ctx(&self) -> Result<&ListContext> {
        self.ctx.as_ref().ok_or_else(|| {
            SdkError::ValidationError(
                "List is not hydrated — select it from a table or use space.list()".into(),
            )
        })
    }
}

// -- Serialize / Deserialize ------------------------------------------------

impl<T> Serialize for List<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.list_number)
    }
}

impl<'de, T> Deserialize<'de> for List<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;

        match value {
            serde_json::Value::Number(ref n) => {
                let list_number = n
                    .as_i64()
                    .ok_or_else(|| serde::de::Error::custom("expected integer for List"))?;
                Ok(List {
                    list_number,
                    ctx: None,
                    _phantom: PhantomData,
                })
            }
            serde_json::Value::Object(ref map) => {
                let list_number = map
                    .get("_li")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| serde::de::Error::custom("missing _li in list object"))?;
                let table = map
                    .get("_lt")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("missing _lt in list object"))?
                    .to_string();
                let row_id = map
                    .get("_lr")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| serde::de::Error::custom("missing _lr in list object"))?;
                let column = map
                    .get("_lc")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("missing _lc in list object"))?
                    .to_string();

                let ctx = take_list_space_ctx().map(|space| {
                    ListContext::with_known_list_number(space, table, row_id, column, list_number)
                });

                Ok(List {
                    list_number,
                    ctx,
                    _phantom: PhantomData,
                })
            }
            _ => Err(serde::de::Error::custom(
                "expected integer or object for List",
            )),
        }
    }
}

// -- Internal helpers -------------------------------------------------------

/// Validate that a list item key is exactly 8 bytes and encodes a positive i64.
fn validate_list_item_key(key: &[u8]) -> Result<i64> {
    if key.len() != 8 {
        return Err(SdkError::ValidationError(
            "key must be exactly 8 bytes".into(),
        ));
    }
    let id = i64::from_be_bytes(key.try_into().unwrap());
    if id <= 0 {
        return Err(SdkError::ValidationError(
            "target id must be positive".into(),
        ));
    }
    Ok(id)
}

// -- Operations -------------------------------------------------------------

impl<T: Serialize + DeserializeOwned + Send + Sync> List<T> {
    /// Get a single item by position (zero-indexed).
    pub async fn get(&self, position: u64) -> Result<ListEntry<T>> {
        let items = self.get_all().await?;
        let len = items.len();
        items.into_iter().nth(position as usize).ok_or_else(|| {
            SdkError::ValidationError(format!(
                "Position {position} out of range (list has {len} items)",
            ))
        })
    }

    /// Get verified list length.
    pub async fn len(&self) -> Result<u64> {
        let items = self.get_all().await?;
        Ok(items.len() as u64)
    }

    /// Get all items in order.
    pub async fn get_all(&self) -> Result<Vec<ListEntry<T>>> {
        let ctx = self.ctx()?;
        let list_number = ctx.resolve_list_number().await?;

        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct ListRow {
            id: Option<i64>,
            list_number: Option<i64>,
            prev_id: Option<i64>,
            next_id: Option<i64>,
            value: Option<String>,
        }

        let rows: Vec<ListRow> = ctx
            .space
            .table::<ListRow>("_lists")
            .select()
            .where_eq("list_number", list_number)
            .all()
            .await?;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // Validate required fields and build map from id -> row
        let mut by_id: HashMap<i64, &ListRow> = HashMap::new();
        let mut head_id: Option<i64> = None;
        let mut head_count = 0;

        for row in &rows {
            let id = row
                .id
                .ok_or_else(|| SdkError::ValidationError("List row missing id column".into()))?;
            if id <= 0 {
                return Err(SdkError::ValidationError(format!(
                    "List row has invalid id {id} (must be positive)"
                )));
            }
            if row.list_number != Some(list_number) {
                return Err(SdkError::ValidationError(format!(
                    "List row {id} has list_number {:?}, expected {list_number}",
                    row.list_number
                )));
            }
            let prev = row.prev_id.ok_or_else(|| {
                SdkError::ValidationError(format!("List row {id} missing prev_id column"))
            })?;
            if prev < 0 {
                return Err(SdkError::ValidationError(format!(
                    "List row {id} has negative prev_id {prev}"
                )));
            }
            let next = row.next_id.ok_or_else(|| {
                SdkError::ValidationError(format!("List row {id} missing next_id column"))
            })?;
            if next < 0 {
                return Err(SdkError::ValidationError(format!(
                    "List row {id} has negative next_id {next}"
                )));
            }
            if row.value.is_none() {
                return Err(SdkError::ValidationError(format!(
                    "List row {id} missing value column"
                )));
            }

            by_id.insert(id, row);
            if prev == 0 {
                head_count += 1;
                head_id = Some(id);
            }
        }

        if head_count == 0 {
            return Err(SdkError::ValidationError(
                "List chain integrity error: no head found (no row with prev_id == 0)".into(),
            ));
        }
        if head_count > 1 {
            return Err(SdkError::ValidationError(
                "List chain integrity error: multiple heads found".into(),
            ));
        }

        let head_id = head_id.unwrap();
        let row_count = rows.len();
        let mut result = Vec::with_capacity(row_count);
        let mut current_id = head_id;
        let mut expected_prev_id: i64 = 0; // head's prev must be 0
        let mut visited_count: usize = 0;

        loop {
            // Cycle detection: if we've visited more nodes than exist, there's a cycle
            if visited_count >= row_count {
                return Err(SdkError::ValidationError(
                    "List chain integrity error: cycle detected".into(),
                ));
            }

            let row = by_id.get(&current_id).ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "List chain integrity error: row {current_id} not found in fetched set"
                ))
            })?;

            let prev = row.prev_id.unwrap(); // validated above
            let next = row.next_id.unwrap(); // validated above

            // Validate that this row's prev_id matches what we expect from the walk
            if prev != expected_prev_id {
                return Err(SdkError::ValidationError(format!(
                    "List chain integrity error: row {} has prev_id={} but expected {}",
                    current_id, prev, expected_prev_id
                )));
            }

            // The standard decrypt_table_rows path already decrypted the
            // value column: `row.value` is base64(plaintext_bytes).
            let value_b64 = row.value.as_deref().unwrap(); // validated above
            let plaintext = base64::engine::general_purpose::STANDARD
                .decode(value_b64)
                .map_err(|e| SdkError::SerializationError(format!("base64 decode failed: {e}")))?;
            let value: T = serde_json::from_slice(&plaintext).map_err(|e| {
                SdkError::SerializationError(format!("Failed to deserialize list value: {e}"))
            })?;

            let key = current_id.to_be_bytes().to_vec();
            result.push(ListEntry {
                key,
                position: visited_count as u64,
                value,
            });

            visited_count += 1;
            if next == 0 {
                break;
            }
            expected_prev_id = current_id;
            current_id = next;
        }

        // Verify all rows were visited (no disconnected nodes)
        if visited_count != row_count {
            return Err(SdkError::ValidationError(format!(
                "List chain integrity error: visited {} rows but fetched {}",
                visited_count, row_count
            )));
        }

        Ok(result)
    }

    /// Append an item to the end of the list. Returns the new item's key.
    pub async fn append(&self, value: &T) -> Result<Vec<u8>> {
        let ctx = self.ctx()?;
        let list_number = ctx.resolve_list_number().await?;
        let plaintext =
            serde_json::to_vec(value).map_err(|e| SdkError::SerializationError(e.to_string()))?;

        let id = crate::table::InsertBuilder::<serde_json::Value>::from_fields(
            LISTS_TABLE_NAME.to_string(),
            Arc::clone(&ctx.space),
            vec![
                ("list_number".to_string(), QueryParam::Integer(list_number)),
                ("value".to_string(), QueryParam::Blob(plaintext)),
            ],
        )
        .execute_as(Some(OpType::ListAppend))
        .await?;

        Ok(id.to_be_bytes().to_vec())
    }

    /// Prepend an item to the beginning of the list. Returns the new item's key.
    pub async fn prepend(&self, value: &T) -> Result<Vec<u8>> {
        self.insert_after_key(&[0u8; 8], value).await
    }

    /// Insert an item immediately after the existing item whose key is
    /// `target_key` (the *predecessor*). Returns the new item's key.
    ///
    /// Use `&[0u8; 8]` (the sentinel) to insert at the beginning (prepend).
    pub async fn insert_after_key(&self, target_key: &[u8], value: &T) -> Result<Vec<u8>> {
        let ctx = self.ctx()?;
        let list_number = ctx.resolve_list_number().await?;

        if target_key.len() != 8 {
            return Err(SdkError::ValidationError(
                "insert_after_key: target_key must be exactly 8 bytes".into(),
            ));
        }
        let prev_id = i64::from_be_bytes(target_key.try_into().unwrap());
        if prev_id < 0 {
            return Err(SdkError::ValidationError(
                "insert_after_key: target_key must encode a non-negative i64".into(),
            ));
        }

        let plaintext =
            serde_json::to_vec(value).map_err(|e| SdkError::SerializationError(e.to_string()))?;

        let id = crate::table::InsertBuilder::<serde_json::Value>::from_fields(
            LISTS_TABLE_NAME.to_string(),
            Arc::clone(&ctx.space),
            vec![
                ("list_number".to_string(), QueryParam::Integer(list_number)),
                ("prev_id".to_string(), QueryParam::Integer(prev_id)),
                ("value".to_string(), QueryParam::Blob(plaintext)),
            ],
        )
        .execute_as(Some(OpType::ListInsert))
        .await?;

        Ok(id.to_be_bytes().to_vec())
    }

    /// Update an existing item by key.
    pub async fn update_by_key(&self, key: &[u8], value: &T) -> Result<()> {
        let ctx = self.ctx()?;
        let _list_number = ctx.resolve_list_number().await?;
        let target_id = validate_list_item_key(key)?;

        let plaintext =
            serde_json::to_vec(value).map_err(|e| SdkError::SerializationError(e.to_string()))?;

        ctx.space
            .table::<serde_json::Value>(LISTS_TABLE_NAME)
            .update()
            .where_eq("id", target_id)
            .set("value", QueryParam::Blob(plaintext))
            .execute_as(Some(OpType::ListUpdate))
            .await?;

        Ok(())
    }

    /// Delete an item by key.
    pub async fn delete_by_key(&self, key: &[u8]) -> Result<()> {
        let ctx = self.ctx()?;
        let _list_number = ctx.resolve_list_number().await?;
        let target_id = validate_list_item_key(key)?;

        ctx.space
            .table::<serde_json::Value>(LISTS_TABLE_NAME)
            .delete()
            .where_eq("id", target_id)
            .execute_as(Some(OpType::ListDelete))
            .await?;

        Ok(())
    }
}

impl Space {
    pub(crate) fn initialize_lists(&self) {
        self.register_table_schema(lists_schema());
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod tests {
    use super::*;
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use crate::Space;
    use encrypted_spaces_backend::error::{Result, SdkError};
    use encrypted_spaces_backend_server::SpaceState;
    use encrypted_spaces_ffproof::EXTEND_FF_ID;
    use serde::{Deserialize, Serialize};

    const TABLE: &str = "test_table";
    const COL: &str = "items";

    #[derive(Debug, Serialize, Deserialize)]
    struct Row {
        id: Option<i64>,
        name: String,
        items: List<String>,
    }

    async fn create_space_with_list() -> Result<(Space, i64)> {
        let schema = SchemaBuilder::new(TABLE)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .column(COL, ColumnType::List)?
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::for_testing(vec![schema], root);
        let space = Space::create(transport, app_schema).await?;
        let row_id = space
            .table::<Row>(TABLE)
            .insert(&Row {
                id: None,
                name: "test".into(),
                items: List::empty(),
            })
            .execute()
            .await?;
        Ok((space, row_id))
    }

    #[tokio::test]
    async fn test_empty_list_get_all() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);
        let items = list.get_all().await?;
        assert!(items.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_empty_list_len() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);
        assert_eq!(list.len().await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_append_single_item() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let key = list.append(&"hello".to_string()).await?;
        assert_eq!(key.len(), 8);

        let items = list.get_all().await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "hello");
        assert_eq!(items[0].key, key);
        Ok(())
    }

    #[tokio::test]
    async fn test_append_multiple_items() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        list.append(&"first".to_string()).await?;
        list.append(&"second".to_string()).await?;
        list.append(&"third".to_string()).await?;

        let items = list.get_all().await?;
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, "first");
        assert_eq!(items[1].value, "second");
        assert_eq!(items[2].value, "third");
        Ok(())
    }

    #[tokio::test]
    async fn test_get_single_item() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let key_a = list.append(&"A".to_string()).await?;
        let key_b = list.append(&"B".to_string()).await?;
        let key_c = list.append(&"C".to_string()).await?;

        let item0 = list.get(0).await?;
        assert_eq!(item0.value, "A");
        assert_eq!(item0.key, key_a);

        let item1 = list.get(1).await?;
        assert_eq!(item1.value, "B");
        assert_eq!(item1.key, key_b);

        let item2 = list.get(2).await?;
        assert_eq!(item2.value, "C");
        assert_eq!(item2.key, key_c);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_out_of_range() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        list.append(&"only".to_string()).await?;
        let result = list.get(1).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_after_key() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let key_a = list.append(&"A".to_string()).await?;
        let _key_c = list.append(&"C".to_string()).await?;
        let _key_b = list.insert_after_key(&key_a, &"B".to_string()).await?;

        let items = list.get_all().await?;
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, "A");
        assert_eq!(items[1].value, "B");
        assert_eq!(items[2].value, "C");
        Ok(())
    }

    #[tokio::test]
    async fn test_prepend_on_empty_list() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let key = list.prepend(&"first".to_string()).await?;
        assert_eq!(key.len(), 8);

        let items = list.get_all().await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "first");
        Ok(())
    }

    #[tokio::test]
    async fn test_prepend_on_non_empty_list() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        list.append(&"second".to_string()).await?;
        list.prepend(&"first".to_string()).await?;

        let items = list.get_all().await?;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, "first");
        assert_eq!(items[1].value, "second");
        Ok(())
    }

    #[tokio::test]
    async fn test_update_by_key() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let key = list.append(&"original".to_string()).await?;
        list.update_by_key(&key, &"updated".to_string()).await?;

        let items = list.get_all().await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "updated");
        assert_eq!(items[0].key, key);
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_by_key() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        list.append(&"first".to_string()).await?;
        let key_middle = list.append(&"middle".to_string()).await?;
        list.append(&"last".to_string()).await?;

        list.delete_by_key(&key_middle).await?;

        let items = list.get_all().await?;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, "first");
        assert_eq!(items[1].value, "last");
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_nonexistent_key_is_noop() -> Result<()> {
        // Now that list ops route through the standard table builders,
        // delete-by-id on a missing row mirrors `table.delete()`'s
        // no-matching-rows behaviour: it succeeds silently (rows_affected
        // = 0) and the existing list state is untouched.
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        list.append(&"item".to_string()).await?;
        let fake_key = 99i64.to_be_bytes();
        list.delete_by_key(&fake_key).await?;

        let items = list.get_all().await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "item");
        Ok(())
    }

    #[tokio::test]
    async fn test_empty_list_serializes_to_integer_zero() -> Result<()> {
        let list: List<String> = List::empty();
        let json = serde_json::to_value(&list).unwrap();
        assert_eq!(json, serde_json::Value::Number(0.into()));

        // Confirm it round-trips
        let deserialized: List<String> = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.list_number(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_list_number_reflects_resolved_value() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        // Before resolution, list_number is 0 (manual handle)
        assert_eq!(list.list_number, 0);

        // Trigger lazy resolution via an operation
        let _ = list.get_all().await?;

        // After resolution, list_number() returns the resolved value
        assert!(list.list_number() > 0);
        Ok(())
    }

    // -- Cache and broadcast tests --------------------------------------------

    #[tokio::test]
    async fn test_parent_insert_caches_committed_list_number() -> Result<()> {
        // Populate a complete empty-table cache first so the local insert has
        // a resident cache entry to update.
        let schema = SchemaBuilder::new(TABLE)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .column(COL, ColumnType::List)?
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::for_testing(vec![schema], root);
        let space = Space::create(transport, app_schema).await?;

        let rows: Vec<Row> = space.table::<Row>(TABLE).select().all().await?;
        assert!(rows.is_empty());

        let row_id = space
            .table::<Row>(TABLE)
            .insert(&Row {
                id: None,
                name: "cache_test".into(),
                items: List::empty(),
            })
            .execute()
            .await?;

        let cached_list_number = space.with_state(|state| {
            state
                .cache
                .get_row(TABLE, row_id)
                .and_then(|row| row.get(COL))
                .and_then(|value| value.as_i64())
        });
        assert!(
            cached_list_number.is_some_and(|list_number| list_number > 0),
            "cached parent row must have allocated list_number, got {cached_list_number:?}"
        );

        let cached_rows =
            space.with_state_mut(|state| state.cache.try_query(TABLE, &[], &[row_id]));
        assert!(
            cached_rows.as_ref().is_some_and(|rows| {
                rows.iter()
                    .any(|row| row.get("id").and_then(|value| value.as_i64()) == Some(row_id))
            }),
            "inserted parent row must remain directly cache-addressable"
        );

        // Re-selecting must keep returning the allocated list_number, not the
        // placeholder 0 from the submitted query.
        let rows: Vec<Row> = space
            .table::<Row>(TABLE)
            .select()
            .where_eq("id", row_id)
            .all()
            .await?;
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].items.list_number > 0,
            "Parent row must have allocated list_number, got {}",
            rows[0].items.list_number
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parent_insert_updates_indexed_where_eq_bucket() -> Result<()> {
        // Regression test: inserting a parent row with a List column must
        // update affected indexed buckets without clearing unrelated cached
        // rows.
        #[derive(Debug, Serialize, Deserialize)]
        struct IndexedRow {
            id: Option<i64>,
            category: i64,
            items: List<String>,
        }

        let schema = SchemaBuilder::new("indexed_list_table")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("category", ColumnType::Integer)?
            .plaintext()
            .index()
            .column("items", ColumnType::List)?
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::for_testing(vec![schema], root);
        let space = Space::create(transport, app_schema).await?;

        let first_id = space
            .table::<IndexedRow>("indexed_list_table")
            .insert(&IndexedRow {
                id: None,
                category: 42,
                items: List::empty(),
            })
            .execute()
            .await?;
        let unrelated_id = space
            .table::<IndexedRow>("indexed_list_table")
            .insert(&IndexedRow {
                id: None,
                category: 7,
                items: List::empty(),
            })
            .execute()
            .await?;

        // Populate two complete indexed buckets. The category=7 row should
        // survive the later category=42 insert.
        let rows: Vec<IndexedRow> = space
            .table::<IndexedRow>("indexed_list_table")
            .select()
            .where_eq("category", 42)
            .all()
            .await?;
        assert_eq!(rows.len(), 1);
        let rows: Vec<IndexedRow> = space
            .table::<IndexedRow>("indexed_list_table")
            .select()
            .where_eq("category", 7)
            .all()
            .await?;
        assert_eq!(rows.len(), 1);

        let second_id = space
            .table::<IndexedRow>("indexed_list_table")
            .insert(&IndexedRow {
                id: None,
                category: 42,
                items: List::empty(),
            })
            .execute()
            .await?;

        let cached_ids = space.with_state(|state| state.cache.row_ids("indexed_list_table"));
        assert!(cached_ids.contains(&first_id));
        assert!(cached_ids.contains(&second_id));
        assert!(
            cached_ids.contains(&unrelated_id),
            "unrelated cached rows must survive a List-column parent insert"
        );
        let second_list_number = space.with_state(|state| {
            state
                .cache
                .get_row("indexed_list_table", second_id)
                .and_then(|row| row.get("items"))
                .and_then(|value| value.as_i64())
        });
        assert!(
            second_list_number.is_some_and(|list_number| list_number > 0),
            "cached inserted row must have allocated list_number, got {second_list_number:?}"
        );

        let rows: Vec<IndexedRow> = space
            .table::<IndexedRow>("indexed_list_table")
            .select()
            .where_eq("category", 42)
            .all()
            .await?;
        assert_eq!(
            rows.len(),
            2,
            "where_eq bucket must include the inserted List-column parent row"
        );
        let rows: Vec<IndexedRow> = space
            .table::<IndexedRow>("indexed_list_table")
            .select()
            .where_eq("category", 7)
            .all()
            .await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, Some(unrelated_id));
        Ok(())
    }

    fn list_row_id(key: &[u8]) -> i64 {
        i64::from_be_bytes(key.try_into().expect("list keys are always 8 bytes"))
    }

    fn cached_list_row(space: &Space, row_id: i64) -> serde_json::Value {
        space
            .with_state(|state| state.cache.get_row("_lists", row_id).cloned())
            .unwrap_or_else(|| panic!("expected _lists row {row_id} to be cached"))
    }

    fn cached_i64(row: &serde_json::Value, column: &str) -> i64 {
        row.get(column)
            .and_then(|value| value.as_i64())
            .unwrap_or_else(|| panic!("expected cached column {column} to be i64"))
    }

    fn cached_string(row: &serde_json::Value, column: &str) -> String {
        row.get(column)
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| panic!("expected cached column {column} to be string"))
            .to_string()
    }

    #[tokio::test]
    async fn test_fast_forward_reports_same_change_id_state_divergence() -> Result<()> {
        // Build a space + transport pair locally so the test can hold on
        // to the transport for direct inspection.
        let schema = SchemaBuilder::new(TABLE)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .column(COL, ColumnType::List)?
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::WithDataCommitment(vec![schema], root, EXTEND_FF_ID);
        let space = Space::create(transport.clone(), app_schema).await?;
        let _row_id = space
            .table::<Row>(TABLE)
            .insert(&Row {
                id: None,
                name: "test".into(),
                items: List::empty(),
            })
            .execute()
            .await?;

        let before_change_id = space.current_change_id();
        let mut client_clc_prefix_before = [0u8; 16];
        client_clc_prefix_before.copy_from_slice(&space.current_clc()[..16]);

        // Corrupt only the client's CLC root, leaving change_id and DC
        // matching the server. With this state, `recover_via_fast_forward`
        // should detect the divergence (server reports the same
        // change_id but a different CLC prefix) and surface
        // `StateDiverged` rather than silently accepting the FF.
        space.with_state_mut(|state| {
            let mut head = state.current_clc_state.clone();
            head.root = [0x42u8; 32].into();
            state.current_clc_state = head;
        });

        let err = space
            .recover_via_fast_forward()
            .await
            .expect_err("same change_id with different CLC must be terminal divergence");

        match err {
            SdkError::StateDiverged(divergence) => {
                assert_eq!(divergence.change_id, before_change_id);
                assert_ne!(
                    divergence.client_clc_prefix, client_clc_prefix_before,
                    "client CLC prefix should reflect the corrupted local state"
                );
                assert_ne!(
                    divergence.client_clc_prefix, divergence.server_clc_prefix,
                    "CLC prefixes must disagree"
                );
                assert_eq!(
                    divergence.client_data_commitment_prefix,
                    divergence.server_data_commitment_prefix,
                    "DC was not corrupted; prefixes should agree"
                );
            }
            other => panic!("expected StateDiverged, got {other:?}"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_lists_cache_not_stale_after_append() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let first_key = list.append(&"first".to_string()).await?;
        let first_id = list_row_id(&first_key);
        let items = list.get_all().await?;
        assert_eq!(items.len(), 1);

        let second_key = list.append(&"second".to_string()).await?;
        let second_id = list_row_id(&second_key);
        let cached_ids = space.with_state(|state| state.cache.row_ids("_lists"));
        assert!(cached_ids.contains(&first_id));
        assert!(cached_ids.contains(&second_id));
        assert_eq!(
            cached_ids.len(),
            2,
            "append should add the new _lists row without clearing existing cached rows"
        );

        let first_row = cached_list_row(&space, first_id);
        let second_row = cached_list_row(&space, second_id);
        assert_eq!(cached_i64(&first_row, "next_id"), second_id);
        assert_eq!(cached_i64(&second_row, "prev_id"), first_id);
        assert_eq!(cached_i64(&second_row, "next_id"), 0);

        let items = list.get_all().await?;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, "first");
        assert_eq!(items[1].value, "second");
        Ok(())
    }

    #[tokio::test]
    async fn test_lists_cache_not_stale_after_delete() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let first_key = list.append(&"first".to_string()).await?;
        let middle_key = list.append(&"middle".to_string()).await?;
        let last_key = list.append(&"last".to_string()).await?;
        let first_id = list_row_id(&first_key);
        let middle_id = list_row_id(&middle_key);
        let last_id = list_row_id(&last_key);

        let items = list.get_all().await?;
        assert_eq!(items.len(), 3);

        list.delete_by_key(&middle_key).await?;
        let cached_ids = space.with_state(|state| state.cache.row_ids("_lists"));
        assert!(cached_ids.contains(&first_id));
        assert!(!cached_ids.contains(&middle_id));
        assert!(cached_ids.contains(&last_id));
        assert_eq!(
            cached_ids.len(),
            2,
            "delete should remove only the deleted _lists row"
        );

        let first_row = cached_list_row(&space, first_id);
        let last_row = cached_list_row(&space, last_id);
        assert_eq!(cached_i64(&first_row, "next_id"), last_id);
        assert_eq!(cached_i64(&last_row, "prev_id"), first_id);

        let items = list.get_all().await?;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, "first");
        assert_eq!(items[1].value, "last");
        Ok(())
    }

    #[tokio::test]
    async fn test_lists_cache_not_stale_after_update() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let key = list.append(&"original".to_string()).await?;
        let id = list_row_id(&key);
        let items = list.get_all().await?;
        assert_eq!(items[0].value, "original");
        let cached_before = cached_list_row(&space, id);
        let value_before = cached_string(&cached_before, "value");
        let list_number_before = cached_i64(&cached_before, "list_number");
        let prev_before = cached_i64(&cached_before, "prev_id");
        let next_before = cached_i64(&cached_before, "next_id");

        list.update_by_key(&key, &"modified".to_string()).await?;
        let cached_ids = space.with_state(|state| state.cache.row_ids("_lists"));
        assert_eq!(
            cached_ids,
            [id].into_iter().collect(),
            "update should preserve the cached _lists row set"
        );
        let cached_after = cached_list_row(&space, id);
        assert_ne!(
            cached_string(&cached_after, "value"),
            value_before,
            "update should replace the cached _lists value"
        );
        assert_eq!(cached_i64(&cached_after, "list_number"), list_number_before);
        assert_eq!(cached_i64(&cached_after, "prev_id"), prev_before);
        assert_eq!(cached_i64(&cached_after, "next_id"), next_before);

        let items = list.get_all().await?;
        assert_eq!(items[0].value, "modified");
        Ok(())
    }

    #[tokio::test]
    async fn test_lists_cache_not_stale_after_insert_after_key() -> Result<()> {
        let (space, row_id) = create_space_with_list().await?;
        let list: List<String> = space.list(TABLE, row_id, COL);

        let key_a = list.append(&"A".to_string()).await?;
        let key_c = list.append(&"C".to_string()).await?;
        let id_a = list_row_id(&key_a);
        let id_c = list_row_id(&key_c);
        let items = list.get_all().await?;
        assert_eq!(items.len(), 2);

        let key_b = list.insert_after_key(&key_a, &"B".to_string()).await?;
        let id_b = list_row_id(&key_b);
        let cached_ids = space.with_state(|state| state.cache.row_ids("_lists"));
        assert!(cached_ids.contains(&id_a));
        assert!(cached_ids.contains(&id_b));
        assert!(cached_ids.contains(&id_c));
        assert_eq!(
            cached_ids.len(),
            3,
            "insert_after_key should add the new _lists row without clearing existing cached rows"
        );

        let row_a = cached_list_row(&space, id_a);
        let row_b = cached_list_row(&space, id_b);
        let row_c = cached_list_row(&space, id_c);
        assert_eq!(cached_i64(&row_a, "next_id"), id_b);
        assert_eq!(cached_i64(&row_b, "prev_id"), id_a);
        assert_eq!(cached_i64(&row_b, "next_id"), id_c);
        assert_eq!(cached_i64(&row_c, "prev_id"), id_b);

        let items = list.get_all().await?;
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, "A");
        assert_eq!(items[1].value, "B");
        assert_eq!(items[2].value, "C");
        Ok(())
    }
}
