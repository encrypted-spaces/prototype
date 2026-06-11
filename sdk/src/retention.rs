use crate::{Space, Table};
use encrypted_spaces_backend::error::Result;
use encrypted_spaces_backend::internal_schemas::retention_schema;
pub(crate) use encrypted_spaces_backend::internal_schemas::RETENTION_TABLE_NAME;
use encrypted_spaces_key_manager::{
    operation::AsyncReader, CollectingOperationBuilder, KeyManagerError,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RetentionRecord {
    pub key: String,
    /// Blob stored as base64 in merk. Custom serde handles the round-trip.
    #[serde(
        serialize_with = "serialize_blob_as_b64",
        deserialize_with = "deserialize_blob_from_b64"
    )]
    pub value: Vec<u8>,
}

fn serialize_blob_as_b64<S: serde::Serializer>(
    bytes: &[u8],
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    use base64::Engine;
    s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn deserialize_blob_from_b64<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    use base64::Engine;
    let s = String::deserialize(d)?;
    base64::engine::general_purpose::STANDARD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

impl Space {
    pub(crate) async fn initialize_retention(&self) -> Result<()> {
        self.register_table_schema(retention_schema());
        // Warm the cache so that subsequent indexed lookups are served locally.
        let _: Vec<RetentionRecord> = self.retention_table().select().all().await?;
        Ok(())
    }

    pub(crate) fn retention_table(&self) -> Table<RetentionRecord> {
        self.table(RETENTION_TABLE_NAME)
    }

    /// Build a `CollectingOperationBuilder` whose reader queries the `_retention`
    /// table asynchronously via `where_eq("key", k)`.
    ///
    /// Uses shared Arc references to state and transport so the reader always
    /// sees the latest data commitment (not a stale snapshot).
    ///
    /// Reads are ordered `id DESC` and take the first row. The retention
    /// table does not enforce key uniqueness at the storage layer, so a
    /// scalar key (e.g. `sl2/fgk/next` going 1 → 2 across a rekey) may be
    /// represented by multiple rows; the highest-id row is always the most
    /// recent write, so ordering descending by id returns the current value.
    pub(crate) fn retention_builder(&self) -> CollectingOperationBuilder {
        let space = Arc::new(self.clone());
        let reader: AsyncReader = Box::new(move |key: &str| {
            let space = Arc::clone(&space);
            let key = key.to_string();
            Box::pin(async move {
                let record: Option<RetentionRecord> = space
                    .retention_table()
                    .select()
                    .where_eq("key", key.as_str())
                    .last()
                    .await
                    .map_err(|_| KeyManagerError)?;
                Ok(record.map(|r| r.value))
            })
        });
        CollectingOperationBuilder::new(reader)
    }
}
