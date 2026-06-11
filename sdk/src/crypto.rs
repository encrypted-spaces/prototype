use crate::Space;
use encrypted_spaces_backend::{
    error::{Result, SdkError},
    query::{Query, QueryOperation, QueryParam},
    schema::{ColumnType, Schema},
};
use encrypted_spaces_crypto::encryption::{
    decrypt_row, encrypt_row, EncryptedColumn, EncryptionKey, FieldType,
};
use encrypted_spaces_crypto::error::EncryptionError;
use encrypted_spaces_key_manager::SimpleKeyId;
use std::collections::HashMap;

/// Convert a schema to a list of encrypted columns (those with `plaintext == false`).
fn encrypted_columns_from_schema(schema: &Schema) -> Vec<EncryptedColumn> {
    schema
        .columns
        .iter()
        .filter(|c| !c.plaintext)
        .map(|c| EncryptedColumn {
            name: c.name.clone(),
            field_type: match c.column_type {
                ColumnType::Integer => FieldType::Integer,
                ColumnType::Real => FieldType::Real,
                ColumnType::String | ColumnType::Text => FieldType::Text,
                ColumnType::Blob => FieldType::Blob,
                ColumnType::FileRef => FieldType::FileRef,
                ColumnType::List => FieldType::List,
            },
        })
        .collect()
}

/// Derive the encryption key for the current key id from the space's key manager.
pub(crate) async fn current_encryption_key(space: &Space) -> Result<EncryptionKey> {
    let builder = space.retention_builder();
    let km = space.key_manager.lock().await;
    let key_id = km
        .current_key_id(&builder)
        .await
        .map_err(|_| SdkError::DecryptionError("current key id failed".into()))?;
    km.data_key_for_key_id(&key_id, &builder)
        .await
        .map(|bytes| EncryptionKey::new(bytes, &key_id))
        .map_err(|_| SdkError::DecryptionError("missing key for current key_id".into()))
}

/// Encrypt fields in a query's Insert or Update operation, using the current
/// key from `space`. No-op for Select/Delete or tables without encrypted columns.
pub(crate) async fn encrypt_query_fields(query: &mut Query, space: &Space) -> Result<()> {
    let schema = match space.get_table_schema(&query.table) {
        Some(s) => s,
        None => return Ok(()),
    };

    let columns = encrypted_columns_from_schema(&schema);
    if columns.is_empty() {
        return Ok(());
    }

    let key = current_encryption_key(space).await?;

    let is_insert = matches!(query.operation, QueryOperation::Insert(_));

    let fields = match &mut query.operation {
        QueryOperation::Insert(fields) => fields,
        QueryOperation::Update(fields) => fields,
        QueryOperation::Select(_) | QueryOperation::Delete => return Ok(()),
    };

    // Validate: all query fields must exist in schema
    for (name, _) in fields.iter() {
        if !schema.columns.iter().any(|c| &c.name == name) {
            return Err(SdkError::InvalidQuery(format!(
                "Query field '{}' not found in schema for table '{}'",
                name, schema.name
            )));
        }
    }

    // Validate: all encrypted columns must be present in insert operations
    if is_insert {
        for col in &columns {
            if !fields.iter().any(|(name, _)| name == &col.name) {
                return Err(SdkError::InvalidQuery(format!(
                    "Encrypted column '{}' missing from query for table '{}'",
                    col.name, schema.name
                )));
            }
        }
    }

    // Build a JSON row map from fields, encrypt, then write back
    let mut row = serde_json::Map::new();
    for (name, param) in fields.iter() {
        row.insert(name.clone(), query_param_to_value(param));
    }

    encrypt_row(&mut row, &columns, &key);

    // Write encrypted values back to fields
    for (name, param) in fields.iter_mut() {
        if let Some(serde_json::Value::String(s)) = row.get(name) {
            if columns.iter().any(|c| &c.name == name) {
                *param = QueryParam::Text(s.clone());
            }
        }
    }

    Ok(())
}

/// Decrypt rows in-place for a specific table. The epoch embedded in each
/// ciphertext header is used to resolve the correct key from `space`.
///
/// Returns an error if key resolution or decryption fails.
pub(crate) async fn decrypt_table_rows(
    rows: &mut Vec<serde_json::Value>,
    table_name: &str,
    schemas: &HashMap<String, Schema>,
    space: &Space,
) -> Result<()> {
    let table_key = table_name.split(" as ").next().unwrap_or(table_name);
    let schema = match schemas.get(table_key) {
        Some(s) => s,
        None => return Ok(()),
    };
    let columns = encrypted_columns_from_schema(schema);
    if columns.is_empty() {
        return Ok(());
    }
    let km = space.key_manager.lock().await;
    let builder = space.retention_builder();
    let resolver = |key_id: SimpleKeyId| {
        let km = &km;
        let builder = &builder;
        async move {
            km.data_key_for_key_id(&key_id, builder)
                .await
                .map(|bytes| EncryptionKey::new(bytes, &key_id))
                .map_err(|_| EncryptionError::MissingKey(format!("{key_id:?}").into_bytes()))
        }
    };
    // Decrypt each row in-place. Rows whose keys have been pruned (e.g.
    // after a reduce) are removed. Because decrypt_row is async we can't
    // use retain_mut, so we drain into a new vec in a single pass.
    let mut decrypted = Vec::with_capacity(rows.len());
    for mut row in rows.drain(..) {
        if let serde_json::Value::Object(ref mut obj) = row {
            if let Err(e) = decrypt_row(obj, &columns, &resolver).await {
                log::warn!("Failed to decrypt row, removing from result set: {e}");
                continue;
            }
        }
        decrypted.push(row);
    }
    *rows = decrypted;
    Ok(())
}

#[cfg(all(test, feature = "local-transport"))]
mod tests {
    use super::{decrypt_table_rows, encrypt_query_fields};
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use crate::Space;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
    use encrypted_spaces_backend::schema::Schema;
    use encrypted_spaces_crypto::encryption::ciphertext_key_id;
    use encrypted_spaces_key_manager::SimpleKeyId;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct SecretNote {
        id: Option<i64>,
        title: String,
        body: String,
    }

    fn schema() -> ApplicationSchema {
        ApplicationSchema::for_testing(vec![], crate::testing::initial_internal_data_commitment())
    }

    async fn create_space() -> Result<(LocalTransport, Space)> {
        let transport = LocalTransport::in_memory().await?;
        let space = Space::create(transport.clone(), schema()).await?;
        Ok((transport, space))
    }

    fn notes_schema() -> Result<Schema> {
        SchemaBuilder::new("notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("title", ColumnType::String)?
            .column("body", ColumnType::String)?
            .build()
    }

    async fn create_notes_table(space: &Space) -> Result<crate::Table<SecretNote>> {
        let table = space.table::<SecretNote>("notes");
        space.create_table(&notes_schema()?).await?;
        Ok(table)
    }

    // ── Unit tests for encrypt_query_fields / decrypt_table_rows ────────

    #[tokio::test]
    async fn encrypt_query_fields_encrypts_non_plaintext_columns() -> Result<()> {
        let (_, space) = create_space().await?;
        // Register the notes schema so encrypt_query_fields can find it.
        let _notes = create_notes_table(&space).await?;

        let mut query = Query::new(
            "notes".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Null),
                ("title".to_string(), QueryParam::Text("secret title".into())),
                ("body".to_string(), QueryParam::Text("secret body".into())),
            ]),
        );

        encrypt_query_fields(&mut query, &space).await?;

        let fields = match &query.operation {
            QueryOperation::Insert(f) => f,
            _ => panic!("expected Insert"),
        };

        // `id` is plaintext — should remain Null.
        let id_param = fields.iter().find(|(n, _)| n == "id").unwrap();
        assert!(matches!(id_param.1, QueryParam::Null));

        // `title` and `body` should now be encrypted (base64 ciphertext).
        for col_name in &["title", "body"] {
            let (_, param) = fields.iter().find(|(n, _)| n == col_name).unwrap();
            let ciphertext_b64 = match param {
                QueryParam::Text(s) => s,
                other => panic!("expected Text for {col_name}, got {other:?}"),
            };
            // Should be valid base64 that decodes to a ciphertext with key_id 0.
            let raw = STANDARD
                .decode(ciphertext_b64)
                .expect("encrypted field should be valid base64");
            assert_eq!(
                ciphertext_key_id::<SimpleKeyId>(&raw),
                Some(SimpleKeyId(0)),
                "{col_name} ciphertext should be tagged with key_id 0"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn encrypt_query_fields_is_noop_for_select() -> Result<()> {
        let (_, space) = create_space().await?;
        let _notes = create_notes_table(&space).await?;

        let mut query = Query::new(
            "notes".to_string(),
            QueryOperation::Select(vec!["*".to_string()]),
        );

        encrypt_query_fields(&mut query, &space).await?;

        // Should still be a Select — unchanged.
        assert!(matches!(query.operation, QueryOperation::Select(_)));

        Ok(())
    }

    #[tokio::test]
    async fn decrypt_table_rows_roundtrips_with_encrypt() -> Result<()> {
        let (_, space) = create_space().await?;
        let _notes = create_notes_table(&space).await?;

        // Encrypt a query's fields.
        let mut query = Query::new(
            "notes".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(1)),
                ("title".to_string(), QueryParam::Text("roundtrip".into())),
                ("body".to_string(), QueryParam::Text("test body".into())),
            ]),
        );
        encrypt_query_fields(&mut query, &space).await?;

        // Build a JSON row from the encrypted fields (simulating what the DB stores).
        let fields = match &query.operation {
            QueryOperation::Insert(f) => f,
            _ => panic!("expected Insert"),
        };
        let mut row = serde_json::Map::new();
        for (name, param) in fields {
            let value = match param {
                QueryParam::Integer(i) => serde_json::Value::Number((*i).into()),
                QueryParam::Text(s) => serde_json::Value::String(s.clone()),
                QueryParam::Null => serde_json::Value::Null,
                _ => panic!("unexpected param type"),
            };
            row.insert(name.clone(), value);
        }

        let mut rows = vec![serde_json::Value::Object(row)];

        // Decrypt using the space's schemas.
        let schemas = space.with_state(|s| s.table_schemas.clone());
        decrypt_table_rows(&mut rows, "notes", &schemas, &space).await?;

        let obj = rows[0].as_object().unwrap();
        assert_eq!(obj.get("id"), Some(&serde_json::Value::Number(1.into())));
        assert_eq!(
            obj.get("title"),
            Some(&serde_json::Value::String("roundtrip".into()))
        );
        assert_eq!(
            obj.get("body"),
            Some(&serde_json::Value::String("test body".into()))
        );

        Ok(())
    }

    #[tokio::test]
    async fn decrypt_table_rows_skips_table_without_schema() -> Result<()> {
        let (_, space) = create_space().await?;

        let mut rows = vec![serde_json::json!({"x": "hello"})];
        let empty_schemas: HashMap<String, Schema> = HashMap::new();

        // Should be a no-op — no error, rows unchanged.
        decrypt_table_rows(&mut rows, "nonexistent", &empty_schemas, &space).await?;
        assert_eq!(
            rows[0].as_object().unwrap().get("x"),
            Some(&serde_json::Value::String("hello".into()))
        );

        Ok(())
    }

    // ── Integration tests via Table ─────────────────────────────────────

    #[tokio::test]
    async fn encrypt_decrypt_at_epoch_zero() -> Result<()> {
        let (_, space) = create_space().await?;
        let notes = create_notes_table(&space).await?;

        // Write encrypted data at epoch 0.
        notes
            .insert(&SecretNote {
                id: None,
                title: "hello".into(),
                body: "world".into(),
            })
            .execute()
            .await?;

        // Read raw rows from the transport (bypassing SDK decryption) to
        // verify stored ciphertext is tagged with epoch 0.
        {
            let raw_query = Query::new(
                "notes".to_string(),
                QueryOperation::Select(vec!["*".to_string()]),
            );
            let commitment = space.current_data_commitment();
            let schemas = HashMap::from([(
                "notes".to_string(),
                space.get_table_schema("notes").expect("notes schema"),
            )]);
            let verified = space
                .transport
                .select(raw_query, &commitment, &schemas)
                .await?;
            let raw_row = verified.main_rows[0].as_object().unwrap();

            for col_name in &["title", "body"] {
                let raw_val = raw_row.get(*col_name).expect("column should exist");
                let b64 = raw_val
                    .as_str()
                    .expect("encrypted column should be a string");
                // Should NOT be the plaintext value.
                assert_ne!(b64, "hello");
                assert_ne!(b64, "world");
                let raw = STANDARD.decode(b64).expect("should be valid base64");
                assert_eq!(
                    ciphertext_key_id::<SimpleKeyId>(&raw),
                    Some(SimpleKeyId(0)),
                    "{col_name} ciphertext should be tagged with key_id 0"
                );
            }
        }

        // Read it back — fields should round-trip through encryption.
        let rows = notes.select().all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "hello");
        assert_eq!(rows[0].body, "world");

        Ok(())
    }

    #[tokio::test]
    async fn both_users_read_after_add_user() -> Result<()> {
        let (transport, alice_space) = create_space().await?;
        let alice_notes = create_notes_table(&alice_space).await?;

        let builder = alice_space.retention_builder();
        let km = alice_space.key_manager.lock().await;
        let key_id_before = km.current_key_id(&builder).await.unwrap();
        drop(km);

        // Alice writes a note at key_id 0.
        alice_notes
            .insert(&SecretNote {
                id: None,
                title: "before invite".into(),
                body: "initial data".into(),
            })
            .execute()
            .await?;

        // Alice invites Bob — key_id does NOT advance.
        let invite = alice_space.invite_user().await?;
        let bob_space = Space::join(
            transport,
            invite,
            ApplicationSchema::for_testing(
                vec![notes_schema()?],
                crate::testing::initial_internal_data_commitment(),
            ),
        )
        .await?;

        let builder_after = alice_space.retention_builder();
        let km = alice_space.key_manager.lock().await;
        let key_id_after = km.current_key_id(&builder_after).await.unwrap();
        drop(km);
        assert_eq!(
            key_id_after, key_id_before,
            "key_id should NOT advance after invite"
        );

        // Alice writes another note (same key_id since invite doesn't advance).
        alice_notes
            .insert(&SecretNote {
                id: None,
                title: "after invite".into(),
                body: "same key data".into(),
            })
            .execute()
            .await?;

        // Read raw rows from the transport to verify key_id tagging.
        {
            let raw_query = Query::new(
                "notes".to_string(),
                QueryOperation::Select(vec!["*".to_string()]),
            );
            let commitment = alice_space.current_data_commitment();
            let schemas = HashMap::from([(
                "notes".to_string(),
                alice_space.get_table_schema("notes").expect("notes schema"),
            )]);
            let verified = alice_space
                .transport
                .select(raw_query, &commitment, &schemas)
                .await?;
            // Both rows written with the same key_id (invite doesn't advance).
            for raw_row in &verified.main_rows {
                let obj = raw_row.as_object().unwrap();
                let id = obj.get("id").and_then(|v| v.as_i64()).unwrap();
                let b64 = obj.get("title").and_then(|v| v.as_str()).unwrap();
                let raw = STANDARD.decode(b64).expect("should be valid base64");
                assert_eq!(
                    ciphertext_key_id::<SimpleKeyId>(&raw),
                    Some(key_id_before.clone()),
                    "row id={id} should be encrypted with initial key_id"
                );
            }
        }

        // Alice can read both old and new data.
        let alice_rows = alice_notes.select().ascending().all().await?;
        assert_eq!(alice_rows.len(), 2);
        assert_eq!(alice_rows[0].title, "before invite");
        assert_eq!(alice_rows[1].title, "after invite");

        // Bob can also read both rows.
        let bob_notes = create_notes_table(&bob_space).await?;
        let bob_rows = bob_notes.select().ascending().all().await?;
        assert_eq!(bob_rows.len(), 2);
        assert_eq!(bob_rows[0].title, "before invite");
        assert_eq!(bob_rows[1].title, "after invite");

        Ok(())
    }
}

fn query_param_to_value(param: &QueryParam) -> serde_json::Value {
    match param {
        QueryParam::Null => serde_json::Value::Null,
        QueryParam::Integer(i) => serde_json::Value::Number((*i).into()),
        QueryParam::Real(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        QueryParam::Text(s) => serde_json::Value::String(s.clone()),
        QueryParam::Blob(b) => {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            serde_json::Value::String(STANDARD.encode(b))
        }
        QueryParam::Boolean(b) => serde_json::Value::Bool(*b),
    }
}
