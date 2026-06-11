use std::collections::HashMap;

use encrypted_spaces_acl_types::Action;
pub use encrypted_spaces_backend::schema::ColumnType;
pub use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_backend::schema_kdl::parse_schema_bundle;
use encrypted_spaces_backend::{
    error::{Result, SdkError},
    merk_storage::ID_FIELD,
    schema::ColumnDefinition,
};

use crate::{DataCommitment, FfImageId, Space};

impl Space {
    /// Register a table schema.
    pub fn register_table_schema(&self, schema: Schema) {
        self.with_state_mut(|state| state.table_schemas.insert(schema.name.clone(), schema));
    }

    /// Get the schema for a table.
    pub fn get_table_schema(&self, table_name: &str) -> Option<Schema> {
        self.with_state(|state| state.table_schemas.get(table_name).cloned())
    }
}

/// Specifies how a [`Space`] should obtain its initial schema, data
/// commitment, and FF-proof guest image ID.
///
/// The image ID is part of the trust bundle: the verifier rejects any
/// FF-proof receipt that wasn't produced by a guest with this ID, which
/// is what closes the "prover dictates the image ID" gap.  Callers
/// typically wire this through the `sdk-codegen` build script's
/// `application_schema()` helper, which emits `FF_GUEST_IMAGE_ID`
/// alongside `DATA_COMMITMENT` so both are anchored to the binary the
/// app was built with.
#[derive(Clone, Debug)]
pub enum ApplicationSchema {
    /// Caller provides schemas, a pre-computed commitment, and the
    /// trusted FF-proof guest image ID.
    WithDataCommitment(Vec<Schema>, DataCommitment, FfImageId),

    /// Parse a [`SchemaBundle`] from raw KDL bytes (e.g. embedded via
    /// `include_bytes!`) and use the explicitly-supplied commitment as
    /// the initial merk root.  The bundle no longer carries a
    /// `data_commitment` itself; callers typically wire this through
    /// the `sdk-codegen` build script's `application_schema()` helper,
    /// which pairs the bytes with a build-time-computed commitment and
    /// the FF-proof guest image ID.
    FromBytes(&'static [u8], DataCommitment, FfImageId),
}

impl ApplicationSchema {
    pub(crate) async fn into_parts(
        self,
    ) -> Result<(
        DataCommitment,
        HashMap<String, Schema>,
        HashMap<String, Action>,
        FfImageId,
    )> {
        match self {
            ApplicationSchema::WithDataCommitment(schemas, commitment, image_id) => {
                let map = schemas.into_iter().map(|s| (s.name.clone(), s)).collect();
                // Explicit-schemas mode doesn't carry actions; callers
                // can `register_action` after-the-fact for tests.
                Ok((commitment, map, HashMap::new(), image_id))
            }
            ApplicationSchema::FromBytes(bytes, commitment, image_id) => {
                Self::app_schema_bundle_into_parts(bytes, commitment, image_id).await
            }
        }
    }

    async fn app_schema_bundle_into_parts(
        bytes: &[u8],
        commitment: DataCommitment,
        image_id: FfImageId,
    ) -> Result<(
        DataCommitment,
        HashMap<String, Schema>,
        HashMap<String, Action>,
        FfImageId,
    )> {
        let text = std::str::from_utf8(bytes).map_err(|e| {
            SdkError::SchemaParsingError(format!("Schema bytes are not valid UTF-8: {e}"))
        })?;
        let bundle = parse_schema_bundle(text)?;

        let schemas = bundle
            .tables
            .into_iter()
            .filter_map(|entry| entry.schema.map(|s| (entry.table, s)))
            .collect();
        let actions = bundle
            .actions
            .into_iter()
            .map(|a| (a.name.clone(), a))
            .collect();

        Ok((commitment, schemas, actions, image_id))
    }
}

#[derive(Debug)]
pub struct SchemaBuilder {
    schema: Schema,
}

impl SchemaBuilder {
    /// Begin construction of a new schema
    pub fn new(name: &str) -> Self {
        Self {
            schema: Schema {
                name: name.to_string(),
                columns: Vec::new(),
                auto_increment: true,
            },
        }
    }

    /// Start building a new column within the schema, specifying
    /// the columns `name`, `type`, and special attributes.
    pub fn column(self, name: &str, column_type: ColumnType) -> ColumnBuilder {
        ColumnBuilder::new(self, name, column_type)
    }

    /// Disable auto-increment on this table.  Every insert must supply an
    /// explicit `id`; the server will not allocate one, and the insert
    /// verifier rejects auto-ID inserts on this table.
    pub fn explicit_ids(mut self) -> Self {
        self.schema.auto_increment = false;
        self
    }

    /// Generate the schema for use in initializing a table.
    pub fn build(self) -> Result<Schema> {
        Ok(self.schema)
    }
}

pub struct ColumnBuilder {
    schema_builder: SchemaBuilder,
    column_def: ColumnDefinition,
}

impl ColumnBuilder {
    fn new(schema_builder: SchemaBuilder, name: &str, column_type: ColumnType) -> Self {
        // FileRef and List columns are always plaintext so the server can
        // read the hash for lifecycle management.
        let plaintext = matches!(column_type, ColumnType::FileRef | ColumnType::List);
        Self {
            schema_builder,
            column_def: ColumnDefinition {
                name: name.to_string(),
                column_type,
                plaintext,
                indexed: false,
            },
        }
    }

    /// Mark this column as the plaintext primary key (used for the `id` column).
    pub fn plaintext_primary_key(mut self) -> Self {
        self.column_def.plaintext = true;
        self
    }

    pub fn encrypted(mut self) -> Self {
        self.column_def.plaintext = false;
        self
    }

    pub fn plaintext(mut self) -> Self {
        self.column_def.plaintext = true;
        self
    }

    /// Add a secondary index on this column (the column must be plaintext).
    pub fn index(mut self) -> Self {
        self.column_def.indexed = true;
        self
    }

    pub fn column(self, name: &str, column_type: ColumnType) -> Result<ColumnBuilder> {
        Ok(self.finish_column()?.column(name, column_type))
    }

    pub fn build(self) -> Result<Schema> {
        self.finish_column()?.build()
    }

    fn finish_column(mut self) -> Result<SchemaBuilder> {
        if self.column_def.name == ID_FIELD && !self.column_def.plaintext {
            return Err(SdkError::ValidationError(
                "The 'id' column must be plaintext".into(),
            ));
        }
        if self.column_def.column_type.is_hash_backed() && self.column_def.indexed {
            return Err(SdkError::ValidationError(format!(
                "Hash-backed column '{}' cannot be indexed",
                self.column_def.name,
            )));
        }
        if self.column_def.indexed && !self.column_def.plaintext {
            return Err(SdkError::ValidationError(format!(
                "Indexed column '{}' must be plaintext",
                self.column_def.name,
            )));
        }
        if matches!(
            self.column_def.column_type,
            ColumnType::FileRef | ColumnType::List
        ) && !self.column_def.plaintext
        {
            return Err(SdkError::ValidationError(format!(
                "{:?} column '{}' must be plaintext",
                self.column_def.column_type, self.column_def.name,
            )));
        }
        if matches!(self.column_def.column_type, ColumnType::List) && self.column_def.indexed {
            return Err(SdkError::ValidationError(format!(
                "List column '{}' cannot be indexed",
                self.column_def.name,
            )));
        }
        self.schema_builder.schema.columns.push(self.column_def);
        Ok(self.schema_builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // SchemaBuilder happy paths
    // ---------------------------------------------------------------------

    #[test]
    fn schema_builder_new_defaults_to_auto_increment_with_no_columns() {
        let schema = SchemaBuilder::new("things").build().unwrap();
        assert_eq!(schema.name, "things");
        assert!(schema.columns.is_empty());
        assert!(schema.auto_increment);
    }

    #[test]
    fn schema_builder_explicit_ids_disables_auto_increment() {
        let schema = SchemaBuilder::new("things").explicit_ids().build().unwrap();
        assert!(!schema.auto_increment);
    }

    #[test]
    fn schema_builder_builds_single_column_schema() {
        let schema = SchemaBuilder::new("things")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .build()
            .unwrap();
        assert_eq!(schema.columns.len(), 1);
        assert_eq!(schema.columns[0].name, "id");
        assert!(schema.columns[0].plaintext);
    }

    #[test]
    fn schema_builder_builds_multi_column_schema_in_order() {
        let schema = SchemaBuilder::new("products")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::Text)
            .unwrap()
            .column("price", ColumnType::Real)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(schema.columns.len(), 3);
        assert_eq!(schema.columns[0].name, "id");
        assert_eq!(schema.columns[1].name, "name");
        assert_eq!(schema.columns[2].name, "price");
    }

    // ---------------------------------------------------------------------
    // ColumnBuilder defaults
    // ---------------------------------------------------------------------

    #[test]
    fn value_column_defaults_to_encrypted() {
        let schema = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("desc", ColumnType::Text)
            .unwrap()
            .build()
            .unwrap();
        // `desc` had no plaintext/encrypted modifier; default is encrypted.
        assert!(!schema.columns[1].plaintext);
    }

    #[test]
    fn fileref_column_defaults_to_plaintext() {
        let schema = SchemaBuilder::new("docs")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("attachment", ColumnType::FileRef)
            .unwrap()
            .build()
            .unwrap();
        assert!(schema.columns[1].plaintext);
    }

    #[test]
    fn list_column_defaults_to_plaintext() {
        let schema = SchemaBuilder::new("notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("comments", ColumnType::List)
            .unwrap()
            .build()
            .unwrap();
        assert!(schema.columns[1].plaintext);
    }

    // ---------------------------------------------------------------------
    // ColumnBuilder modifier chains
    // ---------------------------------------------------------------------

    #[test]
    fn plaintext_modifier_marks_column_plaintext() {
        let schema = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("flag", ColumnType::Integer)
            .unwrap()
            .plaintext()
            .build()
            .unwrap();
        assert!(schema.columns[1].plaintext);
    }

    #[test]
    fn encrypted_modifier_overrides_plaintext_default() {
        let schema = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("secret", ColumnType::Text)
            .unwrap()
            .plaintext()
            .encrypted()
            .build()
            .unwrap();
        assert!(!schema.columns[1].plaintext);
    }

    #[test]
    fn index_modifier_marks_column_indexed_and_surfaces_in_indexed_columns() {
        let schema = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("category", ColumnType::String)
            .unwrap()
            .plaintext()
            .index()
            .build()
            .unwrap();
        assert!(schema.columns[1].indexed);
        assert_eq!(schema.indexed_columns(), vec!["category"]);
    }

    // ---------------------------------------------------------------------
    // Validation errors (finish_column)
    // ---------------------------------------------------------------------

    fn assert_validation_error<T: std::fmt::Debug>(r: Result<T>, needle: &str) {
        match r {
            Err(SdkError::ValidationError(msg)) => {
                assert!(
                    msg.contains(needle),
                    "expected ValidationError containing '{needle}', got: {msg}"
                );
            }
            other => panic!("expected ValidationError containing '{needle}', got: {other:?}"),
        }
    }

    #[test]
    fn id_column_must_be_plaintext() {
        let r = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .encrypted()
            .build();
        assert_validation_error(r, "'id' column must be plaintext");
    }

    #[test]
    fn indexed_column_must_be_plaintext() {
        let r = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("category", ColumnType::String)
            .unwrap()
            .encrypted()
            .index()
            .build();
        assert_validation_error(r, "Indexed column 'category' must be plaintext");
    }

    #[test]
    fn fileref_column_cannot_be_encrypted() {
        let r = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("attachment", ColumnType::FileRef)
            .unwrap()
            .encrypted()
            .build();
        assert_validation_error(r, "FileRef column 'attachment' must be plaintext");
    }

    #[test]
    fn list_column_cannot_be_encrypted() {
        let r = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("items", ColumnType::List)
            .unwrap()
            .encrypted()
            .build();
        assert_validation_error(r, "List column 'items' must be plaintext");
    }

    #[test]
    fn list_column_cannot_be_indexed() {
        let r = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("items", ColumnType::List)
            .unwrap()
            .index()
            .build();
        assert_validation_error(r, "List column 'items' cannot be indexed");
    }

    #[test]
    fn text_column_can_be_plaintext() {
        let schema = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)
            .unwrap()
            .plaintext()
            .build()
            .unwrap();
        let col = schema.columns.iter().find(|c| c.name == "content").unwrap();
        assert!(col.plaintext);
    }

    #[test]
    fn blob_column_can_be_plaintext() {
        let schema = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("data", ColumnType::Blob)
            .unwrap()
            .plaintext()
            .build()
            .unwrap();
        let col = schema.columns.iter().find(|c| c.name == "data").unwrap();
        assert!(col.plaintext);
    }

    #[test]
    fn text_column_cannot_be_indexed() {
        let r = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)
            .unwrap()
            .index()
            .build();
        assert_validation_error(r, "Hash-backed column 'content' cannot be indexed");
    }

    #[test]
    fn blob_column_cannot_be_indexed() {
        let r = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("data", ColumnType::Blob)
            .unwrap()
            .index()
            .build();
        assert_validation_error(r, "Hash-backed column 'data' cannot be indexed");
    }

    #[test]
    fn text_column_defaults_to_encrypted() {
        let schema = SchemaBuilder::new("t")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)
            .unwrap()
            .build()
            .unwrap();
        let col = schema.columns.iter().find(|c| c.name == "content").unwrap();
        assert!(!col.plaintext);
        assert!(!col.indexed);
    }

    // ---------------------------------------------------------------------
    // ApplicationSchema
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn application_schema_with_data_commitment_round_trips_into_parts() {
        let schema = SchemaBuilder::new("things")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .build()
            .unwrap();
        let commitment: DataCommitment = [42u8; 32];
        let image_id: FfImageId = [7u32; 8];
        let app = ApplicationSchema::WithDataCommitment(vec![schema], commitment, image_id);

        let (out_commit, out_map, out_actions, out_image_id) = app.into_parts().await.unwrap();

        assert_eq!(out_commit, commitment);
        assert_eq!(out_map.len(), 1);
        assert!(out_map.contains_key("things"));
        assert!(out_actions.is_empty());
        assert_eq!(out_image_id, image_id);
    }

    #[tokio::test]
    async fn application_schema_from_bytes_rejects_invalid_utf8() {
        let bad: &'static [u8] = &[0xFFu8, 0xFE, 0xFD];
        let err = ApplicationSchema::FromBytes(bad, [0u8; 32], [0u32; 8])
            .into_parts()
            .await
            .expect_err("expected parsing to fail");
        assert!(
            matches!(err, SdkError::SchemaParsingError(ref m) if m.contains("not valid UTF-8")),
            "unexpected error: {err:?}"
        );
    }
}
