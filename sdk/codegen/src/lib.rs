//! Build-time codegen for app schemas.
//!
//! Call [`compile`] from your `build.rs` with a path to a server-schema
//! KDL file.  The output (written to `$OUT_DIR/sdk_codegen.rs`)
//! exposes:
//!
//! - `DATA_COMMITMENT`, the authoritative initial merk root for the
//!   schema, computed at build time by spinning up an in-process
//!   backend with the parsed tables and ACL rows.
//! - `FF_GUEST_IMAGE_ID`, the RISC0 image ID of the FF-proof guest
//!   binary this build is anchored to.  The FF verifier checks each
//!   receipt against this constant rather than a value supplied in the
//!   proof itself, so the prover cannot dictate which binary the
//!   verifier trusts.
//! - `SCHEMA_KDL`, the raw bytes of the KDL file embedded via
//!   `include_bytes!`.
//! - `application_schema()`, a convenience constructor pairing the
//!   bytes with the commitment and image ID so callers can write
//!   `Space::create(transport, sdk_codegen::application_schema())`.
//! - `Actions` extension trait on `encrypted_spaces_sdk::Space`.  Insert
//!   actions are generic over `R: Serialize` (mirroring
//!   `Table::<T>::insert(&data)`); delete actions take `id: i64`;
//!   update actions return a typed setter builder.  Apps define their
//!   own row types with whatever field types fit (`File`, `List<T>`,
//!   app-defined enums for discriminators) and pass them in; serde
//!   walks the fields and the verifier rejects any column-name mismatch
//!   at apply time.
//!
//! Include the generated module from your crate with
//!
//! ```ignore
//! include!(concat!(env!("OUT_DIR"), "/sdk_codegen.rs"));
//! ```
//!
//! # Upgrade-story caveat
//!
//! Baking `FF_GUEST_IMAGE_ID` into the app at build time means rotating
//! the guest binary is currently an app-release event: an app built
//! against an old image ID will reject proofs produced by a new prover,
//! and vice versa.  This is the right *security* shape (pinning prevents
//! a malicious server from substituting a different binary), but it
//! means coordinated guest updates need a release cycle.  Supporting a
//! set of trusted image IDs (rolling-upgrade window) is an explicit
//! follow-up.

use encrypted_spaces_acl_types::{Action, ActionLeg};
use encrypted_spaces_backend::app_schema::{SchemaBundle, SchemaTable};
use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType, Schema};
use std::path::Path;
use std::{env, fs, io};

/// Read `kdl_path`, parse it as a server-schema KDL, compute the
/// `data_commitment` by spinning up an in-process backend with the
/// declared schemas and ACLs, and write `$OUT_DIR/sdk_codegen.rs`.
/// Emits a `cargo:rerun-if-changed=<kdl_path>` directive so edits to
/// the schema trigger rebuilds.
pub fn compile(kdl_path: impl AsRef<Path>) -> io::Result<()> {
    let kdl_path = kdl_path.as_ref();
    println!("cargo:rerun-if-changed={}", kdl_path.display());

    let kdl = fs::read_to_string(kdl_path)?;
    let bundle = encrypted_spaces_backend::schema_kdl::parse_schema_bundle(&kdl)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;

    let kdl_abs = kdl_path
        .canonicalize()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;
    let kdl_abs_str = kdl_abs.to_string_lossy().into_owned();
    let commitment = compute_data_commitment(&kdl_abs_str)?;

    // The FF-proof guest's image ID is normally produced at build time
    // by risc0-build inside the methods crate and re-exported from
    // `encrypted-spaces-ffproof` under the `prove` feature; importing it
    // here anchors the generated `FF_GUEST_IMAGE_ID` to the binary this
    // app was compiled against.
    //
    // For deployment scenarios where the server is built in a different
    // environment (e.g. a Docker image), guest ELF bytes can differ
    // from a local build (embedded absolute paths, cargo metadata
    // hashes, etc.) and produce a different ImageID, so a locally-built
    // client cannot verify the server's receipts. Setting
    // `ENCRYPTED_SPACES_FF_IMAGE_ID_FILE` at build time points sdk-codegen
    // at an externally-supplied ImageID file (typically extracted from
    // the same Docker image the client will talk to) so the client
    // bakes in the matching ID.
    println!("cargo:rerun-if-env-changed=ENCRYPTED_SPACES_FF_IMAGE_ID_FILE");
    let ff_guest_image_id = match env::var_os("ENCRYPTED_SPACES_FF_IMAGE_ID_FILE") {
        Some(path_os) => {
            let path = Path::new(&path_os);
            println!("cargo:rerun-if-changed={}", path.display());
            read_image_id_from_file(path)?
        }
        None => encrypted_spaces_ffproof::EXTEND_FF_ID,
    };

    let generated = render(&bundle, &commitment, &ff_guest_image_id, &kdl_abs_str);

    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "OUT_DIR is not set; call compile() from a build.rs",
        )
    })?;
    let out_path = Path::new(&out_dir).join("sdk_codegen.rs");
    fs::write(out_path, generated)
}

/// Spin up a fresh in-process backend with the schema's tables and
/// ACL rows initialised, then read the merk root.
fn compute_data_commitment(kdl_abs_path: &str) -> io::Result<[u8; 32]> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(async {
            let transport =
                encrypted_spaces_sdk::local_transport::LocalTransport::from_schema_file(
                    kdl_abs_path,
                )
                .await?;
            transport.get_root_hash().await
        })
        .map_err(|e: encrypted_spaces_backend::error::SdkError| {
            io::Error::other(format!("failed to compute data_commitment: {e}"))
        })
}

// ─── Code generation ──────────────────────────────────────────────────────────

/// Read an externally-supplied FF guest image ID from a file.
///
/// The file is expected to contain 8 u32 values, separated by any
/// combination of whitespace, commas, or square brackets. Both decimal
/// (`1062731616`) and hex (`0x3f568220`) literals are accepted. Lines
/// starting with `#` (or anything after `#` on a line) is treated as a
/// comment and ignored. This format accepts both the raw `methods.rs`
/// snippet (`[1062731616, 2942227993, ...]`) and the more human-
/// readable `0xAABBCCDD ...` form emitted by the server's Dockerfile.
fn read_image_id_from_file(path: &Path) -> io::Result<[u32; 8]> {
    let raw = fs::read_to_string(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "ENCRYPTED_SPACES_FF_IMAGE_ID_FILE='{}': {e}",
                path.display()
            ),
        )
    })?;
    // Strip `#` line comments before tokenisation.
    let stripped: String = raw
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    let tokens: Vec<&str> = stripped
        .split(|c: char| c.is_whitespace() || c == ',' || c == '[' || c == ']' || c == ';')
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.len() != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ENCRYPTED_SPACES_FF_IMAGE_ID_FILE='{}': expected 8 u32 tokens, found {}",
                path.display(),
                tokens.len()
            ),
        ));
    }
    let mut out = [0u32; 8];
    for (i, tok) in tokens.iter().enumerate() {
        out[i] = parse_u32(tok).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ENCRYPTED_SPACES_FF_IMAGE_ID_FILE='{}': token #{} '{}': {e}",
                    path.display(),
                    i,
                    tok
                ),
            )
        })?;
    }
    Ok(out)
}

fn parse_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16)
    } else {
        s.parse()
    }
}

fn render(
    bundle: &SchemaBundle,
    commitment: &[u8; 32],
    ff_guest_image_id: &[u32; 8],
    kdl_abs_path: &str,
) -> String {
    let bytes_lit = commitment
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let image_id_lit = ff_guest_image_id
        .iter()
        .map(|w| format!("0x{w:08x}"))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = String::new();
    out.push_str("// Generated by encrypted-spaces-sdk-codegen \u{2014} do not edit.\n");
    out.push_str("#[allow(dead_code, unused_imports, clippy::needless_lifetimes)]\n");
    out.push_str("pub mod sdk_codegen {\n");
    out.push_str(
        "    use encrypted_spaces_sdk::{ApplicationSchema, File, QueryParam, SdkResult as Result, Space};\n\
         \x20   use serde::{Deserialize, Serialize};\n\n",
    );

    out.push_str(&format!(
        "    /// Authoritative initial merk root for the schema, computed at\n\
         \x20   /// build time from the parsed KDL.\n\
         \x20   pub const DATA_COMMITMENT: [u8; 32] = [{bytes_lit}];\n\n"
    ));
    out.push_str(&format!(
        "    /// RISC0 image ID of the FF-proof guest binary this build is\n\
         \x20   /// anchored to.  The FF verifier checks each receipt against\n\
         \x20   /// this constant; rotating it is currently an app-release\n\
         \x20   /// event (rolling-upgrade support is future work).\n\
         \x20   pub const FF_GUEST_IMAGE_ID: [u32; 8] = [{image_id_lit}];\n\n"
    ));
    out.push_str(&format!(
        "    /// Raw KDL bytes for the schema this codegen was run against.\n\
         \x20   pub const SCHEMA_KDL: &[u8] = include_bytes!(\"{kdl_abs_path}\");\n\n"
    ));
    out.push_str(
        "    /// Convenience constructor pairing the schema bytes with the\n\
         \x20   /// build-time commitment and image ID.  Pass to `Space::create` /\n\
         \x20   /// `Space::join`.\n\
         \x20   pub fn application_schema() -> ApplicationSchema {\n\
         \x20       ApplicationSchema::FromBytes(SCHEMA_KDL, DATA_COMMITMENT, FF_GUEST_IMAGE_ID)\n\
         \x20   }\n\n",
    );

    // ─── Actions trait ──────────────────────────────────────────────────
    //
    // Insert / insert_many helpers are generic over `R: Serialize`,
    // mirroring `Table::<T>::insert(&data)`.  App authors define their
    // own row types with rich field types (`File`, `List<T>`,
    // app-defined enums for discriminators) and pass them in.  No
    // codegen-emitted row struct intermediates.
    if !bundle.actions.is_empty() {
        render_actions_trait(&mut out, &bundle.actions, &bundle.tables);
    }

    out.push_str("}\n");
    out
}

fn render_actions_trait(out: &mut String, actions: &[Action], tables: &[SchemaTable]) {
    // Update actions need a builder struct emitted before the trait
    // (the trait method returns the builder type by name).
    for action in actions {
        if matches!(&action.legs[0], ActionLeg::Update { .. }) {
            render_update_builder(out, action, tables);
        }
    }

    out.push_str("    pub trait Actions {\n");
    for action in actions {
        render_trait_method_signature(out, action);
    }
    out.push_str("    }\n\n");

    out.push_str("    impl Actions for Space {\n");
    for action in actions {
        render_trait_method_impl(out, action, tables);
    }
    out.push_str("    }\n");
}

fn render_trait_method_signature(out: &mut String, action: &Action) {
    let name = rust_ident(&action.name);
    match &action.legs[0] {
        ActionLeg::Insert { .. } => {
            out.push_str(&format!(
                "        #[allow(async_fn_in_trait)]\n        async fn {name}<R: Serialize>(&self, row: &R) -> Result<i64>;\n",
            ));
        }
        ActionLeg::Update { .. } => {
            let builder = update_builder_type(&action.name);
            out.push_str(&format!(
                "        fn {name}(&self, id: i64) -> {builder};\n",
            ));
        }
        ActionLeg::Delete { .. } => {
            out.push_str(&format!(
                "        #[allow(async_fn_in_trait)]\n        async fn {name}(&self, id: i64) -> Result<usize>;\n",
            ));
        }
        ActionLeg::CascadeDelete { .. } => panic!(
            "action '{}' has a `cascade_delete` as its primary leg; cascade legs only follow a \
             primary insert/update/delete leg",
            action.name
        ),
    }
}

fn render_trait_method_impl(out: &mut String, action: &Action, _tables: &[SchemaTable]) {
    let name = rust_ident(&action.name);
    match &action.legs[0] {
        ActionLeg::Insert { .. } => {
            // Serialize the row to JSON, walk the object, and convert
            // each field to a `QueryParam`.  Same shape as
            // `InsertBuilder::new(...)`'s internals — the helper trusts
            // `T: Serialize` to match the table's column layout, just
            // like `Table::<T>::insert(&data)` does.  Missing or
            // extra fields surface at the verifier rather than at
            // compile time.
            out.push_str(&format!(
                "        async fn {name}<R: Serialize>(&self, row: &R) -> Result<i64> {{\n\
                 \x20           let json = ::serde_json::to_value(row).map_err(|e| {{\n\
                 \x20               ::encrypted_spaces_sdk::SdkErrorType::SerializationError(format!(\"action '{}': {{e}}\"))\n\
                 \x20           }})?;\n\
                 \x20           let mut fields: Vec<(String, QueryParam)> = Vec::new();\n\
                 \x20           if let ::serde_json::Value::Object(obj) = json {{\n\
                 \x20               for (key, value) in obj {{\n\
                 \x20                   fields.push((key, QueryParam::from(value)));\n\
                 \x20               }}\n\
                 \x20           }}\n\
                 \x20           self.call_insert_action(\"{}\", fields).await\n        }}\n",
                action.name, action.name
            ));
        }
        ActionLeg::Update { .. } => {
            let builder = update_builder_type(&action.name);
            out.push_str(&format!(
                "        fn {name}(&self, id: i64) -> {builder} {{\n\
                 \x20           {builder}::new(self.clone(), id)\n        }}\n",
            ));
        }
        ActionLeg::Delete { .. } => {
            out.push_str(&format!(
                "        async fn {name}(&self, id: i64) -> Result<usize> {{\n\
                 \x20           self.call_delete_action(\"{}\", id).await\n        }}\n",
                action.name
            ));
        }
        ActionLeg::CascadeDelete { .. } => {
            // Sig already errored out for cascade-as-primary.
        }
    }
}

/// `<action_name>` (snake_case) → `<ActionName>Update`.
fn update_builder_type(action_name: &str) -> String {
    let mut out = String::new();
    let mut cap = true;
    for c in action_name.chars() {
        if c == '_' {
            cap = true;
        } else if cap {
            out.extend(c.to_uppercase());
            cap = false;
        } else {
            out.push(c);
        }
    }
    out.push_str("Update");
    out
}

/// Emit a `<ActionName>Update` builder for an update-leg action.  The
/// builder accumulates `(column, value)` pairs via fluent setters and
/// dispatches to `Space::call_update_action` on `.execute().await`.
fn render_update_builder(out: &mut String, action: &Action, tables: &[SchemaTable]) {
    let ActionLeg::Update { table, .. } = &action.legs[0] else {
        unreachable!("caller filters for Update legs");
    };
    let schema = table_schema(table, tables);
    let builder = update_builder_type(&action.name);
    let writable: Vec<&ColumnDefinition> =
        schema.columns.iter().filter(|c| c.name != "id").collect();

    out.push_str(&format!(
        "    /// Builder for the `{}` update action.  Chain one setter\n\
         \x20   /// per column to change, then `.execute().await`.\n\
         \x20   pub struct {builder} {{\n\
         \x20       space: Space,\n\
         \x20       id: i64,\n\
         \x20       fields: Vec<(String, QueryParam)>,\n\
         \x20   }}\n\n",
        action.name
    ));

    out.push_str(&format!(
        "    impl {builder} {{\n\
         \x20       fn new(space: Space, id: i64) -> Self {{\n\
         \x20           Self {{ space, id, fields: Vec::new() }}\n\
         \x20       }}\n\n"
    ));

    for col in &writable {
        let ty = column_rust_type(col);
        let ident = rust_ident(&col.name);
        let qp = row_field_to_query_param(col, &ident);
        // FileRef setters return `Result<Self>` so the underlying
        // `file.hash()?` propagates; all other column types keep the
        // infallible `Self` setter that lets callers chain freely.
        if matches!(col.column_type, ColumnType::FileRef) {
            out.push_str(&format!(
                "        pub fn {ident}(mut self, {ident}: {ty}) -> Result<Self> {{\n\
                 \x20           self.fields.push((\"{}\".to_string(), {qp}));\n\
                 \x20           Ok(self)\n\
                 \x20       }}\n\n",
                col.name
            ));
        } else {
            out.push_str(&format!(
                "        pub fn {ident}(mut self, {ident}: {ty}) -> Self {{\n\
                 \x20           self.fields.push((\"{}\".to_string(), {qp}));\n\
                 \x20           self\n\
                 \x20       }}\n\n",
                col.name
            ));
        }
    }

    out.push_str(&format!(
        "        #[allow(async_fn_in_trait)]\n\
         \x20       pub async fn execute(self) -> Result<usize> {{\n\
         \x20           self.space.call_update_action(\"{}\", self.id, self.fields).await\n\
         \x20       }}\n\
         \x20   }}\n\n",
        action.name
    ));
}

fn table_schema<'a>(table: &str, tables: &'a [SchemaTable]) -> &'a Schema {
    tables
        .iter()
        .find(|t| t.table == table)
        .and_then(|t| t.schema.as_ref())
        .unwrap_or_else(|| {
            panic!("action targets table '{table}' which has no schema in the bundle")
        })
}

/// Map a `ColumnDefinition` to the Rust type used in the row struct
/// (and the action insert parameter).  Future column types extend this
/// match arm; the rest of the codegen consumes the result via
/// `row_field_to_query_param`.
fn column_rust_type(col: &ColumnDefinition) -> &'static str {
    match col.column_type {
        ColumnType::Integer => "i64",
        ColumnType::Real => "f64",
        ColumnType::String | ColumnType::Text => "String",
        ColumnType::Blob => "Vec<u8>",
        ColumnType::FileRef => "File",
        // List columns serialize as the list's anchor id (i64).  Until
        // the schema declares the list's item type, the row carries the
        // raw anchor; callers wrap it in a `encrypted_spaces_sdk::List<T>`
        // at the boundary.
        ColumnType::List => "i64",
    }
}

/// Map a column-value expression (e.g. `parent_id` inside an update
/// builder's setter) to the corresponding `QueryParam` constructor.
fn row_field_to_query_param(col: &ColumnDefinition, expr: &str) -> String {
    match col.column_type {
        ColumnType::Integer | ColumnType::List => format!("QueryParam::Integer({expr})"),
        ColumnType::Real => format!("QueryParam::Real({expr})"),
        ColumnType::String | ColumnType::Text => format!("QueryParam::Text({expr}.clone())"),
        ColumnType::FileRef => format!("QueryParam::Text({expr}.hash()?.to_string())"),
        ColumnType::Blob => format!("QueryParam::Blob({expr}.clone())"),
    }
}

/// Wrap a column / action name so it works as a Rust identifier even
/// when it collides with a keyword (`type` → `r#type`, etc.).
fn rust_ident(name: &str) -> String {
    match name {
        "type" | "ref" | "fn" | "mod" | "match" | "loop" | "move" | "where" | "async" | "await"
        | "yield" | "return" | "break" | "continue" | "as" | "in" | "let" | "if" | "else"
        | "for" | "while" | "do" | "true" | "false" | "impl" | "trait" | "struct" | "enum"
        | "union" | "const" | "static" | "use" | "pub" | "mut" | "unsafe" | "extern" | "crate"
        | "super" | "Self" | "dyn" | "box" => {
            format!("r#{name}")
        }
        _ => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::app_schema::{SchemaBundle, SchemaTable};

    fn sample_bundle() -> SchemaBundle {
        let messages = Schema {
            name: "messages".to_string(),
            columns: vec![
                ColumnDefinition {
                    name: "id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "channel_id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: true,
                },
                ColumnDefinition {
                    name: "content".to_string(),
                    column_type: ColumnType::Blob,
                    plaintext: false,
                    indexed: false,
                },
                ColumnDefinition {
                    name: "thread_id".to_string(),
                    column_type: ColumnType::Integer,
                    plaintext: true,
                    indexed: true,
                },
            ],
            auto_increment: true,
        };
        SchemaBundle {
            tables: vec![SchemaTable {
                table: "messages".to_string(),
                schema: Some(messages),
                rows: vec![],
            }],
            actions: vec![
                Action {
                    name: "send_message".to_string(),
                    asserts: vec![],
                    legs: vec![ActionLeg::Insert {
                        table: "messages".to_string(),
                    }],
                },
                Action {
                    name: "delete_message".to_string(),
                    asserts: vec![],
                    legs: vec![ActionLeg::Delete {
                        table: "messages".to_string(),
                    }],
                },
            ],
            acl_only_via_actions: Default::default(),
        }
    }

    #[test]
    fn render_includes_actions_trait_with_generic_insert() {
        let bundle = sample_bundle();
        let out = render(&bundle, &[0u8; 32], &[0u32; 8], "/dev/null");
        assert!(out.contains("pub trait Actions"));
        // Insert helper is generic over `R: Serialize`; no row-type
        // intermediate is emitted by codegen.
        assert!(out.contains("async fn send_message<R: Serialize>(&self, row: &R) -> Result<i64>"));
        assert!(out.contains("async fn delete_message(&self, id: i64) -> Result<usize>"));
        assert!(!out.contains("pub struct MessagesRow"));
    }

    #[test]
    fn render_insert_impl_routes_through_serde() {
        let bundle = sample_bundle();
        let out = render(&bundle, &[0u8; 32], &[0u32; 8], "/dev/null");
        assert!(out.contains("::serde_json::to_value(row)"));
        assert!(out.contains(".call_insert_action(\"send_message\""));
    }

    #[test]
    fn render_omits_actions_trait_when_no_actions_declared() {
        let mut bundle = sample_bundle();
        bundle.actions.clear();
        let out = render(&bundle, &[0u8; 32], &[0u32; 8], "/dev/null");
        assert!(!out.contains("pub trait Actions"));
    }

    #[test]
    fn rust_ident_escapes_keywords() {
        assert_eq!(rust_ident("type"), "r#type");
        assert_eq!(rust_ident("normal_name"), "normal_name");
    }

    #[test]
    fn hash_backed_columns_codegen_as_logical_value_types() {
        let text_col = ColumnDefinition {
            name: "content".to_string(),
            column_type: ColumnType::Text,
            plaintext: false,
            indexed: false,
        };
        let blob_col = ColumnDefinition {
            name: "payload".to_string(),
            column_type: ColumnType::Blob,
            plaintext: false,
            indexed: false,
        };

        assert_eq!(column_rust_type(&text_col), "String");
        assert_eq!(
            row_field_to_query_param(&text_col, "content"),
            "QueryParam::Text(content.clone())"
        );
        assert_eq!(column_rust_type(&blob_col), "Vec<u8>");
        assert_eq!(
            row_field_to_query_param(&blob_col, "payload"),
            "QueryParam::Blob(payload.clone())"
        );
    }

    #[test]
    fn render_update_action_emits_builder_with_setters_and_execute() {
        let mut bundle = sample_bundle();
        bundle.actions = vec![Action {
            name: "edit_message".to_string(),
            asserts: vec![],
            legs: vec![ActionLeg::Update {
                table: "messages".to_string(),
                cols: None,
            }],
        }];
        let out = render(&bundle, &[0u8; 32], &[0u32; 8], "/dev/null");
        assert!(out.contains("pub struct EditMessageUpdate"));
        assert!(out.contains("fn edit_message(&self, id: i64) -> EditMessageUpdate"));
        assert!(out.contains("pub fn channel_id(mut self, channel_id: i64) -> Self"));
        assert!(out.contains("pub fn content(mut self, content: Vec<u8>) -> Self"));
        assert!(out.contains(".call_update_action(\"edit_message\", self.id, self.fields)"));
    }

    // ─── Tests for the FF guest ImageID file parser ───────────────────────

    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("create tempfile");
        file.write_all(contents.as_bytes()).expect("write tempfile");
        file.flush().expect("flush tempfile");
        file
    }

    // ─── parse_u32 ────────────────────────────────────────────────────────

    #[test]
    fn parse_u32_decimal() {
        assert_eq!(parse_u32("0").unwrap(), 0);
        assert_eq!(parse_u32("42").unwrap(), 42);
        assert_eq!(parse_u32("4294967295").unwrap(), u32::MAX);
    }

    #[test]
    fn parse_u32_hex_lowercase_prefix() {
        assert_eq!(parse_u32("0x0").unwrap(), 0);
        assert_eq!(parse_u32("0xff").unwrap(), 255);
        assert_eq!(parse_u32("0xdeadbeef").unwrap(), 0xdeadbeef);
        assert_eq!(parse_u32("0xffffffff").unwrap(), u32::MAX);
    }

    #[test]
    fn parse_u32_hex_uppercase_prefix() {
        assert_eq!(parse_u32("0XFF").unwrap(), 255);
        assert_eq!(parse_u32("0XDEADBEEF").unwrap(), 0xdeadbeef);
    }

    #[test]
    fn parse_u32_hex_mixed_case_digits() {
        // The prefix-strip is `0x`/`0X`, but the digits themselves go
        // through `u32::from_str_radix(s, 16)` which accepts mixed case.
        assert_eq!(parse_u32("0xDeAdBeEf").unwrap(), 0xdeadbeef);
    }

    #[test]
    fn parse_u32_rejects_decimal_overflow() {
        // u32::MAX + 1
        assert!(parse_u32("4294967296").is_err());
    }

    #[test]
    fn parse_u32_rejects_hex_overflow() {
        // 9 hex digits — exceeds u32
        assert!(parse_u32("0x100000000").is_err());
    }

    #[test]
    fn parse_u32_rejects_empty_string() {
        assert!(parse_u32("").is_err());
    }

    #[test]
    fn parse_u32_rejects_garbage() {
        assert!(parse_u32("not_a_number").is_err());
        assert!(parse_u32("0xZZ").is_err());
        // Plain `-1` is illegal for u32.
        assert!(parse_u32("-1").is_err());
        // Whitespace inside a single token: rejected at parse time.
        assert!(parse_u32("12 34").is_err());
    }

    // ─── read_image_id_from_file ──────────────────────────────────────────

    /// The exact format the Dockerfile produces: 8 decimal numbers on
    /// a single line, space-separated, trailing newline.
    #[test]
    fn read_image_id_dockerfile_format() {
        let file = write_tmp(
            "1322596265 1056232269 2006672428 3899389744 \
             2959694087 2412464369 2219810482 2938350792\n",
        );
        let got = read_image_id_from_file(file.path()).unwrap();
        assert_eq!(
            got,
            [
                1322596265, 1056232269, 2006672428, 3899389744, 2959694087, 2412464369, 2219810482,
                2938350792,
            ]
        );
    }

    /// Raw `methods.rs` array-literal snippet pasted in.
    #[test]
    fn read_image_id_methods_rs_snippet() {
        let file = write_tmp("[1062731616, 2942227993, 3652291461, 2543348237, 2768219337, 2224477943, 2907736369, 2281841076];");
        let got = read_image_id_from_file(file.path()).unwrap();
        assert_eq!(
            got,
            [
                1062731616, 2942227993, 3652291461, 2543348237, 2768219337, 2224477943, 2907736369,
                2281841076,
            ]
        );
    }

    /// All hex with the same value as the dockerfile-format test,
    /// proving the parser handles both bases.
    #[test]
    fn read_image_id_hex_format() {
        let file = write_tmp(
            "0x4ed537a9 0x3ef4d34d 0x779b642c 0xe86bf730 \
             0xb0695907 0x8fcb48f1 0x844f9eb2 0xaf23acc8",
        );
        let got = read_image_id_from_file(file.path()).unwrap();
        assert_eq!(
            got,
            [
                0x4ed537a9, 0x3ef4d34d, 0x779b642c, 0xe86bf730, 0xb0695907, 0x8fcb48f1, 0x844f9eb2,
                0xaf23acc8,
            ]
        );
    }

    /// Mixed bases in a single file are accepted because each token is
    /// parsed independently.
    #[test]
    fn read_image_id_mixed_bases() {
        let file = write_tmp("0x01 2 0x03 4 0x05 6 0x07 8");
        let got = read_image_id_from_file(file.path()).unwrap();
        assert_eq!(got, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// Line comments (everything after `#` on a line) are stripped
    /// before tokenisation. Whitespace between tokens is irrelevant.
    #[test]
    fn read_image_id_strips_line_comments_and_tolerates_whitespace() {
        let file = write_tmp(
            "# FF guest image ID extracted on 2026-05-26\n\
             # build sha256:b85abd63...\n\
             1 2  3\t4\n\
             5 6 7 8 # trailing comment ignored\n",
        );
        let got = read_image_id_from_file(file.path()).unwrap();
        assert_eq!(got, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn read_image_id_rejects_too_few_tokens() {
        let file = write_tmp("1 2 3 4 5 6 7");
        let err = read_image_id_from_file(file.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected 8 u32 tokens, found 7"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn read_image_id_rejects_too_many_tokens() {
        let file = write_tmp("1 2 3 4 5 6 7 8 9");
        let err = read_image_id_from_file(file.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected 8 u32 tokens, found 9"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn read_image_id_rejects_empty_file() {
        let file = write_tmp("");
        let err = read_image_id_from_file(file.path()).unwrap_err();
        assert!(err.to_string().contains("expected 8 u32 tokens, found 0"));
    }

    #[test]
    fn read_image_id_rejects_only_comments() {
        let file = write_tmp("# just a header\n# nothing else\n");
        let err = read_image_id_from_file(file.path()).unwrap_err();
        assert!(err.to_string().contains("expected 8 u32 tokens, found 0"));
    }

    #[test]
    fn read_image_id_rejects_invalid_token() {
        let file = write_tmp("1 2 3 not_a_number 5 6 7 8");
        let err = read_image_id_from_file(file.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("token #3"), "unexpected error message: {msg}");
        assert!(
            msg.contains("not_a_number"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn read_image_id_rejects_overflow_token() {
        let file = write_tmp("1 2 3 4 5 6 7 9999999999999");
        let err = read_image_id_from_file(file.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("token #7"), "unexpected error message: {msg}");
    }

    #[test]
    fn read_image_id_rejects_missing_file() {
        let path =
            std::path::PathBuf::from("/tmp/encrypted_spaces_codegen_definitely_does_not_exist_42");
        let err = read_image_id_from_file(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ENCRYPTED_SPACES_FF_IMAGE_ID_FILE="),
            "expected error to include env-var name for diagnosability: {msg}"
        );
    }
}
