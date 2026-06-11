//! Shadow state and op enum for the SDK fuzzer.
//!
//! `ModelState` mirrors the small subset of SDK state the fuzzer needs to
//! generate valid follow-up ops and check invariants. We deliberately do *not*
//! shadow internals like the changelog or key history.

use std::collections::HashMap;

use encrypted_spaces_acl_types::{Action, Assertion};
use encrypted_spaces_backend::access_control::{AccessOperation, AccessRule};
use encrypted_spaces_backend::schema::{ColumnType, Schema};
use encrypted_spaces_sdk::Space;
use serde_json::Value;

/// Ordered `(server_assigned_key, value)` pairs mirroring a live List cell.
pub type ListContents = Vec<(Vec<u8>, Value)>;

#[derive(Debug, Clone)]
pub enum FuzzOp {
    /// Bootstrap-only: `LocalTransport`'s `create_table` is a test helper,
    /// not a public-facing SDK op. Never picked at runtime.
    CreateTable,
    Insert,
    SelectAll,
    /// Select with a random (column, operator, values) predicate over PK or
    /// any indexed column. Subsumes the v1 `SelectByPk`.
    SelectByPredicate,
    /// Update with a random predicate over PK or any indexed column.
    UpdateByPredicate,
    /// Delete with a random predicate over PK or any indexed column.
    DeleteByPredicate,
    /// Inner join between two tables on (fk_col, pk_col).
    SelectJoin,
    InviteUser,
    RemoveUser,
    NegReservedNameCreate,
    NegReservedNameInsert,

    // ─── List ops ─────────────────────────────────────────────────────
    ListAppend,
    ListInsertAfter,
    ListUpdate,
    ListDelete,
    ListGetAll,

    // ─── TextArea ops ─────────────────────────────────────────────────
    TextAreaAppendString,
    TextAreaInsertString,
    TextAreaDelete,
    TextAreaSnapshot,

    // ─── File ops ─────────────────────────────────────────────────────
    FileDownload,

    // ─── Negative: explicit-id collision ──────────────────────────────
    /// Try to insert a row with an id that's already taken on an
    /// `auto_increment = false` table. Must be rejected.
    NegDuplicateExplicitId,

    // ─── Actions ──────────────────────────────────────────────────────
    /// Invoke a registered action through its codegen-shaped SDK entry
    /// point (`call_insert_action` / `call_update_action` /
    /// `call_delete_action`).
    CallAction,
}

/// One client identity backed by a real `Space` against the shared
/// in-memory server. Each actor signs its own writes with its own key.
pub struct Actor {
    pub uid: i64,
    pub space: Space,
}

pub struct ModelState {
    pub tables: HashMap<String, TableModel>,
    /// Live actors. The first entry is the host (uid = 1).
    pub actors: Vec<Actor>,
    /// Hash → uploaded plaintext bytes, mirroring the in-memory file store.
    /// We use this to verify `FileHandle::download(hash).data()` against
    /// what we originally uploaded.
    pub files: HashMap<String, Vec<u8>>,
    /// `(resource_name, operation) → AND-combined rule`. Matches the
    /// server's per-(table, op) ACL keys, so model-side
    /// `AccessRule::evaluate` should agree with the server's E&V
    /// enforcement on each Write/Delete change.
    pub acl_rules: HashMap<(String, AccessOperation), AccessRule>,
    /// Registered actions keyed by name.  Matches the server's
    /// `action_storage_key(primary_table, name)` entries and the SDK's
    /// local `register_action` cache.  Used by `do_call_action` to pick
    /// a target and by invariants to predict the outcome.
    pub actions: HashMap<String, Action>,
    /// `(table, op) → list of action names`.  Matches the server's
    /// `acl_only_via_actions_key(table, op)` entries.  When a key is
    /// present, direct insert/update/delete on `table` for `op` is
    /// rejected; the entry must invoke a listed action.
    pub action_gating: HashMap<(String, String), Vec<String>>,
}

pub struct TableModel {
    pub schema: Schema,
    /// Server-assigned id -> last-known logical row (id field present).
    /// For `auto_increment = false` tables this is keyed by client-supplied
    /// id; same shape either way.
    pub rows: HashMap<i64, Value>,
    /// Next id to use when inserting into an `auto_increment = false` table.
    /// Ignored when the schema is auto-increment.
    pub next_explicit_id: i64,
    /// Next id the authenticated insert verifier will allocate for an
    /// auto-increment table. Used when modeling id-based Write ACLs for
    /// inserts, because the server evaluates those rules against the resolved
    /// row id rather than the client JSON's `id: null` placeholder.
    pub next_auto_id: i64,
    /// `ColumnType::List` cells flagged as "use as TextArea". Per
    /// `(row_id, col_name)`. The fuzzer fixes the flavour at row-insert time
    /// so list / textarea ops on the same cell don't fight each other.
    pub textarea_flavoured: HashMap<(i64, String), bool>,
    /// Live List entries per `(row_id, col_name)` — the ordered
    /// `(server_key, value)` pairs the SDK has accepted. Append / insert
    /// extend this; update mutates a value; delete removes by key.
    pub list_state: HashMap<(i64, String), ListContents>,
    /// Live TextArea content per `(row_id, col_name)`. Mirrors the SDK's
    /// post-edit string after every append / insert / delete op.
    pub textarea_state: HashMap<(i64, String), String>,
    /// `ColumnType::FileRef` cells: `(row_id, col_name) -> uploaded hash`.
    /// We can look up the bytes via `ModelState.files`.
    pub file_state: HashMap<(i64, String), String>,
}

impl TableModel {
    pub fn from_schema(schema: Schema) -> Self {
        Self {
            // `auto_increment = false` tables reject `id = 0` and `id < 0`
            // (`backend/storage-encoding/src/id_validation.rs`); first valid
            // explicit id is 1.
            next_explicit_id: 1,
            next_auto_id: 1,
            schema,
            rows: HashMap::new(),
            textarea_flavoured: HashMap::new(),
            list_state: HashMap::new(),
            textarea_state: HashMap::new(),
            file_state: HashMap::new(),
        }
    }

    /// Scalar non-id columns suitable for `UPDATE … SET col = …`. Excludes
    /// `ColumnType::List` (mutated via list / textarea ops) and
    /// `ColumnType::FileRef` (mutated by uploading a new file and rebinding
    /// the hash via `Insert`, not by `set`).
    pub fn updatable_scalar_columns(&self) -> impl Iterator<Item = (&str, &ColumnType)> {
        self.schema
            .columns
            .iter()
            .filter(|c| {
                c.name != "id" && !matches!(c.column_type, ColumnType::List | ColumnType::FileRef)
            })
            .map(|c| (c.name.as_str(), &c.column_type))
    }

    /// Column names of every `ColumnType::List` column.
    pub fn list_columns(&self) -> Vec<String> {
        self.schema
            .columns
            .iter()
            .filter(|c| matches!(c.column_type, ColumnType::List))
            .map(|c| c.name.clone())
            .collect()
    }

    /// Column names of every `ColumnType::FileRef` column.
    pub fn fileref_columns(&self) -> Vec<String> {
        self.schema
            .columns
            .iter()
            .filter(|c| matches!(c.column_type, ColumnType::FileRef))
            .map(|c| c.name.clone())
            .collect()
    }
}

impl ModelState {
    pub fn new(host: Actor) -> Self {
        Self {
            tables: HashMap::new(),
            actors: vec![host],
            files: HashMap::new(),
            acl_rules: HashMap::new(),
            actions: HashMap::new(),
            action_gating: HashMap::new(),
        }
    }

    /// Record an action installed via [`Space::add_action`].  The name
    /// is unique across the schema (the server rejects duplicates at
    /// import time), so a second call with the same name overwrites.
    pub fn record_action(&mut self, action: Action) {
        self.actions.insert(action.name.clone(), action);
    }

    /// Record an `only_via_actions` gating clause for `(table, op_str)`
    /// where `op_str` is `"write"` or `"delete"`.
    pub fn record_action_gating(&mut self, table: String, op_str: String, allowed: Vec<String>) {
        self.action_gating.insert((table, op_str), allowed);
    }

    /// Set of action names currently registered.  Used by the
    /// generator to avoid collisions.
    pub fn action_names(&self) -> std::collections::HashSet<String> {
        self.actions.keys().cloned().collect()
    }

    pub fn has_actions(&self) -> bool {
        !self.actions.is_empty()
    }

    /// Evaluate every assertion of `action` against `(auth_uid,
    /// self_row)`.  Mirrors `evaluate_action_asserts` in the verifier's
    /// `action_op.rs`, minus `Assertion::Exists` (cross-table reads
    /// aren't shadowed in the model; treat as unknown → true so we
    /// don't false-negative).  Returns true iff every assertion holds.
    pub fn assert_pass(
        &self,
        action: &Action,
        auth_uid: Option<i64>,
        self_row: &serde_json::Map<String, Value>,
    ) -> bool {
        action
            .asserts
            .iter()
            .all(|a| evaluate_assertion(a, auth_uid, self_row))
    }

    /// Record a rule we just installed via
    /// `LocalTransport::add_access_rule`. Matches the server's behaviour:
    /// multiple rules on the same `(resource, operation)` are
    /// AND-combined (see `MerkStorage::finalize_acl_blob`).
    pub fn record_acl_rule(
        &mut self,
        resource: String,
        operation: AccessOperation,
        rule: AccessRule,
    ) {
        let key = (resource, operation);
        self.acl_rules
            .entry(key)
            .and_modify(|existing| *existing = existing.clone().and(rule.clone()))
            .or_insert(rule);
    }

    /// Mirror of the server's per-row ACL filter (see
    /// `validate_insert_access` for inserts and the rule evaluation
    /// inside `MerkStorage::update_or_delete` for updates/deletes):
    /// given a `(resource, op, actor_uid, row)`, return whether the
    /// server would let the row through.
    ///
    /// Tables with no rule for `(resource, op)` are treated as fully
    /// open, matching `load_access_rule`'s `Ok(None)` short-circuit.
    pub fn row_allowed(
        &self,
        resource: &str,
        operation: &AccessOperation,
        actor_uid: Option<i64>,
        row: &Value,
    ) -> bool {
        match self
            .acl_rules
            .get(&(resource.to_string(), operation.clone()))
        {
            None => true,
            Some(rule) => rule.evaluate(actor_uid, Some(row)).unwrap_or(false),
        }
    }

    pub fn host(&self) -> &Actor {
        &self.actors[0]
    }

    pub fn has_tables(&self) -> bool {
        !self.tables.is_empty()
    }

    pub fn has_rows(&self) -> bool {
        self.tables.values().any(|t| !t.rows.is_empty())
    }

    pub fn n_actors(&self) -> usize {
        self.actors.len()
    }

    /// Any `(table, row_id, col)` tuple that has a list-flavoured List cell
    /// (i.e. not a TextArea). Used by list ops to find a target.
    pub fn list_cells(&self) -> Vec<(String, i64, String)> {
        let mut out = Vec::new();
        for (table_name, t) in &self.tables {
            for ((row_id, col), is_ta) in &t.textarea_flavoured {
                if !is_ta {
                    out.push((table_name.clone(), *row_id, col.clone()));
                }
            }
        }
        out
    }

    /// Any `(table, row_id, col)` tuple that has a non-empty list-flavoured
    /// List cell. Used by list ops that need at least one entry.
    pub fn nonempty_list_cells(&self) -> Vec<(String, i64, String)> {
        self.list_cells()
            .into_iter()
            .filter(|(t, r, c)| {
                self.tables[t]
                    .list_state
                    .get(&(*r, c.clone()))
                    .map(|v| !v.is_empty())
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Any `(table, row_id, col)` tuple that has a textarea-flavoured List
    /// cell. Used by textarea ops to find a target.
    pub fn textarea_cells(&self) -> Vec<(String, i64, String)> {
        let mut out = Vec::new();
        for (table_name, t) in &self.tables {
            for ((row_id, col), is_ta) in &t.textarea_flavoured {
                if *is_ta {
                    out.push((table_name.clone(), *row_id, col.clone()));
                }
            }
        }
        out
    }

    /// Any `(table, row_id, col)` tuple that has a non-empty textarea-flavoured
    /// List cell. Used by textarea delete which needs content to delete.
    pub fn nonempty_textarea_cells(&self) -> Vec<(String, i64, String)> {
        self.textarea_cells()
            .into_iter()
            .filter(|(t, r, c)| {
                self.tables[t]
                    .textarea_state
                    .get(&(*r, c.clone()))
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Any `(table, row_id, col, hash)` tuple with an uploaded FileRef cell.
    pub fn file_cells(&self) -> Vec<(String, i64, String, String)> {
        let mut out = Vec::new();
        for (table_name, t) in &self.tables {
            for ((row_id, col), hash) in &t.file_state {
                out.push((table_name.clone(), *row_id, col.clone(), hash.clone()));
            }
        }
        out
    }

    /// Tables for which the picker should consider an explicit-id insert
    /// (i.e. `auto_increment = false`).
    pub fn has_explicit_id_tables(&self) -> bool {
        self.tables.values().any(|t| !t.schema.auto_increment)
    }
}

fn evaluate_assertion(
    assertion: &Assertion,
    auth_uid: Option<i64>,
    self_row: &serde_json::Map<String, Value>,
) -> bool {
    use encrypted_spaces_acl_types::Assertion;
    match assertion {
        Assertion::Rule(rule) => rule
            .evaluate_with_self(auth_uid, None, Some(self_row))
            .unwrap_or(false),
        // The model can't follow cross-table reads (those would need a
        // mirror of the index-read path).  Assume true so the fuzzer
        // doesn't false-reject; the verifier will still catch a real
        // mismatch.
        Assertion::Exists { .. } => true,
        Assertion::And(a, b) => {
            evaluate_assertion(a, auth_uid, self_row) && evaluate_assertion(b, auth_uid, self_row)
        }
        Assertion::Or(a, b) => {
            evaluate_assertion(a, auth_uid, self_row) || evaluate_assertion(b, auth_uid, self_row)
        }
        Assertion::Not(inner) => !evaluate_assertion(inner, auth_uid, self_row),
    }
}
