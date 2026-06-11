//! Test utilities for creating a mock server with ChangeLog and ChangeResponse data
//!
//! This crate provides helper functions to generate test data for changelog-related tests.
//! It requires the full backend server infrastructure to create realistic test fixtures.

use base64::Engine as _;
use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::merk_storage::{
    build_column_kv_vecs, column_key_placeholder, get_row_data_from_query,
};
use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType, Schema};
use encrypted_spaces_backend::sign_change::sign_change;
use encrypted_spaces_backend::storage::Storage;
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_changelog_core::changelog::{
    Change, ChangeLog, ChangeResponse, OpType, ROOT_TREE_PATH,
};
use encrypted_spaces_crypto::signature::{Ed25519Signature, SignatureKeyPair};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Default UID used for test changes
pub const TEST_CLIENT_UID: u32 = 1;

/// Generate and store fresh test keys signing keys for each user
static TEST_AUTH_KEYS: OnceLock<Mutex<HashMap<u32, SignatureKeyPair<Ed25519Signature>>>> =
    OnceLock::new();

fn test_auth_keys() -> &'static Mutex<HashMap<u32, SignatureKeyPair<Ed25519Signature>>> {
    TEST_AUTH_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn test_auth_key_pair(uid: u32) -> SignatureKeyPair<Ed25519Signature> {
    let mut keys = test_auth_keys().lock().unwrap();
    keys.entry(uid)
        .or_insert_with(SignatureKeyPair::<Ed25519Signature>::new)
        .clone()
}

pub fn test_auth_key_string(uid: u32) -> String {
    let key_pair = test_auth_key_pair(uid);
    let json_bytes = serde_json::to_vec(key_pair.verification_key()).unwrap();
    base64::engine::general_purpose::STANDARD.encode(json_bytes)
}

pub fn sign_test_change(uid: u32, change: &mut Change) {
    let key_pair = test_auth_key_pair(uid);
    sign_change(&mut change.entry, &key_pair);
}

/// Returns the "products" schema used across changelog tests.
pub fn products_schema() -> Schema {
    Schema {
        name: "products".to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "name".to_string(),
                column_type: ColumnType::String,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "price".to_string(),
                column_type: ColumnType::Real,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: true,
    }
}

/// Returns the "_users" system table schema.
/// Must match the canonical definition in backend/src/internal_schemas.kdl.
pub fn users_schema() -> Schema {
    Schema {
        name: "_users".to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "update_key".to_string(),
                column_type: ColumnType::Blob,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "auth_key".to_string(),
                column_type: ColumnType::Blob,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "status".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: true,
    }
}

/// Initialise a `SpaceState` with the products and _users schemas, optionally
/// inserting user rows and setting the FF-proof batch size.
///
/// This is the shared setup used by both `TestServer` and the integration tests
/// in `experiments/ff_test`.
pub async fn init_test_server_state(batch_size: Option<usize>, user_uids: &[u32]) -> SpaceState {
    init_test_server_state_with_schema(batch_size, user_uids, vec![products_schema()]).await
}

/// Initialize a test server with custom schemas and users.
pub async fn init_test_server_state_with_schema(
    batch_size: Option<usize>,
    user_uids: &[u32],
    schemas: Vec<Schema>,
) -> SpaceState {
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([0u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    };

    let mut all_schemas = schemas;
    all_schemas.push(users_schema());

    let mut state = SpaceState::init_server(Some(&all_schemas), Some(init_cfg), batch_size)
        .await
        .unwrap();

    let setup_auth = AuthContext::new(None, SpaceId::from([0u8; 16]));
    for &uid in user_uids {
        let user_insert = user_registration_query(uid);
        state.db.insert(user_insert, &setup_auth).await.unwrap();
    }

    // Re-initialize the changelog so the hash chain starting link matches
    // the current Merk root (after setup inserts).
    let root = state.get_root_hash().await;
    state.changelog = ChangeLog::new(&root);
    // Mirror `reinitialize_changelog`: keep the per-user sigref view
    // coupled to the changelog reset. Harmless today (setup goes through
    // `state.db.insert` directly, not `handle_change`, so the map is
    // already empty), but keeps the invariant from rotting if anyone
    // later routes setup through the tracked-change path.
    state.sigref_map.clear();

    state
}

/// Build the insert query to register a user in the `_users` table.
///
/// `uid` is informational only (used to derive the test auth key); the
/// actual row id comes from the auto-increment counter, which callers
/// align with by seeding users in uid order starting at 1.
pub fn user_registration_query(uid: u32) -> Query {
    Query::new(
        "_users".to_string(),
        QueryOperation::Insert(vec![
            ("update_key".to_string(), QueryParam::Text(String::new())),
            (
                "auth_key".to_string(),
                QueryParam::Text(test_auth_key_string(uid)),
            ),
            ("status".to_string(), QueryParam::Integer(1)), // Full member
        ]),
    )
}

pub struct TestServer {
    state: SpaceState,
    /// Snapshot of the tree before changes were applied (needed for batch proof generation)
    tree_snapshot: Option<merk::Node>,
    /// The UID used for changelog entries in this test server
    user_uid: u32,
}

impl TestServer {
    pub fn changelog(&self) -> &ChangeLog {
        &self.state.changelog
    }
    pub fn responses(&self) -> &Vec<ChangeResponse> {
        &self.state.change_responses
    }
    pub fn tree_snapshot(&self) -> Option<&merk::Node> {
        self.tree_snapshot.as_ref()
    }
    /// Update the tree snapshot to the current state of the database.
    /// Call this after proving a batch to prepare for the next batch.
    pub fn update_tree_snapshot(&mut self) {
        self.tree_snapshot = self.state.db.snapshot();
    }
    /// Creates a new ChangeLog with the specified number of test changes.
    ///
    /// # Arguments
    /// * `length` - Number of changes to generate
    /// * `value_size` - Optional size (in bytes) for each change's value. When `Some(n)`,
    ///   the name field is padded so the serialized row is approximately `n` bytes.
    ///   When `None`, default test data (Apple/Banana/Cherry rows) is used.
    pub async fn new_for_tests(length: usize, value_size: Option<usize>) -> Self {
        Self::new_for_tests_impl(length, value_size, TEST_CLIENT_UID, true).await
    }

    /// Creates a new ChangeLog with the specified number of test changes and a custom user UID.
    /// The `_users` table will contain a row for this UID.
    ///
    /// # Arguments
    /// * `length` - Number of changes to generate
    /// * `value_size` - Optional size (in bytes) for each change's value.
    /// * `user_uid` - The UID to use for changelog entries. A matching row is inserted to `_users`.
    pub async fn new_for_tests_with_uid(
        length: usize,
        value_size: Option<usize>,
        user_uid: u32,
    ) -> Self {
        Self::new_for_tests_impl(length, value_size, user_uid, true).await
    }

    /// Creates a new ChangeLog where entries reference a user that does NOT exist in `_users`.
    /// This is used to test that proofs correctly reject unknown users.
    pub async fn new_for_tests_unknown_user(length: usize) -> Self {
        Self::new_for_tests_impl(length, None, TEST_CLIENT_UID, false).await
    }

    async fn new_for_tests_impl(
        length: usize,
        value_size: Option<usize>,
        user_uid: u32,
        insert_user_row: bool,
    ) -> Self {
        let user_uids: &[u32] = if insert_user_row { &[user_uid] } else { &[] };
        let mut state = init_test_server_state(None, user_uids).await;

        // Take initial tree snapshot before any changes are made
        let tree_snapshot = state.db.snapshot();

        let client_uid = user_uid;
        let auth1 = AuthContext::new(Some(client_uid as i64), SpaceId::from([0u8; 16]));
        let mut client_current_change_id = 0;
        let mut client_my_last_change_id = 0;

        // When a specific value_size is requested, build a padded name string so the
        // serialized row is approximately that many bytes. Otherwise use empty string
        // (the default test data names will be used instead).
        let padded_name: String = match value_size {
            Some(vs) => {
                let json_overhead = r#"{"name":"","price":2.0}"#.len();
                let name_len = if vs > json_overhead {
                    vs - json_overhead
                } else {
                    1
                };
                "X".repeat(name_len)
            }
            None => String::new(),
        };

        let test_rows: Vec<(i64, &str, f64)> = vec![
            (0, "Apple", 2.0),
            (0, "Banana", 1.5),
            (0, "Cherry", 3.0),
            (0, "Apple", 1.0),
            (0, "Banana", 2.5),
            (0, "Cherry", 3.2),
        ];

        let mut num_changes = 0;
        loop {
            for (id, name, price) in &test_rows {
                let actual_name = if padded_name.is_empty() {
                    name.to_string()
                } else {
                    padded_name.clone()
                };
                println!(
                    "Creating client change, insert (id, name, price) = ({id}, {}, {price})",
                    if padded_name.is_empty() {
                        name.to_string()
                    } else {
                        format!("[{}B padded]", padded_name.len())
                    }
                );

                let query = Query::new(
                    "products".to_string(),
                    QueryOperation::Insert(vec![
                        ("id".to_string(), QueryParam::Integer(*id)),
                        ("name".to_string(), QueryParam::Text(actual_name)),
                        ("price".to_string(), QueryParam::Real(*price)),
                    ]),
                );

                let (_, column_data) = get_row_data_from_query(&query).unwrap();
                let (col_keys, col_values) = build_column_kv_vecs(&column_data, |col| {
                    column_key_placeholder("products", col)
                });
                let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
                let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

                let mut change = Change::new(
                    OpType::Insert,
                    client_uid,
                    ROOT_TREE_PATH,
                    &key_refs,
                    &val_refs,
                    client_current_change_id,
                    client_my_last_change_id,
                    state.changelog.current_root(), // The current CLC
                )
                .unwrap();
                sign_test_change(client_uid, &mut change);

                let _response = state.handle_change(&change, &auth1).await;

                num_changes += 1;
                client_current_change_id += 1;
                client_my_last_change_id += 1;
                if num_changes == length {
                    return Self {
                        state,
                        tree_snapshot,
                        user_uid,
                    };
                }
            }
        }
    }

    pub async fn add_more_changes(&mut self, num_new_changes: usize) {
        let client_uid = self.user_uid;
        let auth1 = AuthContext::new(Some(client_uid as i64), SpaceId::from([0u8; 16]));
        let mut client_current_change_id = self.state.changelog.num_changes();
        let mut client_my_last_change_id = client_current_change_id;
        let mut num_changes = 0;

        loop {
            for (id, name, price) in &[
                (0, "Apple", 2.0),
                (0, "Banana", 1.5),
                (0, "Cherry", 3.0),
                (0, "Apple", 1.0),
                (0, "Banana", 2.5),
                (0, "Cherry", 3.2),
            ] {
                println!(
                    "Creating client change, insert (id, name, price) = ({id}, {name}, {price})"
                );

                let query = Query::new(
                    "products".to_string(),
                    QueryOperation::Insert(vec![
                        ("id".to_string(), QueryParam::Integer(*id)),
                        ("name".to_string(), QueryParam::Text(name.to_string())),
                        ("price".to_string(), QueryParam::Real(*price)),
                    ]),
                );

                let (_, column_data) = get_row_data_from_query(&query).unwrap();
                let (col_keys, col_values) = build_column_kv_vecs(&column_data, |col| {
                    column_key_placeholder("products", col)
                });
                let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
                let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

                let mut change = Change::new(
                    OpType::Insert,
                    client_uid,
                    ROOT_TREE_PATH,
                    &key_refs,
                    &val_refs,
                    client_current_change_id,
                    client_my_last_change_id,
                    self.state.changelog.current_root(), // Current CLC
                )
                .unwrap();
                sign_test_change(client_uid, &mut change);

                let _response = self.state.handle_change(&change, &auth1).await;

                num_changes += 1;
                client_current_change_id += 1;
                client_my_last_change_id += 1;
                if num_changes == num_new_changes {
                    return;
                }
            }
        }
    }

    /// Creates a new TestServer with interleaved changes from multiple users.
    /// The pattern repeats the user_uids slice, so [1,2] with length=5 gives: 1,2,1,2,1.
    /// Returns the TestServer along with the per-user last change_id map (for verification).
    pub async fn new_multi_user(length: usize, user_uids: &[u32]) -> (Self, HashMap<u32, u32>) {
        assert!(!user_uids.is_empty(), "need at least one user");

        let mut state = init_test_server_state(None, user_uids).await;
        let tree_snapshot = state.db.snapshot();

        // Track each user's last change_id for sigref
        let mut user_last_change: HashMap<u32, u32> = HashMap::new();
        let mut global_change_id: u32 = 0;

        let test_rows: Vec<(&str, f64)> = vec![
            ("Apple", 2.0),
            ("Banana", 1.5),
            ("Cherry", 3.0),
            ("Date", 1.0),
            ("Elderberry", 2.5),
            ("Fig", 3.2),
        ];

        for i in 0..length {
            let uid = user_uids[i % user_uids.len()];
            let auth = AuthContext::new(Some(uid as i64), SpaceId::from([0u8; 16]));
            let (name, price) = &test_rows[i % test_rows.len()];

            let query = Query::new(
                "products".to_string(),
                QueryOperation::Insert(vec![
                    ("id".to_string(), QueryParam::Integer(0)),
                    ("name".to_string(), QueryParam::Text(name.to_string())),
                    ("price".to_string(), QueryParam::Real(*price)),
                ]),
            );

            let (_, column_data) = get_row_data_from_query(&query).unwrap();
            let (col_keys, col_values) =
                build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
            let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
            let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

            let my_last = user_last_change.get(&uid).copied().unwrap_or(0);

            let mut change = Change::new(
                OpType::Insert,
                uid,
                ROOT_TREE_PATH,
                &key_refs,
                &val_refs,
                global_change_id,
                my_last,
                state.changelog.current_root(),
            )
            .unwrap();
            sign_test_change(uid, &mut change);

            let _response = state.handle_change(&change, &auth).await;

            global_change_id += 1;
            user_last_change.insert(uid, global_change_id); // change_ids are 1-based
        }

        let server = Self {
            state,
            tree_snapshot,
            user_uid: user_uids[0],
        };
        (server, user_last_change)
    }
}

/// Insert an ACL rule into the `_access_control` table and re-finalize the blob.
/// Call this after `init_test_server_state` and before creating changelog entries.
pub async fn insert_acl_rule(
    state: &mut SpaceState,
    resource_name: &str,
    operation: &str,
    rule_json: &str,
) {
    let auth = AuthContext::new(None, SpaceId::from([0u8; 16]));
    let query = Query::new(
        "_access_control".to_string(),
        QueryOperation::Insert(vec![
            (
                "resource_name".to_string(),
                QueryParam::Text(resource_name.to_string()),
            ),
            (
                "operation".to_string(),
                QueryParam::Text(operation.to_string()),
            ),
            (
                "rule_json".to_string(),
                QueryParam::Text(rule_json.to_string()),
            ),
        ]),
    );
    state.db.insert(query, &auth).await.unwrap();
    // Re-finalize the ACL blob so the new rule is visible to the verifier
    state.db.finalize_acl_blob().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify ACL blob round-trip: write via finalize_acl_blob, read back, deserialize.
    #[tokio::test]
    async fn acl_rule_round_trip() {
        let mut state = init_test_server_state(None, &[TEST_CLIENT_UID]).await;

        // Initially no rule for (products, write).
        let initial = state
            .db
            .read_acl_rule("products", "write")
            .expect("read_acl_rule");
        assert!(initial.is_none(), "expected no rule, got: {initial:?}");

        // Insert a rule and re-finalize. The rule must reference an Integer
        // column that exists in the target table — `finalize_acl_blob` lints
        // both. `products.id` satisfies both constraints.
        insert_acl_rule(
            &mut state,
            "products",
            "write",
            r#"{"Comparison":{"left":{"Column":{"namespace":"Resource","name":"id"}},"op":"Equal","right":"AuthUserId"}}"#,
        )
        .await;

        let rule = state
            .db
            .read_acl_rule("products", "write")
            .expect("read_acl_rule");
        assert!(rule.is_some(), "expected rule, got: {rule:?}");
    }
}
