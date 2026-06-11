//! Chat-shaped FF cycle benchmarks.
//!
//! Measures RISC0 guest user cycles for a realistic chat workload using the
//! Tauri demo app schema, ACL rules, secondary indexes, action-routed
//! operations with existence assertions, and cascade deletes.
//!
//! Run with:
//!   RISC0_DEV_MODE=1 cargo bench -p encrypted-spaces-ff-test --bench ffchat_cycle_benchmarks
//!
//! Add `FFCHAT_TIMED_GUEST=1` to use `EXTEND_FF_BENCH_ELF` and print
//! guest timing buckets from `FastForwardJournal`.

mod ff_common;

use chrono::Utc;
use encrypted_spaces_acl_types::Action;
use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::app_schema::SchemaBundle;
use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_backend::storage::Storage;
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_changelog_core::changelog::{initial_clc_state, ChangeLog};
use encrypted_spaces_sdk::schema::ApplicationSchema;
use encrypted_spaces_sdk::{File, List, Space, TextArea};
use ff_common::SharedStateTransport;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

fn pick_indices(n: usize, count: usize, seed: u64) -> Vec<usize> {
    let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
    let mut indices: Vec<usize> = (0..n).collect();
    indices.shuffle(&mut rng);
    indices.truncate(count);
    indices
}

// ─── Domain types ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Task {
    title: String,
    done: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Channel {
    id: Option<i64>,
    name: String,
    description: Option<String>,
    tasks: List<Task>,
    notes: TextArea,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    id: Option<i64>,
    channel_id: i64,
    user_id: i64,
    thread_id: i64,
    content: String,
    timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Reaction {
    id: Option<i64>,
    channel_id: i64,
    message_id: i64,
    user_id: i64,
    emoji: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UsersMeta {
    id: Option<i64>,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Inode {
    id: Option<i64>,
    parent_id: i64,
    author_id: i64,
    name: String,
    #[serde(rename = "type")]
    inode_type: i64,
    size: i64,
    ctime: i64,
    mtime: i64,
    mime_type: String,
    file_hash: File,
}

// ─── Deterministic fixture ────────────────────────────────────────────────

const AUTH_UID: i64 = 1;
const SEEDED_USERS: usize = 100;
const SEEDED_CHANNELS: usize = 10;
const SEEDED_TASKS: usize = 50;
const SEEDED_MESSAGES: usize = 10_000;
const SEEDED_REACTIONS: usize = 1_000;
const SEEDED_REPLY_SELECTION_SEED: u64 = 0xFF_C0_A7_01;
const SEEDED_REPLY_PARENT_SEED: u64 = 0xFF_C0_A7_02;
const SEEDED_REACTION_SEED: u64 = 0xFF_C0_A7_03;

const INODE_FILE: i64 = 1;
const INODE_FOLDER: i64 = 2;

const FS_BRANCHING: usize = 5;
const FS_LEVELS: usize = 4;
const FS_DIRS: usize = 780;
const FS_FILES_PER_DIR: usize = 10;
const FS_FILES: usize = 7_800;
const FS_LEVEL2_DIRS: usize = 25;
const FS_LEVEL2_SUBTREE_DIRS: usize = 31;
const FS_LEVEL2_SUBTREE_FILES: usize = 310;
const FS_LEVEL2_SUBTREE_INODES: usize = 341;

const FS_FILE_INSERT_SEED: u64 = 0xF5F1_1001;
const FS_FILE_DELETE_SEED: u64 = 0xF5F1_1002;
const FS_DIR_INSERT_SEED: u64 = 0xF5F1_1003;
const FS_DIR_DELETE_SEED: u64 = 0xF5F1_1004;

// Manual benchmark schema/version marker for result-file comparisons. Bump
// this when the fixture, operation mix, or reporting semantics change.
const BENCHMARK_VERSION: &str = "1";

struct ChatFixture {
    state: Arc<Mutex<SpaceState>>,
    bench_chain: Arc<Mutex<ff_common::BenchProofChain>>,
    space: Space,
    #[allow(dead_code)]
    baseline_root: [u8; 32],
    channel_ids: Vec<i64>,
    message_ids: Vec<i64>,
    message_channel_ids: Vec<i64>,
    message_thread_ids: Vec<i64>,
    #[allow(dead_code)]
    reaction_ids: Vec<i64>,
    task_channel_id: i64,
    task_keys: Vec<Vec<u8>>,
}

fn fixed_text(prefix: &str, idx: usize, len: usize) -> String {
    let chunk = format!("{prefix}-{idx:04}-");
    let mut text = String::with_capacity(len);
    while text.len() < len {
        text.push_str(&chunk);
    }
    text.truncate(len);
    text
}

fn fs_file_hash(dir_idx: usize, file_idx: usize) -> String {
    format!("{:064x}", ((dir_idx as u128) << 32) | file_idx as u128)
}

fn fs_inserted_file_hash(i: usize) -> String {
    format!("{:064x}", 0xF5F1_0000_0000_0000u128 | i as u128)
}

fn fs_file_name(dir_idx: usize, file_idx: usize) -> String {
    format!("seed-file-{dir_idx:04}-{file_idx:02}.bin")
}

fn fs_dir_name(level: usize, ordinal: usize) -> String {
    format!("seed-dir-l{level}-{ordinal:04}")
}

fn fs_timestamp(i: usize) -> i64 {
    1_700_200_000 + i as i64
}

async fn seed_extra_users_meta_direct(state: &Arc<Mutex<SpaceState>>) {
    // The demo ACL only lets a user write their own display-name row.
    // These extra names are baseline-only fixture data, inserted after SDK
    // seeding and before the changelog reset.
    let auth = AuthContext::anonymous(SpaceId::from([0u8; 16]));
    let state = state.lock().await;
    for uid in 2..=SEEDED_USERS as i64 {
        let query = Query::new(
            "users_meta".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(uid)),
                (
                    "name".to_string(),
                    QueryParam::Text(format!("bench-user-{uid:03}")),
                ),
            ]),
        );
        state
            .db
            .insert(query, &auth)
            .await
            .expect("direct seed users_meta insert");
    }
}

// ─── Tauri schema ──────────────────────────────────────────────────────────

const TAURI_APP_SCHEMA_BYTES: &[u8] = include_bytes!("../../../demos/tauri/app_schema.kdl");

fn tauri_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../demos/tauri/app_schema.kdl")
}

fn tauri_schema_bundle() -> SchemaBundle {
    let text = std::str::from_utf8(TAURI_APP_SCHEMA_BYTES).expect("Tauri schema is UTF-8");
    encrypted_spaces_backend::schema_kdl::parse_schema_bundle(text).expect("Tauri schema parses")
}

fn tauri_schemas() -> Vec<Schema> {
    tauri_schema_bundle()
        .tables
        .into_iter()
        .filter_map(|table| table.schema)
        .collect()
}

fn tauri_actions() -> Vec<Action> {
    tauri_schema_bundle().actions
}

fn register_tauri_actions(space: &Space) {
    for action in tauri_actions() {
        space.register_action(action);
    }
}

// ─── Initialization ────────────────────────────────────────────────────────

async fn init_chat_state_and_space() -> (Arc<Mutex<SpaceState>>, Space) {
    let schemas = tauri_schemas();
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([0u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::SchemaFile(tauri_schema_path().display().to_string()),
    };
    let mut state = SpaceState::init_server(None, Some(init_cfg), Some(1_000_000_000))
        .await
        .expect("init_server");
    state.tree_snapshot = state.db.snapshot();
    let app_root = state.db.root_hash();

    let state = Arc::new(Mutex::new(state));
    let app_schema = ApplicationSchema::for_testing(schemas, app_root);

    let space = Space::create(SharedStateTransport::new(Arc::clone(&state)), app_schema)
        .await
        .expect("Space::create");
    register_tauri_actions(&space);

    (state, space)
}

async fn reset_to_prepopulated_baseline(
    state: &Arc<Mutex<SpaceState>>,
    space: Space,
) -> (Space, [u8; 32]) {
    let baseline_root = {
        let mut state = state.lock().await;
        let current_root = state.db.root_hash();
        state.changelog = ChangeLog::new(&current_root);
        state.change_responses.clear();
        state.ff_proof = None;
        state.tree_snapshot = state.db.snapshot();
        // Mirror `reinitialize_changelog`: clear the per-user sigref view
        // alongside the changelog reset, for symmetry with the production
        // path and to keep this baseline reset future-proof.
        state.sigref_map.clear();

        assert_eq!(state.changelog.num_changes(), 0);
        assert_eq!(state.changelog.proven_up_to, 0);
        assert!(state.change_responses.is_empty());
        assert!(state.ff_proof.is_none());
        assert_eq!(state.db.root_hash(), current_root);
        assert_eq!(
            state
                .tree_snapshot
                .as_ref()
                .expect("tree_snapshot after prepopulation reset")
                .hash(),
            current_root
        );

        current_root
    };

    let mut snapshot = space.snapshot().await.expect("snapshot");
    let state_obj = snapshot
        .get_mut("state")
        .and_then(Value::as_object_mut)
        .expect("snapshot.state must be an object");
    state_obj.insert(
        "current_data_commitment".to_string(),
        serde_json::to_value(baseline_root).unwrap(),
    );
    state_obj.insert(
        "initial_dc".to_string(),
        serde_json::to_value(baseline_root).unwrap(),
    );
    state_obj.insert("current_change_id".to_string(), serde_json::json!(0u32));
    state_obj.insert("my_last_change_id".to_string(), serde_json::json!(0u32));
    // The baseline reset rewinds the changelog to genesis, so the
    // client's per-user sigref view (advanced by `CreateSpace` and the
    // pre-population that follows) is stale. Clear it so the first
    // post-restore signed change (sig_ref=0) passes
    // `check_sigref_continuity` on both client and server (issue #30).
    state_obj.insert(
        "sigref_map".to_string(),
        serde_json::json!(serde_json::Map::new()),
    );
    state_obj.insert(
        "key_valid_from_change_id".to_string(),
        serde_json::json!(0u32),
    );
    state_obj.insert(
        "current_clc_state".to_string(),
        serde_json::to_value(initial_clc_state(&baseline_root)).unwrap(),
    );
    state_obj.insert("current_change_entry".to_string(), Value::Null);

    let restored = Space::restore(SharedStateTransport::new(Arc::clone(state)), snapshot)
        .await
        .expect("restore Space after prepopulation reset");
    register_tauri_actions(&restored);

    assert_eq!(restored.current_data_commitment(), baseline_root);
    assert_eq!(restored.current_change_id(), 0);

    (restored, baseline_root)
}

async fn assert_prepopulated_rows_visible(
    space: &Space,
    channel_id: i64,
    message_id: i64,
    reaction_id: i64,
) {
    let channel = space
        .table::<Channel>("channels")
        .select()
        .where_eq("id", channel_id)
        .first()
        .await
        .expect("select seeded channel")
        .expect("seeded channel must be visible after reset");
    assert_eq!(channel.id, Some(channel_id));

    let message = space
        .table::<Message>("messages")
        .select()
        .where_eq("id", message_id)
        .first()
        .await
        .expect("select seeded message")
        .expect("seeded message must be visible after reset");
    assert_eq!(message.id, Some(message_id));

    let reaction = space
        .table::<Reaction>("reactions")
        .select()
        .where_eq("id", reaction_id)
        .first()
        .await
        .expect("select seeded reaction")
        .expect("seeded reaction must be visible after reset");
    assert_eq!(reaction.id, Some(reaction_id));

    let users: Vec<encrypted_spaces_sdk::UserRecord> = space
        .users()
        .select()
        .all()
        .await
        .expect("select seeded users");
    assert_eq!(users.len(), SEEDED_USERS);
}

async fn init_prepopulated_chat_fixture() -> ChatFixture {
    let (state, space) = init_chat_state_and_space().await;

    let channels = space.table::<Channel>("channels");
    let mut channel_ids = Vec::with_capacity(SEEDED_CHANNELS);
    for i in 0..SEEDED_CHANNELS {
        let id = channels
            .insert(&Channel {
                id: None,
                name: format!("channel-{i:02}"),
                description: Some(fixed_text("seed-channel-description", i, 96)),
                tasks: List::empty(),
                notes: TextArea::empty(),
            })
            .execute()
            .await
            .expect("seed channel insert execute");
        channel_ids.push(id);
    }

    space
        .table::<UsersMeta>("users_meta")
        .insert(&UsersMeta {
            id: Some(AUTH_UID),
            name: "bench-user".to_string(),
        })
        .execute()
        .await
        .expect("seed users_meta insert execute");

    for _ in 1..SEEDED_USERS {
        space.invite_user().await.expect("seed invite_user");
    }

    // Seed tasks on the first channel.
    let task_channel_id = channel_ids[0];
    let tasks: List<Task> = space.list("channels", task_channel_id, "tasks");
    let mut task_keys: Vec<Vec<u8>> = Vec::with_capacity(SEEDED_TASKS);
    for i in 0..SEEDED_TASKS {
        let key = tasks
            .append(&Task {
                title: format!("seed-task-{i}"),
                done: false,
            })
            .await
            .expect("seed task append");
        task_keys.push(key);
    }

    let mut message_ids = Vec::with_capacity(SEEDED_MESSAGES);
    let mut message_channel_ids = Vec::with_capacity(SEEDED_MESSAGES);
    let mut message_thread_ids = Vec::with_capacity(SEEDED_MESSAGES);
    let mut top_level_by_channel: Vec<Vec<i64>> = vec![Vec::new(); channel_ids.len()];
    let mut reply_rng = rand::rngs::SmallRng::seed_from_u64(SEEDED_REPLY_PARENT_SEED);
    let mut is_reply = vec![false; SEEDED_MESSAGES];
    for idx in pick_indices(
        SEEDED_MESSAGES - SEEDED_CHANNELS,
        SEEDED_MESSAGES / 2,
        SEEDED_REPLY_SELECTION_SEED,
    ) {
        is_reply[idx + SEEDED_CHANNELS] = true;
    }

    for (i, is_reply) in is_reply.into_iter().enumerate() {
        let channel_idx = i % channel_ids.len();
        let channel_id = channel_ids[channel_idx];
        let thread_id = if is_reply {
            let parents = &top_level_by_channel[channel_idx];
            let parent_idx = reply_rng.random_range(0..parents.len());
            parents[parent_idx]
        } else {
            0
        };
        let id = space
            .call_insert_action(
                "send_message",
                vec![
                    ("channel_id".into(), QueryParam::Integer(channel_id)),
                    ("user_id".into(), QueryParam::Integer(AUTH_UID)),
                    ("thread_id".into(), QueryParam::Integer(thread_id)),
                    (
                        "content".into(),
                        QueryParam::Text(fixed_text("seed-message-content", i, 160)),
                    ),
                    (
                        "timestamp".into(),
                        QueryParam::Integer(1_700_100_000 + i as i64),
                    ),
                ],
            )
            .await
            .expect("seed send_message action");
        message_ids.push(id);
        message_channel_ids.push(channel_id);
        message_thread_ids.push(thread_id);
        if thread_id == 0 {
            top_level_by_channel[channel_idx].push(id);
        }
    }
    assert_eq!(
        message_thread_ids
            .iter()
            .filter(|&&thread_id| thread_id != 0)
            .count(),
        SEEDED_MESSAGES / 2
    );

    let emoji_names = ["thumbs_up", "heart", "laugh", "eyes", "rocket"];
    let mut reaction_ids = Vec::with_capacity(SEEDED_REACTIONS);
    let mut reaction_rng = rand::rngs::SmallRng::seed_from_u64(SEEDED_REACTION_SEED);
    for i in 0..SEEDED_REACTIONS {
        let message_idx = reaction_rng.random_range(0..message_ids.len());
        let id = space
            .call_insert_action(
                "add_reaction",
                vec![
                    (
                        "channel_id".into(),
                        QueryParam::Integer(message_channel_ids[message_idx]),
                    ),
                    (
                        "message_id".into(),
                        QueryParam::Integer(message_ids[message_idx]),
                    ),
                    ("user_id".into(), QueryParam::Integer(AUTH_UID)),
                    (
                        "emoji".into(),
                        QueryParam::Text(emoji_names[i % emoji_names.len()].to_string()),
                    ),
                ],
            )
            .await
            .expect("seed add_reaction action");
        reaction_ids.push(id);
    }

    assert_eq!(channel_ids.len(), SEEDED_CHANNELS);
    assert_eq!(message_ids.len(), SEEDED_MESSAGES);
    assert_eq!(reaction_ids.len(), SEEDED_REACTIONS);

    seed_extra_users_meta_direct(&state).await;

    let (space, baseline_root) = reset_to_prepopulated_baseline(&state, space).await;
    assert_prepopulated_rows_visible(&space, channel_ids[0], message_ids[0], reaction_ids[0]).await;

    ChatFixture {
        state,
        bench_chain: Arc::new(Mutex::new(ff_common::BenchProofChain::new())),
        space,
        baseline_root,
        channel_ids,
        message_ids,
        message_channel_ids,
        message_thread_ids,
        reaction_ids,
        task_channel_id,
        task_keys,
    }
}

// ─── Filesystem fixture ──────────────────────────────────────────────────────

struct FsFixture {
    state: Arc<Mutex<SpaceState>>,
    bench_chain: Arc<Mutex<ff_common::BenchProofChain>>,
    space: Space,
    #[allow(dead_code)]
    baseline_root: [u8; 32],
    dir_ids: Vec<i64>,
    #[allow(dead_code)]
    dir_parent_ids: Vec<i64>,
    dir_levels: Vec<u8>,
    dir_children: Vec<Vec<usize>>,
    dir_file_ids: Vec<Vec<i64>>,
    file_ids: Vec<i64>,
    #[allow(dead_code)]
    file_parent_dir_indices: Vec<usize>,
    level2_dir_indices: Vec<usize>,
}

/// Insert one `inodes` row via the Tauri `add_inode` action.
///
/// Fields are built explicitly as query parameters; `file_hash` is passed
/// as raw `QueryParam::Text` (a fileref column accepts the hex hash string
/// directly). We do not use the Tauri crate's generated `space.add_inode`
/// helper (only available inside `demos/tauri/src-tauri`) and we never call
/// `space.file().upload(...)` — this benchmark measures metadata only.
struct InodeInsert {
    parent_id: i64,
    name: String,
    inode_type: i64,
    size: i64,
    ctime: i64,
    mtime: i64,
    mime_type: String,
    file_hash: String,
}

async fn insert_inode_action(space: &Space, inode: InodeInsert) -> i64 {
    space
        .call_insert_action(
            "add_inode",
            vec![
                ("parent_id".into(), QueryParam::Integer(inode.parent_id)),
                ("author_id".into(), QueryParam::Integer(AUTH_UID)),
                ("name".into(), QueryParam::Text(inode.name)),
                ("type".into(), QueryParam::Integer(inode.inode_type)),
                ("size".into(), QueryParam::Integer(inode.size)),
                ("ctime".into(), QueryParam::Integer(inode.ctime)),
                ("mtime".into(), QueryParam::Integer(inode.mtime)),
                ("mime_type".into(), QueryParam::Text(inode.mime_type)),
                ("file_hash".into(), QueryParam::Text(inode.file_hash)),
            ],
        )
        .await
        .expect("add_inode action insert")
}

/// Verify the seeded filesystem baseline is visible after the changelog
/// reset, with exact row counts. `inodes.type` is not indexed, so types are
/// counted client-side from a full scan; a seeded parent/child relationship
/// is verified through the indexed `parent_id` column.
async fn assert_prepopulated_fs_rows_visible(
    space: &Space,
    sample_parent_id: i64,
    expected_child_id: i64,
) {
    let rows: Vec<Inode> = space
        .table::<Inode>("inodes")
        .select()
        .all()
        .await
        .expect("select all seeded inodes");

    let dir_count = rows
        .iter()
        .filter(|row| row.inode_type == INODE_FOLDER)
        .count();
    let file_count = rows
        .iter()
        .filter(|row| row.inode_type == INODE_FILE)
        .count();

    assert_eq!(dir_count, FS_DIRS, "seeded directory rows");
    assert_eq!(file_count, FS_FILES, "seeded file rows");
    assert_eq!(rows.len(), FS_DIRS + FS_FILES, "total seeded inode rows");

    let children: Vec<Inode> = space
        .table::<Inode>("inodes")
        .select()
        .where_eq("parent_id", sample_parent_id)
        .all()
        .await
        .expect("select seeded children by parent_id");
    assert!(
        children
            .iter()
            .any(|child| child.id == Some(expected_child_id)),
        "expected child {expected_child_id} visible under parent {sample_parent_id}",
    );
}

/// Build the deterministic filesystem metadata baseline.
///
/// Reuses the chat state/space initializer so schema and Tauri action
/// registration stay consistent, seeds the authenticated user's display-name
/// row, inserts the directory tree breadth-first (5/25/125/625 = 780 dirs),
/// hangs 10 file rows under every directory (7,800 files), then resets the
/// changelog so none of the seeded rows are counted as measured changes.
async fn init_prepopulated_fs_fixture() -> FsFixture {
    let (state, space) = init_chat_state_and_space().await;

    // The shared initializer does not seed `users_meta`; add the
    // authenticated user's display-name row so inode `author_id` joins
    // resolve. The demo ACL only lets a user write their own row, which is
    // exactly `AUTH_UID` here.
    space
        .table::<UsersMeta>("users_meta")
        .insert(&UsersMeta {
            id: Some(AUTH_UID),
            name: "bench-user".to_string(),
        })
        .execute()
        .await
        .expect("seed users_meta insert execute");

    let mut ts_counter = 0usize;
    let mut dir_ids: Vec<i64> = Vec::with_capacity(FS_DIRS);
    let mut dir_parent_ids: Vec<i64> = Vec::with_capacity(FS_DIRS);
    let mut dir_levels: Vec<u8> = Vec::with_capacity(FS_DIRS);
    let mut dir_children: Vec<Vec<usize>> = Vec::with_capacity(FS_DIRS);
    let mut level2_dir_indices: Vec<usize> = Vec::with_capacity(FS_LEVEL2_DIRS);

    // Level 1 directories live under the implicit root (parent_id == 0).
    let mut current_level: Vec<usize> = Vec::with_capacity(FS_BRANCHING);
    for ordinal in 0..FS_BRANCHING {
        let ts = fs_timestamp(ts_counter);
        ts_counter += 1;
        let id = insert_inode_action(
            &space,
            InodeInsert {
                parent_id: 0,
                name: fs_dir_name(1, ordinal),
                inode_type: INODE_FOLDER,
                size: 0,
                ctime: ts,
                mtime: ts,
                mime_type: String::new(),
                file_hash: "0".repeat(64),
            },
        )
        .await;
        let idx = dir_ids.len();
        dir_ids.push(id);
        dir_parent_ids.push(0);
        dir_levels.push(1);
        dir_children.push(Vec::new());
        current_level.push(idx);
    }

    // Levels 2..=FS_LEVELS: every directory at the previous level gets
    // FS_BRANCHING child directories. Parents (folders) are already
    // inserted, so the `add_inode` parent-folder assertion holds.
    for level in 2..=FS_LEVELS {
        let mut next_level: Vec<usize> = Vec::with_capacity(current_level.len() * FS_BRANCHING);
        let mut ordinal = 0usize;
        for &parent_idx in &current_level {
            let parent_id = dir_ids[parent_idx];
            for _ in 0..FS_BRANCHING {
                let ts = fs_timestamp(ts_counter);
                ts_counter += 1;
                let id = insert_inode_action(
                    &space,
                    InodeInsert {
                        parent_id,
                        name: fs_dir_name(level, ordinal),
                        inode_type: INODE_FOLDER,
                        size: 0,
                        ctime: ts,
                        mtime: ts,
                        mime_type: String::new(),
                        file_hash: "0".repeat(64),
                    },
                )
                .await;
                let idx = dir_ids.len();
                dir_ids.push(id);
                dir_parent_ids.push(parent_id);
                dir_levels.push(level as u8);
                dir_children.push(Vec::new());
                dir_children[parent_idx].push(idx);
                if level == 2 {
                    level2_dir_indices.push(idx);
                }
                next_level.push(idx);
                ordinal += 1;
            }
        }
        current_level = next_level;
    }

    // Hang FS_FILES_PER_DIR file rows under every seeded directory.
    let mut dir_file_ids: Vec<Vec<i64>> = Vec::with_capacity(dir_ids.len());
    let mut file_ids: Vec<i64> = Vec::with_capacity(FS_FILES);
    let mut file_parent_dir_indices: Vec<usize> = Vec::with_capacity(FS_FILES);
    for (dir_idx, &parent_id) in dir_ids.iter().enumerate() {
        let mut these_files: Vec<i64> = Vec::with_capacity(FS_FILES_PER_DIR);
        for file_idx in 0..FS_FILES_PER_DIR {
            let ts = fs_timestamp(ts_counter);
            ts_counter += 1;
            let id = insert_inode_action(
                &space,
                InodeInsert {
                    parent_id,
                    name: fs_file_name(dir_idx, file_idx),
                    inode_type: INODE_FILE,
                    size: 1_024,
                    ctime: ts,
                    mtime: ts,
                    mime_type: "application/octet-stream".to_string(),
                    file_hash: fs_file_hash(dir_idx, file_idx),
                },
            )
            .await;
            these_files.push(id);
            file_ids.push(id);
            file_parent_dir_indices.push(dir_idx);
        }
        dir_file_ids.push(these_files);
    }

    assert_eq!(dir_ids.len(), FS_DIRS, "seeded directory count");
    assert_eq!(
        level2_dir_indices.len(),
        FS_LEVEL2_DIRS,
        "level-2 directory count"
    );
    assert_eq!(file_ids.len(), FS_FILES, "seeded file count");
    assert_eq!(
        dir_ids.len() + file_ids.len(),
        FS_DIRS + FS_FILES,
        "total seeded inode count"
    );

    // Reset the changelog to this seeded baseline so the filesystem rows
    // above are not measured by later proofs.
    let (space, baseline_root) = reset_to_prepopulated_baseline(&state, space).await;

    // A level-1 directory has both child directories and 10 files; verify a
    // file under the first level-1 directory is selectable after the reset.
    let sample_parent_id = dir_ids[0];
    let expected_child_id = dir_file_ids[0][0];
    assert_prepopulated_fs_rows_visible(&space, sample_parent_id, expected_child_id).await;

    FsFixture {
        state,
        bench_chain: Arc::new(Mutex::new(ff_common::BenchProofChain::new())),
        space,
        baseline_root,
        dir_ids,
        dir_parent_ids,
        dir_levels,
        dir_children,
        dir_file_ids,
        file_ids,
        file_parent_dir_indices,
        level2_dir_indices,
    }
}

// ─── Proving ────────────────────────────────────────────────────────────────

struct ChatProveResult {
    changes: usize,
    cycles: u64,
    bench: Option<ff_common::BenchProveResult>,
}

struct PendingProveResult {
    cycles: u64,
    bench: Option<ff_common::BenchProveResult>,
}

fn timed_guest_enabled() -> bool {
    std::env::var_os("FFCHAT_TIMED_GUEST").is_some()
}

async fn prove_fixture_pending_changes(
    state: &Arc<Mutex<SpaceState>>,
    bench_chain: &Arc<Mutex<ff_common::BenchProofChain>>,
) -> PendingProveResult {
    if timed_guest_enabled() {
        let mut chain = bench_chain.lock().await;
        let result = ff_common::prove_pending_changes_bench(state, &mut chain).await;
        PendingProveResult {
            cycles: result.cycles,
            bench: Some(result),
        }
    } else {
        let result = ff_common::prove_pending_changes(state).await;
        PendingProveResult {
            cycles: result.cycles,
            bench: None,
        }
    }
}

async fn prove_chat_changes(fixture: &ChatFixture) -> ChatProveResult {
    let changes = {
        let s = fixture.state.lock().await;
        s.changelog.num_changes() as usize - s.changelog.proven_up_to
    };
    let result = prove_fixture_pending_changes(&fixture.state, &fixture.bench_chain).await;
    ChatProveResult {
        changes,
        cycles: result.cycles,
        bench: result.bench,
    }
}

fn report_chat_result(case: &str, changes: u64, result: &ChatProveResult) {
    eprintln!("[ff-chat-result] {case}");
    eprintln!("  changes: {changes}");
    eprintln!("  cycles:");
    eprintln!("    total: {}", result.cycles);
    eprintln!("    per_change: {}", result.cycles / changes);
    if let Some(bench) = result.bench.as_ref() {
        ff_common::print_bench_timing(case, bench);
    }
}

// ─── Benchmark cases ──────────────────────────────────────────────────────

const CHAT_CASES: &[(&str, usize)] = &[
    ("channel_insert", 1),
    ("channel_insert_10", 10),
    ("channel_update", 1),
    ("channel_update_10", 10),
    ("message_insert", 1),
    ("message_insert_10", 10),
    ("message_update", 1),
    ("message_update_10", 10),
    ("reaction_insert", 1),
    ("reaction_insert_10", 10),
    ("message_delete", 1),
    ("message_delete_10", 10),
    ("task_append", 1),
    ("task_append_10", 10),
    ("task_update", 1),
    ("task_update_10", 10),
    ("task_delete", 1),
    ("task_delete_10", 10),
    ("mixed_chat", 1),
    ("mixed_chat_10", 10),
    ("invite_user", 1),
    ("accept_invite", 1),
    ("remove_user_and_rekey", 1),
];

// Filesystem benchmark registry, kept separate from `CHAT_CASES` so the chat
// report and its parser never see filesystem rows. Only 1-op and 10-op cases
// exist; there are deliberately no `_100` filesystem cases.
const FS_CASES: &[(&str, usize)] = &[
    ("fs_file_insert", 1),
    ("fs_file_insert_10", 10),
    ("fs_file_delete", 1),
    ("fs_file_delete_10", 10),
    ("fs_directory_insert", 1),
    ("fs_directory_insert_10", 10),
    ("fs_directory_delete", 1),
    ("fs_directory_delete_10", 10),
];

/// Select chat and filesystem cases from an optional positional filter.
///
/// Returns `(selected_chat_cases, selected_fs_cases)`:
/// - With no filter, every chat case and every filesystem case is selected.
/// - With a filter, each registry is matched independently by substring.
/// - A filter that matches filesystem cases but no chat cases runs only the
///   matching filesystem cases; it must not fall back to the full chat suite.
/// - A filter that matches neither registry preserves the historical no-match
///   behavior of running the full chat suite, except for an `fs`-style filter,
///   which reports a clear no-match and runs nothing.
fn selected_cases() -> (Vec<&'static str>, Vec<&'static str>) {
    let all_chat: Vec<&'static str> = CHAT_CASES.iter().map(|&(case, _)| case).collect();
    let all_fs: Vec<&'static str> = FS_CASES.iter().map(|&(case, _)| case).collect();

    let Some(filter) = std::env::args().skip(1).find(|arg| !arg.starts_with('-')) else {
        return (all_chat, all_fs);
    };

    let chat_matches: Vec<&'static str> = CHAT_CASES
        .iter()
        .filter_map(|&(case, _)| case.contains(filter.as_str()).then_some(case))
        .collect();
    let fs_matches: Vec<&'static str> = FS_CASES
        .iter()
        .filter_map(|&(case, _)| case.contains(filter.as_str()).then_some(case))
        .collect();

    if chat_matches.is_empty() && fs_matches.is_empty() {
        if filter.starts_with("fs") {
            eprintln!("[bench] no chat or filesystem cases match filter '{filter}'");
            return (Vec::new(), Vec::new());
        }
        // Preserve the historical no-match behavior for non-filesystem filters.
        return (all_chat, Vec::new());
    }

    (chat_matches, fs_matches)
}

fn case_selected(selected_cases: &[&'static str], case: &'static str) -> bool {
    selected_cases.contains(&case)
}

fn mixed_chat_counts(n: usize) -> (usize, usize, usize, usize, usize, usize) {
    if n == 1 {
        return (1, 0, 0, 0, 0, 0);
    }

    if n == 10 {
        // Preserve a real cascade-delete component in the small mixed case.
        return (4, 2, 1, 1, 1, 1);
    }

    // For larger N: 40% + 25% + 15% + 10% + 5% + 5%.
    let n_msg_insert = n * 40 / 100;
    let n_react_insert = n * 25 / 100;
    let n_msg_edit = n * 15 / 100;
    let n_react_delete = n * 10 / 100;
    let n_msg_delete = n * 5 / 100;
    let n_ch_update =
        n - n_msg_insert - n_react_insert - n_msg_edit - n_react_delete - n_msg_delete;

    (
        n_msg_insert,
        n_react_insert,
        n_msg_edit,
        n_react_delete,
        n_msg_delete,
        n_ch_update,
    )
}

fn chat_cycle_fixture(selected_cases: &[&'static str]) -> HashMap<&'static str, u64> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(build_chat_cycles(selected_cases))
}

async fn run_channel_insert(fixture: &ChatFixture, n: usize) {
    let channels = fixture.space.table::<Channel>("channels");
    for i in 0..n {
        channels
            .insert(&Channel {
                id: None,
                name: format!("bench-ch-{i:02}"),
                description: Some(fixed_text("bench-ch-desc", i, 96)),
                tasks: List::empty(),
                notes: TextArea::empty(),
            })
            .execute()
            .await
            .expect("channel insert execute");
    }
}

async fn run_channel_update(fixture: &ChatFixture, n: usize) {
    let channels = fixture.space.table::<Channel>("channels");
    for i in 0..n {
        let target_id = fixture.channel_ids[i % fixture.channel_ids.len()];
        channels
            .update()
            .set("description", fixed_text("bench-upd-desc", i, 96))
            .where_eq("id", target_id)
            .execute()
            .await
            .expect("channel update execute");
    }
}

async fn run_message_insert(fixture: &ChatFixture, n: usize) {
    for i in 0..n {
        let channel_id = fixture.channel_ids[i % fixture.channel_ids.len()];
        fixture
            .space
            .call_insert_action(
                "send_message",
                vec![
                    ("channel_id".into(), QueryParam::Integer(channel_id)),
                    ("user_id".into(), QueryParam::Integer(AUTH_UID)),
                    ("thread_id".into(), QueryParam::Integer(0)),
                    (
                        "content".into(),
                        QueryParam::Text(fixed_text("bench-msg", i, 160)),
                    ),
                    (
                        "timestamp".into(),
                        QueryParam::Integer(1_800_100_000 + i as i64),
                    ),
                ],
            )
            .await
            .expect("send_message action");
    }
}

async fn run_message_update(fixture: &ChatFixture, n: usize) {
    let indices = pick_indices(fixture.message_ids.len(), n, 0xBEEF_0001);
    for (i, &idx) in indices.iter().enumerate() {
        let msg_id = fixture.message_ids[idx];
        fixture
            .space
            .call_update_action(
                "update_message",
                msg_id,
                vec![(
                    "content".into(),
                    QueryParam::Text(fixed_text("bench-edit", i, 160)),
                )],
            )
            .await
            .expect("update_message action");
    }
}

async fn run_reaction_insert(fixture: &ChatFixture, n: usize) {
    let msg_indices = pick_indices(fixture.message_ids.len(), n, 0xBEEF_0003);
    for (i, &msg_idx) in msg_indices.iter().enumerate() {
        let msg_id = fixture.message_ids[msg_idx];
        let ch_id = fixture.message_channel_ids[msg_idx];
        fixture
            .space
            .call_insert_action(
                "add_reaction",
                vec![
                    ("channel_id".into(), QueryParam::Integer(ch_id)),
                    ("message_id".into(), QueryParam::Integer(msg_id)),
                    ("user_id".into(), QueryParam::Integer(AUTH_UID)),
                    ("emoji".into(), QueryParam::Text(format!("bench-emoji-{i}"))),
                ],
            )
            .await
            .expect("add_reaction action");
    }
}

fn random_message_delete_targets(fixture: &ChatFixture, n: usize, seed: u64) -> Vec<usize> {
    let mut targets = pick_indices(fixture.message_ids.len(), n, seed);
    targets.sort_by_key(|&idx| {
        if fixture.message_thread_ids[idx] == 0 {
            1
        } else {
            0
        }
    });
    targets
}

async fn run_message_delete(fixture: &ChatFixture, n: usize) -> Space {
    let delete_targets = random_message_delete_targets(fixture, n, 0xBEEF_0004);
    let space = fixture.space.clone();

    for &msg_idx in &delete_targets {
        let msg_id = fixture.message_ids[msg_idx];
        space
            .call_delete_action("delete_message", msg_id)
            .await
            .expect("delete_message action");
    }
    space
}

async fn run_task_append(fixture: &ChatFixture, n: usize) {
    let tasks: List<Task> = fixture
        .space
        .list("channels", fixture.task_channel_id, "tasks");
    for i in 0..n {
        tasks
            .append(&Task {
                title: format!("bench-task-{i}"),
                done: false,
            })
            .await
            .expect("task append");
    }
}

async fn run_task_update(fixture: &ChatFixture, n: usize) {
    let tasks: List<Task> = fixture
        .space
        .list("channels", fixture.task_channel_id, "tasks");
    let indices = pick_indices(fixture.task_keys.len(), n, 0xBEEF_0010);
    for (i, &idx) in indices.iter().enumerate() {
        tasks
            .update_by_key(
                &fixture.task_keys[idx],
                &Task {
                    title: format!("bench-task-upd-{i}"),
                    done: true,
                },
            )
            .await
            .expect("task update");
    }
}

async fn run_task_delete(fixture: &ChatFixture, n: usize) {
    let tasks: List<Task> = fixture
        .space
        .list("channels", fixture.task_channel_id, "tasks");
    let indices = pick_indices(fixture.task_keys.len(), n, 0xBEEF_0011);
    for &idx in &indices {
        tasks
            .delete_by_key(&fixture.task_keys[idx])
            .await
            .expect("task delete");
    }
}

async fn run_invite_user(fixture: &ChatFixture) {
    fixture.space.invite_user().await.expect("invite_user");
}

async fn run_accept_invite(fixture: &ChatFixture) {
    let invite = fixture
        .space
        .invite_user()
        .await
        .expect("invite_user for join");
    prove_chat_changes(fixture).await;
    let app_schema = ApplicationSchema::for_testing(tauri_schemas(), fixture.baseline_root);
    let joined = Space::join(
        SharedStateTransport::new(Arc::clone(&fixture.state)),
        invite,
        app_schema,
    )
    .await
    .expect("Space::join (accept_invite)");
    register_tauri_actions(&joined);
}

async fn run_remove_user_and_rekey(fixture: &ChatFixture) {
    let invite = fixture
        .space
        .invite_user()
        .await
        .expect("invite_user for remove");
    let target_uid = invite.id().expect("invite uid");
    prove_chat_changes(fixture).await;
    fixture.space.sync().await.expect("sync before remove");
    fixture
        .space
        .remove_user(target_uid)
        .await
        .expect("remove_user_and_rekey");
}

async fn run_case(case: &str, n: usize, fixture: &ChatFixture) {
    let base = strip_numeric_suffix(case);
    match base {
        "channel_insert" => run_channel_insert(fixture, n).await,
        "channel_update" => run_channel_update(fixture, n).await,
        "message_insert" => run_message_insert(fixture, n).await,
        "message_update" => run_message_update(fixture, n).await,
        "reaction_insert" => run_reaction_insert(fixture, n).await,
        "message_delete" => {
            run_message_delete(fixture, n).await;
        }
        "task_append" => run_task_append(fixture, n).await,
        "task_update" => run_task_update(fixture, n).await,
        "task_delete" => run_task_delete(fixture, n).await,
        _ => {}
    }
}

// ─── Filesystem operation runners ───────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct FsRunStats {
    ops: usize,
    ff_changes: usize,
}

async fn fs_changelog_len(state: &Arc<Mutex<SpaceState>>) -> usize {
    let state = state.lock().await;
    state.changelog.num_changes() as usize
}

async fn fs_delete_inode_direct(fixture: &FsFixture, inode_id: i64) {
    let deleted = fixture
        .space
        .table::<Inode>("inodes")
        .delete()
        .where_eq("id", inode_id)
        .execute()
        .await
        .expect("direct inode delete");
    assert_eq!(deleted, 1, "direct inode delete affected rows");
}

async fn run_fs_file_insert(fixture: &FsFixture, n: usize) -> FsRunStats {
    assert!(
        n <= fixture.dir_ids.len(),
        "cannot insert {n} files with unique seeded parents"
    );
    let before = fs_changelog_len(&fixture.state).await;
    let parent_indices = pick_indices(fixture.dir_ids.len(), n, FS_FILE_INSERT_SEED);

    for (i, &parent_idx) in parent_indices.iter().enumerate() {
        let ts = fs_timestamp(FS_DIRS + FS_FILES + i);
        insert_inode_action(
            &fixture.space,
            InodeInsert {
                parent_id: fixture.dir_ids[parent_idx],
                name: format!("bench-file-insert-{i:02}.bin"),
                inode_type: INODE_FILE,
                size: 2_048,
                ctime: ts,
                mtime: ts,
                mime_type: "application/octet-stream".to_string(),
                file_hash: fs_inserted_file_hash(i),
            },
        )
        .await;
    }

    let ff_changes = fs_changelog_len(&fixture.state).await - before;
    assert_eq!(ff_changes, n, "file insert ff changes");
    FsRunStats { ops: n, ff_changes }
}

async fn run_fs_file_delete(fixture: &FsFixture, n: usize) -> FsRunStats {
    assert!(
        n <= fixture.file_ids.len(),
        "cannot delete {n} unique seeded files"
    );
    let before = fs_changelog_len(&fixture.state).await;
    let file_indices = pick_indices(fixture.file_ids.len(), n, FS_FILE_DELETE_SEED);

    for &file_idx in &file_indices {
        fs_delete_inode_direct(fixture, fixture.file_ids[file_idx]).await;
    }

    let ff_changes = fs_changelog_len(&fixture.state).await - before;
    assert_eq!(ff_changes, n, "file delete ff changes");
    FsRunStats { ops: n, ff_changes }
}

async fn run_fs_directory_insert(fixture: &FsFixture, n: usize) -> FsRunStats {
    assert!(
        n <= fixture.dir_ids.len(),
        "cannot insert {n} directories with unique seeded parents"
    );
    let before = fs_changelog_len(&fixture.state).await;
    let parent_indices = pick_indices(fixture.dir_ids.len(), n, FS_DIR_INSERT_SEED);

    for (i, &parent_idx) in parent_indices.iter().enumerate() {
        let ts = fs_timestamp(FS_DIRS + FS_FILES + 10_000 + i);
        insert_inode_action(
            &fixture.space,
            InodeInsert {
                parent_id: fixture.dir_ids[parent_idx],
                name: format!("bench-dir-insert-{i:02}"),
                inode_type: INODE_FOLDER,
                size: 0,
                ctime: ts,
                mtime: ts,
                mime_type: String::new(),
                file_hash: "0".repeat(64),
            },
        )
        .await;
    }

    let ff_changes = fs_changelog_len(&fixture.state).await - before;
    assert_eq!(ff_changes, n, "directory insert ff changes");
    FsRunStats { ops: n, ff_changes }
}

fn fs_collect_dir_postorder(fixture: &FsFixture, dir_idx: usize, out: &mut Vec<usize>) {
    for &child_idx in &fixture.dir_children[dir_idx] {
        fs_collect_dir_postorder(fixture, child_idx, out);
    }
    out.push(dir_idx);
}

async fn run_fs_directory_delete(fixture: &FsFixture, n: usize) -> FsRunStats {
    assert!(
        n <= fixture.level2_dir_indices.len(),
        "cannot delete {n} distinct level-2 subtrees"
    );
    let before = fs_changelog_len(&fixture.state).await;
    let target_positions = pick_indices(fixture.level2_dir_indices.len(), n, FS_DIR_DELETE_SEED);

    for &target_pos in &target_positions {
        let target_idx = fixture.level2_dir_indices[target_pos];
        assert_eq!(
            fixture.dir_levels[target_idx], 2,
            "directory delete target level"
        );

        let mut subtree_dirs = Vec::with_capacity(FS_LEVEL2_SUBTREE_DIRS);
        fs_collect_dir_postorder(fixture, target_idx, &mut subtree_dirs);
        assert_eq!(
            subtree_dirs.len(),
            FS_LEVEL2_SUBTREE_DIRS,
            "level-2 subtree directory count"
        );
        let subtree_files: usize = subtree_dirs
            .iter()
            .map(|&dir_idx| fixture.dir_file_ids[dir_idx].len())
            .sum();
        assert_eq!(
            subtree_files, FS_LEVEL2_SUBTREE_FILES,
            "level-2 subtree file count"
        );

        for &dir_idx in &subtree_dirs {
            for &file_id in &fixture.dir_file_ids[dir_idx] {
                fs_delete_inode_direct(fixture, file_id).await;
            }
            fs_delete_inode_direct(fixture, fixture.dir_ids[dir_idx]).await;
        }
    }

    let ff_changes = fs_changelog_len(&fixture.state).await - before;
    assert_eq!(
        ff_changes,
        n * FS_LEVEL2_SUBTREE_INODES,
        "directory delete ff changes"
    );
    FsRunStats { ops: n, ff_changes }
}

const USER_MGMT_CASES: &[&str] = &["invite_user", "accept_invite", "remove_user_and_rekey"];

async fn build_chat_cycles(selected_cases: &[&'static str]) -> HashMap<&'static str, u64> {
    let t0 = std::time::Instant::now();
    let mut cycles: HashMap<&'static str, u64> = HashMap::new();

    for &(case, n) in CHAT_CASES {
        if !case_selected(selected_cases, case) {
            continue;
        }
        if case.starts_with("mixed_chat") || USER_MGMT_CASES.contains(&case) {
            continue; // handled separately below
        }
        eprintln!("[chat] running {case} ...");
        let fixture = init_prepopulated_chat_fixture().await;
        run_case(case, n, &fixture).await;
        let result = prove_chat_changes(&fixture).await;
        report_chat_result(case, n as u64, &result);
        cycles.insert(case, result.cycles);
    }

    // ─── User management ops (1 change per proof) ───────────────────────
    if case_selected(selected_cases, "invite_user") {
        eprintln!("[chat] running invite_user ...");
        let fixture = init_prepopulated_chat_fixture().await;
        run_invite_user(&fixture).await;
        let result = prove_chat_changes(&fixture).await;
        report_chat_result("invite_user", 1, &result);
        cycles.insert("invite_user", result.cycles);
    }

    if case_selected(selected_cases, "accept_invite") {
        eprintln!("[chat] running accept_invite ...");
        let fixture = init_prepopulated_chat_fixture().await;
        run_accept_invite(&fixture).await;
        let result = prove_chat_changes(&fixture).await;
        report_chat_result("accept_invite", 1, &result);
        cycles.insert("accept_invite", result.cycles);
    }

    if case_selected(selected_cases, "remove_user_and_rekey") {
        eprintln!("[chat] running remove_user_and_rekey ...");
        let fixture = init_prepopulated_chat_fixture().await;
        run_remove_user_and_rekey(&fixture).await;
        let result = prove_chat_changes(&fixture).await;
        report_chat_result("remove_user_and_rekey", 1, &result);
        cycles.insert("remove_user_and_rekey", result.cycles);
    }

    // ─── mixed_chat ───────────────────────────────────────────────────
    for &(case, n) in CHAT_CASES {
        if !case.starts_with("mixed_chat") || !case_selected(selected_cases, case) {
            continue;
        }
        eprintln!("[chat] running {case} ...");
        let fixture = init_prepopulated_chat_fixture().await;

        let (n_msg_insert, n_react_insert, n_msg_edit, n_react_delete, n_msg_delete, n_ch_update) =
            mixed_chat_counts(n);

        let delete_targets = random_message_delete_targets(&fixture, n_msg_delete, 0xBEEF_0005);
        let space = fixture.space.clone();

        for i in 0..n_msg_insert {
            let channel_id = fixture.channel_ids[i % fixture.channel_ids.len()];
            space
                .call_insert_action(
                    "send_message",
                    vec![
                        ("channel_id".into(), QueryParam::Integer(channel_id)),
                        ("user_id".into(), QueryParam::Integer(AUTH_UID)),
                        ("thread_id".into(), QueryParam::Integer(0)),
                        (
                            "content".into(),
                            QueryParam::Text(fixed_text("mixed-msg", i, 160)),
                        ),
                        (
                            "timestamp".into(),
                            QueryParam::Integer(1_810_100_000 + i as i64),
                        ),
                    ],
                )
                .await
                .expect("mixed send_message");
        }

        let react_msg_indices =
            pick_indices(fixture.message_ids.len(), n_react_insert, 0xBEEF_0006);
        for (i, &msg_idx) in react_msg_indices.iter().enumerate() {
            let msg_id = fixture.message_ids[msg_idx];
            let ch_id = fixture.message_channel_ids[msg_idx];
            space
                .call_insert_action(
                    "add_reaction",
                    vec![
                        ("channel_id".into(), QueryParam::Integer(ch_id)),
                        ("message_id".into(), QueryParam::Integer(msg_id)),
                        ("user_id".into(), QueryParam::Integer(AUTH_UID)),
                        ("emoji".into(), QueryParam::Text(format!("mixed-emoji-{i}"))),
                    ],
                )
                .await
                .expect("mixed add_reaction");
        }

        let edit_indices = pick_indices(fixture.message_ids.len(), n_msg_edit, 0xBEEF_0007);
        for (i, &idx) in edit_indices.iter().enumerate() {
            let msg_id = fixture.message_ids[idx];
            space
                .call_update_action(
                    "update_message",
                    msg_id,
                    vec![(
                        "content".into(),
                        QueryParam::Text(fixed_text("mixed-edit", i, 160)),
                    )],
                )
                .await
                .expect("mixed update_message");
        }

        if n_react_delete > 0 {
            let reactions = space.table::<Reaction>("reactions");
            let react_del = pick_indices(fixture.reaction_ids.len(), n_react_delete, 0xBEEF_0008);
            for &idx in &react_del {
                reactions
                    .delete()
                    .where_eq("id", fixture.reaction_ids[idx])
                    .execute()
                    .await
                    .expect("mixed reaction delete");
            }
        }

        for &msg_idx in &delete_targets {
            let msg_id = fixture.message_ids[msg_idx];
            space
                .call_delete_action("delete_message", msg_id)
                .await
                .expect("mixed delete_message");
        }

        let channels = space.table::<Channel>("channels");
        for i in 0..n_ch_update {
            let target_id = fixture.channel_ids[i % fixture.channel_ids.len()];
            channels
                .update()
                .set("description", fixed_text("mixed-channel-desc", i, 96))
                .where_eq("id", target_id)
                .execute()
                .await
                .expect("mixed channel update");
        }

        let result = prove_chat_changes(&fixture).await;
        let changes = n as u64;
        assert_eq!(result.changes as u64, changes);
        report_chat_result(case, changes, &result);
        cycles.insert(case, result.cycles);
    }

    eprintln!("[chat] all chat cases done in {:.2?}", t0.elapsed());
    cycles
}

// ─── Filesystem dispatch, proving, and metrics ──────────────────────────────

/// Measured filesystem result for a single registry case.
#[derive(Debug, Clone, Copy)]
struct FsMetric {
    // Retained for documentation/parallelism with the chat path; the rendered
    // marginal model derives everything from `cycles`.
    #[allow(dead_code)]
    ops: usize,
    cycles: u64,
}

async fn run_fs_case(case: &str, n: usize, fixture: &FsFixture) -> FsRunStats {
    match strip_numeric_suffix(case) {
        "fs_file_insert" => run_fs_file_insert(fixture, n).await,
        "fs_file_delete" => run_fs_file_delete(fixture, n).await,
        "fs_directory_insert" => run_fs_directory_insert(fixture, n).await,
        "fs_directory_delete" => run_fs_directory_delete(fixture, n).await,
        other => panic!("unknown filesystem case: {other}"),
    }
}

fn fs_cycle_fixture(selected_cases: &[&'static str]) -> HashMap<&'static str, FsMetric> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(build_fs_cycles(selected_cases))
}

/// Run every selected filesystem case from its own fresh seeded baseline.
///
/// Each case builds a dedicated `FsFixture`, runs `n` operations cumulatively
/// against that single baseline, proves once, asserts the proof's change count
/// equals the dynamically counted `ff_changes`, then discards the fixture
/// before the next case builds a fresh one. The `_10` case is an independent
/// same-baseline run, not a continuation of the 1-op case.
async fn build_fs_cycles(selected_cases: &[&'static str]) -> HashMap<&'static str, FsMetric> {
    let t0 = std::time::Instant::now();
    let mut metrics: HashMap<&'static str, FsMetric> = HashMap::new();

    for &(case, n) in FS_CASES {
        if !selected_cases.contains(&case) {
            continue;
        }
        eprintln!("[fs] running {case} ...");
        let fixture = init_prepopulated_fs_fixture().await;
        let stats = run_fs_case(case, n, &fixture).await;
        // `ProveResult` carries cycles, not a change count, so count the
        // pending changes here (as the chat path does) and confirm the number
        // of changes about to be proven equals the dynamically counted
        // `ff_changes` before proving once.
        let pending = {
            let s = fixture.state.lock().await;
            s.changelog.num_changes() as usize - s.changelog.proven_up_to
        };
        assert_eq!(
            pending, stats.ff_changes,
            "fs case {case}: pending change count must equal counted ff_changes"
        );
        let prove = prove_fixture_pending_changes(&fixture.state, &fixture.bench_chain).await;
        eprintln!("[ff-fs-result] {case}");
        eprintln!("  ops: {}", stats.ops);
        eprintln!("  cycles:");
        eprintln!("    total: {}", prove.cycles);
        if let Some(bench) = prove.bench.as_ref() {
            ff_common::print_bench_timing(case, bench);
        }
        metrics.insert(
            case,
            FsMetric {
                ops: stats.ops,
                cycles: prove.cycles,
            },
        );
        // `fixture` is dropped here, discarding the dataset before the next case.
    }

    eprintln!("[fs] all filesystem cases done in {:.2?}", t0.elapsed());
    metrics
}

fn results_file_path() -> std::path::PathBuf {
    let dir = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("CARGO_MANIFEST_DIR")
                .map(|d| std::path::PathBuf::from(d).join("../../target"))
                .unwrap_or_else(|_| std::path::PathBuf::from("target"))
        });
    dir.join("ffchat_cycle_results.txt")
}

#[derive(Clone, Default)]
struct FamilyReportParts {
    new: Option<String>,
    old: Option<String>,
    delta: Option<String>,
}

fn extract_grouped_table(contents: &str, label: &str) -> Option<String> {
    let group_header = format!("{label} results:");
    let mut table = String::new();
    let mut in_group = false;

    for line in contents.lines() {
        if line == group_header {
            in_group = true;
            continue;
        }
        if !in_group {
            continue;
        }
        if line == "NEW results:" || line == "OLD results:" || line == "DELTA results:" {
            break;
        }
        if line.starts_with('[') {
            return None;
        }
        if !line.is_empty() {
            table.push_str(line);
            table.push('\n');
        }
    }

    (!table.trim().is_empty()).then(|| table.trim_end().to_string())
}

fn table_header() -> String {
    format!(
        "  {:<24} {:>14} {:>14} {:>14}",
        "case", "cycles/op", "cycles(1)", "cycles(10)",
    )
}

fn table_separator() -> String {
    format!("  {}", "─".repeat(69))
}

fn is_report_row(line: &str) -> bool {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() != 4 {
        return false;
    }
    cols[0] != "case" && !cols[0].starts_with('─') && !cols[0].starts_with('[')
}

fn append_table_rows(out: &mut String, table: &str) -> bool {
    let mut wrote_any = false;
    for line in table.lines().filter(|line| is_report_row(line)) {
        out.push_str(line.trim_end());
        out.push('\n');
        wrote_any = true;
    }
    wrote_any
}

fn render_combined_section(
    label: &str,
    chat_table: Option<&str>,
    fs_table: Option<&str>,
) -> Option<String> {
    let mut out = String::new();
    out.push_str(&format!("{label} results:\n"));
    out.push_str(&table_header());
    out.push('\n');
    out.push_str(&table_separator());
    out.push('\n');

    let mut wrote_any = false;
    if let Some(table) = chat_table.filter(|table| !table.trim().is_empty()) {
        wrote_any |= append_table_rows(&mut out, table);
    }
    if let Some(table) = fs_table.filter(|table| !table.trim().is_empty()) {
        wrote_any |= append_table_rows(&mut out, table);
    }

    wrote_any.then(|| out.trim_end().to_string())
}

fn render_combined_report(
    chat: Option<&FamilyReportParts>,
    fs: Option<&FamilyReportParts>,
) -> String {
    let path = results_file_path();
    let mut sections = vec![render_results_metadata()];

    if let Some(section) = render_combined_section(
        "NEW",
        chat.and_then(|parts| parts.new.as_deref()),
        fs.and_then(|parts| parts.new.as_deref()),
    ) {
        sections.push(section);
    }
    if let Some(section) = render_combined_section(
        "OLD",
        chat.and_then(|parts| parts.old.as_deref()),
        fs.and_then(|parts| parts.old.as_deref()),
    ) {
        sections.push(section);
    }
    if let Some(section) = render_combined_section(
        "DELTA",
        chat.and_then(|parts| parts.delta.as_deref()),
        fs.and_then(|parts| parts.delta.as_deref()),
    ) {
        sections.push(section);
    }

    sections.push(format!("Results saved to {}", path.display()));
    format!("{}\n", sections.join("\n\n"))
}

fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn render_results_metadata() -> String {
    [
        "# ffchat_cycle_benchmarks results".to_string(),
        format!("# generated_at_utc: {}", Utc::now().to_rfc3339()),
        format!("# benchmark_version: {BENCHMARK_VERSION}"),
        format!("# build_profile: {}", build_profile()),
        format!(
            "# build_target: {}-{}",
            std::env::consts::ARCH,
            std::env::consts::OS
        ),
    ]
    .join("\n")
}

fn save_results(report: &str) {
    let path = results_file_path();
    if let Err(e) = std::fs::write(&path, report.trim_end().to_string() + "\n") {
        eprintln!(
            "[bench] warning: could not save results to {}: {e}",
            path.display()
        );
    }
}

fn load_previous_new_results() -> HashMap<String, u64> {
    let path = results_file_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    extract_grouped_table(&contents, "NEW")
        .map(|table| parse_chat_results_table(&table))
        .unwrap_or_default()
}

fn chat_case_exists(case_name: &str, n: usize) -> bool {
    CHAT_CASES
        .iter()
        .any(|&(case, case_n)| case == case_name && case_n == n)
}

fn parse_chat_results_table(table: &str) -> HashMap<String, u64> {
    let mut results = HashMap::new();

    for line in table.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() != 4 || cols[0] == "case" || cols[0].starts_with('─') {
            continue;
        }

        let name = cols[0];
        let case_10 = format!("{name}_10");
        if let Ok(v) = cols[2].parse::<u64>() {
            if chat_case_exists(name, 1) {
                results.insert(name.to_string(), v);
            }
        }
        if let Ok(v) = cols[3].parse::<u64>() {
            if chat_case_exists(&case_10, 10) {
                results.insert(case_10, v);
            }
        }
    }

    results
}

/// One row per base operation, showing marginal, cycles(1), and cycles(10).
struct SummaryRow {
    name: String,
    c1: Option<u64>,
    c10: Option<u64>,
    marginal: Option<u64>,
}

fn strip_numeric_suffix(case: &str) -> &str {
    case.strip_suffix("_10")
        .or_else(|| case.strip_suffix("_100"))
        .unwrap_or(case)
}

fn derived_cycles_per_op(c1: Option<u64>, c10: Option<u64>) -> Option<u64> {
    match (c1, c10) {
        (Some(t1), Some(t10)) => t10.checked_sub(t1).map(|delta| delta / 9),
        (Some(t1), None) => Some(t1),
        _ => None,
    }
}

fn build_summary_rows(
    cycles: &HashMap<impl std::borrow::Borrow<str> + std::hash::Hash + Eq, u64>,
) -> Vec<SummaryRow> {
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::new();
    for &(case, _) in CHAT_CASES {
        let base = strip_numeric_suffix(case);
        if !seen.insert(base.to_string()) {
            continue;
        }
        let case_10 = format!("{base}_10");
        let c1 = cycles.get(base).copied();
        let c10 = cycles.get(case_10.as_str()).copied();
        if c1.is_none() && c10.is_none() {
            continue;
        }
        rows.push(SummaryRow {
            name: base.to_string(),
            c1,
            c10,
            marginal: derived_cycles_per_op(c1, c10),
        });
    }
    rows
}

fn render_chat_results_table<K>(cycles: &HashMap<K, u64>) -> String
where
    K: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let rows = build_summary_rows(cycles);
    let mut out = String::new();
    out.push_str(&table_header());
    out.push('\n');
    out.push_str(&table_separator());
    out.push('\n');
    for row in &rows {
        out.push_str(&format!(
            "  {:<24} {:>14} {:>14} {:>14}",
            row.name,
            fmt_opt_u64(row.marginal),
            fmt_opt_u64(row.c1),
            fmt_opt_u64(row.c10),
        ));
        out.push('\n');
    }
    out
}

fn build_chat_report_parts(
    cycles: &HashMap<&str, u64>,
    previous: &HashMap<String, u64>,
) -> FamilyReportParts {
    FamilyReportParts {
        new: Some(render_chat_results_table(cycles)),
        old: Some(render_chat_results_table(previous)),
        delta: Some(render_chat_delta_table(cycles, previous)),
    }
}

fn render_delta_cell(new: Option<u64>, old: Option<u64>) -> String {
    match (new, old) {
        (Some(new), Some(old)) if old > 0 => {
            let mut pct = (new as f64 - old as f64) * 100.0 / old as f64;
            if pct.abs() < 0.05 {
                pct = 0.0;
            }
            format!("{pct:+.1}%")
        }
        (Some(_), Some(_)) => "—".to_string(),
        (Some(_), None) => "new".to_string(),
        (None, _) => "—".to_string(),
    }
}

fn render_chat_delta_table(cycles: &HashMap<&str, u64>, previous: &HashMap<String, u64>) -> String {
    let new_rows = build_summary_rows(cycles);
    let old_rows = build_summary_rows(previous);
    let old_row_map: HashMap<&str, &SummaryRow> =
        old_rows.iter().map(|r| (r.name.as_str(), r)).collect();

    let mut out = String::new();
    out.push_str(&table_header());
    out.push('\n');
    out.push_str(&table_separator());
    out.push('\n');
    for row in &new_rows {
        let old_row = old_row_map.get(row.name.as_str()).copied();
        let marginal_str = render_delta_cell(row.marginal, old_row.and_then(|row| row.marginal));
        let c1_str = render_delta_cell(row.c1, old_row.and_then(|row| row.c1));
        let c10_str = render_delta_cell(row.c10, old_row.and_then(|row| row.c10));
        out.push_str(&format!(
            "  {:<24} {:>14} {:>14} {:>14}",
            row.name, marginal_str, c1_str, c10_str,
        ));
        out.push('\n');
    }
    out
}

// ─── Filesystem reporting ────────────────────────────────────────────────────

/// One filesystem report row: the raw 1-op and 10-op cycles for a single base
/// operation. `cycles/op` is recomputed at render time from these raw values, so
/// a saved table can be parsed back without persisting the derived column.
struct FsSummaryRow {
    name: String,
    cycles_1: Option<u64>,
    cycles_10: Option<u64>,
}

fn fmt_opt_u64(v: Option<u64>) -> String {
    v.map_or_else(|| "—".to_string(), |v| v.to_string())
}

/// `cycles/op = (cycles_10 - cycles_1) / 9` (ops_10 - ops_1 == 9) and
/// returns `None` when inputs are missing or non-monotonic.
fn fs_cycles_per_op(cycles_1: Option<u64>, cycles_10: Option<u64>) -> Option<u64> {
    let (Some(c1), Some(c10)) = (cycles_1, cycles_10) else {
        return None;
    };
    let delta = c10.checked_sub(c1)?;
    Some(delta / 9)
}

fn build_fs_summary_rows(
    metrics: &HashMap<impl std::borrow::Borrow<str> + std::hash::Hash + Eq, FsMetric>,
) -> Vec<FsSummaryRow> {
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::new();
    for &(case, _) in FS_CASES {
        let base = strip_numeric_suffix(case);
        if !seen.insert(base.to_string()) {
            continue;
        }
        let case_10 = format!("{base}_10");
        let m1 = metrics.get(base).copied();
        let m10 = metrics.get(case_10.as_str()).copied();
        if m1.is_none() && m10.is_none() {
            continue;
        }
        rows.push(FsSummaryRow {
            name: base.to_string(),
            cycles_1: m1.map(|m| m.cycles),
            cycles_10: m10.map(|m| m.cycles),
        });
    }
    rows
}

fn render_fs_table(rows: &[FsSummaryRow]) -> String {
    let mut out = String::new();
    out.push_str(&table_header());
    out.push('\n');
    out.push_str(&table_separator());
    out.push('\n');
    for row in rows {
        let cycles_per_op = fs_cycles_per_op(row.cycles_1, row.cycles_10);
        out.push_str(&format!(
            "  {:<24} {:>14} {:>14} {:>14}",
            row.name,
            fmt_opt_u64(cycles_per_op),
            fmt_opt_u64(row.cycles_1),
            fmt_opt_u64(row.cycles_10),
        ));
        out.push('\n');
    }
    out
}

/// Parse filesystem rows from a saved combined table. Only raw cycle columns
/// are read; `cycles/op` is recomputed at render time.
fn parse_fs_results_table(table: &str) -> Vec<FsSummaryRow> {
    let mut rows = Vec::new();
    for line in table.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        if cols[0] == "case" || cols[0].starts_with('─') {
            continue;
        }
        let base = cols[0];
        if !FS_CASES
            .iter()
            .any(|&(case, _)| strip_numeric_suffix(case) == base)
        {
            continue;
        }
        if cols.len() != 4 {
            continue;
        }
        rows.push(FsSummaryRow {
            name: base.to_string(),
            cycles_1: cols[2].parse().ok(),
            cycles_10: cols[3].parse().ok(),
        });
    }
    rows
}

fn load_previous_fs_results() -> Vec<FsSummaryRow> {
    let path = results_file_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    extract_grouped_table(&contents, "NEW")
        .map(|table| parse_fs_results_table(&table))
        .unwrap_or_default()
}

fn render_fs_delta_table(new_rows: &[FsSummaryRow], old_rows: &[FsSummaryRow]) -> String {
    let old_map: HashMap<&str, &FsSummaryRow> =
        old_rows.iter().map(|r| (r.name.as_str(), r)).collect();

    let mut out = String::new();
    out.push_str(&table_header());
    out.push('\n');
    out.push_str(&table_separator());
    out.push('\n');
    for row in new_rows {
        let old = old_map.get(row.name.as_str()).copied();
        let new_op = fs_cycles_per_op(row.cycles_1, row.cycles_10);
        let old_op = old.and_then(|o| fs_cycles_per_op(o.cycles_1, o.cycles_10));
        out.push_str(&format!(
            "  {:<24} {:>14} {:>14} {:>14}",
            row.name,
            render_delta_cell(new_op, old_op),
            render_delta_cell(row.cycles_1, old.and_then(|o| o.cycles_1)),
            render_delta_cell(row.cycles_10, old.and_then(|o| o.cycles_10)),
        ));
        out.push('\n');
    }
    out
}

fn build_fs_report_parts(
    metrics: &HashMap<&str, FsMetric>,
    previous: &[FsSummaryRow],
) -> FamilyReportParts {
    let new_rows = build_fs_summary_rows(metrics);
    FamilyReportParts {
        new: Some(render_fs_table(&new_rows)),
        old: Some(render_fs_table(previous)),
        delta: Some(render_fs_delta_table(&new_rows, previous)),
    }
}

fn main() {
    let (selected_chat, selected_fs) = selected_cases();

    let mut chat_report: Option<FamilyReportParts> = None;
    let mut fs_report: Option<FamilyReportParts> = None;

    if !selected_chat.is_empty() {
        let previous = load_previous_new_results();
        let cycles = chat_cycle_fixture(&selected_chat);
        chat_report = Some(build_chat_report_parts(&cycles, &previous));
    }

    if !selected_fs.is_empty() {
        let previous_fs = load_previous_fs_results();
        let fs_metrics = fs_cycle_fixture(&selected_fs);
        fs_report = Some(build_fs_report_parts(&fs_metrics, &previous_fs));
    }

    if chat_report.is_none() && fs_report.is_none() {
        eprintln!("[bench] no cases selected; nothing to run");
        return;
    }

    let report = render_combined_report(chat_report.as_ref(), fs_report.as_ref());
    eprintln!("\n{}", report.trim_end());
    save_results(&report);
}
