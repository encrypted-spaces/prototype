//! Action-routed workloads (parents/children schemas + the 4 actions
//! `passthrough_insert`, `exists_insert`, `cascade_delete`,
//! `unchanged_update`).
//!
//! Shared bench helper — included by multiple bench targets, each of
//! which uses only a subset. Suppress dead_code warnings module-wide.
//!
//! Each `run_*` builds a fresh state + space, pre-populates whatever
//! the action needs, proves those setup changes (and drops the
//! result), then submits ~100 action invocations and returns the
//! state + count.  The next `prove_pending_changes` call against the
//! returned state therefore only covers the workload-specific
//! changes — the same shape as `run_table` / `run_list`.

#![allow(dead_code)]

use encrypted_spaces_acl_types::{
    AccessRule, Action, ActionLeg, Assertion, ColumnNamespace, ComparisonOp, RuleValue,
};
use encrypted_spaces_backend::query::QueryParam;
use encrypted_spaces_backend::schema::Schema;
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_sdk::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
use encrypted_spaces_sdk::Space;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::{prepopulate_parents_fast, prove_pending_changes, SharedStateTransport};

// ─── Row types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Parent {
    id: Option<i64>,
    name: String,
    category: String,
    value: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Child {
    id: Option<i64>,
    parent_id: i64,
    body: String,
}

// ─── Schemas + actions ─────────────────────────────────────────────────────

pub fn action_schemas() -> Vec<Schema> {
    let parents = SchemaBuilder::new("parents")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("name", ColumnType::Text)
        .unwrap()
        .column("category", ColumnType::Text)
        .unwrap()
        .column("value", ColumnType::Integer)
        .unwrap()
        .build()
        .unwrap();

    let children = SchemaBuilder::new("children")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("parent_id", ColumnType::Integer)
        .unwrap()
        .plaintext()
        .index()
        .column("body", ColumnType::Text)
        .unwrap()
        .build()
        .unwrap();

    vec![parents, children]
}

pub fn action_definitions() -> Vec<Action> {
    vec![
        Action {
            name: "passthrough_insert_parent".into(),
            legs: vec![ActionLeg::Insert {
                table: "parents".into(),
            }],
            asserts: vec![],
        },
        Action {
            name: "exists_insert_child".into(),
            legs: vec![ActionLeg::Insert {
                table: "children".into(),
            }],
            asserts: vec![Assertion::Exists {
                table: "parents".into(),
                predicate: AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "id"),
                    ComparisonOp::Equal,
                    RuleValue::column(ColumnNamespace::SelfRow, "parent_id"),
                ),
            }],
        },
        Action {
            name: "cascade_delete_parent".into(),
            legs: vec![
                ActionLeg::Delete {
                    table: "parents".into(),
                },
                ActionLeg::CascadeDelete {
                    table: "children".into(),
                    where_column: "parent_id".into(),
                    where_self_column: "id".into(),
                },
            ],
            asserts: vec![],
        },
        Action {
            name: "unchanged_update_parent".into(),
            legs: vec![ActionLeg::Update {
                table: "parents".into(),
                cols: Some(vec!["value".into()]),
            }],
            asserts: vec![],
        },
    ]
}

// ─── Workload constants ────────────────────────────────────────────────────

const N_ACTIONS: usize = 100;
const CASCADE_CHILDREN: usize = 3;
/// 25 cascade actions × (1 parent + 3 children) = 100 underlying row ops.
const N_CASCADE_PARENTS: usize = 25;

// ─── Shared init ───────────────────────────────────────────────────────────

/// Build a fresh `SpaceState` + `Space` with the parents/children
/// schemas and all four actions registered.  No row data is created
/// here.
async fn init_action_state_and_space() -> (Arc<Mutex<SpaceState>>, Space) {
    let schemas = action_schemas();
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([9u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    };
    let mut state_raw =
        SpaceState::init_server(Some(&schemas), Some(init_cfg), Some(1_000_000_000))
            .await
            .expect("init_server");

    let actions = action_definitions();
    state_raw
        .db
        .import_actions(&actions)
        .await
        .expect("import_actions");
    state_raw
        .db
        .import_acl_only_via_actions(&BTreeMap::new())
        .await
        .expect("import_acl_only_via_actions");
    state_raw
        .reinitialize_changelog()
        .await
        .expect("reinitialize_changelog");
    state_raw.tree_snapshot = state_raw.db.snapshot();
    let app_root = state_raw.db.root_hash();

    let state = Arc::new(Mutex::new(state_raw));
    let app_schema = ApplicationSchema::for_testing(schemas, app_root);
    let space = Space::create(SharedStateTransport::new(Arc::clone(&state)), app_schema)
        .await
        .expect("Space::create");
    for a in actions {
        space.register_action(a);
    }
    (state, space)
}

async fn seed_parents(space: &Space, n: usize) -> Vec<i64> {
    let parents = space.table::<Parent>("parents");
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let id = parents
            .insert(&Parent {
                id: None,
                name: format!("Parent{i}"),
                category: "default".into(),
                value: i as i64,
            })
            .execute()
            .await
            .expect("parent insert execute");
        ids.push(id);
    }
    ids
}

// ─── Workload runners ──────────────────────────────────────────────────────

/// 100 invocations of `passthrough_insert_parent` (1 insert leg, no
/// asserts).
///
/// `pre_pop` adds that many extra parents to the tree via a fast bulk
/// merk write before the measured action calls.
pub async fn run_pure_insert(pre_pop: usize) -> (Arc<Mutex<SpaceState>>, usize) {
    let (state, space) = init_action_state_and_space().await;
    let space = if pre_pop > 0 {
        prepopulate_parents_fast(&state, space, pre_pop).await
    } else {
        space
    };
    for i in 0..N_ACTIONS {
        space
            .call_insert_action(
                "passthrough_insert_parent",
                vec![
                    ("name".into(), QueryParam::Text(format!("pure-{i}"))),
                    ("category".into(), QueryParam::Text("default".into())),
                    ("value".into(), QueryParam::Integer(i as i64)),
                ],
            )
            .await
            .expect("passthrough action");
    }
    (state, N_ACTIONS)
}

/// 100 invocations of `exists_insert_child` (1 insert leg + 1
/// `exists()` assert against `parents`).  Parents are pre-populated
/// and proved before the measured changes are submitted.
pub async fn run_exists_insert(pre_pop: usize) -> (Arc<Mutex<SpaceState>>, usize) {
    let (state, space) = init_action_state_and_space().await;
    let space = if pre_pop > 0 {
        prepopulate_parents_fast(&state, space, pre_pop).await
    } else {
        space
    };
    let parent_ids = seed_parents(&space, 1).await;
    let _ = prove_pending_changes(&state).await;

    let anchor = parent_ids[0];
    for i in 0..N_ACTIONS {
        space
            .call_insert_action(
                "exists_insert_child",
                vec![
                    ("parent_id".into(), QueryParam::Integer(anchor)),
                    ("body".into(), QueryParam::Text(format!("exists-{i}"))),
                ],
            )
            .await
            .expect("exists action");
    }
    (state, N_ACTIONS)
}

/// `N_CASCADE_PARENTS` invocations of `cascade_delete_parent`, each
/// dropping a parent and its `CASCADE_CHILDREN` children.  Parents +
/// children are pre-populated and proved before the cascade-deletes
/// are submitted.  Returns `N_CASCADE_PARENTS * (1 + CASCADE_CHILDREN)`
/// so per-change cycles line up with the underlying row-op cost.
pub async fn run_cascade_delete(pre_pop: usize) -> (Arc<Mutex<SpaceState>>, usize) {
    let (state, space) = init_action_state_and_space().await;
    let space = if pre_pop > 0 {
        prepopulate_parents_fast(&state, space, pre_pop).await
    } else {
        space
    };
    let parent_ids = seed_parents(&space, N_CASCADE_PARENTS).await;
    let children = space.table::<Child>("children");
    for &pid in &parent_ids {
        for j in 0..CASCADE_CHILDREN {
            children
                .insert(&Child {
                    id: None,
                    parent_id: pid,
                    body: format!("cascade-seed-{pid}-{j}"),
                })
                .execute()
                .await
                .expect("seed cascade child execute");
        }
    }
    let _ = prove_pending_changes(&state).await;

    for &pid in &parent_ids {
        space
            .call_delete_action("cascade_delete_parent", pid)
            .await
            .expect("cascade action");
    }
    (state, N_CASCADE_PARENTS * (1 + CASCADE_CHILDREN))
}

/// 100 invocations of `unchanged_update_parent` (1 update leg + 2
/// `unchanged()` asserts).  Parents are pre-populated and proved
/// before the measured changes.
pub async fn run_unchanged_update(pre_pop: usize) -> (Arc<Mutex<SpaceState>>, usize) {
    let (state, space) = init_action_state_and_space().await;
    let space = if pre_pop > 0 {
        prepopulate_parents_fast(&state, space, pre_pop).await
    } else {
        space
    };
    let parent_ids = seed_parents(&space, N_ACTIONS).await;
    let _ = prove_pending_changes(&state).await;

    #[allow(clippy::needless_range_loop)]
    for i in 0..N_ACTIONS {
        space
            .call_update_action(
                "unchanged_update_parent",
                parent_ids[i],
                vec![("value".into(), QueryParam::Integer(10_000 + i as i64))],
            )
            .await
            .expect("unchanged action");
    }
    (state, N_ACTIONS)
}
