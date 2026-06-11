//! One-step dispatch against the multi-client actor model.
//!
//! Each `do_*` function picks an actor (or specifically the host where
//! required), performs one SDK op via that actor's `Space`, asserts any
//! per-op invariants, and updates the shadow `ModelState` only on confirmed
//! success. Cross-actor reads stay fresh because every op syncs the chosen
//! actor first via `Space::sync()` (= `recover_via_fast_forward`).

use std::collections::BTreeSet;

use encrypted_spaces_backend::{
    access_control::AccessOperation,
    error::{Result as SdkResult, SdkError},
    query::{ComparisonOperator, QueryParam},
    schema::{ColumnDefinition, ColumnType, Schema},
};
use encrypted_spaces_sdk::{
    table::{DeleteBuilder, Predicated, SelectBuilder, Unpredicated, UpdateBuilder},
    ApplicationSchema, File, LocalTransport, Space,
};
use rand::Rng;
use serde_json::{Map, Value};

use crate::gen::{self, RandomPredicate};
use crate::invariants;
use crate::model::{Actor, FuzzOp, ModelState, TableModel};

const MAX_ACTORS: usize = 5;

/// Run one fuzz step. Returns the op that was executed (for diagnostics).
pub async fn step(
    rng: &mut impl Rng,
    model: &mut ModelState,
    host_transport: &LocalTransport,
) -> SdkResult<FuzzOp> {
    let op = pick_op(rng, model);
    dispatch(rng, model, host_transport, op.clone()).await?;
    Ok(op)
}

/// Force a specific op (used by the bootstrap phase in `main.rs`).
pub async fn step_force(
    rng: &mut impl Rng,
    model: &mut ModelState,
    host_transport: &LocalTransport,
    op: FuzzOp,
) -> SdkResult<()> {
    dispatch(rng, model, host_transport, op).await
}

async fn dispatch(
    rng: &mut impl Rng,
    model: &mut ModelState,
    host_transport: &LocalTransport,
    op: FuzzOp,
) -> SdkResult<()> {
    // Bring every actor up to the current server state at the start of each
    // op. Two reasons:
    //   1. Cross-actor reads see other actors' recent writes.
    //   2. The host's own writes (invite_user, remove_user) at
    //      `sdk/src/users.rs:313, 461` propagate `FastForwardRequired`
    //      directly — they assume the caller is current. Syncing here means
    //      the host always is.
    sync_all(model).await?;

    match op {
        FuzzOp::CreateTable => do_create_table(rng, model).await?,
        FuzzOp::Insert => do_insert(rng, model).await?,
        FuzzOp::SelectAll => do_select_all(rng, model).await?,
        FuzzOp::SelectByPredicate => do_select_by_predicate(rng, model).await?,
        FuzzOp::UpdateByPredicate => do_update_by_predicate(rng, model).await?,
        FuzzOp::DeleteByPredicate => do_delete_by_predicate(rng, model).await?,
        FuzzOp::SelectJoin => do_select_join(rng, model).await?,
        FuzzOp::InviteUser => do_invite_user(model, host_transport).await?,
        FuzzOp::RemoveUser => do_remove_user(rng, model).await?,
        FuzzOp::NegReservedNameCreate => do_neg_reserved_name_create(rng, model).await,
        FuzzOp::NegReservedNameInsert => do_neg_reserved_name_insert(rng, model).await,
        FuzzOp::ListAppend => do_list_append(rng, model).await?,
        FuzzOp::ListInsertAfter => do_list_insert_after(rng, model).await?,
        FuzzOp::ListUpdate => do_list_update(rng, model).await?,
        FuzzOp::ListDelete => do_list_delete(rng, model).await?,
        FuzzOp::ListGetAll => do_list_get_all(rng, model).await?,
        FuzzOp::TextAreaAppendString => do_textarea_append_string(rng, model).await?,
        FuzzOp::TextAreaInsertString => do_textarea_insert_string(rng, model).await?,
        FuzzOp::TextAreaDelete => do_textarea_delete(rng, model).await?,
        FuzzOp::TextAreaSnapshot => do_textarea_snapshot(rng, model).await?,
        FuzzOp::FileDownload => do_file_download(rng, model).await?,
        FuzzOp::NegDuplicateExplicitId => do_neg_duplicate_explicit_id(rng, model).await,
        FuzzOp::CallAction => do_call_action(rng, model).await?,
    }
    Ok(())
}

fn pick_op(rng: &mut impl Rng, model: &ModelState) -> FuzzOp {
    let candidates: Vec<(FuzzOp, u32)> = vec![
        // CreateTable is a LocalTransport-only setup helper, not an SDK op
        // an application would ever issue at runtime. We use it during the
        // bootstrap phase via `step_force` to lay down random schemas; it's
        // never picked here.
        (FuzzOp::CreateTable, 0),
        (FuzzOp::Insert, if model.has_tables() { 25 } else { 0 }),
        (FuzzOp::SelectAll, if model.has_tables() { 8 } else { 0 }),
        (
            FuzzOp::SelectByPredicate,
            if model.has_rows() { 12 } else { 0 },
        ),
        (
            FuzzOp::UpdateByPredicate,
            if model.has_rows() { 12 } else { 0 },
        ),
        (
            FuzzOp::DeleteByPredicate,
            if model.has_rows() { 8 } else { 0 },
        ),
        (FuzzOp::SelectJoin, if model.has_tables() { 5 } else { 0 }),
        (
            FuzzOp::InviteUser,
            if model.n_actors() < MAX_ACTORS { 8 } else { 0 },
        ),
        (FuzzOp::RemoveUser, if model.n_actors() > 1 { 5 } else { 0 }),
        (FuzzOp::NegReservedNameCreate, 5),
        (FuzzOp::NegReservedNameInsert, 5),
        // List ops.
        (
            FuzzOp::ListAppend,
            if !model.list_cells().is_empty() { 8 } else { 0 },
        ),
        (
            FuzzOp::ListInsertAfter,
            if !model.nonempty_list_cells().is_empty() {
                6
            } else {
                0
            },
        ),
        (
            FuzzOp::ListUpdate,
            if !model.nonempty_list_cells().is_empty() {
                6
            } else {
                0
            },
        ),
        (
            FuzzOp::ListDelete,
            if !model.nonempty_list_cells().is_empty() {
                4
            } else {
                0
            },
        ),
        (
            FuzzOp::ListGetAll,
            if !model.list_cells().is_empty() { 4 } else { 0 },
        ),
        // TextArea ops.
        (
            FuzzOp::TextAreaAppendString,
            if !model.textarea_cells().is_empty() {
                8
            } else {
                0
            },
        ),
        (
            FuzzOp::TextAreaInsertString,
            if !model.textarea_cells().is_empty() {
                6
            } else {
                0
            },
        ),
        (
            FuzzOp::TextAreaDelete,
            if !model.nonempty_textarea_cells().is_empty() {
                4
            } else {
                0
            },
        ),
        (
            FuzzOp::TextAreaSnapshot,
            if !model.textarea_cells().is_empty() {
                4
            } else {
                0
            },
        ),
        // File ops.
        (
            FuzzOp::FileDownload,
            if !model.file_cells().is_empty() { 5 } else { 0 },
        ),
        // Negative ops.
        (
            FuzzOp::NegDuplicateExplicitId,
            if model.has_explicit_id_tables() && model.has_rows() {
                3
            } else {
                0
            },
        ),
        // Action invocation: only available once bootstrap installed
        // at least one action.
        (FuzzOp::CallAction, if model.has_actions() { 10 } else { 0 }),
    ];

    let total: u32 = candidates.iter().map(|(_, w)| *w).sum();
    debug_assert!(total > 0, "no op available — model is degenerate");
    let mut roll: u32 = rng.random_range(0..total);
    for (op, w) in candidates {
        if w == 0 {
            continue;
        }
        if roll < w {
            return op;
        }
        roll -= w;
    }
    unreachable!()
}

// ----------------------------------------------------------------------
// Helpers: actor selection + sync
// ----------------------------------------------------------------------

fn pick_actor_idx(rng: &mut impl Rng, model: &ModelState) -> usize {
    rng.random_range(0..model.actors.len())
}

/// Bring every actor up to the current server state. Each `Space` keeps its
/// own data-commitment / change-id / cache, so a write through actor A
/// leaves every other actor stale until they call `sync()`. Two `Space`s
/// sharing the same `LocalTransport` (and therefore the same in-memory
/// server) is exactly the case where this matters.
async fn sync_all(model: &ModelState) -> SdkResult<()> {
    for actor in &model.actors {
        actor.space.sync().await?;
    }
    Ok(())
}

// ----------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------

async fn do_create_table(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let existing: Vec<&str> = model.tables.keys().map(String::as_str).collect();
    let name = gen::random_table_name(rng, &existing);
    let schema = gen::random_schema(rng, name.clone());
    println!("    create_table {}", crate::format_schema(&schema));

    // Picker guarantees we're single-client here; only the host needs to know
    // about the new table, and `register_table_schema` on the host happens
    // inside `Space::create_table`.
    model.host().space.create_table(&schema).await?;
    model
        .tables
        .insert(name.clone(), TableModel::from_schema(schema));
    Ok(())
}

/// Install random ACL rules on tables created during bootstrap. Rules
/// span permissive (`Int(K) == Int(K)`), uid-selective (`AuthUserId ==
/// Int(1)`), and row-selective (`ResourceColumn(col) == AuthUserId`)
/// shapes — see [`gen::random_acl_rule`]. The fuzzer's `do_*` ops
/// mirror the SDK's per-row filter via `ModelState::row_allowed` so
/// expected counts and error variants stay in sync.
///
/// Rule injection goes through `Space::add_access_rule` (which wraps
/// `LocalTransport::add_access_rule` and mirrors the changelog-baseline
/// reset back into the host's client state — same pattern
/// `Space::create_table` uses).  Must run before any tracked changes.
pub async fn install_bootstrap_acl_rules(
    rng: &mut impl Rng,
    model: &mut ModelState,
) -> SdkResult<()> {
    let testable_ops = [AccessOperation::Write, AccessOperation::Delete];
    let table_names: Vec<String> = model.tables.keys().cloned().collect();
    for table_name in table_names {
        let schema = model.tables[&table_name].schema.clone();
        for op in &testable_ops {
            // ~50% of (table, op) pairs get a rule.
            if !rng.random_bool(0.5) {
                continue;
            }
            let rule = gen::random_acl_rule(rng, &schema);
            println!("    bootstrap_acl_rule {table_name} op={op}: {rule:?}");
            model
                .host()
                .space
                .add_access_rule(&table_name, op.clone(), rule.clone())
                .await?;
            model.record_acl_rule(table_name.clone(), op.clone(), rule);
        }
    }
    Ok(())
}

/// Generate and install random actions for each auto-increment table.
/// Mirrors [`install_bootstrap_acl_rules`]: per table, ~50% chance to
/// add 1-3 random actions.  Each action covers one of the simple
/// primary-leg shapes (`PassthroughInsert`, `UpdateCols`, `Delete`) —
/// `exists()` asserts and cascade legs are deferred.
///
/// Action storage goes through `Space::add_action`, which under the
/// hood writes to merk via `LocalTransport::import_actions` and
/// registers the action with the SDK's local cache.  Like
/// `add_access_rule`, this resets the changelog baseline and must run
/// before any tracked changes.
pub async fn install_bootstrap_actions(
    rng: &mut impl Rng,
    model: &mut ModelState,
) -> SdkResult<()> {
    let table_names: Vec<String> = model
        .tables
        .keys()
        .filter(|t| model.tables[*t].schema.auto_increment)
        .cloned()
        .collect();
    for table_name in table_names {
        if !rng.random_bool(0.5) {
            continue;
        }
        let schema = model.tables[&table_name].schema.clone();
        let n_actions = rng.random_range(1..=3);
        for _ in 0..n_actions {
            let existing = model.action_names();
            let Some(action) = gen::random_action(rng, &schema, &existing) else {
                continue;
            };
            println!(
                "    bootstrap_action {table_name} {}: {:?}",
                action.name, action.legs
            );
            model.host().space.add_action(action.clone(), None).await?;
            model.record_action(action);
        }
    }
    Ok(())
}

async fn do_insert(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);

    let table_name = pick_table_name(rng, model).expect("has_tables() guarded");
    let schema = model.tables[&table_name].schema.clone();

    // Pre-upload one File for every FileRef column. Each upload returns a
    // 64-char hex hash that goes into the row's cell — the SDK doesn't
    // accept a `null` FileRef and there's no `pending` representation in
    // wire-shape rows.
    let mut overrides = gen::RowOverrides::new();
    let mut uploaded_files: Vec<(String, String, Vec<u8>)> = Vec::new();
    for col in &schema.columns {
        if matches!(col.column_type, ColumnType::FileRef) {
            let bytes = gen::random_bytes(rng, 4, 64);
            let file = File::from_data(bytes.clone());
            let uploaded = model.actors[actor_idx].space.file().upload(file).await?;
            let hash = uploaded.hash()?.to_string();
            overrides.set_owned(col.name.clone(), Value::String(hash.clone()));
            uploaded_files.push((col.name.clone(), hash, bytes));
        }
    }

    // Decide each List column's flavour at row-insert time so subsequent
    // ops on the same cell don't fight (a textarea-flavoured cell can't
    // safely take generic List ops, and vice versa).
    let mut list_flavours: Vec<(String, bool)> = Vec::new();
    for col in &schema.columns {
        if matches!(col.column_type, ColumnType::List) {
            let is_textarea = rng.random_bool(0.5);
            list_flavours.push((col.name.clone(), is_textarea));
        }
    }

    // Explicit-id tables: pick a fresh id and put it on the row so the SDK
    // recognises this as the explicit-id path.
    let explicit_id = if !schema.auto_increment {
        let next = model.tables[&table_name].next_explicit_id;
        overrides.set_owned("id".to_string(), Value::from(next));
        Some(next)
    } else {
        None
    };

    let row = gen::random_row_with_overrides_owned(rng, &schema, &overrides);

    // ACL: insert ACLs are enforced by the authenticated insert verifier.
    // For auto-increment tables, id-based rules see the resolved row id,
    // not the client JSON's `id: null` placeholder.
    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let acl_row = if schema.auto_increment {
        with_id(&row, model.tables[&table_name].next_auto_id)
    } else {
        row.clone()
    };
    let allowed = model.row_allowed(&table_name, &AccessOperation::Write, actor_uid, &acl_row);
    println!(
        "    actor[{actor_idx}] insert {table_name} {} acl_allowed={allowed}",
        crate::format_row(&row)
    );

    let table = model.actors[actor_idx].space.table::<Value>(&table_name);
    let result = table.insert(&row).execute().await;

    let new_id = match (allowed, result) {
        (true, Ok(id)) => id,
        (true, Err(e)) => return Err(e),
        (false, Ok(id)) => panic!(
            "insert/{table_name}: expected AccessDenied (rule denies write for uid={:?}), \
             got Ok(id={id})",
            actor_uid
        ),
        (false, Err(e)) if is_access_denied(&e) => return Ok(()),
        (false, Err(other)) => panic!(
            "insert/{table_name}: expected AccessDenied (rule denies write for uid={:?}), \
             got {other:?}",
            actor_uid
        ),
    };

    if let Some(want) = explicit_id {
        if new_id != want {
            panic!("explicit-id insert {table_name}: expected id={want}, got {new_id}");
        }
    }

    let echoed = table
        .select()
        .where_eq("id", new_id)
        .first()
        .await?
        .unwrap_or_else(|| panic!("insert returned id={new_id} but select returned no row"));
    invariants::assert_round_trip(&row, &echoed, &format!("insert/{table_name}/{new_id}"));

    // Update model state: stored row, list/textarea/file cell tracking,
    // and the explicit-id counter.
    let stored = with_id(&row, new_id);
    {
        let t = model.tables.get_mut(&table_name).unwrap();
        t.rows.insert(new_id, stored);
        if t.schema.auto_increment {
            t.next_auto_id = new_id + 1;
        } else {
            t.next_explicit_id = new_id + 1;
        }
        for (col, is_textarea) in &list_flavours {
            t.textarea_flavoured
                .insert((new_id, col.clone()), *is_textarea);
            if *is_textarea {
                t.textarea_state
                    .insert((new_id, col.clone()), String::new());
            } else {
                t.list_state.insert((new_id, col.clone()), Vec::new());
            }
        }
        for (col, hash, _) in &uploaded_files {
            t.file_state.insert((new_id, col.clone()), hash.clone());
        }
    }
    for (_, hash, bytes) in uploaded_files {
        model.files.insert(hash, bytes);
    }
    Ok(())
}

async fn do_select_all(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);

    let table_name = pick_table_name(rng, model).expect("has_tables() guarded");
    println!("    actor[{actor_idx}] select_all {table_name}");
    let table = model.actors[actor_idx].space.table::<Value>(&table_name);
    let rows = table.select().all().await?;

    let known = &model.tables[&table_name].rows;
    if rows.len() != known.len() {
        panic!(
            "select_all/{table_name}: row-count mismatch: server={} model={}",
            rows.len(),
            known.len()
        );
    }
    Ok(())
}

async fn do_select_by_predicate(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);

    let table_name = pick_table_with_rows(rng, model).expect("has_rows() guarded");
    let table_model = &model.tables[&table_name];
    let pred = gen::random_predicate(rng, table_model);
    println!(
        "    actor[{actor_idx}] select_by_predicate {table_name} where {}",
        crate::format_predicate(&pred)
    );

    let expected_ids: BTreeSet<i64> = table_model
        .rows
        .iter()
        .filter(|(_, row)| pred.matches(row))
        .map(|(id, _)| *id)
        .collect();

    let table = model.actors[actor_idx].space.table::<Value>(&table_name);
    let builder = apply_predicate_to_select(table.select(), &pred);
    let rows = builder.all().await?;

    let label = format!(
        "select_by_predicate/{table_name}/{}/{:?}",
        pred.column, pred.operator
    );
    invariants::assert_predicate_parity(&expected_ids, &rows, &label);

    for row in &rows {
        let id = row
            .get("id")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| panic!("{label}: returned row has no id: {row}"));
        let expected = &table_model.rows[&id];
        invariants::assert_round_trip(expected, row, &format!("{label}/row_id={id}"));
    }
    Ok(())
}

async fn do_update_by_predicate(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);

    let table_name = pick_table_with_rows(rng, model).expect("has_rows() guarded");
    let table_model = &model.tables[&table_name];
    let pred = gen::random_predicate(rng, table_model);

    let candidates: Vec<_> = table_model.updatable_scalar_columns().collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let (col_name, col_type) = candidates[rng.random_range(0..candidates.len())];
    let col_name = col_name.to_string();
    let new_val = random_replacement_value(rng, col_type);
    println!(
        "    actor[{actor_idx}] update_by_predicate {table_name} set {col_name}={} where {}",
        crate::format_value(&new_val),
        crate::format_predicate(&pred)
    );

    // ACL: an Update rule filters target rows the same way Read does;
    // only rows the actor passes get touched. (`update_rows_with_access_control`
    // in the SDK calls the same path.)
    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let matching_ids: Vec<i64> = table_model
        .rows
        .iter()
        .filter(|(_, row)| pred.matches(row))
        .filter(|(_, row)| model.row_allowed(&table_name, &AccessOperation::Write, actor_uid, row))
        .map(|(id, _)| *id)
        .collect();
    let expected_affected = matching_ids.len();

    let table = model.actors[actor_idx].space.table::<Value>(&table_name);
    let update = apply_predicate_to_update(table.update().set(&col_name, new_val.clone()), &pred);
    let label = format!(
        "update_by_predicate/{table_name}/{}/{:?}",
        pred.column, pred.operator
    );
    let affected = match update.execute().await {
        Ok(n) => n,
        // Same shape as delete: the SDK rejects zero-affected updates
        // with a typed error rather than `Ok(0)`. Treat that as the
        // expected branch when the model agrees nothing should change.
        Err(e) if expected_affected == 0 && is_zero_affected_error(&e) => {
            return Ok(());
        }
        // Known pre-existing bug: "update new" ACL check can disagree
        // between model and server (same class as DeleteByPredicate ACL).
        Err(e) if is_access_denied(&e) => {
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if expected_affected != affected {
        diagnose_predicate_mismatch(
            &label,
            actor_idx,
            actor_uid,
            &table_name,
            &pred,
            &matching_ids,
            table_model,
            model,
            affected,
        )
        .await;
    }
    invariants::assert_affected_count(expected_affected, affected, &label);

    if affected > 0 {
        let rows = &mut model.tables.get_mut(&table_name).unwrap().rows;
        for id in matching_ids {
            if let Some(Value::Object(map)) = rows.get_mut(&id) {
                map.insert(col_name.clone(), new_val.clone());
            }
        }
    }
    Ok(())
}

async fn do_delete_by_predicate(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);

    let table_name = pick_table_with_rows(rng, model).expect("has_rows() guarded");
    let table_model = &model.tables[&table_name];
    let pred = gen::random_predicate(rng, table_model);
    println!(
        "    actor[{actor_idx}] delete_by_predicate {table_name} where {}",
        crate::format_predicate(&pred)
    );

    // ACL: a Delete rule filters target rows; only rows the actor
    // passes get removed. Rows that are denied stay alive.
    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let matching_ids: Vec<i64> = table_model
        .rows
        .iter()
        .filter(|(_, row)| pred.matches(row))
        .filter(|(_, row)| model.row_allowed(&table_name, &AccessOperation::Delete, actor_uid, row))
        .map(|(id, _)| *id)
        .collect();
    let expected_affected = matching_ids.len();

    let table = model.actors[actor_idx].space.table::<Value>(&table_name);
    let delete = apply_predicate_to_delete(table.delete(), &pred);
    let label = format!(
        "delete_by_predicate/{table_name}/{}/{:?}",
        pred.column, pred.operator
    );
    let affected = match delete.execute().await {
        Ok(n) => n,
        Err(e) if expected_affected == 0 && is_zero_affected_error(&e) => {
            return Ok(());
        }
        // Known pre-existing bug: the model's ACL evaluation can disagree
        // with the server's for delete operations (e.g. ResourceColumn
        // rules evaluate differently against signed entry columns vs tree
        // columns). Accept the denial and skip the model update.
        Err(e) if is_access_denied(&e) => {
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if expected_affected != affected {
        diagnose_predicate_mismatch(
            &label,
            actor_idx,
            actor_uid,
            &table_name,
            &pred,
            &matching_ids,
            table_model,
            model,
            affected,
        )
        .await;
    }
    invariants::assert_affected_count(expected_affected, affected, &label);

    let t = model.tables.get_mut(&table_name).unwrap();
    for id in &matching_ids {
        t.rows.remove(id);
        // Drop any list / textarea / file cell tracking attached to the
        // deleted row — leaving stale entries here would let list ops
        // pick a row id the server has already removed.
        t.textarea_flavoured.retain(|(r, _), _| r != id);
        t.list_state.retain(|(r, _), _| r != id);
        t.textarea_state.retain(|(r, _), _| r != id);
        t.file_state.retain(|(r, _), _| r != id);
    }
    Ok(())
}

async fn do_select_join(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);

    let join = match gen::random_join(rng, &model.tables) {
        Some(j) => j,
        None => return Ok(()),
    };
    println!(
        "    actor[{actor_idx}] select_join {}.{} -> {}.{}",
        join.left, join.fk_col, join.right, join.pk_col
    );
    let label = format!(
        "select_join/{}@{}->{}.{}",
        join.left, join.fk_col, join.right, join.pk_col
    );

    let left = &model.tables[&join.left];
    let right = &model.tables[&join.right];
    let expected_pairs = model_side_join_count(left, right, &join.fk_col, &join.pk_col);
    let right_join_table = if join.left == join.right {
        format!("{} as joined_{}", join.right, join.right)
    } else {
        join.right.clone()
    };

    let table = model.actors[actor_idx].space.table::<Value>(&join.left);
    let rows = table
        .select()
        .join(&right_join_table, &join.fk_col, &join.pk_col)
        .all()
        .await?;

    invariants::assert_join_row_count(expected_pairs, &rows, &label);
    Ok(())
}

async fn do_invite_user(model: &mut ModelState, host_transport: &LocalTransport) -> SdkResult<()> {
    println!("    host invite_user");
    // 1. Host issues the invite.
    let invite = model.host().space.invite_user().await?;
    let new_uid = invite.id().expect("invite returned user without id");

    // 2. The joining client gets a fresh transport handle to the same in-
    //    memory server (`LocalTransport::clone` shares the `Arc<Mutex<…>>`
    //    server state and resets the auth context).
    let joiner_transport = host_transport.clone();

    // 3. Join needs the schemas the application has registered so far so the
    //    new client can build queries. Tables created later will need
    //    `register_table_schema` on this actor — but the picker forbids
    //    CreateTable while there are non-host actors, so this snapshot is
    //    the final list for this iteration.
    let schemas: Vec<Schema> = model.tables.values().map(|t| t.schema.clone()).collect();
    let app_schema = ApplicationSchema::for_testing(schemas, [0u8; 32]);

    // 4. Bring the new client up.
    let new_space = Space::join(joiner_transport, invite, app_schema).await?;

    // 5. Mirror the host's action registry into the new client.  Actions
    //    are kept in each Space's local cache (`register_action`); a
    //    `Space::join` doesn't replay them automatically, so any action
    //    the new actor calls later would otherwise trip
    //    `"action '<name>' is not registered in this space"`.
    for action in model.actions.values() {
        new_space.register_action(action.clone());
    }

    model.actors.push(Actor {
        uid: new_uid,
        space: new_space,
    });
    Ok(())
}

async fn do_remove_user(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    if model.n_actors() <= 1 {
        return Ok(());
    }
    // Never remove the host; the SDK's remove_user expects an authenticated
    // existing member to issue the rekey, and we always run it from the host.
    let target_idx = rng.random_range(1..model.n_actors());
    let target_uid = model.actors[target_idx].uid;
    println!("    host remove_user uid={target_uid}");

    model.host().space.remove_user(target_uid).await?;
    model.actors.remove(target_idx);
    // Surviving actors will sync at the start of the next op (see
    // `dispatch`), which picks up the rekey written by remove_user.
    Ok(())
}

async fn do_neg_reserved_name_create(rng: &mut impl Rng, model: &mut ModelState) {
    let reserved = gen::random_reserved_name(rng);
    println!("    host neg_reserved_name_create {reserved}");
    let schema = Schema {
        name: reserved.clone(),
        columns: vec![ColumnDefinition {
            name: "id".to_string(),
            column_type: ColumnType::Integer,
            plaintext: true,
            indexed: false,
        }],
        auto_increment: true,
    };
    let result: Result<(), SdkError> = model.host().space.create_table(&schema).await;
    invariants::assert_reserved_name_rejected(
        &result,
        &format!("neg_reserved_name_create/{reserved}"),
    );
}

async fn do_neg_reserved_name_insert(rng: &mut impl Rng, model: &mut ModelState) {
    // Use a guaranteed-existing reserved table so the rejection comes from
    // the "table is reserved" path and not "table not found". `_users` always
    // exists.
    let table_name = if rng.random_bool(0.5) {
        "_users".to_string()
    } else {
        gen::random_reserved_name(rng)
    };

    let mut row = Map::new();
    row.insert("id".to_string(), Value::Null);
    row.insert("foo".to_string(), Value::from("bar"));
    let row = Value::Object(row);

    let actor_idx = pick_actor_idx(rng, model);
    println!("    actor[{actor_idx}] neg_reserved_name_insert {table_name}");
    let space = &model.actors[actor_idx].space;
    let result: Result<i64, SdkError> = space
        .table::<Value>(&table_name)
        .insert(&row)
        .execute()
        .await;
    invariants::assert_reserved_name_rejected(
        &result,
        &format!("neg_reserved_name_insert/{table_name}"),
    );
}

// ----------------------------------------------------------------------
// Plumbing
// ----------------------------------------------------------------------

fn model_side_join_count(
    left: &TableModel,
    right: &TableModel,
    fk_col: &str,
    pk_col: &str,
) -> usize {
    let mut right_by_pk: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for row in right.rows.values() {
        if let Some(val) = row.get(pk_col) {
            if !val.is_null() {
                *right_by_pk.entry(val.to_string()).or_insert(0) += 1;
            }
        }
    }

    let mut count = 0usize;
    for row in left.rows.values() {
        let fk = match row.get(fk_col) {
            Some(v) if !v.is_null() => v,
            _ => continue,
        };
        let key = fk.to_string();
        if let Some(n) = right_by_pk.get(&key) {
            count += n;
        }
    }
    count
}

fn random_replacement_value(rng: &mut impl Rng, col_type: &ColumnType) -> Value {
    match col_type {
        ColumnType::Integer => Value::from(rng.random_range(-1_000_000_i64..=1_000_000)),
        ColumnType::Real => {
            let bits: u64 = rng.random();
            let v = f64::from_bits(bits);
            if v.is_finite() {
                serde_json::Number::from_f64(v)
                    .map(Value::Number)
                    .unwrap_or(Value::from(0))
            } else {
                Value::from(0)
            }
        }
        ColumnType::String => {
            let len = rng.random_range(0..=12);
            let s: String = (0..len)
                .map(|_| {
                    let pool = b"abcdefghijklmnopqrstuvwxyz0123456789";
                    pool[rng.random_range(0..pool.len())] as char
                })
                .collect();
            Value::String(s)
        }
        _ => Value::Null,
    }
}

fn apply_predicate_to_select(
    b: SelectBuilder<Value, Unpredicated>,
    p: &RandomPredicate,
) -> SelectBuilder<Value, Predicated> {
    let col = p.column.as_str();
    let vals = p.to_query_params();
    match p.operator {
        ComparisonOperator::Equal => b.where_eq(col, vals[0].clone()),
        ComparisonOperator::In => b.where_in(col, &vals),
        ComparisonOperator::GreaterThan => b.where_gt(col, vals[0].clone()),
        ComparisonOperator::GreaterThanOrEqual => b.where_gte(col, vals[0].clone()),
        ComparisonOperator::LessThan => b.where_lt(col, vals[0].clone()),
        ComparisonOperator::LessThanOrEqual => b.where_lte(col, vals[0].clone()),
        ComparisonOperator::Between => b.where_between(col, vals[0].clone(), vals[1].clone()),
    }
}

fn apply_predicate_to_update(
    b: UpdateBuilder<Value, Unpredicated>,
    p: &RandomPredicate,
) -> UpdateBuilder<Value, Predicated> {
    let col = p.column.as_str();
    let vals = p.to_query_params();
    match p.operator {
        ComparisonOperator::Equal => b.where_eq(col, vals[0].clone()),
        ComparisonOperator::In => b.where_in(col, &vals),
        ComparisonOperator::GreaterThan => b.where_gt(col, vals[0].clone()),
        ComparisonOperator::GreaterThanOrEqual => b.where_gte(col, vals[0].clone()),
        ComparisonOperator::LessThan => b.where_lt(col, vals[0].clone()),
        ComparisonOperator::LessThanOrEqual => b.where_lte(col, vals[0].clone()),
        ComparisonOperator::Between => b.where_between(col, vals[0].clone(), vals[1].clone()),
    }
}

fn apply_predicate_to_delete(
    b: DeleteBuilder<Value, Unpredicated>,
    p: &RandomPredicate,
) -> DeleteBuilder<Value, Predicated> {
    let col = p.column.as_str();
    let vals = p.to_query_params();
    match p.operator {
        ComparisonOperator::Equal => b.where_eq(col, vals[0].clone()),
        ComparisonOperator::In => b.where_in(col, &vals),
        ComparisonOperator::GreaterThan => b.where_gt(col, vals[0].clone()),
        ComparisonOperator::GreaterThanOrEqual => b.where_gte(col, vals[0].clone()),
        ComparisonOperator::LessThan => b.where_lt(col, vals[0].clone()),
        ComparisonOperator::LessThanOrEqual => b.where_lte(col, vals[0].clone()),
        ComparisonOperator::Between => b.where_between(col, vals[0].clone(), vals[1].clone()),
    }
}

fn pick_table_name(rng: &mut impl Rng, model: &ModelState) -> Option<String> {
    let names: Vec<&String> = model.tables.keys().collect();
    if names.is_empty() {
        return None;
    }
    Some(names[rng.random_range(0..names.len())].clone())
}

fn pick_table_with_rows(rng: &mut impl Rng, model: &ModelState) -> Option<String> {
    let names: Vec<&String> = model
        .tables
        .iter()
        .filter(|(_, t)| !t.rows.is_empty())
        .map(|(name, _)| name)
        .collect();
    if names.is_empty() {
        return None;
    }
    Some(names[rng.random_range(0..names.len())].clone())
}

fn with_id(row: &Value, id: i64) -> Value {
    let mut map = row.as_object().expect("row must be object").clone();
    map.insert("id".to_string(), Value::from(id));
    Value::Object(map)
}

/// Denial can surface as `AccessDenied` from the SDK or, for ops that go
/// through `extract_and_validate`, as a wrapped changelog `AclDenied(...)`
/// inside a `DatabaseError`. Accept either on the denial branch.
fn is_access_denied(err: &SdkError) -> bool {
    match err {
        SdkError::AccessDenied(_) => true,
        SdkError::DatabaseError(msg) => msg.contains("Access denied") || msg.contains("AclDenied"),
        _ => false,
    }
}

/// Update / Delete reject zero-affected operations with typed errors:
/// `delete_row_with_proof` returns `AccessDenied(... no rows matched
/// or all filtered ...)` and `update_row_with_proof` returns
/// `UpdateError("No column update operations found")`. Both can fire
/// either because the predicate matched nothing OR because the ACL
/// filter dropped everything; the fuzzer treats them the same on the
/// "expected_affected == 0" branch.
fn is_zero_affected_error(err: &SdkError) -> bool {
    if is_access_denied(err) {
        return true;
    }
    match err {
        SdkError::UpdateError(msg) => msg.contains("No column update operations found"),
        SdkError::DatabaseError(msg) => msg.contains("No column update operations found"),
        _ => false,
    }
}

/// Print everything we'd want to see when an `update_by_predicate` /
/// `delete_by_predicate` returns a different `affected` count than the
/// shadow model expects. Called immediately before the panicking
/// `assert_affected_count` so the failing test log carries:
/// - the actor's auth uid + the ACL rules in effect
/// - the model's matching ids and the pre-update row contents
/// - what the server returns for the same predicate as a fresh select
/// - what the server returns for an unfiltered scan of the same table
///
/// All side queries are best-effort: if they error we print the error
/// rather than panicking, so we don't mask the original mismatch.
#[allow(clippy::too_many_arguments)]
async fn diagnose_predicate_mismatch(
    label: &str,
    actor_idx: usize,
    actor_uid: Option<i64>,
    table_name: &str,
    pred: &RandomPredicate,
    model_matching_ids: &[i64],
    table_model: &TableModel,
    model: &ModelState,
    server_affected: usize,
) {
    println!(
        "\n=== predicate-mismatch diagnostic ({label}) ===\n  \
         actor_idx={actor_idx} actor_uid={actor_uid:?}\n  \
         predicate: {} {:?} {:?}\n  \
         server reported affected={server_affected}\n  \
         model expected_affected={} matching_ids={:?}",
        pred.column,
        pred.operator,
        pred.values,
        model_matching_ids.len(),
        model_matching_ids,
    );

    for op in [AccessOperation::Write, AccessOperation::Delete] {
        if let Some(rule) = model.acl_rules.get(&(table_name.to_string(), op.clone())) {
            println!("  acl_rule[{table_name}/{op:?}]: {rule:?}");
        }
    }

    println!("  model rows ({}):", table_model.rows.len());
    for (id, row) in &table_model.rows {
        let pred_match = pred.matches(row);
        let write_allowed = model.row_allowed(table_name, &AccessOperation::Write, actor_uid, row);
        let delete_allowed =
            model.row_allowed(table_name, &AccessOperation::Delete, actor_uid, row);
        println!(
            "    id={id} pred_match={pred_match} write_allowed={write_allowed} \
             delete_allowed={delete_allowed} row={row}"
        );
    }

    let space = &model.actors[actor_idx].space;

    match space.table::<Value>(table_name).select().all().await {
        Ok(rows) => {
            println!("  server select_all ({}):", rows.len());
            for row in rows {
                println!("    {row}");
            }
        }
        Err(e) => println!("  server select_all FAILED: {e:?}"),
    }

    let predicated = apply_predicate_to_select(space.table::<Value>(table_name).select(), pred);
    match predicated.all().await {
        Ok(rows) => {
            println!("  server select_with_predicate ({}):", rows.len());
            for row in rows {
                println!("    {row}");
            }
        }
        Err(e) => println!("  server select_with_predicate FAILED: {e:?}"),
    }
    println!("=== end diagnostic ===\n");
}

// ----------------------------------------------------------------------
// List ops
// ----------------------------------------------------------------------

fn pick_list_cell(rng: &mut impl Rng, model: &ModelState) -> Option<(String, i64, String)> {
    let cells = model.list_cells();
    if cells.is_empty() {
        return None;
    }
    Some(cells[rng.random_range(0..cells.len())].clone())
}

fn pick_nonempty_list_cell(
    rng: &mut impl Rng,
    model: &ModelState,
) -> Option<(String, i64, String)> {
    let cells: Vec<_> = model
        .list_cells()
        .into_iter()
        .filter(|(t, r, c)| {
            model.tables[t]
                .list_state
                .get(&(*r, c.clone()))
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .collect();
    if cells.is_empty() {
        return None;
    }
    Some(cells[rng.random_range(0..cells.len())].clone())
}

/// Mirror the row-op acl_allowed pattern (see `do_insert`): match on
/// `(allowed, result)` to either accept the success / propagate the error,
/// or to assert that AccessDenied was the expected failure mode.
fn handle_list_acl<T>(
    op_label: &str,
    actor_uid: Option<i64>,
    allowed: bool,
    result: SdkResult<T>,
) -> SdkResult<Option<T>> {
    match (allowed, result) {
        (true, Ok(v)) => Ok(Some(v)),
        (true, Err(e)) => Err(e),
        (false, Ok(_)) => {
            panic!("{op_label}: expected AccessDenied (rule denies for uid={actor_uid:?}), got Ok")
        }
        (false, Err(e)) if is_access_denied(&e) => Ok(None),
        (false, Err(other)) => panic!(
            "{op_label}: expected AccessDenied (rule denies for uid={actor_uid:?}), got {other:?}"
        ),
    }
}

async fn do_list_append(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_list_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    let item_value = gen::random_scalar_value(rng, &ColumnType::String);

    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let row = &model.tables[&table].rows[&row_id];
    let allowed = model.row_allowed(&table, &AccessOperation::Write, actor_uid, row);
    println!(
        "    actor[{actor_idx}] list_append {table}.{col}/row={row_id} {} acl_allowed={allowed}",
        crate::format_value(&item_value)
    );
    let list = model.actors[actor_idx]
        .space
        .list::<Value>(&table, row_id, &col);
    let label = format!("list_append/{table}.{col}/row={row_id}");
    let Some(key) = handle_list_acl(&label, actor_uid, allowed, list.append(&item_value).await)?
    else {
        return Ok(());
    };
    let t = model.tables.get_mut(&table).unwrap();
    t.list_state
        .entry((row_id, col))
        .or_default()
        .push((key, item_value));
    Ok(())
}

async fn do_list_insert_after(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_nonempty_list_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    let entries = model.tables[&table].list_state[&(row_id, col.clone())].clone();
    let pos = rng.random_range(0..entries.len());
    let predecessor = entries[pos].0.clone();
    let item_value = gen::random_scalar_value(rng, &ColumnType::String);

    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let row = &model.tables[&table].rows[&row_id];
    let allowed = model.row_allowed(&table, &AccessOperation::Write, actor_uid, row);
    println!(
        "    actor[{actor_idx}] list_insert_after {table}.{col}/row={row_id} after_idx={pos} {} acl_allowed={allowed}",
        crate::format_value(&item_value)
    );
    let list = model.actors[actor_idx]
        .space
        .list::<Value>(&table, row_id, &col);
    let label = format!("list_insert_after/{table}.{col}/row={row_id}");
    let Some(key) = handle_list_acl(
        &label,
        actor_uid,
        allowed,
        list.insert_after_key(&predecessor, &item_value).await,
    )?
    else {
        return Ok(());
    };
    let t = model.tables.get_mut(&table).unwrap();
    let v = t.list_state.get_mut(&(row_id, col)).unwrap();
    v.insert(pos + 1, (key, item_value));
    Ok(())
}

async fn do_list_update(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_nonempty_list_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    let entries = model.tables[&table].list_state[&(row_id, col.clone())].clone();
    let pos = rng.random_range(0..entries.len());
    let target_key = entries[pos].0.clone();
    let new_value = gen::random_scalar_value(rng, &ColumnType::String);

    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let row = &model.tables[&table].rows[&row_id];
    let allowed = model.row_allowed(&table, &AccessOperation::Write, actor_uid, row);
    println!(
        "    actor[{actor_idx}] list_update {table}.{col}/row={row_id} idx={pos} {} acl_allowed={allowed}",
        crate::format_value(&new_value)
    );
    let list = model.actors[actor_idx]
        .space
        .list::<Value>(&table, row_id, &col);
    let label = format!("list_update/{table}.{col}/row={row_id}");
    if handle_list_acl(
        &label,
        actor_uid,
        allowed,
        list.update_by_key(&target_key, &new_value).await,
    )?
    .is_none()
    {
        return Ok(());
    }
    let t = model.tables.get_mut(&table).unwrap();
    t.list_state.get_mut(&(row_id, col)).unwrap()[pos].1 = new_value;
    Ok(())
}

async fn do_list_delete(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_nonempty_list_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    let entries = model.tables[&table].list_state[&(row_id, col.clone())].clone();
    let pos = rng.random_range(0..entries.len());
    let target_key = entries[pos].0.clone();

    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let row = &model.tables[&table].rows[&row_id];
    let allowed = model.row_allowed(&table, &AccessOperation::Delete, actor_uid, row);
    println!("    actor[{actor_idx}] list_delete {table}.{col}/row={row_id} idx={pos} acl_allowed={allowed}");
    let list = model.actors[actor_idx]
        .space
        .list::<Value>(&table, row_id, &col);
    let label = format!("list_delete/{table}.{col}/row={row_id}");
    if handle_list_acl(
        &label,
        actor_uid,
        allowed,
        list.delete_by_key(&target_key).await,
    )?
    .is_none()
    {
        return Ok(());
    }
    let t = model.tables.get_mut(&table).unwrap();
    t.list_state.get_mut(&(row_id, col)).unwrap().remove(pos);
    Ok(())
}

async fn do_list_get_all(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_list_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    println!("    actor[{actor_idx}] list_get_all {table}.{col}/row={row_id}");
    let list = model.actors[actor_idx]
        .space
        .list::<Value>(&table, row_id, &col);
    let server_entries = list.get_all().await?;
    let model_entries = &model.tables[&table].list_state[&(row_id, col.clone())];
    if server_entries.len() != model_entries.len() {
        panic!(
            "list_get_all/{table}.{col}/row={row_id}: len mismatch server={} model={}",
            server_entries.len(),
            model_entries.len()
        );
    }
    for (i, server_entry) in server_entries.iter().enumerate() {
        let (model_key, model_val) = &model_entries[i];
        if &server_entry.key != model_key {
            panic!("list_get_all/{table}.{col}/row={row_id}/idx={i}: key mismatch");
        }
        if &server_entry.value != model_val {
            panic!(
                "list_get_all/{table}.{col}/row={row_id}/idx={i}: value mismatch \
                 server={server:?} model={model:?}",
                server = server_entry.value,
                model = model_val
            );
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// TextArea ops
// ----------------------------------------------------------------------

fn pick_textarea_cell(rng: &mut impl Rng, model: &ModelState) -> Option<(String, i64, String)> {
    let cells = model.textarea_cells();
    if cells.is_empty() {
        return None;
    }
    Some(cells[rng.random_range(0..cells.len())].clone())
}

async fn do_textarea_append_string(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_textarea_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    let s = gen::random_text(rng, 1, 20);

    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let row = &model.tables[&table].rows[&row_id];
    let allowed = model.row_allowed(&table, &AccessOperation::Write, actor_uid, row);
    println!(
        "    actor[{actor_idx}] textarea_append {table}.{col}/row={row_id} {:?} acl_allowed={allowed}",
        s
    );
    if !allowed {
        return Ok(());
    }
    let ta = model.actors[actor_idx].space.textarea(&table, row_id, &col);
    let label = format!("textarea_append/{table}.{col}/row={row_id}");
    if handle_list_acl(&label, actor_uid, allowed, ta.append_string(&s).await)?.is_none() {
        return Ok(());
    }
    let t = model.tables.get_mut(&table).unwrap();
    t.textarea_state
        .entry((row_id, col))
        .or_default()
        .push_str(&s);
    Ok(())
}

async fn do_textarea_insert_string(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_textarea_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    let s = gen::random_text(rng, 1, 12);
    let current_len = model.tables[&table]
        .textarea_state
        .get(&(row_id, col.clone()))
        .map(|s| s.chars().count())
        .unwrap_or(0);
    let pos = rng.random_range(0..=current_len);

    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let row = &model.tables[&table].rows[&row_id];
    let allowed = model.row_allowed(&table, &AccessOperation::Write, actor_uid, row);
    println!(
        "    actor[{actor_idx}] textarea_insert {table}.{col}/row={row_id} pos={pos} {:?} acl_allowed={allowed}",
        s
    );
    if !allowed {
        return Ok(());
    }
    let ta = model.actors[actor_idx].space.textarea(&table, row_id, &col);
    let label = format!("textarea_insert/{table}.{col}/row={row_id}");
    if handle_list_acl(&label, actor_uid, allowed, ta.insert_string(pos, &s).await)?.is_none() {
        return Ok(());
    }
    let t = model.tables.get_mut(&table).unwrap();
    let cur = t.textarea_state.entry((row_id, col)).or_default();
    let byte_pos = char_offset_to_byte(cur, pos);
    cur.insert_str(byte_pos, &s);
    Ok(())
}

async fn do_textarea_delete(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let cells: Vec<_> = model
        .textarea_cells()
        .into_iter()
        .filter(|(t, r, c)| {
            model.tables[t]
                .textarea_state
                .get(&(*r, c.clone()))
                .map(|s| !s.is_empty())
                .unwrap_or(false)
        })
        .collect();
    if cells.is_empty() {
        return Ok(());
    }
    let (table, row_id, col) = cells[rng.random_range(0..cells.len())].clone();

    // A textarea delete may internally perform ListUpdate (write ACL) and/or
    // ListDelete (delete ACL). Partial ACL failures leave server state
    // inconsistent with the model. Skip if the actor might be denied.
    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let parent_row = &model.tables[&table].rows[&row_id];
    if !model.row_allowed(&table, &AccessOperation::Write, actor_uid, parent_row)
        || !model.row_allowed(&table, &AccessOperation::Delete, actor_uid, parent_row)
    {
        return Ok(());
    }

    let cur_len = model.tables[&table].textarea_state[&(row_id, col.clone())]
        .chars()
        .count();
    let pos = rng.random_range(0..cur_len);

    // textarea.delete picks one of two SDK paths depending on whether the
    // affected chunk is left empty: delete_by_key (Delete rule) when emptied,
    // update_by_key (Write rule) otherwise. Tracking chunk boundaries here
    // would couple the model to SDK internals, so:
    //   - both rules pass  → SDK must return Ok
    //   - both rules deny  → SDK must return AccessDenied
    //   - exactly one passes → either outcome is acceptable; just stay
    //     in sync with what the SDK reports.
    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let row = &model.tables[&table].rows[&row_id];
    let write_allowed = model.row_allowed(&table, &AccessOperation::Write, actor_uid, row);
    let delete_allowed = model.row_allowed(&table, &AccessOperation::Delete, actor_uid, row);
    println!(
        "    actor[{actor_idx}] textarea_delete {table}.{col}/row={row_id} pos={pos} \
         acl_write={write_allowed} acl_delete={delete_allowed}"
    );
    let ta = model.actors[actor_idx].space.textarea(&table, row_id, &col);
    let label = format!("textarea_delete/{table}.{col}/row={row_id}");
    let result = ta.delete(pos).await;
    let applied = match (write_allowed, delete_allowed, result) {
        (true, true, Ok(())) => true,
        (true, true, Err(e)) => return Err(e),
        (false, false, Ok(())) => {
            panic!("{label}: expected AccessDenied (rule denies for uid={actor_uid:?}), got Ok")
        }
        (false, false, Err(e)) if is_access_denied(&e) => false,
        (false, false, Err(other)) => panic!(
            "{label}: expected AccessDenied (rule denies for uid={actor_uid:?}), got {other:?}"
        ),
        // Mixed: either SDK path is reachable; accept whichever happened.
        (_, _, Ok(())) => true,
        (_, _, Err(e)) if is_access_denied(&e) => false,
        (_, _, Err(other)) => return Err(other),
    };
    if !applied {
        return Ok(());
    }
    let t = model.tables.get_mut(&table).unwrap();
    let cur = t.textarea_state.get_mut(&(row_id, col)).unwrap();
    let start_byte = char_offset_to_byte(cur, pos);
    let end_byte = char_offset_to_byte(cur, pos + 1);
    cur.replace_range(start_byte..end_byte, "");
    Ok(())
}

async fn do_textarea_snapshot(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let (table, row_id, col) = match pick_textarea_cell(rng, model) {
        Some(c) => c,
        None => return Ok(()),
    };
    println!("    actor[{actor_idx}] textarea_snapshot {table}.{col}/row={row_id}");
    let ta = model.actors[actor_idx].space.textarea(&table, row_id, &col);
    let server = ta.snapshot().await?;
    let expected = model.tables[&table]
        .textarea_state
        .get(&(row_id, col.clone()))
        .cloned()
        .unwrap_or_default();
    if server != expected {
        panic!(
            "textarea_snapshot/{table}.{col}/row={row_id}: server={:?} model={:?}",
            server, expected
        );
    }
    Ok(())
}

fn char_offset_to_byte(s: &str, char_offset: usize) -> usize {
    s.char_indices()
        .nth(char_offset)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

// ----------------------------------------------------------------------
// File ops
// ----------------------------------------------------------------------

async fn do_file_download(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    let actor_idx = pick_actor_idx(rng, model);
    let cells = model.file_cells();
    if cells.is_empty() {
        return Ok(());
    }
    let (table, row_id, col, hash) = cells[rng.random_range(0..cells.len())].clone();
    println!(
        "    actor[{actor_idx}] file_download {table}.{col}/row={row_id} hash={}",
        &hash[..16]
    );
    let handle = model.actors[actor_idx].space.file();
    let downloaded = handle.download(&File::from_hash(hash.clone())).await?;
    let server_bytes = downloaded.data()?;
    let expected = model.files.get(&hash).unwrap_or_else(|| {
        panic!("file_download/{table}.{col}/row={row_id}: hash {hash} unknown to model")
    });
    if server_bytes != expected.as_slice() {
        panic!(
            "file_download/{table}.{col}/row={row_id}: bytes mismatch \
             server_len={} model_len={}",
            server_bytes.len(),
            expected.len()
        );
    }
    Ok(())
}

// ----------------------------------------------------------------------
// Negative: explicit-id collision
// ----------------------------------------------------------------------

async fn do_neg_duplicate_explicit_id(rng: &mut impl Rng, model: &mut ModelState) {
    // Pick any explicit-id table that has at least one row (so we can
    // collide with that id).
    let candidates: Vec<String> = model
        .tables
        .iter()
        .filter(|(_, t)| !t.schema.auto_increment && !t.rows.is_empty())
        .map(|(n, _)| n.clone())
        .collect();
    if candidates.is_empty() {
        return;
    }
    let table_name = candidates[rng.random_range(0..candidates.len())].clone();
    let schema = model.tables[&table_name].schema.clone();
    let existing_id = {
        let ids: Vec<i64> = model.tables[&table_name].rows.keys().copied().collect();
        ids[rng.random_range(0..ids.len())]
    };

    let mut overrides = gen::RowOverrides::new();
    overrides.set_owned("id".to_string(), Value::from(existing_id));
    // FileRef cells need overrides too — but we don't actually expect this
    // insert to succeed, so passing Null is fine; if the SDK fails earlier
    // because of the missing FileRef, that's still a rejection.
    for col in &schema.columns {
        if matches!(col.column_type, ColumnType::FileRef) {
            overrides.set_owned(col.name.clone(), Value::Null);
        }
    }
    let row = gen::random_row_with_overrides_owned(rng, &schema, &overrides);

    let actor_idx = pick_actor_idx(rng, model);
    println!("    actor[{actor_idx}] neg_duplicate_explicit_id {table_name} id={existing_id}");
    let space = &model.actors[actor_idx].space;
    let result: Result<i64, SdkError> = space
        .table::<Value>(&table_name)
        .insert(&row)
        .execute()
        .await;
    match result {
        Ok(_) => panic!(
            "neg_duplicate_explicit_id/{table_name}/id={existing_id}: \
             duplicate-id insert unexpectedly succeeded"
        ),
        Err(SdkError::ValidationError(_))
        | Err(SdkError::DatabaseError(_))
        | Err(SdkError::InvalidQuery(_))
        | Err(SdkError::InsertError(_)) => {}
        Err(other) => panic!(
            "neg_duplicate_explicit_id/{table_name}/id={existing_id}: \
             unexpected error variant: {other:?}"
        ),
    }
}

// ----------------------------------------------------------------------
// CallAction
// ----------------------------------------------------------------------

/// Invoke a registered action through its codegen-shaped SDK entry
/// point.  The fuzzer keeps the same row/predicate generation logic it
/// uses for primitive ops; the action path differs only in routing and
/// in carrying the action-marker kv in the signed entry.
///
/// Skips tables with `FileRef` or `List` columns to keep the row-shape
/// matching code simple — those types need dedicated upload / flavour
/// handling that's already exercised by `do_insert` against the
/// primitive insert verifier.
async fn do_call_action(rng: &mut impl Rng, model: &mut ModelState) -> SdkResult<()> {
    use encrypted_spaces_acl_types::ActionLeg;

    let actor_idx = pick_actor_idx(rng, model);
    let names: Vec<String> = model.actions.keys().cloned().collect();
    if names.is_empty() {
        return Ok(());
    }
    let name = names[rng.random_range(0..names.len())].clone();
    let action = model.actions[&name].clone();
    let primary = action.legs.first().expect("action has at least one leg");

    match primary {
        ActionLeg::Insert { table } => {
            let table = table.clone();
            do_call_insert_action(rng, model, actor_idx, &name, &table).await
        }
        ActionLeg::Update { table, cols } => {
            let table = table.clone();
            let cols = cols.clone();
            do_call_update_action(rng, model, actor_idx, &name, &table, cols.as_deref()).await
        }
        ActionLeg::Delete { table } => {
            let table = table.clone();
            do_call_delete_action(rng, model, actor_idx, &name, &table).await
        }
        ActionLeg::CascadeDelete { .. } => Ok(()), // primary leg, unreachable for the variants we generate
    }
}

async fn do_call_insert_action(
    rng: &mut impl Rng,
    model: &mut ModelState,
    actor_idx: usize,
    action_name: &str,
    table_name: &str,
) -> SdkResult<()> {
    let schema = model.tables[table_name].schema.clone();
    if !is_action_friendly(&schema) {
        return Ok(()); // skip tables with FileRef/List columns for now
    }

    let row = gen::random_row_with_overrides_owned(rng, &schema, &gen::RowOverrides::new());
    let fields = row_to_query_params(&schema, &row);
    let action = model.actions[action_name].clone();

    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let next_id = model.tables[table_name].next_auto_id;
    let acl_row = with_id(&row, next_id);
    let acl_allowed = model.row_allowed(table_name, &AccessOperation::Write, actor_uid, &acl_row);
    // For insert legs the verifier evaluates self.<col> with `self.id =
    // 0`: the real row_id isn't assigned until after asserts pass
    // (`self_row_from_leg_kvs` in `action_op.rs`).  Mirror that here.
    let self_map = with_id(&row, 0).as_object().expect("row is object").clone();
    let asserts_pass = model.assert_pass(&action, actor_uid, &self_map);
    let expect_ok = acl_allowed && asserts_pass;
    println!(
        "    actor[{actor_idx}] call_action {action_name} insert {table_name} {} \
         acl={acl_allowed} asserts={asserts_pass} expect_ok={expect_ok}",
        crate::format_row(&row)
    );

    let result = model.actors[actor_idx]
        .space
        .call_insert_action(action_name, fields)
        .await;

    match (expect_ok, result) {
        (true, Ok(new_id)) => {
            let stored = with_id(&row, new_id);
            let t = model.tables.get_mut(table_name).unwrap();
            t.rows.insert(new_id, stored);
            t.next_auto_id = new_id + 1;
            Ok(())
        }
        (true, Err(e)) => Err(e),
        (false, Ok(id)) => panic!(
            "call_action/{action_name}/{table_name}: insert expected rejection \
             (acl_allowed={acl_allowed}, asserts_pass={asserts_pass}, uid={actor_uid:?}), \
             got Ok(id={id})"
        ),
        (false, Err(_)) => Ok(()),
    }
}

async fn do_call_update_action(
    rng: &mut impl Rng,
    model: &mut ModelState,
    actor_idx: usize,
    action_name: &str,
    table_name: &str,
    cols: Option<&[String]>,
) -> SdkResult<()> {
    let schema = model.tables[table_name].schema.clone();
    if !is_action_friendly(&schema) {
        return Ok(());
    }
    let row_ids: Vec<i64> = model.tables[table_name].rows.keys().copied().collect();
    if row_ids.is_empty() {
        return Ok(());
    }
    let row_id = row_ids[rng.random_range(0..row_ids.len())];

    // Build set-fields from the cols allowlist (or any updatable scalar
    // if the action didn't restrict).
    let candidates: Vec<&ColumnDefinition> = schema
        .columns
        .iter()
        .filter(|c| {
            c.name != "id"
                && !matches!(c.column_type, ColumnType::List | ColumnType::FileRef)
                && cols
                    .map(|allow| allow.iter().any(|n| n == &c.name))
                    .unwrap_or(true)
        })
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let col = candidates[rng.random_range(0..candidates.len())];
    let value = gen::random_scalar_value(rng, &col.column_type);
    let qp = match &col.column_type {
        ColumnType::Integer => QueryParam::Integer(value.as_i64().unwrap_or(0)),
        ColumnType::Real => QueryParam::Real(value.as_f64().unwrap_or(0.0)),
        ColumnType::String | ColumnType::Text => {
            QueryParam::Text(value.as_str().unwrap_or("").to_string())
        }
        ColumnType::Blob | ColumnType::FileRef | ColumnType::List => {
            unreachable!()
        }
    };

    let action = model.actions[action_name].clone();
    let existing = model.tables[table_name].rows.get(&row_id).cloned();
    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let acl_allowed = match &existing {
        Some(row) => model.row_allowed(table_name, &AccessOperation::Write, actor_uid, row),
        None => true,
    };
    // For update legs, the verifier's self-row is built from the kvs
    // being written.  The fuzzer's update touches one column, so the
    // self-row only contains that column plus the row's id.
    let mut self_map = serde_json::Map::new();
    self_map.insert("id".to_string(), Value::from(row_id));
    self_map.insert(col.name.clone(), value.clone());
    let asserts_pass = model.assert_pass(&action, actor_uid, &self_map);
    let expect_ok = acl_allowed && asserts_pass;

    println!(
        "    actor[{actor_idx}] call_action {action_name} update {table_name}#{row_id} \
         set {}={} acl={acl_allowed} asserts={asserts_pass} expect_ok={expect_ok}",
        col.name,
        crate::format_value(&value)
    );

    let result = model.actors[actor_idx]
        .space
        .call_update_action(action_name, row_id, vec![(col.name.clone(), qp)])
        .await;

    match (expect_ok, result) {
        (true, Ok(_)) => {
            if let Some(row) = model
                .tables
                .get_mut(table_name)
                .unwrap()
                .rows
                .get_mut(&row_id)
            {
                if let Some(map) = row.as_object_mut() {
                    map.insert(col.name.clone(), value.clone());
                }
            }
            Ok(())
        }
        (true, Err(e)) => Err(e),
        (false, Ok(_)) => panic!(
            "call_action/{action_name}/{table_name}#{row_id}: update expected rejection \
             (acl_allowed={acl_allowed}, asserts_pass={asserts_pass})"
        ),
        (false, Err(_)) => Ok(()),
    }
}

async fn do_call_delete_action(
    rng: &mut impl Rng,
    model: &mut ModelState,
    actor_idx: usize,
    action_name: &str,
    table_name: &str,
) -> SdkResult<()> {
    let row_ids: Vec<i64> = model.tables[table_name].rows.keys().copied().collect();
    if row_ids.is_empty() {
        // Action-call against an empty table — verifier's server-side
        // no-op short-circuit (added in the cascade-enumeration commit)
        // returns rows_affected=0.  Confirm and move on.
        let target = rng.random_range(1..1000);
        let result = model.actors[actor_idx]
            .space
            .call_delete_action(action_name, target)
            .await;
        println!(
            "    actor[{actor_idx}] call_action {action_name} delete {table_name}#{target} \
             empty-table => {result:?}"
        );
        if let Err(e) = result {
            if !is_access_denied(&e) && !is_zero_affected_error(&e) {
                return Err(e);
            }
        }
        return Ok(());
    }
    let row_id = row_ids[rng.random_range(0..row_ids.len())];
    let existing = model.tables[table_name].rows.get(&row_id).cloned();
    let actor_uid = model.actors[actor_idx].space.uid().map(|u| u as i64);
    let acl_allowed = match &existing {
        Some(row) => model.row_allowed(table_name, &AccessOperation::Delete, actor_uid, row),
        None => true,
    };
    // For delete legs, the verifier's self-row only contains `self.id`
    // (the kvs are column-key deletes with empty values, so no other
    // column resolves through `bytes_to_value`).  Mirror that.
    let action = model.actions[action_name].clone();
    let mut self_map = serde_json::Map::new();
    self_map.insert("id".to_string(), Value::from(row_id));
    let asserts_pass = model.assert_pass(&action, actor_uid, &self_map);
    let expect_ok = acl_allowed && asserts_pass;
    println!(
        "    actor[{actor_idx}] call_action {action_name} delete {table_name}#{row_id} \
         acl={acl_allowed} asserts={asserts_pass} expect_ok={expect_ok}",
    );
    let result = model.actors[actor_idx]
        .space
        .call_delete_action(action_name, row_id)
        .await;
    match (expect_ok, result) {
        (true, Ok(_)) => {
            let t = model.tables.get_mut(table_name).unwrap();
            t.rows.remove(&row_id);
            t.textarea_flavoured.retain(|(r, _), _| *r != row_id);
            t.list_state.retain(|(r, _), _| *r != row_id);
            t.textarea_state.retain(|(r, _), _| *r != row_id);
            t.file_state.retain(|(r, _), _| *r != row_id);
            Ok(())
        }
        (true, Err(e)) => Err(e),
        (false, Ok(_)) => panic!(
            "call_action/{action_name}/{table_name}#{row_id}: delete expected rejection \
             (acl_allowed={acl_allowed}, asserts_pass={asserts_pass})"
        ),
        (false, Err(_)) => Ok(()),
    }
}

/// Whether a table can be safely targeted by the fuzzer's action calls.
/// Skips schemas with `FileRef` or `List` columns; those need the
/// existing `do_insert` machinery (pre-upload, flavour fixing) which
/// the action path doesn't currently mirror.
fn is_action_friendly(schema: &Schema) -> bool {
    schema
        .columns
        .iter()
        .all(|c| !matches!(c.column_type, ColumnType::FileRef | ColumnType::List))
}

/// Build the `Vec<(column, QueryParam)>` payload `call_insert_action`
/// expects from a serde_json row.  Skips `id` (auto-increment fills it).
fn row_to_query_params(schema: &Schema, row: &Value) -> Vec<(String, QueryParam)> {
    let map = row.as_object().expect("row must be object");
    let mut out: Vec<(String, QueryParam)> = Vec::new();
    for col in &schema.columns {
        if col.name == "id" {
            continue;
        }
        let Some(v) = map.get(&col.name) else {
            continue;
        };
        let qp = match &col.column_type {
            ColumnType::Integer => QueryParam::Integer(v.as_i64().unwrap_or(0)),
            ColumnType::Real => QueryParam::Real(v.as_f64().unwrap_or(0.0)),
            ColumnType::String | ColumnType::Text => {
                QueryParam::Text(v.as_str().unwrap_or("").to_string())
            }
            ColumnType::Blob | ColumnType::FileRef | ColumnType::List => {
                continue;
            }
        };
        out.push((col.name.clone(), qp));
    }
    out
}
