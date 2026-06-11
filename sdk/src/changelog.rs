use crate::{state::ClcState, table::Table, Space};
use encrypted_spaces_backend::{
    error::{Result, SdkError, StateDivergence},
    internal_schemas::{is_internal_table, KEY_HISTORY_TABLE_NAME},
    merk_storage::{
        build_column_kv_vecs, column_key, column_key_placeholder, get_row_data_from_query,
        parse_key, stored_value, ParsedKey, ID_FIELD,
    },
    query::{ComparisonOperator, Predicate, Query, QueryOperation, QueryParam},
    schema::{ColumnType, MAX_STRING_COLUMN_BYTES},
    sign_change::sign_change,
};
use encrypted_spaces_changelog_core::changelog::{
    check_sigref_continuity as core_check_sigref_continuity, Change, ChangeLog, ChangeResponse,
    ChangelogEntry, FastForwardData, HashedValues, OpType, MAX_PARENT_DISTANCE, ROOT_TREE_PATH,
};
use encrypted_spaces_changelog_core::mmr_tree::{h_leaf, verify_with_leaf_hash};
use encrypted_spaces_changelog_core::time::{
    validate_accepted_at_server_time_against_local_clock, validate_change_timestamp_at_acceptance,
    validate_timestamp_hwm, TIMESTAMP_HWM_TOLERANCE_SECONDS,
};
use encrypted_spaces_changelog_core::BatchOp;
use encrypted_spaces_storage_encoding::{classify_insert_id, hashstore_hash, InsertId, HASH_LEN};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Max attempts when retrying a change submission rejected by the server
/// because the client's `parent_change`/`parent_clc` anchor is stale (the
/// server returned `FastForwardRequired`, surfaced from `ServerError::StaleParent`).
///
/// Each retry recovers via FF (which advances the client's anchor) then
/// re-anchors and re-signs the change against the fresh state and
/// resubmits. The cap
/// guards against pathological races where every retry is immediately
/// invalidated by yet another concurrent broadcast. In practice 1-2
/// attempts suffice; we allow a few more before surfacing the error to
/// the caller so the client can decide whether to keep trying.
const MAX_STALE_PARENT_RETRIES: usize = 3;

/// Map from user uid to the `(change_id, entry_hash)` pair for their most
/// recent signed change inside an FF range. `entry_hash` is the
/// journal-proven `h_leaf(entry_bytes)` and binds the supplied
/// [`SigrefEntries`] payload to the bytes the FF guest actually processed.
type SigrefMap = std::collections::BTreeMap<u32, (u32, [u8; 32])>;

/// Map from `change_id` to the full [`ChangelogEntry`] supplied alongside an
/// FF proof, used to verify the sigref chain signatures after fast-forward.
type SigrefEntries = std::collections::BTreeMap<u32, ChangelogEntry>;

/// Outcome of a signature verification attempt, distinguishing between
/// failures that are retryable (key resolution blocked by stale DC) and
/// hard failures (bad signature or missing key after DC is current).
pub(crate) enum SigVerifyOutcome {
    /// Cryptographic signature verified successfully.
    Verified,
    /// Could not resolve the signing key (e.g. stale data commitment caused
    /// the server to reject the `_users` / `_key_history` SELECT).
    /// Retryable once the data commitment is advanced.
    KeyResolutionFailed(SdkError),
    /// The signing key was resolved but the cryptographic signature check
    /// failed. This is a hard error — the change must be rejected.
    SignatureInvalid(SdkError),
}

impl SigVerifyOutcome {
    /// Extract the error from a non-`Verified` outcome.
    ///
    /// # Panics
    ///
    /// Panics if called on `Verified`. Callers must guard with
    /// `!matches!(outcome, Verified)` first.
    fn into_err(self) -> SdkError {
        match self {
            SigVerifyOutcome::Verified => unreachable!("into_err called on Verified"),
            SigVerifyOutcome::KeyResolutionFailed(e) | SigVerifyOutcome::SignatureInvalid(e) => e,
        }
    }
}

/// Snapshot of the changelog-related fields in [`State`] used to rollback
/// if deferred signature verification fails after proof application.
struct SavedChangelogState {
    data_commitment: [u8; 32],
    change_id: u32,
    my_last_change_id: u32,
    sigref_map: BTreeMap<u32, u32>,
    timestamp_hwm: u64,
    clc: ClcState,
    change_entry: Option<ChangelogEntry>,
    /// Acknowledged change_ids of pending local submissions that were *not yet
    /// discharged* when this snapshot was taken. On rollback, any of these that
    /// were discharged during the now-undone apply are reset to undischarged so
    /// a rolled-back ragged apply / inclusion proof can never leave a stale
    /// discharge for a chain we did not commit (issue #212).
    undischarged_pending: Vec<u32>,
}

#[derive(Clone)]
struct FastForwardAnchor {
    change_id: u32,
    change_entry: Option<ChangelogEntry>,
}

/// Result of [`Space::submit_and_complete`]: the (possibly re-signed) change
/// that was acknowledged and proven incorporated, plus the writes needed for
/// cache updates and insert row-id extraction.
pub(crate) struct CompletedChange {
    pub(crate) change: Change,
    pub(crate) response: ChangeResponse,
    /// Verified per-op writes from a *sequential* append, when available.
    /// `None` when the entry was discharged via a fast-forward path (ragged
    /// apply or inclusion proof); in that case callers fall back to
    /// [`CompletedChange::ff_inserted_ids`] / a re-verified response.
    pub(crate) sequential_writes: Option<Vec<BatchOp>>,
    /// Row ids captured from ragged fast-forward application, keyed by entry
    /// signature. Empty for the sequential path.
    pub(crate) ff_inserted_ids: std::collections::BTreeMap<Vec<u8>, i64>,
}

/// Internal carrier for the writes produced while discharging a pending
/// change; folded into a [`CompletedChange`] by [`Space::submit_and_complete`].
struct CompletionWrites {
    sequential: Option<Vec<BatchOp>>,
    ff_inserted_ids: std::collections::BTreeMap<Vec<u8>, i64>,
}

/// Total wall-clock budget for a single `recover_via_fast_forward` call.
/// Each iteration round-trips one FF request to the server, so this caps the
/// time we'll spend re-trying when concurrent broadcasts keep advancing the
/// client's anchor mid-flight. Sized to absorb a few bursts of chatty-app
/// broadcasts without surfacing a spurious error to callers.
const FAST_FORWARD_RECOVERY_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
/// Backoff between FF retries when the anchor advanced under us. Small enough
/// that we don't add meaningful latency, large enough to avoid hot-spinning.
const FAST_FORWARD_RECOVERY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

impl Space {
    fn save_changelog_state(&self) -> SavedChangelogState {
        self.with_state(|state| SavedChangelogState {
            data_commitment: state.current_data_commitment,
            change_id: state.current_change_id,
            my_last_change_id: state.my_last_change_id,
            sigref_map: state.sigref_map.clone(),
            timestamp_hwm: state.timestamp_hwm,
            clc: state.current_clc_state.clone(),
            change_entry: state.current_change_entry.clone(),
            undischarged_pending: state
                .pending_local_changes
                .iter()
                .filter(|(_, p)| !p.discharged)
                .map(|(&cid, _)| cid)
                .collect(),
        })
    }

    fn rollback_changelog_state(&self, saved: &SavedChangelogState) {
        self.with_state_mut(|state| {
            state.current_data_commitment = saved.data_commitment;
            state.current_change_id = saved.change_id;
            state.my_last_change_id = saved.my_last_change_id;
            state.sigref_map = saved.sigref_map.clone();
            state.timestamp_hwm = saved.timestamp_hwm;
            state.current_clc_state = saved.clc.clone();
            state.current_change_entry = saved.change_entry.clone();
            // Revert any discharge that happened during the rolled-back apply.
            for cid in &saved.undischarged_pending {
                if let Some(p) = state.pending_local_changes.get_mut(cid) {
                    p.discharged = false;
                }
            }
        });
    }

    fn fast_forward_anchor(&self) -> FastForwardAnchor {
        self.with_state(|state| FastForwardAnchor {
            change_id: state.current_change_id,
            change_entry: state.current_change_entry.clone(),
        })
    }

    fn rollback_if_applied<T>(
        &self,
        saved: &SavedChangelogState,
        applied_state: bool,
        err: SdkError,
    ) -> Result<T> {
        if applied_state {
            self.rollback_changelog_state(saved);
        }
        Err(err)
    }

    /// After a fast-forward batch is applied, cross-check that the client's
    /// new head agrees with the server's reported head (16-byte prefixes
    /// of CLC and DC, plus `change_id`).
    ///
    /// Returns `StateDiverged` when the client and server agree on
    /// `change_id` but their CLC or DC prefixes differ. This is a terminal
    /// error: re-running fast-forward will not help, and the caller must
    /// surface it rather than retrying. Returns `ValidationError` when the
    /// client/server change ids are inconsistent (a server bug or a truncated
    /// FF response).
    ///
    /// The server only ever sends prefixes, so this check cannot be
    /// "fixed" by adopting the server's roots — that's deliberate.
    fn verify_fast_forward_server_head(
        &self,
        ff_data: &FastForwardData,
        anchor_change_id: u32,
    ) -> Result<()> {
        let Some(server_head) = &ff_data.server_head else {
            return Err(SdkError::ValidationError(
                "Server head not provided".to_string(),
            ));
        };

        validate_fast_forward_server_head_ids(ff_data, anchor_change_id)?;

        let (client_change_id, client_clc_full, client_dc_full) = self.with_state(|state| {
            let clc_root: [u8; 32] = state.current_clc_state.root.into();
            (
                state.current_change_id,
                clc_root,
                state.current_data_commitment,
            )
        });

        if client_change_id < server_head.change_id {
            return Err(SdkError::ValidationError(format!(
                "fast-forward ended at change_id {client_change_id}, but server head is {}",
                server_head.change_id
            )));
        }

        if client_change_id == server_head.change_id {
            let mut client_clc_prefix = [0u8; 16];
            client_clc_prefix.copy_from_slice(&client_clc_full[..16]);
            let mut client_dc_prefix = [0u8; 16];
            client_dc_prefix.copy_from_slice(&client_dc_full[..16]);

            if client_clc_prefix != server_head.clc_prefix
                || client_dc_prefix != server_head.data_commitment_prefix
            {
                return Err(SdkError::StateDiverged(Box::new(StateDivergence {
                    change_id: client_change_id,
                    client_clc_prefix,
                    server_clc_prefix: server_head.clc_prefix,
                    client_data_commitment_prefix: client_dc_prefix,
                    server_data_commitment_prefix: server_head.data_commitment_prefix,
                })));
            }
        }

        if client_change_id > server_head.change_id {
            // The anchor and FF target were already checked against
            // `server_head`, and this apply path cannot advance past its
            // target. A larger client id here means another local path applied
            // a newer server response while this FF was in progress.
            log::debug!(
                "[SDK] fast-forward server-head check: client advanced from anchor {} to {}, beyond response server head {}; treating as concurrent local advancement",
                anchor_change_id,
                client_change_id,
                server_head.change_id
            );
        }

        Ok(())
    }
}

fn fast_forward_target_change_id(ff_data: &FastForwardData) -> u32 {
    let proof_target = ff_data
        .proof
        .as_ref()
        .map(|proof| proof.end_change_id)
        .unwrap_or(0);
    let ragged_target = ff_data
        .responses
        .iter()
        .map(|response| response.change_id)
        .max()
        .unwrap_or(0);
    proof_target.max(ragged_target)
}

fn validate_fast_forward_server_head_ids(
    ff_data: &FastForwardData,
    anchor_change_id: u32,
) -> Result<()> {
    let Some(server_head) = &ff_data.server_head else {
        return Err(SdkError::ValidationError(
            "Server head not provided".to_string(),
        ));
    };

    let ff_target_change_id = fast_forward_target_change_id(ff_data);
    if anchor_change_id > server_head.change_id {
        return Err(SdkError::ValidationError(format!(
            "fast-forward anchor change_id {anchor_change_id} is ahead of server head {}",
            server_head.change_id
        )));
    }
    if ff_target_change_id > server_head.change_id {
        return Err(SdkError::ValidationError(format!(
            "fast-forward response targets change_id {ff_target_change_id}, beyond server head {}",
            server_head.change_id
        )));
    }

    Ok(())
}

/// Enforce the sigref-chain invariant for a single change on the client.
///
/// `expected_sig_ref` is `state.sigref_map[change.uid]` (or `0` if absent).
/// The change's `sig_ref` must match: a fresh user has `sig_ref == 0`, and
/// every subsequent change by the same user must point at that user's
/// previously accepted change_id. This mirrors `validate_sigref` in the FF
/// guest and closes the post-FF / pre-next-FF window where the client used
/// to advance on an unverified sigref chain (issue #30).
///
/// Delegates to [`encrypted_spaces_changelog_core::changelog::check_sigref_continuity`]
/// so the server (which enforces the same invariant at submission time)
/// and the SDK share a single implementation.
fn check_sigref_continuity(change: &ChangelogEntry, expected_sig_ref: u32) -> Result<()> {
    core_check_sigref_continuity(change, expected_sig_ref)
        .map_err(|e| SdkError::ValidationError(e.to_string()))
}

fn validate_replay_timestamp_policy(
    change: &ChangelogEntry,
    response: &ChangeResponse,
) -> Result<()> {
    validate_change_timestamp_at_acceptance(change.timestamp, response.accepted_at_server_time)
        .map_err(|e| SdkError::ValidationError(e.to_string()))?;
    validate_accepted_at_server_time_against_local_clock(
        response.accepted_at_server_time,
        ChangelogEntry::get_unix_timestamp(),
    )
    .map_err(|e| SdkError::ValidationError(e.to_string()))
}

fn validate_replay_timestamp_hwm(change: &ChangelogEntry, timestamp_hwm: &mut u64) -> Result<()> {
    if validate_timestamp_hwm(change.timestamp, timestamp_hwm) {
        return Ok(());
    }

    Err(SdkError::ValidationError(format!(
        "Change timestamp {} is older than timestamp HWM {} by more than {TIMESTAMP_HWM_TOLERANCE_SECONDS}s",
        change.timestamp, *timestamp_hwm
    )))
}

fn validate_fast_forward_tail_timestamp_policy(
    change: &ChangelogEntry,
    response: &ChangeResponse,
    timestamp_hwm: &mut u64,
) -> Result<()> {
    validate_change_timestamp_at_acceptance(change.timestamp, response.accepted_at_server_time)
        .map_err(|e| SdkError::ValidationError(e.to_string()))?;
    validate_replay_timestamp_hwm(change, timestamp_hwm)
}

pub(crate) struct ChangeBuilder<'q> {
    query: Option<&'q mut Query>,
    space: Arc<Space>,
    op_type_override: Option<OpType>,
    /// Optional `(key, value)` to prepend at position 0 of the
    /// resulting entry's kvs.  Used to attach an action marker on
    /// `OpType::AppDefined` entries.
    prepended_kv: Option<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmptyHashBackedValue {
    Hash,
    SkipDeleteSentinel,
}

impl<'q> ChangeBuilder<'q> {
    pub fn new(query: &'q mut Query, space: Arc<Space>) -> Self {
        Self {
            query: Some(query),
            space,
            op_type_override: None,
            prepended_kv: None,
        }
    }

    /// Create a builder for retention-only operations (no main-table query).
    pub fn retention_only(space: Arc<Space>) -> Self {
        Self {
            query: None,
            space,
            op_type_override: None,
            prepended_kv: None,
        }
    }

    fn query(&self) -> Result<&Query> {
        self.query
            .as_deref()
            .ok_or_else(|| SdkError::InvalidQuery("no query set on this builder".into()))
    }

    fn query_mut(&mut self) -> Result<&mut Query> {
        self.query
            .as_deref_mut()
            .ok_or_else(|| SdkError::InvalidQuery("no query set on this builder".into()))
    }

    /// Override the changelog `OpType` for this entry.
    pub fn with_op_type(mut self, op_type: OpType) -> Self {
        self.op_type_override = Some(op_type);
        self
    }

    /// Prepend a `(key, value)` to the entry's kvs at position 0.
    /// Used by app-defined actions to attach the action-marker kv.
    pub fn with_prepended_kv(mut self, key: Vec<u8>, value: Vec<u8>) -> Self {
        self.prepended_kv = Some((key, value));
        self
    }

    /// Sign the change in-place using the current user's signing keypair.
    async fn sign(&self, change: &mut Change) {
        let km = self.space.key_manager.lock().await;
        sign_change(&mut change.entry, km.auth_key_pair());
    }

    /// Build a changelog entry for this query.
    ///
    /// - **Insert**: builds directly from query fields (no async needed).
    /// - **Update / Delete**: runs a SELECT for matching rows to discover IDs, then builds
    ///   per-column keys for each matched row.  Returns `Ok(None)` when no rows match.
    pub async fn build(&mut self) -> Result<Option<Change>> {
        match self.query()?.operation {
            QueryOperation::Insert(_) => {
                let op = self.op_type_override.unwrap_or(OpType::Insert);
                self.build_insert(op).await.map(Some)
            }
            QueryOperation::Update(_) => {
                let op = self.op_type_override.unwrap_or(OpType::Update);
                self.build_update_or_delete(op).await
            }
            QueryOperation::Delete => {
                let op = self.op_type_override.unwrap_or(OpType::Delete);
                self.build_update_or_delete(op).await
            }
            QueryOperation::Select(_) => Err(SdkError::InvalidQuery(
                "Cannot generate changelog entry for select queries".to_string(),
            )),
        }
    }

    /// Read the SDK-side state needed to build a signed change. Returns
    /// `(uid, current_change_id, my_last_change_id, current_clc_root)`.
    ///
    /// `current_change_id` is used as the new entry's `parent_change`,
    /// giving a construction-time distance of 1, well inside the
    /// FF/server-enforced window (see [`MAX_PARENT_DISTANCE`]). The
    /// constant is imported here so any future refactor that widens the
    /// gap (e.g. building changes against a snapshot older than the
    /// SDK's current tip) trips the consistency assertion below at
    /// compile time, and so tests can pin server/FF/client to the same
    /// value.
    async fn auth_state(&self) -> Result<(u32, u32, u32, [u8; 32])> {
        // Compile-time sanity: callers below build entries with
        // parent_change == current_change_id, so the prospective
        // distance is always 1. If MAX_PARENT_DISTANCE ever drops below
        // 1, the whole submission pipeline would deadlock.
        const _: () = assert!(MAX_PARENT_DISTANCE >= 1);

        // Issue #212 (#4): serialize against fast-forward application so the
        // captured anchor is always verified, committed state — never the
        // provisional position a concurrent FF installs before its deferred
        // signature verification (which a failure would roll back). The guard
        // is released before signing; if FF advances afterwards the resulting
        // entry is merely stale and the server's stale-parent path re-signs it.
        let _guard = self.space.serialize_mutations.lock().await;
        self.space.with_state(|state| {
            if let Some(uid) = state.auth_context.uid {
                let clc_root: [u8; 32] = state.current_clc_state.root.into();
                log::debug!(
                    "[SDK] building change: current_change_id={} current_clc={}",
                    state.current_change_id,
                    hex::encode(clc_root)
                );
                Ok((
                    uid as u32,
                    state.current_change_id,
                    state.my_last_change_id,
                    clc_root,
                ))
            } else {
                Err(SdkError::DatabaseError(
                    "User is not authenticated".to_string(),
                ))
            }
        })
    }

    fn apply_hash_backed_storage(
        &self,
        keys: &[Vec<u8>],
        values: &mut [Vec<u8>],
        empty_values: EmptyHashBackedValue,
    ) -> Result<HashedValues> {
        if keys.len() != values.len() {
            return Err(SdkError::ValidationError(format!(
                "key/value count mismatch while preparing hashed values: {} keys, {} values",
                keys.len(),
                values.len()
            )));
        }

        let mut hashed_values = HashedValues::new();
        for (key, value) in keys.iter().zip(values.iter_mut()) {
            if value.is_empty() && empty_values == EmptyHashBackedValue::SkipDeleteSentinel {
                continue;
            }
            let Ok(ParsedKey::Column { table, column, .. }) = parse_key(key) else {
                continue;
            };
            let Some(schema) = self.space.get_table_schema(&table) else {
                continue;
            };
            let Some(column_def) = schema.columns.iter().find(|c| c.name == column) else {
                continue;
            };
            if column_def.column_type == ColumnType::String && !is_internal_table(&table) {
                if let Ok(json_val) = stored_value::bytes_to_value(value) {
                    let raw_len = json_val.as_str().map(|s| s.len()).unwrap_or(value.len());
                    if raw_len > MAX_STRING_COLUMN_BYTES {
                        return Err(SdkError::ValidationError(format!(
                            "String column '{table}.{column}' value is {raw_len} bytes, max is {MAX_STRING_COLUMN_BYTES}",
                        )));
                    }
                }
            }
            if !column_def.column_type.is_hash_backed() {
                continue;
            }

            let hash = hashstore_hash(value);
            hashed_values.insert(hash, value.clone());
            *value = hash.to_vec();
        }

        Ok(hashed_values)
    }

    async fn build_insert(&self, op_type: OpType) -> Result<Change> {
        let query = self.query()?;
        let (row, column_data) = get_row_data_from_query(query)?;
        let (uid, current_change_id, my_last_change_id, current_clc) = self.auth_state().await?;

        let table = &query.table;
        let raw_id = row.get(ID_FIELD).and_then(|v| v.as_i64());

        // Auto-ID inserts sign with the placeholder row_id; explicit-ID
        // inserts sign with the real row_id.  Refuse to build the entry
        // if the table isn't in the local schema cache — we can't pick
        // the right signing shape without the mode.
        let auto_increment = self
            .space
            .with_state(|state| state.table_schemas.get(table).map(|s| s.auto_increment))
            .ok_or_else(|| {
                SdkError::InvalidQuery(format!("table '{table}' is not registered locally"))
            })?;
        let explicit_id = match classify_insert_id(raw_id, auto_increment)
            .map_err(|e| SdkError::InvalidQuery(e.describe(table)))?
        {
            InsertId::Explicit(id) => Some(id),
            InsertId::AutoAssign => None,
        };

        let (mut keys, mut values) = build_column_kv_vecs(&column_data, |col| match explicit_id {
            Some(id) => column_key(table, id, col),
            None => column_key_placeholder(table, col),
        });
        self.prepend_marker_kv(&mut keys, &mut values);
        let hashed_values =
            self.apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)?;

        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            op_type,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| SdkError::DatabaseError(format!("Failed to create changelog entry: {e}")))?;
        change.hashed_values = hashed_values;
        self.sign(&mut change).await;
        Ok(change)
    }

    /// Apply `with_prepended_kv` (if set) by inserting the kv at the
    /// front of the keys / values vectors.
    fn prepend_marker_kv(&self, keys: &mut Vec<Vec<u8>>, values: &mut Vec<Vec<u8>>) {
        if let Some((k, v)) = &self.prepended_kv {
            keys.insert(0, k.clone());
            values.insert(0, v.clone());
        }
    }

    /// Append retention writes to changelog key/value vectors.
    fn append_retention_to_changelog(
        keys: &mut Vec<Vec<u8>>,
        values: &mut Vec<Vec<u8>>,
        retention_writes: &[(String, Vec<u8>)],
    ) -> Result<()> {
        use base64::Engine;
        use encrypted_spaces_backend::merk_storage::stored_value;
        let retention_table = crate::retention::RETENTION_TABLE_NAME;
        for (rk, rv) in retention_writes {
            let key_bytes = stored_value::value_to_bytes(&serde_json::Value::String(rk.clone()))?;
            // Retention values are base64-encoded into a String column.
            let b64 = base64::engine::general_purpose::STANDARD.encode(rv);
            let value_bytes = stored_value::value_to_bytes(&serde_json::Value::String(b64))?;
            keys.push(column_key_placeholder(retention_table, "key"));
            values.push(key_bytes);
            keys.push(column_key_placeholder(retention_table, "value"));
            values.push(value_bytes);
        }
        Ok(())
    }

    /// Build a CreateSpace changelog entry with retention writes.
    pub async fn build_create_space(
        &self,
        retention_writes: &[(String, Vec<u8>)],
    ) -> Result<Change> {
        let query = self.query()?;
        let (_, column_data) = get_row_data_from_query(query)?;
        let (uid, current_change_id, my_last_change_id, current_clc) = self.auth_state().await?;

        let table = &query.table;
        let (mut keys, mut values) =
            build_column_kv_vecs(&column_data, |col| column_key_placeholder(table, col));

        Self::append_retention_to_changelog(&mut keys, &mut values, retention_writes)?;
        let hashed_values =
            self.apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)?;

        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            OpType::CreateSpace,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| SdkError::DatabaseError(format!("Failed to create changelog entry: {e}")))?;
        change.hashed_values = hashed_values;
        self.sign(&mut change).await;
        Ok(change)
    }

    /// Build an InviteUser changelog entry.
    pub async fn build_invite_user(
        &self,
        retention_writes: &[(String, Vec<u8>)],
    ) -> Result<Change> {
        let query = self.query()?;
        let (_, column_data) = get_row_data_from_query(query)?;
        let (uid, current_change_id, my_last_change_id, current_clc) = self.auth_state().await?;

        let table = &query.table;
        let (mut keys, mut values) =
            build_column_kv_vecs(&column_data, |col| column_key_placeholder(table, col));

        Self::append_retention_to_changelog(&mut keys, &mut values, retention_writes)?;
        let hashed_values =
            self.apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)?;

        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            OpType::InviteUser,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| SdkError::DatabaseError(format!("Failed to create changelog entry: {e}")))?;
        change.hashed_values = hashed_values;
        self.sign(&mut change).await;
        Ok(change)
    }

    /// Build a RemoveUser changelog entry covering the user delete plus
    /// matching `_key_history` and retention writes.
    pub async fn build_remove_user(
        &mut self,
        key_history_data: &[(String, QueryParam)],
        retention_writes: &[(String, Vec<u8>)],
    ) -> Result<Option<Change>> {
        // Build the delete keys using the existing delete logic
        let query = self.query()?;
        let table: Table<serde_json::Value> =
            Table::new(query.table.clone(), Arc::clone(&self.space));
        let mut select = table.select().columns(&["id"]);
        select.query.predicate = query.predicate.clone();
        let rows: Vec<serde_json::Value> = select.all().await?;

        if rows.is_empty() {
            return Ok(None);
        }

        if rows.len() != 1 {
            return Err(SdkError::InvalidQuery(format!(
                "RemoveUser must match exactly 1 row in '{}', got {}",
                query.table,
                rows.len()
            )));
        }

        let row_id = rows[0].get("id").and_then(|v| v.as_i64()).ok_or_else(|| {
            SdkError::InvalidRowData("RemoveUser matched row is missing integer 'id'".to_string())
        })?;

        let query_table = query.table.clone();
        let schema = self
            .space
            .get_table_schema(&query_table)
            .ok_or(SdkError::InvalidRowData(format!(
                "Schema not found for table '{query_table}'"
            )))?;
        let non_id_columns: Vec<&str> = schema
            .columns
            .iter()
            .filter(|c| c.name != "id")
            .map(|c| c.name.as_str())
            .collect();

        let mut keys: Vec<Vec<u8>> = Vec::new();
        for col in &non_id_columns {
            keys.push(column_key(&query_table, row_id, col));
        }
        keys.sort();
        let values: Vec<Vec<u8>> = vec![vec![]; keys.len()];

        // Build _key_history insert entries
        let kh_table = KEY_HISTORY_TABLE_NAME;
        let kh_query = Query::new(
            kh_table.to_string(),
            QueryOperation::Insert(key_history_data.to_vec()),
        );
        let (_, kh_column_data) = get_row_data_from_query(&kh_query)?;
        let (kh_keys, kh_values) =
            build_column_kv_vecs(&kh_column_data, |col| column_key_placeholder(kh_table, col));

        // Combine all keys/values in the order RemoveUserOp::verify expects:
        // kh entries, retention entries (each retention query contributes
        // its columns interleaved per-row), user entries. Do not re-sort —
        // the server's retention_column_ops stays in (key col, value col)
        // per-row order, and a global sort by column_key_placeholder would
        // regroup all "key" cols before all "value" cols (placeholders omit
        // row_id, so all 6 "key" placeholders are byte-identical and the
        // stable sort leaves per-column bunching). That regrouping broke
        // the value-hash check in remove_user_with_proof at column 1.
        let mut all_keys = kh_keys;
        let mut all_values = kh_values;
        Self::append_retention_to_changelog(&mut all_keys, &mut all_values, retention_writes)?;
        all_keys.extend(keys);
        all_values.extend(values);
        let hashed_values = self.apply_hash_backed_storage(
            &all_keys,
            &mut all_values,
            EmptyHashBackedValue::SkipDeleteSentinel,
        )?;

        let (uid, current_change_id, my_last_change_id, current_clc) = self.auth_state().await?;

        // Rewrite WHERE clause to an explicit id = <matched row> so the server
        // resolves the same single row deterministically.
        self.query_mut()?.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(row_id)],
            cursor_id: None,
        });

        let key_refs: Vec<&[u8]> = all_keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = all_values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            OpType::RemoveUser,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| SdkError::DatabaseError(format!("Failed to create changelog entry: {e}")))?;
        change.hashed_values = hashed_values;
        self.sign(&mut change).await;
        Ok(Some(change))
    }

    /// Build a RefreshKeys changelog entry that includes both the `_users`
    /// update and a `_key_history` insert.
    pub async fn build_refresh_keys(
        &mut self,
        key_history_data: &[(String, QueryParam)],
    ) -> Result<Option<Change>> {
        // --- Resolve the _users update ---
        let query = self.query()?;
        let table: Table<serde_json::Value> =
            Table::new(query.table.clone(), Arc::clone(&self.space));
        let mut select = table.select().columns(&[ID_FIELD]);
        select.query.predicate = query.predicate.clone();
        let query_table = query.table.clone();
        let rows: Vec<serde_json::Value> = select.all().await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut ids: Vec<i64> = rows
            .iter()
            .filter_map(|row| row.get(ID_FIELD).and_then(|v| v.as_i64()))
            .collect();
        ids.sort_unstable();

        // Build _users update keys/values
        let (_, column_data) = get_row_data_from_query(self.query()?)?;
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut values: Vec<Vec<u8>> = Vec::new();
        for id in &ids {
            for (col, val) in &column_data {
                keys.push(column_key(&query_table, *id, col));
                values.push(val.clone());
            }
        }

        // --- Build _key_history insert entries ---
        let kh_table = KEY_HISTORY_TABLE_NAME;
        let kh_query = Query::new(
            kh_table.to_string(),
            QueryOperation::Insert(key_history_data.to_vec()),
        );
        let (_, kh_column_data) = get_row_data_from_query(&kh_query)?;
        let (kh_keys, kh_values) =
            build_column_kv_vecs(&kh_column_data, |col| column_key_placeholder(kh_table, col));

        keys.extend(kh_keys);
        values.extend(kh_values);

        // Sort all entries by key so the ChangelogEntry is in canonical order.
        // _key_history keys sort before _users keys alphabetically.
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = keys.into_iter().zip(values).collect();
        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        let keys: Vec<Vec<u8>> = pairs.iter().map(|(k, _)| k.clone()).collect();
        let mut values: Vec<Vec<u8>> = pairs.into_iter().map(|(_, v)| v).collect();
        let hashed_values =
            self.apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)?;

        let (uid, current_change_id, my_last_change_id, current_clc) = self.auth_state().await?;

        // Rewrite predicate to target matched IDs
        self.query_mut()?.predicate = Some(if ids.len() == 1 {
            Predicate {
                column: ID_FIELD.to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(ids[0])],
                cursor_id: None,
            }
        } else {
            Predicate {
                column: ID_FIELD.to_string(),
                operator: ComparisonOperator::In,
                values: ids.iter().map(|&id| QueryParam::Integer(id)).collect(),
                cursor_id: None,
            }
        });

        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            OpType::RefreshKeys,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| SdkError::DatabaseError(format!("Failed to create changelog entry: {e}")))?;
        change.hashed_values = hashed_values;
        self.sign(&mut change).await;
        Ok(Some(change))
    }

    /// Build an Extend changelog entry (retention-only, no main-table query).
    pub async fn build_extend(&self, retention_writes: &[(String, Vec<u8>)]) -> Result<Change> {
        self.build_retention_only(OpType::Extend, retention_writes)
            .await
    }

    /// Build a Reduce changelog entry (retention-only, no main-table query).
    pub async fn build_reduce(&self, retention_writes: &[(String, Vec<u8>)]) -> Result<Change> {
        self.build_retention_only(OpType::Reduce, retention_writes)
            .await
    }

    /// Build a standalone Rekey changelog entry (retention-only, no main-table query).
    pub async fn build_rekey(&self, retention_writes: &[(String, Vec<u8>)]) -> Result<Change> {
        self.build_retention_only(OpType::Rekey, retention_writes)
            .await
    }

    async fn build_retention_only(
        &self,
        op_type: OpType,
        retention_writes: &[(String, Vec<u8>)],
    ) -> Result<Change> {
        let (uid, current_change_id, my_last_change_id, current_clc) = self.auth_state().await?;

        let mut keys = Vec::new();
        let mut values = Vec::new();
        Self::append_retention_to_changelog(&mut keys, &mut values, retention_writes)?;
        let hashed_values =
            self.apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)?;

        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            op_type,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| SdkError::DatabaseError(format!("Failed to create changelog entry: {e}")))?;
        change.hashed_values = hashed_values;
        self.sign(&mut change).await;
        Ok(change)
    }

    /// Shared builder for UPDATE and DELETE: SELECT matching rows, build per-column keys.
    async fn build_update_or_delete(&mut self, op_type: OpType) -> Result<Option<Change>> {
        let query = self.query()?;
        let query_table = query.table.clone();

        let table: Table<serde_json::Value> =
            Table::new(query_table.clone(), Arc::clone(&self.space));
        let mut select = table.select().columns(&[ID_FIELD]);
        select.query.predicate = query.predicate.clone();
        let rows: Vec<serde_json::Value> = select.all().await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut ids: Vec<i64> = rows
            .iter()
            .filter_map(|row| row.get(ID_FIELD).and_then(|v| v.as_i64()))
            .collect();
        ids.sort_unstable();

        // Build per-column keys and values from the query shape (the
        // op_type override only affects the entry's wire-level op_type;
        // an AppDefined update / delete still has Update / Delete query
        // operations under the hood).
        let is_update = matches!(self.query()?.operation, QueryOperation::Update(_))
            || matches!(op_type, OpType::RefreshKeys | OpType::ListUpdate);
        let (mut keys, mut values) = if is_update {
            // Extract serialized column data from the query (skips id)
            let (_, column_data) = get_row_data_from_query(self.query()?)?;
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            for id in &ids {
                for (col, val) in &column_data {
                    pairs.push((column_key(&query_table, *id, col), val.clone()));
                }
            }
            let keys = pairs.iter().map(|(k, _)| k.clone()).collect();
            let values = pairs.iter().map(|(_, v)| v.clone()).collect();
            (keys, values)
        } else {
            let schema =
                self.space
                    .get_table_schema(&query_table)
                    .ok_or(SdkError::InvalidRowData(format!(
                        "Schema not found for table '{query_table}'"
                    )))?;
            let non_id_columns: Vec<&str> = schema
                .columns
                .iter()
                .filter(|c| c.name != ID_FIELD)
                .map(|c| c.name.as_str())
                .collect();

            let mut keys: Vec<Vec<u8>> = Vec::new();
            for id in &ids {
                for col in &non_id_columns {
                    keys.push(column_key(&query_table, *id, col));
                }
            }
            keys.sort();
            let values = vec![vec![]; keys.len()];
            (keys, values)
        };
        self.prepend_marker_kv(&mut keys, &mut values);
        let empty_hash_backed_values = if is_update {
            EmptyHashBackedValue::Hash
        } else {
            EmptyHashBackedValue::SkipDeleteSentinel
        };
        let hashed_values =
            self.apply_hash_backed_storage(&keys, &mut values, empty_hash_backed_values)?;

        let (uid, current_change_id, my_last_change_id, current_clc) = self.auth_state().await?;

        // Rewrite predicate to target the matched IDs so the server resolves
        // the same set of rows deterministically.
        self.query_mut()?.predicate = Some(if ids.len() == 1 {
            Predicate {
                column: ID_FIELD.to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(ids[0])],
                cursor_id: None,
            }
        } else {
            Predicate {
                column: ID_FIELD.to_string(),
                operator: ComparisonOperator::In,
                values: ids.iter().map(|&id| QueryParam::Integer(id)).collect(),
                cursor_id: None,
            }
        });

        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            op_type,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| SdkError::DatabaseError(format!("Failed to create changelog entry: {e}")))?;
        change.hashed_values = hashed_values;
        self.sign(&mut change).await;
        Ok(Some(change))
    }
}

/// Extract the table name from a changelog entry's keys, parsing the
/// first recognisable column key.
fn table_name_from_change_entry(entry: &ChangelogEntry) -> String {
    use encrypted_spaces_backend::merk_storage::{parse_key, ParsedKey};

    for e in &entry.message.entries {
        match parse_key(&e.key) {
            Ok(ParsedKey::Column { table, .. }) => return table,
            Ok(ParsedKey::Row { table, .. }) => return table,
            _ => continue,
        }
    }
    String::new()
}

fn resolve_hashed_value(
    table: &str,
    column: &str,
    value: &[u8],
    hashed_values: &HashedValues,
) -> Result<Vec<u8>> {
    let Ok(hash) = <[u8; HASH_LEN]>::try_from(value) else {
        return Ok(value.to_vec());
    };

    let full_value = hashed_values.get(&hash).ok_or_else(|| {
        SdkError::ValidationError(format!(
            "missing hashed value for hash-backed column {table}.{column}"
        ))
    })?;
    Ok(full_value.clone())
}

/// Resolve the auth verification key for a `CreateSpace` change from the
/// signed entry's `_users.auth_key` value, using `hashed_values` when the
/// entry carries a hash-backed reference.
fn extract_auth_key_from_create_space_change(
    change: &ChangelogEntry,
    hashed_values: &HashedValues,
) -> Result<ed25519_dalek::VerifyingKey> {
    use encrypted_spaces_backend::internal_schemas::USERS_TABLE_NAME;
    use encrypted_spaces_backend::merk_storage::{parse_key, stored_value, ParsedKey};

    let auth_key_entry = change
        .message
        .entries
        .iter()
        .find(|entry| {
            matches!(
                parse_key(&entry.key),
                Ok(ParsedKey::Column { table, column, .. })
                    if table == USERS_TABLE_NAME && column == "auth_key"
            )
        })
        .ok_or_else(|| {
            SdkError::ValidationError(
                "CreateSpace change is missing the _users.auth_key entry".to_string(),
            )
        })?;

    let auth_key_bytes = resolve_hashed_value(
        USERS_TABLE_NAME,
        "auth_key",
        &auth_key_entry.value,
        hashed_values,
    )?;

    let auth_key_value = stored_value::bytes_to_value(&auth_key_bytes).map_err(|e| {
        SdkError::ValidationError(format!("Failed to decode CreateSpace auth_key bytes: {e}"))
    })?;
    let auth_key_b64 = auth_key_value.as_str().ok_or_else(|| {
        SdkError::ValidationError("CreateSpace auth_key is not a base64 string".into())
    })?;

    crate::users::deserialize_verification_key_from_base64(auth_key_b64)
}

/// Outcome of applying a broadcast change to changelog state.
///
/// Tells the broadcast pipeline whether granular cache updates are still
/// needed: the deferred-sig-retry path invalidates touched-table caches
/// internally; the upfront-verified path leaves cache updates to the
/// caller.
pub(crate) enum BroadcastApplyOutcome {
    Skipped,
    Applied {
        change: Change,
        writes: Vec<BatchOp>,
    },
    AppliedCacheInvalidated,
}

impl Space {
    pub(crate) async fn apply_broadcast_change(
        &self,
        change: Change,
        change_response: ChangeResponse,
    ) -> BroadcastApplyOutcome {
        let change_entry = change.entry.clone();
        let (cid, clc) =
            self.with_state(|state| (state.current_change_id, state.current_clc_state.root));
        log::debug!(
            "[SDK] handle_broadcast: op={:?} broadcast_change_id={} client_change_id={} client_clc={}",
            change_entry.message.op_type,
            change_response.change_id,
            cid,
            hex::encode::<[u8; 32]>(clc.into())
        );

        // If we already have this change, skip it — the sender's own
        // execute_change already applied it before the broadcast arrived.
        if change_response.change_id <= cid {
            log::debug!(
                "[SDK] handle_broadcast: ignoring stale broadcast (change {} <= current {})",
                change_response.change_id,
                cid
            );
            return BroadcastApplyOutcome::Skipped;
        }

        // Verify the change signature before applying.
        //
        // If key resolution fails (stale DC), we defer verification:
        // apply the proof to advance the DC, then retry. If the
        // signature itself is invalid, reject immediately.
        let sig_outcome = self
            .try_verify_change_signature(
                &change_entry,
                change_response.change_id,
                &change.hashed_values,
            )
            .await;

        match &sig_outcome {
            SigVerifyOutcome::SignatureInvalid(e) => {
                log::warn!(
                    "[SDK] handle_broadcast: signature invalid for change {}: {e} — rejecting",
                    change_response.change_id
                );
                return BroadcastApplyOutcome::Skipped;
            }
            SigVerifyOutcome::KeyResolutionFailed(e) => {
                log::debug!(
                    "[SDK] handle_broadcast: key resolution failed for change {}: {e} \
                     — deferring verification until after proof application",
                    change_response.change_id
                );
            }
            SigVerifyOutcome::Verified => {}
        }

        let sig_deferred = matches!(sig_outcome, SigVerifyOutcome::KeyResolutionFailed(_));

        // Save state before applying so we can rollback if deferred
        // signature verification fails after the proof advances the DC.
        let saved = self.save_changelog_state();

        match self.validate_and_apply_change(&change_entry, &change_response) {
            Ok(writes) => {
                if sig_deferred {
                    // Key resolution failed earlier (likely stale DC).
                    // Now that validate_and_apply_change has advanced
                    // the DC, retry. Roll back if it still fails.
                    let retry = self
                        .try_verify_change_signature(
                            &change_entry,
                            change_response.change_id,
                            &change.hashed_values,
                        )
                        .await;
                    if !matches!(retry, SigVerifyOutcome::Verified) {
                        log::warn!(
                            "[SDK] handle_broadcast: deferred sig verification failed for \
                             change {}: {} — rolling back",
                            change_response.change_id,
                            retry.into_err()
                        );
                        self.rollback_changelog_state(&saved);
                        return BroadcastApplyOutcome::Skipped;
                    }
                    // Sig now verified. Invalidate caches for every
                    // table the entry touches after the first
                    // key-resolution-failed pass.
                    let touched: std::collections::BTreeSet<String> = change_entry
                        .message
                        .entries
                        .iter()
                        .filter_map(|kv| match parse_key(&kv.key).ok()? {
                            ParsedKey::Column { table, .. }
                            | ParsedKey::Row { table, .. }
                            | ParsedKey::RowPrefix { table } => Some(table),
                            _ => None,
                        })
                        .collect();
                    self.with_state_mut(|state| {
                        for t in &touched {
                            state.cache.invalidate_table(t);
                        }
                    });
                    BroadcastApplyOutcome::AppliedCacheInvalidated
                } else {
                    BroadcastApplyOutcome::Applied { change, writes }
                }
            }
            Err(SdkError::FastForwardRequired { ref reason }) => {
                log::debug!(
                    "[SDK] handle_broadcast: FastForwardRequired reason={}",
                    reason
                );
                let _ = self.recover_via_fast_forward().await;
                let (cid, clc) = self
                    .with_state(|state| (state.current_change_id, state.current_clc_state.root));
                log::debug!(
                    "[SDK] handle_broadcast: after FF recovery change_id={} clc={}",
                    cid,
                    hex::encode::<[u8; 32]>(clc.into())
                );
                BroadcastApplyOutcome::Skipped
            }
            Err(ref e) => {
                log::warn!("[SDK] handle_broadcast: error={}", e);
                BroadcastApplyOutcome::Skipped
            }
        }
    }

    /// Try to verify the signature on a change entry.
    ///
    /// Returns a [`SigVerifyOutcome`] that distinguishes between:
    /// - `Verified`: signature is valid.
    /// - `KeyResolutionFailed`: could not fetch the signing key (retryable
    ///   once the data commitment is current).
    /// - `SignatureInvalid`: the key was resolved but the signature check
    ///   failed (hard reject).
    ///
    /// For `CreateSpace`, the auth key is resolved from the entry's
    /// `_users.auth_key` value plus any hashed values sent alongside the
    /// change response. For all other op types the key is resolved via
    /// [`resolve_signing_key_for_change`].
    async fn try_verify_change_signature(
        &self,
        change: &ChangelogEntry,
        change_id: u32,
        hashed_values: &HashedValues,
    ) -> SigVerifyOutcome {
        use encrypted_spaces_backend::sign_change::verify_change_signature;
        use encrypted_spaces_key_manager::DefaultSignature;

        if change.signature.is_empty() {
            return SigVerifyOutcome::SignatureInvalid(SdkError::ValidationError(
                "Change is missing a signature".to_string(),
            ));
        }

        let vk = if change.message.op_type == OpType::CreateSpace {
            match extract_auth_key_from_create_space_change(change, hashed_values) {
                Ok(vk) => vk,
                Err(e) => return SigVerifyOutcome::SignatureInvalid(e),
            }
        } else {
            match self
                .resolve_signing_key_for_change(
                    change.uid,
                    change_id,
                    change.message.op_type,
                    change.sig_ref,
                )
                .await
            {
                Ok(vk) => vk,
                Err(e) => return SigVerifyOutcome::KeyResolutionFailed(e),
            }
        };

        match verify_change_signature::<DefaultSignature>(change, &vk) {
            Ok(()) => SigVerifyOutcome::Verified,
            Err(e) => SigVerifyOutcome::SignatureInvalid(SdkError::ValidationError(format!(
                "Signature verification failed: {e:?}"
            ))),
        }
    }

    /// Validate the pruned Merkle tree and apply the change response to client state.
    /// Returns `SdkError::FastForwardRequired` if the client is out-of-sync,
    /// otherwise the per-op `BatchOp` writes from the verified proof.
    pub fn validate_and_apply_change(
        &self,
        change: &ChangelogEntry,
        response: &ChangeResponse,
    ) -> Result<Vec<BatchOp>> {
        // Read all state fields atomically in one lock to prevent races with
        // the broadcast listener (which can also call this method).
        // `expected_sig_ref` is the signer's last known change_id (0 if the
        // user has no prior change); used to enforce sigref-chain continuity
        // before mutating state.
        let (
            current_change_id,
            current_data_commitment,
            my_last_change_id,
            uid,
            current_clc,
            expected_sig_ref,
            timestamp_hwm,
        ) = self.with_state(|state| {
            if let Some(uid) = state.auth_context.uid {
                let clc_root: [u8; 32] = state.current_clc_state.root.into();
                let expected_sig_ref = state.sigref_map.get(&change.uid).copied().unwrap_or(0);
                Ok((
                    state.current_change_id,
                    state.current_data_commitment,
                    state.my_last_change_id,
                    uid as u32,
                    clc_root,
                    expected_sig_ref,
                    state.timestamp_hwm,
                ))
            } else {
                Err(SdkError::ValidationError(
                    "User is not authenticated".to_string(),
                ))
            }
        })?;

        validate_replay_timestamp_policy(change, response)?;

        if response.change_id != current_change_id + 1 {
            // The broadcast listener may have already applied this change
            // (race between the broadcast arriving and the caller processing
            // the response).  If so, succeed silently — the state is already
            // up to date.
            if response.change_id <= current_change_id {
                log::debug!(
                    "[SDK] validate_and_apply_change: change {} already applied (current={}), verifying proof without mutating state",
                    response.change_id,
                    current_change_id
                );
                if response.pruned_merkle_tree.is_empty() {
                    return Ok(Vec::new());
                }
                return ChangeLog::verify_proof_and_validate(
                    change,
                    &response.pruned_merkle_tree,
                    &response.old_root,
                    &response.new_root,
                    response.change_id as usize,
                )
                .map_err(|e| {
                    SdkError::DatabaseError(format!("verify_pruned_merkle_tree failed: {e:?}"))
                });
            }
            return Err(SdkError::FastForwardRequired {
                reason: format!(
                    "Change out of sequence: expected {}, got {}",
                    current_change_id + 1,
                    response.change_id
                ),
            });
        }

        if response.old_root != current_data_commitment {
            return Err(SdkError::FastForwardRequired {
                reason: format!(
                    "Data commitment mismatch: expected {}, got {}",
                    hex::encode(current_data_commitment),
                    hex::encode(response.old_root)
                ),
            });
        }

        let mut new_timestamp_hwm = timestamp_hwm;
        validate_replay_timestamp_hwm(change, &mut new_timestamp_hwm)?;

        let writes = ChangeLog::verify_proof_and_validate(
            change,
            &response.pruned_merkle_tree,
            &response.old_root,
            &response.new_root,
            // current_change_id is 1-indexed: this incoming change becomes #(current+1).
            (current_change_id as usize).saturating_add(1),
        )
        .map_err(|e| SdkError::DatabaseError(format!("verify_pruned_merkle_tree failed: {e:?}")))?;

        // Sigref-chain continuity: a change's `sig_ref` must point at the
        // signer's previous accepted change_id (0 if this is their first).
        // The FF guest enforces this for proven ranges; this check covers
        // the single-change broadcast / direct-response path so the client
        // does not advance on a tail that the next FF proof would reject.
        // See issue #30.
        check_sigref_continuity(change, expected_sig_ref)?;

        self.apply_state_update(
            change,
            response,
            current_change_id,
            my_last_change_id,
            uid,
            current_clc,
            new_timestamp_hwm,
        )?;

        Ok(writes)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_state_update(
        &self,
        change: &ChangelogEntry,
        response: &ChangeResponse,
        current_change_id: u32,
        my_last_change_id: u32,
        uid: u32,
        prev_clc: [u8; 32],
        new_timestamp_hwm: u64,
    ) -> Result<()> {
        // Extend the client's changelog commitment with this entry.
        // prev_clc was captured atomically with current_change_id to prevent
        // races with the broadcast listener.
        let entry_bytes = change.as_bytes();

        log::debug!(
            "[SDK] apply_state_update: change_id {} -> {} op={:?} entry_len={} prev_clc={}",
            current_change_id,
            current_change_id + 1,
            change.message.op_type,
            entry_bytes.len(),
            hex::encode(prev_clc),
        );
        self.with_state_mut(|state| {
            // Compare-and-swap: if the broadcast listener already applied
            // this change (advanced current_change_id), skip the write.
            if state.current_change_id != current_change_id {
                log::debug!(
                    "[SDK] apply_state_update: skipping write, state already advanced to change_id={}",
                    state.current_change_id
                );
                return;
            }
            if response.change_id != current_change_id + 1 {
                // Guard: the response must be for the expected next change.
                // During concurrent FF recovery a direct-response handler may
                // advance current_change_id to N while the FF ragged-change
                // loop captures the same value N. The CAS above passes, but
                // the ragged change is actually for change N (already applied).
                // This check prevents double-incrementing.
                log::debug!(
                    "[SDK] apply_state_update: skipping, response.change_id={} != expected {}",
                    response.change_id,
                    current_change_id + 1
                );
                return;
            }
            state.current_data_commitment = response.new_root;
            state.current_change_id = current_change_id + 1;
            state.my_last_change_id = my_last_change_id;
            // Advance the per-user sigref chain for `change.uid` (the signer).
            // Guards subsequent ragged / single-change validation against
            // out-of-order or replayed entries from the same user.
            state.sigref_map.insert(change.uid, response.change_id);
            state.timestamp_hwm = new_timestamp_hwm;
            // Extend the changelog commitment state with the entry.
            state.current_clc_state.append(&entry_bytes);
            // Store the entry as the changelog anchor for the next FF cycle's
            // `from_inclusion_proof` check.
            state.current_change_entry = Some(change.clone());
            if change.uid == uid {
                state.my_last_change_id = response.change_id;
            }
            // Issue #212: discharge any pending local submission whose exact
            // entry we just appended at this change_id. Match on the journal
            // leaf hash so a different (even validly signed) entry from the
            // same user cannot discharge the wrong pending submission. This is
            // the single append point shared by the sequential, broadcast, and
            // ragged-fast-forward paths, so all three discharge here.
            crate::state::discharge_pending_local_change(
                &mut state.pending_local_changes,
                response.change_id,
                &entry_bytes,
            );
        });
        Ok(())
    }

    pub(crate) async fn recover_via_fast_forward(&self) -> Result<()> {
        self.recover_via_fast_forward_capturing_inserts()
            .await
            .map(|_| ())
    }

    /// Submit an already-built, signed [`Change`], transparently recovering
    /// from stale-parent rejections.
    ///
    /// The caller builds the change exactly once — including the
    /// non-idempotent field encryption and (for update / delete) row
    /// resolution. If the server rejects it with
    /// [`SdkError::FastForwardRequired`] because the client's
    /// `parent_change` / `parent_clc` anchor is stale, we run fast-forward
    /// recovery to advance the anchor, then re-anchor and re-sign *the same
    /// change* against the fresh state and resubmit. This keeps build-time
    /// work out of the retry loop.
    ///
    /// Retries are capped at [`MAX_STALE_PARENT_RETRIES`].
    pub(crate) async fn submit_change_with_ff_retry(
        &self,
        mut change: Change,
    ) -> Result<(Change, ChangeResponse)> {
        let mut attempts: usize = 0;
        loop {
            match self.transport.submit_change(&change, vec![]).await {
                Ok(resp) => return Ok((change, resp)),
                Err(SdkError::FastForwardRequired { reason })
                    if attempts < MAX_STALE_PARENT_RETRIES =>
                {
                    log::info!(
                        "[SDK] change submit rejected (FF required: {reason}); \
                         recovering and re-signing (attempt {attempts})"
                    );
                    self.recover_via_fast_forward().await?;
                    self.reanchor_and_resign(&mut change).await;
                    attempts += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Submit a built change and report success only once its *exact* entry is
    /// proven incorporated on the verified CLC chain (issue #212).
    ///
    /// This is the single "submit, prove, then complete" path that every
    /// mutation surface routes through. It:
    ///
    /// 1. submits via [`Self::submit_change_with_ff_retry`] (transparent
    ///    stale-parent re-anchor / re-sign),
    /// 2. registers the acknowledged entry as a pending local change keyed by
    ///    its acknowledged `change_id` and journal leaf hash,
    /// 3. discharges it by one of: a sequential append, a racing broadcast that
    ///    applied the exact bytes, a ragged fast-forward apply of the exact
    ///    bytes, or a fast-forward inclusion proof for the exact bytes, and
    /// 4. fails closed with a validation error if the acknowledged entry cannot
    ///    be proven — replacing the old behaviour of returning success after a
    ///    generic fast-forward.
    pub(crate) async fn submit_and_complete(&self, change: Change) -> Result<CompletedChange> {
        let (change, response) = self.submit_change_with_ff_retry(change).await?;
        self.complete_submitted(change, response).await
    }

    /// Complete an *already-submitted and accepted* change: register it as a
    /// pending local change, discharge it (sequential apply, racing broadcast,
    /// ragged fast-forward apply, or fast-forward inclusion proof), and fail
    /// closed if its exact entry cannot be proven incorporated (issue #212).
    ///
    /// Used by call sites that submit directly (without stale-parent re-sign)
    /// because re-anchoring would invalidate entry-embedded metadata — e.g.
    /// `RefreshKeys` (which bakes `_key_history.valid_to`) and actions (which
    /// bake an action-marker kv / cascade-delete derivation). `submit_change`
    /// stale-parent rejections still propagate to the caller unchanged; only
    /// the accepted-but-not-sequential path gains the discharge requirement.
    pub(crate) async fn complete_submitted(
        &self,
        change: Change,
        response: ChangeResponse,
    ) -> Result<CompletedChange> {
        // Graceful server no-op (e.g. a delete or delete/update action whose
        // predicate matched no rows): the server writes nothing and appends no
        // changelog entry, signalled by `rows_affected == 0` together with an
        // unchanged data root (`old_root == new_root`). There is no entry to
        // prove incorporated, so the issue #212 discharge requirement does not
        // apply. We still run the change through `validate_and_apply_change`
        // (which takes its empty-proof / already-applied branch, or triggers a
        // fast-forward if the client is behind the server head) to keep client
        // state consistent, then report the no-op without demanding discharge.
        // This is sound: the caller is told `0 rows affected`, nothing changed
        // on-chain, and no cryptographic state advances.
        if response.rows_affected == 0 && response.old_root == response.new_root {
            match self.validate_and_apply_change(&change.entry, &response) {
                Ok(writes) => {
                    return Ok(CompletedChange {
                        change,
                        response,
                        sequential_writes: Some(writes),
                        ff_inserted_ids: std::collections::BTreeMap::new(),
                    })
                }
                Err(SdkError::FastForwardRequired { .. }) => {
                    self.recover_via_fast_forward().await?;
                    return Ok(CompletedChange {
                        change,
                        response,
                        sequential_writes: None,
                        ff_inserted_ids: std::collections::BTreeMap::new(),
                    });
                }
                Err(e) => return Err(e),
            }
        }

        let ack = response.change_id;
        let leaf_hash: [u8; 32] = h_leaf(&change.entry.as_bytes()).into();

        // Register before attempting apply so a concurrent broadcast applying
        // the exact bytes discharges it, and so FF recovery knows to prove it.
        self.with_state_mut(|s| {
            s.pending_local_changes.insert(
                ack,
                crate::state::PendingLocalChange {
                    leaf_hash,
                    discharged: false,
                },
            );
        });

        let outcome = self.complete_pending(&change, &response, ack).await;

        // Always remove our registration; capture whether it was discharged.
        let discharged = self.with_state_mut(|s| {
            s.pending_local_changes
                .remove(&ack)
                .map(|p| p.discharged)
                .unwrap_or(false)
        });

        let writes = outcome?;
        if !discharged {
            return Err(SdkError::ValidationError(format!(
                "issue #212: server acknowledged change {ack} but fast-forward did not prove the \
                 exact submitted entry was incorporated; failing closed"
            )));
        }
        Ok(CompletedChange {
            change,
            response,
            sequential_writes: writes.sequential,
            ff_inserted_ids: writes.ff_inserted_ids,
        })
    }

    /// Drive a registered pending change to discharge: try a sequential apply
    /// first, otherwise recover via fast-forward (which proves the pending
    /// entry through a ragged apply or an inclusion proof). Returns the writes
    /// available for cache/row-id extraction; does not itself enforce that the
    /// entry was discharged — [`Self::submit_and_complete`] does that.
    async fn complete_pending(
        &self,
        change: &Change,
        response: &ChangeResponse,
        ack: u32,
    ) -> Result<CompletionWrites> {
        match self.validate_and_apply_change(&change.entry, response) {
            Ok(writes) => {
                // A sequential append discharges inline (apply_state_update
                // matched our pending entry). The "already applied" branch
                // (ack <= current) returns Ok *without* appending and verifies
                // the proof only in isolation, so it does not by itself prove
                // the exact entry is on our verified chain. If a racing
                // broadcast already discharged it, great; otherwise prove it
                // via fast-forward inclusion before reporting success.
                let discharged = self.with_state(|s| {
                    s.pending_local_changes
                        .get(&ack)
                        .map(|p| p.discharged)
                        .unwrap_or(false)
                });
                if discharged {
                    Ok(CompletionWrites {
                        sequential: Some(writes),
                        ff_inserted_ids: std::collections::BTreeMap::new(),
                    })
                } else {
                    let ff_inserted_ids = self.recover_via_fast_forward_capturing_inserts().await?;
                    Ok(CompletionWrites {
                        sequential: None,
                        ff_inserted_ids,
                    })
                }
            }
            Err(SdkError::FastForwardRequired { .. }) => {
                let ff_inserted_ids = self.recover_via_fast_forward_capturing_inserts().await?;
                Ok(CompletionWrites {
                    sequential: None,
                    ff_inserted_ids,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// (`parent_change` / `sig_ref` / `parent_clc`), refresh its timestamp,
    /// and re-sign it in place. Used by [`Self::submit_change_with_ff_retry`]
    /// after fast-forward recovery advances the anchor.
    async fn reanchor_and_resign(&self, change: &mut Change) {
        // Issue #212 (#4): read the fresh anchor under the mutation guard so we
        // never re-anchor against provisional, not-yet-verified FF state.
        let (parent_change, sig_ref, parent_clc) = {
            let _guard = self.serialize_mutations.lock().await;
            self.with_state(|state| {
                let clc_root: [u8; 32] = state.current_clc_state.root.into();
                (state.current_change_id, state.my_last_change_id, clc_root)
            })
        };
        change.entry.parent_change = parent_change;
        change.entry.sig_ref = sig_ref;
        change.entry.parent_clc = parent_clc;
        change.entry.timestamp = ChangelogEntry::get_unix_timestamp();
        change.entry.signature = vec![];
        let km = self.key_manager.lock().await;
        sign_change(&mut change.entry, km.auth_key_pair());
    }

    /// Like `recover_via_fast_forward`, but returns a map of (entry signature
    /// → row id) for any ragged changes whose verified proof produced
    /// an inserted row id. Callers that submitted an Insert which the server
    /// rolled into FF data can use this to read the row id from the
    /// FF-verified path instead of re-parsing the rejected response proof.
    pub(crate) async fn recover_via_fast_forward_capturing_inserts(
        &self,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, i64>> {
        // Issue #212 (#4): refuse to re-enter fast-forward recovery while an
        // apply is already in flight on this Space. The only caller that can
        // trigger this is a deferred-verification table read inside the active
        // apply; recursing here would deadlock on the non-reentrant
        // `serialize_mutations` guard. Failing fast lets the in-flight apply
        // roll back and the outer caller retry from a fresh anchor.
        if self
            .ff_in_progress
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(SdkError::FastForwardRequired {
                reason: "fast-forward already in progress on this Space; \
                         re-entrant recovery suppressed"
                    .to_string(),
            });
        }
        self.with_state_mut(|state| state.cache.clear_all());
        let deadline = std::time::Instant::now() + FAST_FORWARD_RECOVERY_BUDGET;
        let mut attempt: u32 = 0;
        let outcome: Option<(std::collections::BTreeMap<Vec<u8>, i64>, bool)> = 'retry: loop {
            attempt += 1;
            let anchor = self.fast_forward_anchor();
            // Issue #212: undischarged pending local submissions whose exact
            // entry must be proven incorporated by this fast-forward. The
            // server returns inclusion proofs for any that fall in the proven
            // range; ones in the ragged tail discharge through apply_state_update.
            let expected_change_ids: Vec<u32> = self.with_state(|state| {
                state
                    .pending_local_changes
                    .iter()
                    .filter(|(_, p)| !p.discharged)
                    .map(|(&cid, _)| cid)
                    .collect()
            });
            log::info!(
                "[SDK] recover_via_fast_forward: requesting FF from change_id={} (attempt {attempt})",
                anchor.change_id
            );
            let ff = self
                .transport
                .fast_forward_with_expected(anchor.change_id, &expected_change_ids)
                .await?;
            log::info!(
                "[SDK] recover_via_fast_forward: received proof={} ragged_changes={}",
                ff.proof.is_some(),
                ff.changes.len()
            );

            // Highest change_id this FF response would deliver, if applied.
            // Combines the proof's end_change_id (if any) with the ragged
            // response change_ids.
            let ff_target_change_id = fast_forward_target_change_id(&ff);

            let current_change_id = self.with_state(|state| state.current_change_id);
            if current_change_id != anchor.change_id {
                // A concurrent broadcast applied while our FF request was
                // in flight. If those broadcasts already brought us at or
                // past the FF's target tip, the FF response is moot — we
                // can return without applying it. Otherwise, retry from
                // the new anchor (subject to the wall-clock budget).
                if ff_target_change_id > 0 && current_change_id >= ff_target_change_id {
                    log::debug!(
                        "[SDK] recover_via_fast_forward: concurrent broadcasts advanced \
                         state from {} to {} (FF target was {}); already caught up",
                        anchor.change_id,
                        current_change_id,
                        ff_target_change_id
                    );
                    break 'retry Some((std::collections::BTreeMap::new(), false));
                }
                log::debug!(
                    "[SDK] recover_via_fast_forward: state advanced from {} to {} while FF request was in flight (FF target {}); retrying",
                    anchor.change_id,
                    current_change_id,
                    ff_target_change_id
                );
                if std::time::Instant::now() >= deadline {
                    break 'retry None;
                }
                tokio::time::sleep(FAST_FORWARD_RECOVERY_BACKOFF).await;
                continue;
            }

            // Aggregate delivery-slot impact over the full batch. Ragged
            // changes we can inspect directly via their op types. The proof (when
            // present) covers changes we cannot introspect here, so treat its
            // presence as a conservative trigger — the sync tri-state will
            // short-circuit cheaply if no fresh group key was actually introduced.
            let needs_slot_check = ff.proof.is_some()
                || ff
                    .changes
                    .iter()
                    .any(|c| crate::SpaceKeyManager::op_may_need_delivery(c.message.op_type));

            match self
                .apply_fast_forward_from_anchor(ff, anchor, &expected_change_ids)
                .await
            {
                Ok(inserted_ids) => break 'retry Some((inserted_ids, needs_slot_check)),
                Err(SdkError::FastForwardStateAdvanced) => {
                    log::debug!(
                        "[SDK] recover_via_fast_forward: state advanced during FF apply attempt {attempt}; retrying"
                    );
                    if std::time::Instant::now() >= deadline {
                        break 'retry None;
                    }
                    tokio::time::sleep(FAST_FORWARD_RECOVERY_BACKOFF).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        let (inserted_ids, needs_slot_check) = match outcome {
            Some(v) => v,
            None => {
                return Err(SdkError::FastForwardRequired {
                    reason: format!(
                        "client state kept advancing during fast-forward (\
                         {attempt} attempts over {:?} budget)",
                        FAST_FORWARD_RECOVERY_BUDGET
                    ),
                });
            }
        };
        let (cid, clc) =
            self.with_state(|state| (state.current_change_id, state.current_clc_state.root));
        log::info!(
            "[SDK] recover_via_fast_forward: after FF change_id={} clc={}",
            cid,
            hex::encode::<[u8; 32]>(clc.into())
        );
        // Re-warm internal table caches so that subsequent
        // validate_and_apply_change calls can resolve user/schema reads.
        self.initialize_users().await?;

        // At most one post-apply hook per FF batch, against the final
        // retention snapshot now present in the cache.
        self.post_apply_delivery_slot_recovery(needs_slot_check)
            .await?;
        Ok(inserted_ids)
    }

    pub async fn apply_fast_forward(
        &self,
        ff_data: FastForwardData,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, i64>> {
        let anchor = self.fast_forward_anchor();
        self.apply_fast_forward_from_anchor(ff_data, anchor, &[])
            .await
    }

    async fn apply_fast_forward_from_anchor(
        &self,
        ff_data: FastForwardData,
        anchor: FastForwardAnchor,
        expected_change_ids: &[u32],
    ) -> Result<std::collections::BTreeMap<Vec<u8>, i64>> {
        use encrypted_spaces_ffproof::verifier::verify_ff;

        // Issue #212 (#4): hold the mutation-serialization guard for the whole
        // apply — including deferred signature verification and any rollback —
        // so a concurrent signer cannot observe the provisional changelog
        // position this method installs before verification completes.
        let _ff_guard = self.serialize_mutations.lock().await;

        // Mark FF in progress so a deferred-verification read that hits a stale
        // select cannot recurse back into FF (which would deadlock on the
        // non-reentrant guard above). Reset on every return path via RAII.
        struct FfInProgressGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for FfInProgressGuard {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        self.ff_in_progress
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ff_in_progress = FfInProgressGuard(std::sync::Arc::clone(&self.ff_in_progress));

        let saved_state = self.save_changelog_state();
        let mut applied_state = false;

        if ff_data.changes.len() != ff_data.responses.len() {
            return Err(SdkError::DatabaseError(
                "Invalid FF data -- mismatching number of changes and responses".to_string(),
            ));
        }
        validate_fast_forward_server_head_ids(&ff_data, anchor.change_id)?;

        // sigref data extracted here so it's available for deferred
        // verification after the state (including data commitment) is
        // up-to-date. Table reads during key resolution require a
        // current DC, so we can't verify sigref signatures eagerly.
        //
        // The map value is `(change_id, entry_hash)`: `entry_hash` is
        // the journal-proven `h_leaf(entry_bytes)` of the entry at
        // `change_id` and binds the supplied `sigref_entries` payload
        // to the bytes the guest actually processed.
        let mut deferred_sigref: Option<(SigrefMap, SigrefEntries)> = None;

        if let Some(ref proof) = ff_data.proof {
            println!(
                "Received FF proof covering changes up to {}, proof size: {} bytes",
                proof.end_change_id,
                proof.proof.len()
            );

            let ff_image_id = self.with_state(|state| state.ff_image_id);
            let range = verify_ff(&proof.proof, ff_image_id)
                .map_err(|e| SdkError::ValidationError(e.to_string()))?;

            if !range.sigref_map.is_empty() {
                deferred_sigref = Some((range.sigref_map.clone(), proof.sigref_entries.clone()));
            }

            let start_dc: [u8; 32] = range.start_dc;
            let end_dc: [u8; 32] = range.end_dc;
            let start_clc: [u8; 32] = range.start_clc_state.root.into();
            let end_clc: [u8; 32] = range.end_clc_state.root.into();
            let proof_timestamp_hwm = range.timestamp_hwm;

            println!(
                "FF proof verified: start_dc={}, end_dc={}",
                hex::encode(start_dc),
                hex::encode(end_dc)
            );

            // The FF proof starts from the canonical genesis data
            // commitment and the corresponding initial changelog
            // commitment. Check both so the statement is tied to the
            // data origin and the changelog origin.
            let initial_dc = self.with_state(|state| state.initial_dc);
            if start_dc != initial_dc {
                return Err(SdkError::ValidationError(format!(
                    "FF proof start_dc {} does not match initial_dc {}",
                    hex::encode(start_dc),
                    hex::encode(initial_dc)
                )));
            }
            let expected_start_clc = crate::state::initial_clc_state(&initial_dc);
            if range.start_clc_state != expected_start_clc {
                return Err(SdkError::ValidationError(
                    "FF proof start_clc_state does not match initial_clc_state(initial_dc)"
                        .to_string(),
                ));
            }
            if proof.end_change_id != range.end_change_id {
                return Err(SdkError::ValidationError(format!(
                    "FF proof wrapper end_change_id {} does not match verified journal end_change_id {}",
                    proof.end_change_id, range.end_change_id
                )));
            }
            if !range
                .end_clc_state
                .verify_for_change_id(range.end_change_id)
            {
                return Err(SdkError::ValidationError(format!(
                    "FF proof end_clc_state is inconsistent with end_change_id {}",
                    range.end_change_id
                )));
            }
            println!("FF proof start_dc matches initial_dc");

            // Branch-continuity check. Bind the client's prior
            // changelog position to the FF proof's `end_clc_state` by
            // verifying the inclusion proof for `current_change_id`.
            //
            // The pre-image is the client's locally-stored
            // `current_change_entry` — captured at the FF
            // request/application boundary before this response is
            // validated. For `current_change_id == 0`, the initial
            // changelog commitment is already pinned by the
            // `start_clc_state == initial_clc_state(initial_dc)` check
            // above, so no inclusion proof is needed.
            let (prior_change_id, prior_entry) = (anchor.change_id, anchor.change_entry.clone());
            if prior_change_id > 0 {
                let prior_entry = prior_entry.ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "FF: client at change_id {prior_change_id} has no stored changelog \
                         anchor entry; cannot verify branch continuity"
                    ))
                })?;
                let prior_proof = proof.from_inclusion_proof.as_ref().ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "FF: server omitted from_inclusion_proof for \
                         from_change_id={prior_change_id}"
                    ))
                })?;
                if prior_proof.i != prior_change_id {
                    return Err(SdkError::ValidationError(format!(
                        "FF: from_inclusion_proof.i={} does not match client's \
                         current_change_id={prior_change_id}",
                        prior_proof.i
                    )));
                }
                let prior_leaf_hash = h_leaf(&prior_entry.as_bytes());
                if !verify_with_leaf_hash(&range.end_clc_state, prior_proof, prior_leaf_hash) {
                    return Err(SdkError::ValidationError(format!(
                        "FF: branch substitution detected — from_inclusion_proof \
                         does not verify against end_clc_state at \
                         change_id={prior_change_id}"
                    )));
                }
                println!("FF branch continuity verified at change_id={prior_change_id}");
            } else if proof.from_inclusion_proof.is_some() {
                // Defensive: a from_change_id==0 request should not
                // come back with a from_inclusion_proof; reject rather
                // than silently ignore.
                return Err(SdkError::ValidationError(
                    "FF: server included from_inclusion_proof for \
                     from_change_id == 0"
                        .to_string(),
                ));
            }

            // If no ragged changes follow the proof, authenticate the
            // proof boundary entry as the next changelog anchor. When
            // ragged changes are present, the last applied ragged
            // change is already signed and becomes the next anchor.
            let verified_end_entry = if ff_data.responses.is_empty() {
                let end_entry = proof.end_entry.as_ref().ok_or_else(|| {
                    SdkError::ValidationError(
                        "FF: server omitted end_entry for proof-only response".to_string(),
                    )
                })?;
                let end_entry_inclusion_proof =
                    proof.end_entry_inclusion_proof.as_ref().ok_or_else(|| {
                        SdkError::ValidationError(
                            "FF: server omitted end_entry_inclusion_proof for proof-only response"
                                .to_string(),
                        )
                    })?;
                if end_entry_inclusion_proof.i != range.end_change_id {
                    return Err(SdkError::ValidationError(format!(
                        "FF: end_entry_inclusion_proof.i={} does not match \
                         end_change_id={}",
                        end_entry_inclusion_proof.i, range.end_change_id
                    )));
                }
                let end_leaf_hash = h_leaf(&end_entry.as_bytes());
                if !verify_with_leaf_hash(
                    &range.end_clc_state,
                    end_entry_inclusion_proof,
                    end_leaf_hash,
                ) {
                    return Err(SdkError::ValidationError(
                        "FF: end_entry_inclusion_proof does not verify against \
                         end_clc_state"
                            .to_string(),
                    ));
                }
                Some(end_entry.clone())
            } else {
                None
            };

            println!(
                "FF proof CLCs: start={}, end={}",
                hex::encode(start_clc),
                hex::encode(end_clc)
            );

            if let Some(first_response) = ff_data.responses.first() {
                let first_old_root = first_response.old_root;
                if first_old_root != end_dc {
                    return Err(SdkError::ValidationError(format!(
                        "First ragged change old_root {} does not match FF proof end_dc {}",
                        hex::encode(first_old_root),
                        hex::encode(end_dc)
                    )));
                }
            }

            let end_clc_state = range.end_clc_state.clone();

            // Issue #212: discharge expected local entries that fall inside the
            // proven range using server-supplied inclusion proofs against
            // `end_clc_state`. Each proof's leaf is the client's own submitted
            // entry, recomputed here from the pending entry's journal leaf hash
            // — a server that returns a proof for a *different* entry at the same
            // change_id fails verification, so it cannot forge discharge.
            // Expected ids beyond `range.end_change_id` are in the ragged tail
            // and discharge through `apply_state_update`'s leaf-hash match.
            //
            // Verification here is read-only; the discharge flags are flipped
            // *atomically* with committing `end_clc_state` in the
            // anchor-guarded block below, so an apply that aborts because the
            // anchor advanced (`FastForwardStateAdvanced`) never leaves a stale
            // discharge for a chain we did not commit.
            let mut proven_expected: Vec<u32> = Vec::new();
            for &cid in expected_change_ids {
                if cid == 0 || cid > range.end_change_id {
                    continue;
                }
                let Some(incl) = proof.expected_inclusion_proofs.get(&cid) else {
                    continue;
                };
                let Some(leaf_hash) =
                    self.with_state(|s| s.pending_local_changes.get(&cid).map(|p| p.leaf_hash))
                else {
                    continue;
                };
                if incl.i == cid && verify_with_leaf_hash(&end_clc_state, incl, leaf_hash.into()) {
                    proven_expected.push(cid);
                }
            }

            let state_update = self.with_state_mut(|state| {
                if state.current_change_id != anchor.change_id {
                    return Err(SdkError::FastForwardStateAdvanced);
                }
                state.current_change_id = range.end_change_id;
                state.current_clc_state = end_clc_state;
                // Seed the client's per-user sigref view from the proven
                // map. The FF outputs `sigref_map`, so `range.sigref_map` is the
                // full accumulated chain from genesis through
                // `range.end_change_id` — REPLACE rather than merge. The
                // entry hashes are dropped; only uid -> change_id is needed
                // for downstream ragged / single-change continuity checks.
                state.sigref_map = range
                    .sigref_map
                    .iter()
                    .map(|(&uid, &(cid, _))| (uid, cid))
                    .collect();
                state.timestamp_hwm = proof_timestamp_hwm;
                if let Some(uid) = state
                    .auth_context
                    .uid
                    .and_then(|uid| u32::try_from(uid).ok())
                {
                    if let Some(&(my_last_change_id, _)) = range.sigref_map.get(&uid) {
                        state.my_last_change_id = my_last_change_id;
                    }
                }
                if let Some(end_entry) = verified_end_entry {
                    state.current_change_entry = Some(end_entry);
                }
                // Discharge proof-covered expected entries atomically with the
                // committed `end_clc_state` (issue #212): only reached when the
                // anchor check above passes, so a stale discharge can never
                // survive a `FastForwardStateAdvanced` abort and leak into a
                // later, differently-anchored commit.
                for cid in &proven_expected {
                    if let Some(p) = state.pending_local_changes.get_mut(cid) {
                        p.discharged = true;
                    }
                }
                Ok(())
            });
            state_update?;
            applied_state = true;

            if ff_data.responses.is_empty() {
                self.with_state_mut(|state| {
                    state.current_data_commitment = end_dc;
                });
                println!(
                    "Set data commitment from FF proof end_dc: {}",
                    hex::encode(end_dc)
                );
                // Note on `end_entry` signature: we don't separately verify
                // it on the client, since it's verified as part of FF proof
                // verification.
            } else {
                let first_old_root = ff_data.responses[0].old_root;
                self.with_state_mut(|state| {
                    state.current_data_commitment = first_old_root;
                });
                println!(
                    "Set data commitment from first ragged change's old_root: {}",
                    hex::encode(first_old_root)
                );
            }

            println!(
                "Client state updated to change_id {} via verified FF proof",
                proof.end_change_id
            );
        }

        // Ragged changes (after the last FF proof).  Use schema_only=true
        // because the client cache may be stale after fast-forward; schema
        // checks are still validated but user-existence / table-emptiness
        // checks are deferred to the next FF proof.
        //
        // We save the state before applying ragged changes so we can rollback
        // if deferred signature verification fails. This prevents the client
        // from advancing to an unverified state.
        let mut inserted_ids: std::collections::BTreeMap<Vec<u8>, i64> =
            std::collections::BTreeMap::new();
        let mut ragged_cache_updates: Vec<(Change, Vec<BatchOp>)> = Vec::new();

        for (change, response) in ff_data.changes.iter().zip(ff_data.responses.iter()) {
            let state_values = self.with_state(|state| {
                if let Some(uid) = state.auth_context.uid {
                    let expected_sig_ref = state.sigref_map.get(&change.uid).copied().unwrap_or(0);
                    Ok((
                        state.current_change_id,
                        state.my_last_change_id,
                        uid as u32,
                        state.current_clc_state.root.into(),
                        expected_sig_ref,
                        state.timestamp_hwm,
                    ))
                } else {
                    Err(SdkError::ValidationError(
                        "User is not authenticated".to_string(),
                    ))
                }
            });
            let (
                current_change_id,
                my_last_change_id,
                uid,
                current_clc,
                expected_sig_ref,
                timestamp_hwm,
            ) = match state_values {
                Ok(values) => values,
                Err(e) => return self.rollback_if_applied(&saved_state, applied_state, e),
            };

            // Skip ragged changes already applied (e.g. by a concurrent
            // validate_and_apply_change from an in-flight mutation).
            if response.change_id <= current_change_id {
                log::debug!(
                    "[SDK] apply_fast_forward: skipping already-applied change {} (current={})",
                    response.change_id,
                    current_change_id
                );
                continue;
            }

            let mut new_timestamp_hwm = timestamp_hwm;
            if let Err(e) = validate_fast_forward_tail_timestamp_policy(
                change,
                response,
                &mut new_timestamp_hwm,
            ) {
                return self.rollback_if_applied(&saved_state, applied_state, e);
            }

            // The state's current_change_id reflects what we've already
            // applied; the incoming change becomes #(current+1).
            let next_change_id = (current_change_id as usize).saturating_add(1);
            let writes = match ChangeLog::verify_proof_and_validate(
                change,
                &response.pruned_merkle_tree,
                &response.old_root,
                &response.new_root,
                next_change_id,
            ) {
                Ok(writes) => writes,
                Err(e) => {
                    return self.rollback_if_applied(
                        &saved_state,
                        applied_state,
                        SdkError::DatabaseError(format!("verify_pruned_merkle_tree failed: {e:?}")),
                    );
                }
            };
            let table = table_name_from_change_entry(change);
            if let Some(row_id) = crate::cache::new_row_id_for_table(self, &writes, &table) {
                inserted_ids.insert(change.signature.clone(), row_id);
            }

            // Sigref-chain continuity for ragged changes (issue #30).
            // The FF guest only enforces this for proven ranges; without
            // this check the client could advance on a tail that the next
            // FF would reject. Snapshot read above + CAS in
            // `apply_state_update` keep the check atomic w.r.t. broadcasts.
            if let Err(e) = check_sigref_continuity(change, expected_sig_ref) {
                return self.rollback_if_applied(&saved_state, applied_state, e);
            }

            if let Err(e) = self.apply_state_update(
                change,
                response,
                current_change_id,
                my_last_change_id,
                uid,
                current_clc,
                new_timestamp_hwm,
            ) {
                return self.rollback_if_applied(&saved_state, applied_state, e);
            }

            ragged_cache_updates.push((
                Change {
                    entry: change.clone(),
                    hashed_values: response.hashed_values.clone(),
                },
                writes,
            ));

            // Required when the FF response carries ragged changes without
            // a proof (server-side `fast_forward` can return `proof: None`
            // with non-empty `changes`). In that case the proof block above
            // is skipped, so `applied_state` is still `false` when we enter
            // this loop, and we need to flip it here so that a failure on a
            // later ragged change triggers rollback of the earlier ones.
            applied_state = true;
        }

        // Deferred signature verification: we cannot verify during the loop
        // above because reads (needed to resolve signing keys from _users /
        // _key_history) require a valid data commitment, and during ragged
        // change processing the client's DC is at an intermediate root that
        // doesn't match the server's current state. Now that all ragged
        // changes have been applied, current_data_commitment matches the
        // server root, so reads verify correctly.
        //
        // If any signature is invalid or key resolution still fails after
        // the DC is current, rollback to the saved state so the client
        // does not advance past unverified changes.
        for (change, response) in ff_data.changes.iter().zip(ff_data.responses.iter()) {
            let outcome = self
                .try_verify_change_signature(change, response.change_id, &response.hashed_values)
                .await;
            if !matches!(outcome, SigVerifyOutcome::Verified) {
                let e = outcome.into_err();
                log::warn!(
                    "[SDK] apply_fast_forward: sig verification failed for ragged \
                     change {}: {e} — rolling back",
                    response.change_id
                );
                return self.rollback_if_applied(&saved_state, applied_state, e);
            }
        }

        // Deferred sigref verification: verify one signature per user from
        // the FF proof's sigref chain. This must happen after ragged changes
        // are applied so that the data commitment is current and table reads
        // (needed for key resolution) verify correctly.
        if let Some((sigref_map, sigref_entries)) = &deferred_sigref {
            if let Err(e) = self
                .verify_sigref_signatures(sigref_map, sigref_entries)
                .await
            {
                log::warn!(
                    "[SDK] apply_fast_forward: sigref verification failed: {e} — rolling back"
                );
                return self.rollback_if_applied(&saved_state, applied_state, e);
            }
        }

        if let Err(e) = self.verify_fast_forward_server_head(&ff_data, anchor.change_id) {
            return self.rollback_if_applied(&saved_state, applied_state, e);
        }

        // All verification passed — apply ragged change writes to the
        // cache so hash-backed column values are immediately available
        // without requiring a subsequent select.
        //
        // The cache was cleared at the start of FF recovery, so app
        // tables have no entries yet. Ensure each touched table exists
        // in the cache before inserting rows.
        if !ragged_cache_updates.is_empty() {
            self.with_state_mut(|state| {
                for (_, writes) in &ragged_cache_updates {
                    for op in writes {
                        if let BatchOp::Put { key, .. } = op {
                            if let Ok(ParsedKey::Column { ref table, .. }) = parse_key(key) {
                                if let Some(schema) = state.table_schemas.get(table) {
                                    let indexed = crate::cache::indexed_columns_for_schema(schema);
                                    state.cache.init_table(table, &indexed);
                                }
                            }
                        }
                    }
                }
            });
        }
        for (change, writes) in &ragged_cache_updates {
            self.apply_broadcast_cache_updates(change, writes).await;
        }

        Ok(inserted_ids)
    }

    /// Verify sigref chain signatures
    async fn verify_sigref_signatures(
        &self,
        sigref_map: &SigrefMap,
        sigref_entries: &SigrefEntries,
    ) -> Result<()> {
        use encrypted_spaces_backend::sign_change::verify_change_signature;
        use encrypted_spaces_key_manager::DefaultSignature;

        // Validate entries before attempting expensive key resolution / sig checks.
        // This also binds each supplied entry's bytes to the journal-proven
        // `h_leaf` hash, so the server cannot substitute a different
        // (but genuinely signed) entry for signature verification.
        validate_sigref_entries(sigref_map, sigref_entries)?;

        for (&uid, &(change_id, _entry_hash)) in sigref_map {
            let entry = &sigref_entries[&change_id];

            let vk = self
                .resolve_signing_key_for_change(
                    uid,
                    change_id,
                    entry.message.op_type,
                    entry.sig_ref,
                )
                .await
                .map_err(|e| {
                    SdkError::ValidationError(format!(
                        "Failed to resolve signing key for uid {uid} \
                         (change {change_id}): {e}"
                    ))
                })?;

            verify_change_signature::<DefaultSignature>(entry, &vk).map_err(|e| {
                SdkError::ValidationError(format!(
                    "Sigref signature verification failed for uid {uid} \
                     (change {change_id}): {e:?}"
                ))
            })?;
        }
        println!(
            "Sigref chain verified: {} user signature(s) checked",
            sigref_map.len()
        );
        Ok(())
    }
}

/// Validate sigref_entries against sigref_map before attempting cryptographic checks.
/// Ensures every user in the map has a corresponding entry with matching uid,
/// non-empty signature, and entry bytes whose `h_leaf` hash matches the
/// journal-proven hash carried in `sigref_map`.
fn validate_sigref_entries(sigref_map: &SigrefMap, sigref_entries: &SigrefEntries) -> Result<()> {
    for (&uid, &(change_id, expected_hash)) in sigref_map {
        let entry = sigref_entries.get(&change_id).ok_or_else(|| {
            SdkError::ValidationError(format!(
                "sigref_entries missing entry for change_id {change_id} (uid {uid})"
            ))
        })?;

        if entry.uid != uid {
            return Err(SdkError::ValidationError(format!(
                "sigref entry uid mismatch: expected {uid}, got {}",
                entry.uid
            )));
        }

        if entry.signature.is_empty() {
            return Err(SdkError::ValidationError(format!(
                "sigref entry for uid {uid} (change {change_id}) has no signature"
            )));
        }

        // Bind supplied entry bytes to the journal-proven leaf hash.
        // Rejecting here ensures we never verify a signature against
        // bytes the FF guest didn't actually process.
        let actual_hash: [u8; 32] = (*h_leaf(&entry.as_bytes()).as_bytes())
            .try_into()
            .expect("digest is 32 bytes");
        if actual_hash != expected_hash {
            return Err(SdkError::ValidationError(format!(
                "sigref entry hash mismatch for uid {uid} (change {change_id}): \
                 supplied entry does not match the FF-proven entry hash"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_changelog_core::changelog::{ChangelogEntry, KvData, LogMessage, OpType};
    use encrypted_spaces_changelog_core::time::{
        CHANGE_EXPIRY_SECONDS, CLIENT_CLOCK_TOLERANCE_SECONDS, CLOCK_SKEW_TOLERANCE_SECONDS,
        TIMESTAMP_HWM_TOLERANCE_SECONDS,
    };
    use std::collections::BTreeMap;

    fn make_sigref_entry(uid: u32, sig_ref: u32) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![KvData {
                    key: b"k".to_vec(),
                    value: vec![0xAA; 32],
                }],
            },
            sig_ref,
            parent_clc: [0u8; 32],
            signature: vec![0xDE, 0xAD], // non-empty dummy signature
        }
    }

    fn entry_leaf_hash(entry: &ChangelogEntry) -> [u8; 32] {
        (*h_leaf(&entry.as_bytes()).as_bytes())
            .try_into()
            .expect("digest is 32 bytes")
    }

    fn response_at(accepted_at_server_time: u64) -> ChangeResponse {
        ChangeResponse {
            change_id: 1,
            old_root: [0u8; 32],
            new_root: [1u8; 32],
            pruned_merkle_tree: Vec::new(),
            rows_affected: 1,
            accepted_at_server_time,
            hashed_values: Default::default(),
        }
    }

    #[test]
    fn replay_timestamp_policy_accepts_expiry_boundary() {
        let now = ChangelogEntry::get_unix_timestamp();
        let mut entry = make_sigref_entry(1, 0);
        entry.timestamp = now.saturating_sub(CHANGE_EXPIRY_SECONDS);

        validate_replay_timestamp_policy(&entry, &response_at(now)).unwrap();
    }

    #[test]
    fn replay_timestamp_policy_rejects_expired_change() {
        let now = ChangelogEntry::get_unix_timestamp();
        let mut entry = make_sigref_entry(1, 0);
        entry.timestamp = now.saturating_sub(CHANGE_EXPIRY_SECONDS + 1);

        let err = validate_replay_timestamp_policy(&entry, &response_at(now)).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn replay_timestamp_policy_accepts_bounded_response_age_beyond_clock_skew() {
        let now = ChangelogEntry::get_unix_timestamp();
        let accepted_at = now.saturating_sub(CLOCK_SKEW_TOLERANCE_SECONDS + 1);
        let mut entry = make_sigref_entry(1, 0);
        entry.timestamp = accepted_at;

        validate_replay_timestamp_policy(&entry, &response_at(accepted_at)).unwrap();
    }

    #[test]
    fn replay_timestamp_policy_rejects_backdated_acceptance_time() {
        let now = ChangelogEntry::get_unix_timestamp();
        let accepted_at = now.saturating_sub(CLIENT_CLOCK_TOLERANCE_SECONDS + 1);
        let mut entry = make_sigref_entry(1, 0);
        entry.timestamp = accepted_at;

        let err = validate_replay_timestamp_policy(&entry, &response_at(accepted_at)).unwrap_err();
        assert!(err.to_string().contains("freshness window"));
    }

    #[test]
    fn replay_timestamp_policy_rejects_future_acceptance_time() {
        let now = ChangelogEntry::get_unix_timestamp();
        let accepted_at = now.saturating_add(CLIENT_CLOCK_TOLERANCE_SECONDS + 60);
        let mut entry = make_sigref_entry(1, 0);
        // Match the change timestamp to the acceptance time so the acceptance
        // rule passes and the local-clock future bound is what rejects.
        entry.timestamp = accepted_at;

        let err = validate_replay_timestamp_policy(&entry, &response_at(accepted_at)).unwrap_err();
        assert!(err.to_string().contains("future"));
    }

    #[test]
    fn fast_forward_tail_timestamp_policy_accepts_historical_acceptance_time() {
        let now = ChangelogEntry::get_unix_timestamp();
        let accepted_at = now.saturating_sub(CLIENT_CLOCK_TOLERANCE_SECONDS + 60);
        let mut entry = make_sigref_entry(1, 0);
        entry.timestamp = accepted_at;
        let mut timestamp_hwm = accepted_at;

        validate_fast_forward_tail_timestamp_policy(
            &entry,
            &response_at(accepted_at),
            &mut timestamp_hwm,
        )
        .unwrap();
    }

    #[test]
    fn fast_forward_tail_timestamp_policy_rejects_stale_relative_to_hwm() {
        let mut timestamp_hwm = 1_000;
        let mut entry = make_sigref_entry(1, 0);
        entry.timestamp = timestamp_hwm - TIMESTAMP_HWM_TOLERANCE_SECONDS - 1;

        let err = validate_fast_forward_tail_timestamp_policy(
            &entry,
            &response_at(entry.timestamp),
            &mut timestamp_hwm,
        )
        .unwrap_err();
        assert!(err.to_string().contains("timestamp HWM"));
    }

    #[test]
    fn verify_sigref_entries_rejects_uid_mismatch() {
        let uid_a = 10;
        let uid_b = 11;
        let change_id = 42;

        // Provide an entry for change_id 42, but it belongs to uid_b (wrong user).
        // Use uid_b's entry hash so the test fails on the uid check, not the hash check.
        let entry = make_sigref_entry(uid_b, 0);
        let mut sigref_map = BTreeMap::new();
        sigref_map.insert(uid_a, (change_id, entry_leaf_hash(&entry)));

        let mut sigref_entries = BTreeMap::new();
        sigref_entries.insert(change_id, entry);

        let err = validate_sigref_entries(&sigref_map, &sigref_entries);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("uid mismatch"),
            "expected uid mismatch error, got: {msg}"
        );
    }

    #[test]
    fn verify_sigref_entries_rejects_missing_entry() {
        let uid_a = 10;
        let uid_b = 11;

        let entry_a = make_sigref_entry(uid_a, 0);
        let mut sigref_map = BTreeMap::new();
        sigref_map.insert(uid_a, (1, entry_leaf_hash(&entry_a)));
        sigref_map.insert(uid_b, (2, [0u8; 32]));

        // Only provide the entry for uid_a, omit uid_b's
        let mut sigref_entries = BTreeMap::new();
        sigref_entries.insert(1, entry_a);

        let err = validate_sigref_entries(&sigref_map, &sigref_entries);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("missing entry for change_id 2"),
            "expected missing entry error, got: {msg}"
        );
    }

    #[test]
    fn verify_sigref_entries_rejects_empty_signature() {
        let uid = 10;
        let change_id = 1;

        let mut entry = make_sigref_entry(uid, 0);
        entry.signature = vec![]; // empty signature

        let mut sigref_map = BTreeMap::new();
        sigref_map.insert(uid, (change_id, entry_leaf_hash(&entry)));

        let mut sigref_entries = BTreeMap::new();
        sigref_entries.insert(change_id, entry);

        let err = validate_sigref_entries(&sigref_map, &sigref_entries);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("has no signature"),
            "expected empty signature error, got: {msg}"
        );
    }

    #[test]
    fn verify_sigref_entries_accepts_valid_entries() {
        let entry_a = make_sigref_entry(10, 0);
        let entry_b = make_sigref_entry(11, 0);

        let mut sigref_map = BTreeMap::new();
        sigref_map.insert(10, (1, entry_leaf_hash(&entry_a)));
        sigref_map.insert(11, (2, entry_leaf_hash(&entry_b)));

        let mut sigref_entries = BTreeMap::new();
        sigref_entries.insert(1, entry_a);
        sigref_entries.insert(2, entry_b);

        assert!(validate_sigref_entries(&sigref_map, &sigref_entries).is_ok());
    }

    /// Regression for #30: `check_sigref_continuity` enforces the
    /// per-user sigref chain on the client. A first-time signer must
    /// have `sig_ref == 0`; subsequent signers must point at their
    /// previously accepted change_id.
    #[test]
    fn check_sigref_continuity_accepts_first_signer_with_zero() {
        let entry = make_sigref_entry(42, 0);
        assert!(check_sigref_continuity(&entry, 0).is_ok());
    }

    #[test]
    fn check_sigref_continuity_accepts_match() {
        let entry = make_sigref_entry(42, 7);
        assert!(check_sigref_continuity(&entry, 7).is_ok());
    }

    #[test]
    fn check_sigref_continuity_rejects_first_signer_with_nonzero() {
        let entry = make_sigref_entry(42, 5);
        let err = check_sigref_continuity(&entry, 0).unwrap_err();
        assert!(
            err.to_string().contains("Sigref chain broken"),
            "got: {err}"
        );
    }

    #[test]
    fn check_sigref_continuity_rejects_mismatch() {
        let entry = make_sigref_entry(42, 3);
        let err = check_sigref_continuity(&entry, 7).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Sigref chain broken"), "got: {msg}");
        assert!(msg.contains("expected sig_ref=7"), "got: {msg}");
        assert!(msg.contains("got 3"), "got: {msg}");
    }

    /// Regression for #30: a server that supplies a *different* signed
    /// entry than the one the FF guest processed must be rejected, even
    /// when the supplied entry has a valid uid and non-empty signature.
    /// The journal-proven leaf hash binds entry bytes to the proven
    /// `sigref_map`.
    #[test]
    fn verify_sigref_entries_rejects_substituted_entry() {
        let uid = 10;
        let change_id = 1;

        // Honest entry (what the FF guest processed): the proven hash
        // is `h_leaf(honest.as_bytes())`.
        let honest = make_sigref_entry(uid, 0);
        let proven_hash = entry_leaf_hash(&honest);

        // Server supplies a DIFFERENT entry (same uid, also signed) —
        // tweak the timestamp so the bytes (and therefore `h_leaf`)
        // differ. A signature check alone could be tricked into passing
        // here; the hash binding catches it first.
        let mut substituted = make_sigref_entry(uid, 0);
        substituted.timestamp = 2000;
        assert_ne!(
            entry_leaf_hash(&substituted),
            proven_hash,
            "test setup: substituted entry must hash differently"
        );

        let mut sigref_map = BTreeMap::new();
        sigref_map.insert(uid, (change_id, proven_hash));

        let mut sigref_entries = BTreeMap::new();
        sigref_entries.insert(change_id, substituted);

        let err = validate_sigref_entries(&sigref_map, &sigref_entries);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("entry hash mismatch"),
            "expected hash-mismatch error, got: {msg}"
        );
    }

    /// Even a one-byte tamper in the signature flips the leaf hash and
    /// must be caught — signatures are part of the entry bytes hashed
    /// into the MMR leaf.
    #[test]
    fn verify_sigref_entries_rejects_byte_flip_in_signature() {
        let uid = 7;
        let change_id = 3;

        let honest = make_sigref_entry(uid, 0);
        let proven_hash = entry_leaf_hash(&honest);

        let mut tampered = honest.clone();
        tampered.signature[0] ^= 0x01;
        assert_ne!(
            entry_leaf_hash(&tampered),
            proven_hash,
            "test setup: tampered entry must hash differently"
        );

        let mut sigref_map = BTreeMap::new();
        sigref_map.insert(uid, (change_id, proven_hash));

        let mut sigref_entries = BTreeMap::new();
        sigref_entries.insert(change_id, tampered);

        let err = validate_sigref_entries(&sigref_map, &sigref_entries).unwrap_err();
        assert!(
            err.to_string().contains("entry hash mismatch"),
            "expected hash-mismatch error, got: {err}"
        );
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod hash_backed_change_tests {
    use super::*;
    use crate::crypto::encrypt_query_fields;
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::merk_storage::{get_row_data_from_query, parse_key, ParsedKey};
    use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
    use encrypted_spaces_backend_server::SpaceState;
    use encrypted_spaces_storage_encoding::hashstore_hash;
    use std::sync::Arc;

    async fn create_hash_backed_space() -> Result<Space> {
        let schema = SchemaBuilder::new("messages")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)?
            .column("title", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        Space::create(
            transport,
            ApplicationSchema::for_testing(vec![schema], root),
        )
        .await
    }

    fn entry_value_for_column(change: &Change, column_name: &str) -> Vec<u8> {
        change
            .entry
            .message
            .entries
            .iter()
            .find_map(|entry| match parse_key(&entry.key) {
                Ok(ParsedKey::Column { column, .. }) if column == column_name => {
                    Some(entry.value.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing entry for column {column_name}"))
    }

    #[tokio::test]
    async fn hash_backed_change_builder_insert_hashes_schema_columns() -> Result<()> {
        let space = create_hash_backed_space().await?;
        let mut query = Query::new(
            "messages".to_string(),
            QueryOperation::Insert(vec![
                (
                    "content".to_string(),
                    QueryParam::Text("large body".to_string()),
                ),
                (
                    "title".to_string(),
                    QueryParam::Text("inline title".to_string()),
                ),
            ]),
        );
        encrypt_query_fields(&mut query, &space).await?;

        let (_, column_data) = get_row_data_from_query(&query)?;
        let content_bytes = column_data
            .iter()
            .find(|(name, _)| name == "content")
            .map(|(_, value)| value.clone())
            .expect("content bytes");
        let title_bytes = column_data
            .iter()
            .find(|(name, _)| name == "title")
            .map(|(_, value)| value.clone())
            .expect("title bytes");

        let change = ChangeBuilder::new(&mut query, Arc::new(space))
            .build()
            .await?
            .expect("insert change");

        let expected_hash = hashstore_hash(&content_bytes);
        assert_eq!(
            entry_value_for_column(&change, "content"),
            expected_hash.to_vec()
        );
        assert_eq!(entry_value_for_column(&change, "title"), title_bytes);
        assert_eq!(change.hashed_values.len(), 1);
        assert_eq!(change.hashed_values[&expected_hash], content_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_storage_hashes_empty_values_when_not_delete_sentinel() -> Result<()> {
        let space = create_hash_backed_space().await?;
        let mut query = Query::new("messages".to_string(), QueryOperation::Insert(vec![]));
        let builder = ChangeBuilder::new(&mut query, Arc::new(space));
        let keys = vec![column_key_placeholder("messages", "content")];
        let mut values = vec![Vec::new()];

        let material =
            builder.apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)?;
        let expected_hash = hashstore_hash(&[]);

        assert_eq!(values, vec![expected_hash.to_vec()]);
        assert_eq!(material.len(), 1);
        assert!(material[&expected_hash].is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_storage_skips_empty_delete_sentinels() -> Result<()> {
        let space = create_hash_backed_space().await?;
        let mut query = Query::new("messages".to_string(), QueryOperation::Delete);
        let builder = ChangeBuilder::new(&mut query, Arc::new(space));
        let keys = vec![column_key_placeholder("messages", "content")];
        let mut values = vec![Vec::new()];

        let material = builder.apply_hash_backed_storage(
            &keys,
            &mut values,
            EmptyHashBackedValue::SkipDeleteSentinel,
        )?;

        assert!(material.is_empty());
        assert_eq!(values, vec![Vec::<u8>::new()]);
        Ok(())
    }

    #[tokio::test]
    async fn string_column_rejects_oversized_value() -> Result<()> {
        let space = create_hash_backed_space().await?;
        let mut query = Query::new("messages".to_string(), QueryOperation::Delete);
        let builder = ChangeBuilder::new(&mut query, Arc::new(space));
        let keys = vec![column_key_placeholder("messages", "title")];
        let oversized_str = "x".repeat(MAX_STRING_COLUMN_BYTES + 1);
        let oversized_bytes =
            stored_value::value_to_bytes(&serde_json::Value::String(oversized_str)).unwrap();
        let mut values = vec![oversized_bytes];

        let err = builder
            .apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)
            .unwrap_err();
        assert!(
            err.to_string().contains("max is"),
            "expected size error, got: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn string_column_accepts_max_size_value() -> Result<()> {
        let space = create_hash_backed_space().await?;
        let mut query = Query::new("messages".to_string(), QueryOperation::Delete);
        let builder = ChangeBuilder::new(&mut query, Arc::new(space));
        let keys = vec![column_key_placeholder("messages", "title")];
        let exact_str = "x".repeat(MAX_STRING_COLUMN_BYTES);
        let exact_bytes =
            stored_value::value_to_bytes(&serde_json::Value::String(exact_str)).unwrap();
        let mut values = vec![exact_bytes];

        builder.apply_hash_backed_storage(&keys, &mut values, EmptyHashBackedValue::Hash)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod internal_hash_key_change_builder_tests {
    use super::*;
    use crate::transport::Transport;
    use crate::users::{UserStatus, UserWithSecrets};
    use crate::AuthContext;
    use async_trait::async_trait;
    use encrypted_spaces_backend::error::{Result, SdkError};
    use encrypted_spaces_backend::internal_schemas::{
        key_history_schema, retention_schema, users_schema, KEY_HISTORY_COL_OLD_AUTH_KEY,
        KEY_HISTORY_COL_UID, KEY_HISTORY_COL_VALID_FROM, KEY_HISTORY_COL_VALID_TO,
        KEY_HISTORY_TABLE_NAME, USERS_TABLE_NAME,
    };
    use encrypted_spaces_backend::merk_storage::proofs::VerifiedRows;
    use encrypted_spaces_backend::merk_storage::{
        get_row_data_from_query, parse_key, stored_value, ParsedKey,
    };
    use encrypted_spaces_backend::query::{
        ComparisonOperator, Predicate, Query, QueryOperation, QueryParam,
    };
    use encrypted_spaces_backend::schema::Schema;
    use encrypted_spaces_changelog_core::changelog::{ChangeResponse, FastForwardData};
    use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
    use encrypted_spaces_storage_encoding::hashstore_hash;
    use serde_json::json;
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct SelectRowsTransport {
        rows_by_table: HashMap<String, Vec<serde_json::Value>>,
    }

    #[async_trait]
    impl Transport for SelectRowsTransport {
        async fn submit_change(
            &self,
            _change: &Change,
            _retention_proofs: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            Err(SdkError::DatabaseError(
                "submit_change is not used by internal key hash builder tests".into(),
            ))
        }

        async fn fast_forward(&self, _change_id: u32) -> Result<FastForwardData> {
            Err(SdkError::DatabaseError(
                "fast_forward is not used by internal key hash builder tests".into(),
            ))
        }

        async fn select(
            &self,
            query: Query,
            _commitment: &[u8; 32],
            _schemas: &HashMap<String, Schema>,
        ) -> Result<VerifiedRows> {
            Ok(VerifiedRows {
                main_rows: self
                    .rows_by_table
                    .get(&query.table)
                    .cloned()
                    .unwrap_or_default(),
                rows_by_table: HashMap::new(),
            })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        async fn add_member(
            &self,
            _request: InviteRequest,
            _insert_change: &Change,
            _retention_proofs: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            Err(SdkError::DatabaseError(
                "add_member is not used by internal key hash builder tests".into(),
            ))
        }

        async fn remove_member(
            &self,
            _request: RekeyRequest,
            _remaining_uids: &[i64],
            _delete_change: &Change,
            _retention_proofs: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            Err(SdkError::DatabaseError(
                "remove_member is not used by internal key hash builder tests".into(),
            ))
        }

        async fn submit_retention(
            &self,
            _change: &Change,
            _retention_proofs: Vec<Vec<u8>>,
            _rekey_request: Option<RekeyRequest>,
        ) -> Result<ChangeResponse> {
            Err(SdkError::DatabaseError(
                "submit_retention is not used by internal key hash builder tests".into(),
            ))
        }

        async fn authenticate(&self, _auth_context: &AuthContext) -> Result<()> {
            Ok(())
        }

        async fn file_upload(&self, _hash: &str, _data: Vec<u8>) -> Result<()> {
            Ok(())
        }

        async fn file_download(&self, _hash: &str) -> Result<Vec<u8>> {
            Err(SdkError::DatabaseError(
                "file_download is not used by internal key hash builder tests".into(),
            ))
        }
    }

    async fn internal_builder_space(user_ids: &[i64]) -> Result<Arc<Space>> {
        let rows_by_table = HashMap::from([(
            USERS_TABLE_NAME.to_string(),
            user_ids
                .iter()
                .map(|id| json!({ "id": id }))
                .collect::<Vec<_>>(),
        )]);
        let transport = SelectRowsTransport { rows_by_table };
        let space = Space::new_without_schema_init(
            transport,
            crate::testing::initial_internal_data_commitment(),
        )
        .await?;
        let sid = space.id;
        space.with_state_mut(|state| {
            state.auth_context = AuthContext::new(Some(1), sid);
            state.current_change_id = 12;
            state.my_last_change_id = 11;
            state.current_clc_state = crate::state::initial_clc_state(&state.initial_dc);
        });
        space.register_table_schema(users_schema());
        space.register_table_schema(key_history_schema());
        space.register_table_schema(retention_schema());
        Ok(Arc::new(space))
    }

    fn query_text_field<'a>(query: &'a Query, column: &str) -> &'a str {
        let fields = match &query.operation {
            QueryOperation::Insert(fields) | QueryOperation::Update(fields) => fields,
            _ => panic!("expected insert or update query"),
        };
        fields
            .iter()
            .find_map(|(name, param)| {
                if name == column {
                    match param {
                        QueryParam::Text(s) => Some(s.as_str()),
                        other => panic!("{column} should remain QueryParam::Text, got {other:?}"),
                    }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("missing query field {column}"))
    }

    fn serialized_column_bytes(query: &Query, column: &str) -> Result<Vec<u8>> {
        let (_, column_data) = get_row_data_from_query(query)?;
        Ok(column_data
            .into_iter()
            .find_map(|(name, value)| (name == column).then_some(value))
            .unwrap_or_else(|| panic!("missing serialized column {column}")))
    }

    fn entry_value(change: &Change, table_name: &str, column_name: &str) -> Vec<u8> {
        change
            .entry
            .message
            .entries
            .iter()
            .find_map(|entry| match parse_key(&entry.key) {
                Ok(ParsedKey::Column { table, column, .. })
                    if table == table_name && column == column_name =>
                {
                    Some(entry.value.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing entry for {table_name}.{column_name}"))
    }

    fn assert_hash_backed_entry(
        change: &Change,
        table_name: &str,
        column_name: &str,
        full_value: &[u8],
    ) {
        let stored = entry_value(change, table_name, column_name);
        let expected_hash = hashstore_hash(full_value);
        assert_eq!(
            stored.len(),
            32,
            "{table_name}.{column_name} should be stored as a 32-byte hash"
        );
        assert_eq!(stored, expected_hash.to_vec());
        assert_eq!(
            change.hashed_values.get(&expected_hash).map(Vec::as_slice),
            Some(full_value),
            "{table_name}.{column_name} hashed values should carry the full stored bytes"
        );
    }

    fn assert_inline_entry(
        change: &Change,
        table_name: &str,
        column_name: &str,
        expected_value: &[u8],
    ) {
        let stored = entry_value(change, table_name, column_name);
        assert_eq!(
            stored, expected_value,
            "{table_name}.{column_name} should remain inline"
        );
        let unexpected_hash = hashstore_hash(expected_value);
        assert_ne!(
            change
                .hashed_values
                .get(&unexpected_hash)
                .map(Vec::as_slice),
            Some(expected_value),
            "{table_name}.{column_name} should not produce hashed values"
        );
    }

    fn record_key_strings(user: &UserWithSecrets) -> (String, String) {
        let record_json = serde_json::to_value(user.as_record()).expect("serialize user record");
        let update_key = record_json["update_key"]
            .as_str()
            .expect("update_key is base64 text")
            .to_string();
        let auth_key = record_json["auth_key"]
            .as_str()
            .expect("auth_key is base64 text")
            .to_string();
        (update_key, auth_key)
    }

    fn key_history_data(uid: i64, old_auth_key: String) -> Vec<(String, QueryParam)> {
        vec![
            (KEY_HISTORY_COL_UID.to_string(), QueryParam::Integer(uid)),
            (
                KEY_HISTORY_COL_OLD_AUTH_KEY.to_string(),
                QueryParam::Text(old_auth_key),
            ),
            (
                KEY_HISTORY_COL_VALID_FROM.to_string(),
                QueryParam::Integer(0),
            ),
            (
                KEY_HISTORY_COL_VALID_TO.to_string(),
                QueryParam::Integer(11),
            ),
        ]
    }

    fn key_history_query(data: &[(String, QueryParam)]) -> Query {
        Query::new(
            KEY_HISTORY_TABLE_NAME.to_string(),
            QueryOperation::Insert(data.to_vec()),
        )
    }

    fn users_update_query(uid: i64, update_key: String, auth_key: String) -> Query {
        let mut query = Query::new(
            USERS_TABLE_NAME.to_string(),
            QueryOperation::Update(vec![
                ("update_key".to_string(), QueryParam::Text(update_key)),
                ("auth_key".to_string(), QueryParam::Text(auth_key)),
                (
                    "status".to_string(),
                    QueryParam::Integer(UserStatus::Full as i64),
                ),
            ]),
        );
        query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(uid)],
            cursor_id: None,
        });
        query
    }

    fn users_delete_query(uid: i64) -> Query {
        let mut query = Query::new(USERS_TABLE_NAME.to_string(), QueryOperation::Delete);
        query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(uid)],
            cursor_id: None,
        });
        query
    }

    #[tokio::test]
    async fn internal_hash_key_change_builder_hashes_key_management_entries() -> Result<()> {
        let space = internal_builder_space(&[1, 2]).await?;

        let mut creator = UserWithSecrets::new();
        creator.id = Some(1);
        let mut creator_record = creator.as_record();
        creator_record.id = None;
        let mut create_insert = space.users().insert(&creator_record);
        let create_auth_text = query_text_field(&create_insert.query, "auth_key").to_string();
        let create_update_text = query_text_field(&create_insert.query, "update_key").to_string();
        let create_auth_bytes = serialized_column_bytes(&create_insert.query, "auth_key")?;
        let create_update_bytes = serialized_column_bytes(&create_insert.query, "update_key")?;
        let create_status_bytes = serialized_column_bytes(&create_insert.query, "status")?;
        assert_eq!(
            stored_value::bytes_to_value(&create_auth_bytes)?,
            serde_json::Value::String(create_auth_text)
        );
        assert_eq!(
            stored_value::bytes_to_value(&create_update_bytes)?,
            serde_json::Value::String(create_update_text)
        );

        let create_change = ChangeBuilder::new(&mut create_insert.query, Arc::clone(&space))
            .build_create_space(&[])
            .await?;
        assert_eq!(create_change.entry.message.op_type, OpType::CreateSpace);
        assert_hash_backed_entry(
            &create_change,
            USERS_TABLE_NAME,
            "auth_key",
            &create_auth_bytes,
        );
        assert_hash_backed_entry(
            &create_change,
            USERS_TABLE_NAME,
            "update_key",
            &create_update_bytes,
        );
        assert_inline_entry(
            &create_change,
            USERS_TABLE_NAME,
            "status",
            &create_status_bytes,
        );

        let invitee = UserWithSecrets::provisional();
        let invitee_record = invitee.as_record();
        let mut invite_insert = space.users().insert(&invitee_record);
        query_text_field(&invite_insert.query, "auth_key");
        query_text_field(&invite_insert.query, "update_key");
        let invite_auth_bytes = serialized_column_bytes(&invite_insert.query, "auth_key")?;
        let invite_update_bytes = serialized_column_bytes(&invite_insert.query, "update_key")?;
        let invite_status_bytes = serialized_column_bytes(&invite_insert.query, "status")?;
        let invite_change = ChangeBuilder::new(&mut invite_insert.query, Arc::clone(&space))
            .build_invite_user(&[])
            .await?;
        assert_eq!(invite_change.entry.message.op_type, OpType::InviteUser);
        assert_hash_backed_entry(
            &invite_change,
            USERS_TABLE_NAME,
            "auth_key",
            &invite_auth_bytes,
        );
        assert_hash_backed_entry(
            &invite_change,
            USERS_TABLE_NAME,
            "update_key",
            &invite_update_bytes,
        );
        assert_inline_entry(
            &invite_change,
            USERS_TABLE_NAME,
            "status",
            &invite_status_bytes,
        );

        let fresh_user = UserWithSecrets::new();
        let old_user = UserWithSecrets::new();
        let (fresh_update_key, fresh_auth_key) = record_key_strings(&fresh_user);
        let (_, old_auth_key) = record_key_strings(&old_user);
        let mut refresh_query = users_update_query(1, fresh_update_key, fresh_auth_key);
        query_text_field(&refresh_query, "auth_key");
        query_text_field(&refresh_query, "update_key");
        let refresh_auth_bytes = serialized_column_bytes(&refresh_query, "auth_key")?;
        let refresh_update_bytes = serialized_column_bytes(&refresh_query, "update_key")?;
        let refresh_status_bytes = serialized_column_bytes(&refresh_query, "status")?;
        let refresh_kh_data = key_history_data(1, old_auth_key);
        let refresh_kh_query = key_history_query(&refresh_kh_data);
        let refresh_old_auth_bytes =
            serialized_column_bytes(&refresh_kh_query, KEY_HISTORY_COL_OLD_AUTH_KEY)?;
        let refresh_uid_bytes = serialized_column_bytes(&refresh_kh_query, KEY_HISTORY_COL_UID)?;
        let refresh_change = ChangeBuilder::new(&mut refresh_query, Arc::clone(&space))
            .build_refresh_keys(&refresh_kh_data)
            .await?
            .expect("refresh keys should match seeded user");
        assert_eq!(refresh_change.entry.message.op_type, OpType::RefreshKeys);
        assert_hash_backed_entry(
            &refresh_change,
            USERS_TABLE_NAME,
            "auth_key",
            &refresh_auth_bytes,
        );
        assert_hash_backed_entry(
            &refresh_change,
            USERS_TABLE_NAME,
            "update_key",
            &refresh_update_bytes,
        );
        assert_hash_backed_entry(
            &refresh_change,
            KEY_HISTORY_TABLE_NAME,
            KEY_HISTORY_COL_OLD_AUTH_KEY,
            &refresh_old_auth_bytes,
        );
        assert_inline_entry(
            &refresh_change,
            USERS_TABLE_NAME,
            "status",
            &refresh_status_bytes,
        );
        assert_inline_entry(
            &refresh_change,
            KEY_HISTORY_TABLE_NAME,
            KEY_HISTORY_COL_UID,
            &refresh_uid_bytes,
        );

        let removed_user = UserWithSecrets::new();
        let (_, removed_old_auth_key) = record_key_strings(&removed_user);
        let remove_kh_data = key_history_data(2, removed_old_auth_key);
        let remove_kh_query = key_history_query(&remove_kh_data);
        let remove_old_auth_bytes =
            serialized_column_bytes(&remove_kh_query, KEY_HISTORY_COL_OLD_AUTH_KEY)?;
        let remove_uid_bytes = serialized_column_bytes(&remove_kh_query, KEY_HISTORY_COL_UID)?;
        let mut remove_query = users_delete_query(2);
        let remove_change = ChangeBuilder::new(&mut remove_query, Arc::clone(&space))
            .build_remove_user(&remove_kh_data, &[])
            .await?
            .expect("remove user should match seeded user");
        assert_eq!(remove_change.entry.message.op_type, OpType::RemoveUser);
        assert_hash_backed_entry(
            &remove_change,
            KEY_HISTORY_TABLE_NAME,
            KEY_HISTORY_COL_OLD_AUTH_KEY,
            &remove_old_auth_bytes,
        );
        assert_inline_entry(
            &remove_change,
            KEY_HISTORY_TABLE_NAME,
            KEY_HISTORY_COL_UID,
            &remove_uid_bytes,
        );
        assert_eq!(
            entry_value(&remove_change, USERS_TABLE_NAME, "status"),
            Vec::<u8>::new(),
            "_users.status delete should remain an inline empty value"
        );
        assert_eq!(
            entry_value(&remove_change, USERS_TABLE_NAME, "auth_key"),
            Vec::<u8>::new(),
            "_users.auth_key delete should not carry full key bytes"
        );

        Ok(())
    }

    #[tokio::test]
    async fn key_hash_change_builder_deduplicates_internal_key_material() -> Result<()> {
        let space = internal_builder_space(&[1]).await?;
        let fresh_user = UserWithSecrets::new();
        let (fresh_update_key, duplicate_auth_key) = record_key_strings(&fresh_user);

        let mut refresh_query = users_update_query(1, fresh_update_key, duplicate_auth_key.clone());
        let auth_bytes = serialized_column_bytes(&refresh_query, "auth_key")?;
        let key_history_data = key_history_data(1, duplicate_auth_key);
        let kh_query = key_history_query(&key_history_data);
        let old_auth_bytes = serialized_column_bytes(&kh_query, KEY_HISTORY_COL_OLD_AUTH_KEY)?;
        assert_eq!(
            auth_bytes, old_auth_bytes,
            "test setup should use identical stored bytes for duplicate material"
        );

        let change = ChangeBuilder::new(&mut refresh_query, Arc::clone(&space))
            .build_refresh_keys(&key_history_data)
            .await?
            .expect("refresh keys should match seeded user");
        let auth_hash = hashstore_hash(&auth_bytes);
        assert_eq!(
            entry_value(&change, USERS_TABLE_NAME, "auth_key"),
            auth_hash.to_vec()
        );
        assert_eq!(
            entry_value(
                &change,
                KEY_HISTORY_TABLE_NAME,
                KEY_HISTORY_COL_OLD_AUTH_KEY
            ),
            auth_hash.to_vec()
        );

        // A map holds one entry per hash, so identical internal key material is
        // inherently emitted once.
        assert_eq!(
            change.hashed_values.get(&auth_hash).map(Vec::as_slice),
            Some(auth_bytes.as_slice()),
            "identical internal key material should be emitted once"
        );

        Ok(())
    }

    #[tokio::test]
    async fn key_hash_signature_resolution_create_space_uses_hashed_values() -> Result<()> {
        let space = internal_builder_space(&[]).await?;
        let signer_vk = {
            let km = space.key_manager.lock().await;
            *km.auth_key_pair().verification_key()
        };

        let mut record = UserWithSecrets::new().as_record();
        record.id = None;
        record.auth_key = signer_vk;
        let mut insert = space.users().insert(&record);
        let auth_bytes = serialized_column_bytes(&insert.query, "auth_key")?;

        let change = ChangeBuilder::new(&mut insert.query, Arc::clone(&space))
            .build_create_space(&[])
            .await?;
        assert_hash_backed_entry(&change, USERS_TABLE_NAME, "auth_key", &auth_bytes);

        let outcome = space
            .try_verify_change_signature(&change.entry, 1, &change.hashed_values)
            .await;
        if !matches!(outcome, SigVerifyOutcome::Verified) {
            panic!(
                "CreateSpace signature should verify from HashedValues: {}",
                outcome.into_err()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn key_hash_signature_resolution_create_space_missing_material_rejects() -> Result<()> {
        let space = internal_builder_space(&[]).await?;
        let signer_vk = {
            let km = space.key_manager.lock().await;
            *km.auth_key_pair().verification_key()
        };

        let mut record = UserWithSecrets::new().as_record();
        record.id = None;
        record.auth_key = signer_vk;
        let mut insert = space.users().insert(&record);

        let change = ChangeBuilder::new(&mut insert.query, Arc::clone(&space))
            .build_create_space(&[])
            .await?;

        match space
            .try_verify_change_signature(&change.entry, 1, &HashedValues::new())
            .await
        {
            SigVerifyOutcome::SignatureInvalid(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("missing hashed value"),
                    "unexpected error: {msg}"
                );
            }
            SigVerifyOutcome::Verified => {
                panic!("CreateSpace signature unexpectedly verified without HashedValues")
            }
            SigVerifyOutcome::KeyResolutionFailed(e) => {
                panic!("CreateSpace should fail closed without key resolution retry: {e}")
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod hash_store_tests {
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use crate::Space;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
    use encrypted_spaces_backend_server::SpaceState;
    use encrypted_spaces_storage_encoding::hashstore_hash;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Note {
        id: Option<i64>,
        content: String,
        title: String,
    }

    async fn create_hash_backed_space() -> Result<(LocalTransport, Space)> {
        let schema = SchemaBuilder::new("notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)?
            .column("title", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema], root),
        )
        .await?;
        Ok((transport, space))
    }

    #[tokio::test]
    async fn hash_store_insert_populates_server_store() -> Result<()> {
        let (transport, space) = create_hash_backed_space().await?;
        let notes = space.table::<Note>("notes");

        notes
            .insert(&Note {
                id: None,
                content: "large body text".into(),
                title: "my title".into(),
            })
            .execute()
            .await?;

        assert!(
            transport.hash_store_len().await > 0,
            "hash store should contain entries after hash-backed insert"
        );

        Ok(())
    }

    #[tokio::test]
    async fn hash_store_each_encrypted_insert_adds_entry() -> Result<()> {
        let (transport, space) = create_hash_backed_space().await?;
        let notes = space.table::<Note>("notes");

        let baseline = transport.hash_store_len().await;

        notes
            .insert(&Note {
                id: None,
                content: "first content".into(),
                title: "first".into(),
            })
            .execute()
            .await?;

        assert_eq!(transport.hash_store_len().await, baseline + 1);

        notes
            .insert(&Note {
                id: None,
                content: "second content".into(),
                title: "second".into(),
            })
            .execute()
            .await?;

        assert_eq!(
            transport.hash_store_len().await,
            baseline + 2,
            "each unique hash-backed value should add one hash store entry"
        );

        Ok(())
    }

    #[tokio::test]
    async fn hash_store_insert_empty_text_round_trips() -> Result<()> {
        let (transport, space) = create_hash_backed_space().await?;
        let notes = space.table::<Note>("notes");
        let baseline = transport.hash_store_len().await;

        notes
            .insert(&Note {
                id: None,
                content: String::new(),
                title: "empty content".into(),
            })
            .execute()
            .await?;

        assert_eq!(
            transport.hash_store_len().await,
            baseline + 1,
            "empty hash-backed text should still add one hash store entry"
        );

        let rows: Vec<Note> = notes.select().all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content, "");
        assert_eq!(rows[0].title, "empty content");

        Ok(())
    }

    #[tokio::test]
    async fn hash_store_response_includes_hashed_values() -> Result<()> {
        let (_transport, space) = create_hash_backed_space().await?;

        let mut query = Query::new(
            "notes".to_string(),
            QueryOperation::Insert(vec![
                (
                    "content".to_string(),
                    QueryParam::Text("response material test".to_string()),
                ),
                ("title".to_string(), QueryParam::Text("title".to_string())),
            ]),
        );
        crate::crypto::encrypt_query_fields(&mut query, &space).await?;

        let change = super::ChangeBuilder::new(&mut query, std::sync::Arc::new(space.clone()))
            .build()
            .await?
            .expect("insert change");

        let response = space.transport.submit_change(&change, vec![]).await?;

        assert!(
            !response.hashed_values.is_empty(),
            "response should include hashed values for hash-backed columns"
        );

        let (hash, value) = response.hashed_values.iter().next().unwrap();
        assert_eq!(*hash, hashstore_hash(value));

        Ok(())
    }

    #[tokio::test]
    async fn hash_store_inline_columns_have_no_hashed_values() -> Result<()> {
        let schema = SchemaBuilder::new("plain_notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("body", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema], root),
        )
        .await?;

        #[derive(Debug, Serialize, Deserialize)]
        struct PlainNote {
            id: Option<i64>,
            body: String,
        }

        let notes = space.table::<PlainNote>("plain_notes");
        let baseline = transport.hash_store_len().await;

        notes
            .insert(&PlainNote {
                id: None,
                body: "inline data".into(),
            })
            .execute()
            .await?;

        assert_eq!(
            transport.hash_store_len().await,
            baseline,
            "inline-only insert should not add hash store entries"
        );

        Ok(())
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod broadcast_cache_tests {
    use crate::cache::new_row_id_for_table;
    use crate::list::List;
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use crate::Space;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
    use encrypted_spaces_backend_server::SpaceState;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    #[tokio::test]
    async fn broadcast_insert_with_list_column_caches_committed_list_number() -> Result<()> {
        use crate::changelog::ChangeBuilder;
        use crate::crypto::encrypt_query_fields;

        #[derive(Debug, Serialize, Deserialize)]
        struct Row {
            id: Option<i64>,
            category: i64,
            items: List<String>,
        }

        let schema = SchemaBuilder::new("parent_table")
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

        // Insert a first row normally (advances server state to change_id 2).
        let first_id = space
            .table::<Row>("parent_table")
            .insert(&Row {
                id: None,
                category: 7,
                items: List::empty(),
            })
            .execute()
            .await?;

        // Populate cache with a where_eq query so the first row is cached.
        let _: Vec<Row> = space
            .table::<Row>("parent_table")
            .select()
            .where_eq("category", 7)
            .all()
            .await?;

        // Build a second insert manually: construct the query, build the
        // changelog entry, submit to the transport, and validate+apply the
        // proof (advancing the DC) — but skip the InsertBuilder cache update
        // so we can test apply_broadcast_cache_updates separately.
        let mut insert_query = Query::new(
            "parent_table".to_string(),
            QueryOperation::Insert(vec![
                ("category".to_string(), QueryParam::Integer(42)),
                ("items".to_string(), QueryParam::Integer(0)),
            ]),
        );
        encrypt_query_fields(&mut insert_query, &space).await?;
        let change = ChangeBuilder::new(&mut insert_query, Arc::new(space.clone()))
            .build()
            .await?
            .unwrap();
        let change_response = space.transport.submit_change(&change, vec![]).await?;
        let writes = space.validate_and_apply_change(&change.entry, &change_response)?;
        let new_id = new_row_id_for_table(&space, &writes, "parent_table").unwrap();

        // At this point the cache still has row 1 from the normal insert.
        // validate_and_apply_change only advances the DC, not the cache.
        let cached_ids = space.with_state(|state| state.cache.row_ids("parent_table"));
        assert!(
            cached_ids.contains(&first_id),
            "first row should still be in cache after validate_and_apply_change"
        );

        // Apply the broadcast insert using the real proof.
        space.apply_broadcast_cache_updates(&change, &writes).await;

        // The broadcast-inserted row must be cached with a real list_number.
        let cached_list_number = space.with_state(|state| {
            state
                .cache
                .get_row("parent_table", new_id)
                .and_then(|row| row.get("items"))
                .and_then(|v| v.as_i64())
        });
        assert!(
            cached_list_number.is_some_and(|n| n > 0),
            "broadcast-inserted row must have committed list_number, got {cached_list_number:?}"
        );

        // The unrelated row must survive.
        let cached_ids = space.with_state(|state| state.cache.row_ids("parent_table"));
        assert!(
            cached_ids.contains(&first_id),
            "unrelated cached row must survive broadcast insert"
        );
        assert!(
            cached_ids.contains(&new_id),
            "broadcast-inserted row must be cached"
        );

        Ok(())
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod hash_backed_broadcast_tests {
    use crate::cache::new_row_id_for_table;
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, Schema, SchemaBuilder};
    use crate::Space;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend::merk_storage::proofs::extract_query_proof_entries_for_response_material;
    use encrypted_spaces_backend::merk_storage::{parse_key, stored_value, ParsedKey};
    use encrypted_spaces_backend::proto::{self, db_response, ws_frame};
    use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
    use encrypted_spaces_backend_server::SpaceState;
    use encrypted_spaces_changelog_core::changelog::Change;
    use encrypted_spaces_storage_encoding::{hashstore_hash, HASH_LEN};
    use prost::Message;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    #[derive(Debug, Deserialize, Serialize)]
    struct BroadcastNote {
        id: Option<i64>,
        content: String,
        title: String,
    }

    async fn hash_backed_broadcast_space(
    ) -> std::result::Result<(LocalTransport, Space, Schema), Box<dyn std::error::Error>> {
        let schema = SchemaBuilder::new("broadcast_notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)?
            .column("title", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema.clone()], root),
        )
        .await?;
        Ok((transport, space, schema))
    }

    async fn plaintext_hash_backed_broadcast_space(
    ) -> std::result::Result<(LocalTransport, Space, Schema), Box<dyn std::error::Error>> {
        let schema = SchemaBuilder::new("plaintext_hash_notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)?
            .plaintext()
            .column("title", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema.clone()], root),
        )
        .await?;
        Ok((transport, space, schema))
    }

    #[tokio::test]
    async fn plaintext_hash_backed_round_trips_cache_and_broadcast_material() -> Result<()> {
        let (_transport, space, _schema) = plaintext_hash_backed_broadcast_space().await.unwrap();
        let notes = space.table::<BroadcastNote>("plaintext_hash_notes");
        let content = "plain hash-backed body".to_string();
        let title = "plain title".to_string();

        let row_id = notes
            .insert(&BroadcastNote {
                id: None,
                content: content.clone(),
                title: title.clone(),
            })
            .execute()
            .await?;

        let rows: Vec<BroadcastNote> = notes.select().all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content, content);
        assert_eq!(rows[0].title, title);

        let cached = space
            .with_state(|state| state.cache.get_row("plaintext_hash_notes", row_id).cloned())
            .expect("select should cache the plaintext hash-backed row");
        assert_eq!(cached["content"], content);
        assert_eq!(cached["title"], title);

        let broadcast_content = "plain broadcast hash-backed body".to_string();
        let expected_value =
            stored_value::value_to_bytes(&serde_json::Value::String(broadcast_content.clone()))?;
        let expected_hash = hashstore_hash(&expected_value);
        let mut insert_query = Query::new(
            "plaintext_hash_notes".to_string(),
            QueryOperation::Insert(vec![
                (
                    "content".to_string(),
                    QueryParam::Text(broadcast_content.clone()),
                ),
                (
                    "title".to_string(),
                    QueryParam::Text("plain broadcast title".to_string()),
                ),
            ]),
        );
        crate::crypto::encrypt_query_fields(&mut insert_query, &space).await?;
        let change = super::ChangeBuilder::new(&mut insert_query, Arc::new(space.clone()))
            .build()
            .await?
            .unwrap();

        assert_eq!(
            change.hashed_values.get(&expected_hash).map(Vec::as_slice),
            Some(expected_value.as_slice())
        );

        let change_response = space.transport.submit_change(&change, vec![]).await?;
        assert_eq!(
            change_response
                .hashed_values
                .get(&expected_hash)
                .map(Vec::as_slice),
            Some(expected_value.as_slice())
        );

        let writes = space.validate_and_apply_change(&change.entry, &change_response)?;
        let remote_change = Change {
            entry: change.entry.clone(),
            hashed_values: change_response.hashed_values.clone(),
        };
        space
            .apply_broadcast_cache_updates(&remote_change, &writes)
            .await;

        let new_id = new_row_id_for_table(&space, &writes, "plaintext_hash_notes").unwrap();
        let broadcast_cached = space
            .with_state(|state| state.cache.get_row("plaintext_hash_notes", new_id).cloned())
            .expect("broadcast cache update should use hashed values");
        assert_eq!(broadcast_cached["content"], broadcast_content);

        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_broadcast_applies_full_values_to_cache() -> Result<()> {
        let (_transport, space, _schema) = hash_backed_broadcast_space().await.unwrap();
        let notes = space.table::<BroadcastNote>("broadcast_notes");

        // Insert a first row to initialise the cache table.
        notes
            .insert(&BroadcastNote {
                id: None,
                content: "seed content".to_string(),
                title: "seed title".to_string(),
            })
            .execute()
            .await?;
        let _: Vec<BroadcastNote> = notes.select().all().await?;

        // Build a second insert manually so we can test broadcast cache
        // update independently of the InsertBuilder cache path.
        let mut insert_query = Query::new(
            "broadcast_notes".to_string(),
            QueryOperation::Insert(vec![
                (
                    "content".to_string(),
                    QueryParam::Text("broadcast hash-backed body".to_string()),
                ),
                (
                    "title".to_string(),
                    QueryParam::Text("broadcast title".to_string()),
                ),
            ]),
        );
        crate::crypto::encrypt_query_fields(&mut insert_query, &space).await?;
        let change = super::ChangeBuilder::new(&mut insert_query, Arc::new(space.clone()))
            .build()
            .await?
            .unwrap();

        assert!(
            !change.hashed_values.is_empty(),
            "change should carry hashed values for hash-backed columns"
        );

        let change_response = space.transport.submit_change(&change, vec![]).await?;
        let writes = space.validate_and_apply_change(&change.entry, &change_response)?;
        let new_id = new_row_id_for_table(&space, &writes, "broadcast_notes").unwrap();

        space.apply_broadcast_cache_updates(&change, &writes).await;

        let cached =
            space.with_state(|state| state.cache.get_row("broadcast_notes", new_id).cloned());
        let cached = cached.expect("broadcast cache update should populate row");
        assert_eq!(
            cached["title"], "broadcast title",
            "inline column should be cached correctly"
        );
        assert_eq!(
            cached["content"], "broadcast hash-backed body",
            "hash-backed column should be resolved to full value in cache"
        );

        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_broadcast_response_material_resolves_remote_values() -> Result<()> {
        let (_transport, space, _schema) = hash_backed_broadcast_space().await.unwrap();
        let notes = space.table::<BroadcastNote>("broadcast_notes");

        // Seed the cache table.
        notes
            .insert(&BroadcastNote {
                id: None,
                content: "seed".to_string(),
                title: "seed".to_string(),
            })
            .execute()
            .await?;
        let _: Vec<BroadcastNote> = notes.select().all().await?;

        let mut insert_query = Query::new(
            "broadcast_notes".to_string(),
            QueryOperation::Insert(vec![
                (
                    "content".to_string(),
                    QueryParam::Text("remote broadcast content".to_string()),
                ),
                (
                    "title".to_string(),
                    QueryParam::Text("remote title".to_string()),
                ),
            ]),
        );
        crate::crypto::encrypt_query_fields(&mut insert_query, &space).await?;
        let change = super::ChangeBuilder::new(&mut insert_query, Arc::new(space.clone()))
            .build()
            .await?
            .unwrap();

        let change_response = space.transport.submit_change(&change, vec![]).await?;

        assert!(
            !change_response.hashed_values.is_empty(),
            "server response should include hashed values"
        );

        let writes = space.validate_and_apply_change(&change.entry, &change_response)?;

        // Build a Change as a remote client would receive via broadcast:
        // the Change's hashed_values comes from the ChangeResponse.
        let remote_change = Change {
            entry: change.entry.clone(),
            hashed_values: change_response.hashed_values.clone(),
        };

        space
            .apply_broadcast_cache_updates(&remote_change, &writes)
            .await;

        let new_id = new_row_id_for_table(&space, &writes, "broadcast_notes").unwrap();
        let cached = space
            .with_state(|state| state.cache.get_row("broadcast_notes", new_id).cloned())
            .expect("broadcast should populate cache");

        assert_eq!(cached["content"], "remote broadcast content");
        assert_eq!(cached["title"], "remote title");

        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_broadcast_direct_submitter_caches_full_values() -> Result<()> {
        let (_transport, space, _schema) = hash_backed_broadcast_space().await.unwrap();
        let notes = space.table::<BroadcastNote>("broadcast_notes");

        // Seed the cache table so insert_row has somewhere to land.
        let _: Vec<BroadcastNote> = notes.select().all().await?;

        let row_id = notes
            .insert(&BroadcastNote {
                id: None,
                content: "submitter content".to_string(),
                title: "submitter title".to_string(),
            })
            .execute()
            .await?;

        let cached =
            space.with_state(|state| state.cache.get_row("broadcast_notes", row_id).cloned());
        let cached = cached.expect("direct insert should populate cache");
        assert_eq!(
            cached["content"], "submitter content",
            "direct submitter cache should have full hash-backed value"
        );
        assert_eq!(cached["title"], "submitter title");

        Ok(())
    }

    #[derive(Debug)]
    struct PayloadSizes {
        direct_response_frame: usize,
        broadcast_frame: usize,
        select_response_frame: usize,
        pruned_tree: usize,
        select_proof: usize,
        response_hashed_values_bytes: usize,
        select_hashed_values_bytes: usize,
    }

    async fn measure_payload_sizes(
        table: &str,
        content_type: ColumnType,
        content: String,
    ) -> std::result::Result<PayloadSizes, Box<dyn std::error::Error>> {
        let schema = SchemaBuilder::new(table)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", content_type)?
            .column("title", ColumnType::String)?
            .plaintext()
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing(vec![schema.clone()], root),
        )
        .await?;

        let mut insert_query = Query::new(
            table.to_string(),
            QueryOperation::Insert(vec![
                ("content".to_string(), QueryParam::Text(content)),
                (
                    "title".to_string(),
                    QueryParam::Text("inline title".to_string()),
                ),
            ]),
        );
        crate::crypto::encrypt_query_fields(&mut insert_query, &space).await?;
        let change = super::ChangeBuilder::new(&mut insert_query, Arc::new(space.clone()))
            .build()
            .await?
            .expect("insert should build a change");

        let change_response = space.transport.submit_change(&change, vec![]).await?;
        let _writes = space.validate_and_apply_change(&change.entry, &change_response)?;

        let proto_change_response = proto::ChangeResponse::from(&change_response);
        let direct_response = proto::WsFrame {
            payload: Some(ws_frame::Payload::DbResponse(proto::DbResponse {
                request_id: "measure".to_string(),
                status: "ok".to_string(),
                error: String::new(),
                result: Some(db_response::Result::Change(proto_change_response.clone())),
            })),
        }
        .encode_to_vec()
        .len();
        let broadcast = proto::WsFrame {
            payload: Some(ws_frame::Payload::Broadcast(proto::Broadcast {
                change_response: Some(proto_change_response),
                change_entry: Some((&change.entry).into()),
            })),
        }
        .encode_to_vec()
        .len();

        let select_query = Query::new(table.to_string(), QueryOperation::Select(Vec::new()));
        let commitment = space.current_data_commitment();
        let select_proof = transport.select_proof_bytes(&select_query).await?;
        let mut select_hashed_values: Vec<Vec<u8>> = Vec::new();
        let response_hashed_values_bytes: usize =
            change_response.hashed_values.values().map(Vec::len).sum();

        let entries = extract_query_proof_entries_for_response_material(
            &select_query,
            &select_proof,
            &commitment,
        )?;
        for (key, value) in entries {
            let is_content = matches!(
                parse_key(&key),
                Ok(ParsedKey::Column { column, .. })
                    if column == "content"
            );
            if !is_content || value.len() != HASH_LEN {
                continue;
            }
            let hash: [u8; HASH_LEN] = value.as_slice().try_into()?;
            if let Some(full_value) = transport.hash_store_get(&hash).await {
                select_hashed_values.push(full_value);
            }
        }
        let select_hashed_values_bytes: usize = select_hashed_values.iter().map(Vec::len).sum();
        let select_response = proto::WsFrame {
            payload: Some(ws_frame::Payload::DbResponse(proto::DbResponse {
                request_id: "measure".to_string(),
                status: "ok".to_string(),
                error: String::new(),
                result: Some(db_response::Result::Select(proto::SelectResponse {
                    proof: select_proof.clone(),
                    values_sidecar: select_hashed_values.clone(),
                })),
            })),
        }
        .encode_to_vec()
        .len();

        Ok(PayloadSizes {
            direct_response_frame: direct_response,
            broadcast_frame: broadcast,
            select_response_frame: select_response,
            pruned_tree: change_response.pruned_merkle_tree.len(),
            select_proof: select_proof.len(),
            response_hashed_values_bytes,
            select_hashed_values_bytes,
        })
    }

    #[tokio::test]
    #[ignore = "measurement helper: compares legacy large inline String against Text"]
    async fn hash_backed_payload_size_large_values(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let content = "x".repeat(4096);
        let inline =
            measure_payload_sizes("inline_payload_notes", ColumnType::String, content.clone())
                .await?;
        let hash_backed =
            measure_payload_sizes("hash_payload_notes", ColumnType::Text, content).await?;

        println!(
            "payload_size inline direct={} broadcast={} select={} pruned_tree={} select_proof={} response_material={} select_material={}",
            inline.direct_response_frame,
            inline.broadcast_frame,
            inline.select_response_frame,
            inline.pruned_tree,
            inline.select_proof,
            inline.response_hashed_values_bytes,
            inline.select_hashed_values_bytes,
        );
        println!(
            "payload_size hash_backed direct={} broadcast={} select={} pruned_tree={} select_proof={} response_material={} select_material={}",
            hash_backed.direct_response_frame,
            hash_backed.broadcast_frame,
            hash_backed.select_response_frame,
            hash_backed.pruned_tree,
            hash_backed.select_proof,
            hash_backed.response_hashed_values_bytes,
            hash_backed.select_hashed_values_bytes,
        );

        assert!(hash_backed.select_proof < inline.select_proof);
        assert!(hash_backed.response_hashed_values_bytes > 0);
        assert!(hash_backed.select_hashed_values_bytes > 0);

        Ok(())
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod hash_backed_fast_forward_tests {
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, Schema, SchemaBuilder};
    use crate::transport::Transport;
    use crate::Space;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend_server::SpaceState;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    struct FfNote {
        id: Option<i64>,
        content: String,
        title: String,
    }

    fn hash_backed_ff_schema() -> Schema {
        SchemaBuilder::new("ff_notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("content", ColumnType::Text)
            .unwrap()
            .column("title", ColumnType::String)
            .unwrap()
            .plaintext()
            .build()
            .unwrap()
    }

    fn hash_backed_ff_app_schema(schema: Schema, root: [u8; 32]) -> ApplicationSchema {
        ApplicationSchema::for_testing(vec![schema], root)
    }

    #[tokio::test]
    async fn hash_backed_fast_forward_resolves_values_after_recovery() -> Result<()> {
        let schema = hash_backed_ff_schema();
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await
        .unwrap();
        let root = transport.get_root_hash().await?;
        let alice = Space::create(
            transport.clone(),
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let invite = alice.invite_user().await?;
        let bob = Space::join(
            transport.clone(),
            invite,
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let alice_notes = alice.table::<FfNote>("ff_notes");
        alice_notes
            .insert(&FfNote {
                id: None,
                content: "ff hash-backed content".to_string(),
                title: "ff title".to_string(),
            })
            .execute()
            .await?;

        bob.recover_via_fast_forward().await?;

        let bob_notes = bob.table::<FfNote>("ff_notes");
        let rows: Vec<FfNote> = bob_notes.select().all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].content, "ff hash-backed content",
            "hash-backed column should be resolved to full value after FF"
        );
        assert_eq!(rows[0].title, "ff title");

        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_fast_forward_multiple_inserts() -> Result<()> {
        let schema = hash_backed_ff_schema();
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await
        .unwrap();
        let root = transport.get_root_hash().await?;
        let alice = Space::create(
            transport.clone(),
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let invite = alice.invite_user().await?;
        let bob = Space::join(
            transport.clone(),
            invite,
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let alice_notes = alice.table::<FfNote>("ff_notes");
        for i in 0..3 {
            alice_notes
                .insert(&FfNote {
                    id: None,
                    content: format!("content {i}"),
                    title: format!("title {i}"),
                })
                .execute()
                .await?;
        }

        bob.recover_via_fast_forward().await?;

        let bob_notes = bob.table::<FfNote>("ff_notes");
        let mut rows: Vec<FfNote> = bob_notes.select().all().await?;
        rows.sort_by_key(|r| r.id);
        assert_eq!(rows.len(), 3);
        for (i, row) in rows.iter().enumerate().take(3) {
            assert_eq!(row.content, format!("content {i}"));
            assert_eq!(row.title, format!("title {i}"));
        }

        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_fast_forward_ragged_changes_carry_material() -> Result<()> {
        let schema = hash_backed_ff_schema();
        // Use a very large batch size so no FF proof is generated; all
        // changes will be delivered as ragged.
        let transport = LocalTransport::new(std::slice::from_ref(&schema), None, Some(1000))
            .await
            .unwrap();
        let root = transport.get_root_hash().await?;
        let alice = Space::create(
            transport.clone(),
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let invite = alice.invite_user().await?;
        let bob = Space::join(
            transport.clone(),
            invite,
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let alice_notes = alice.table::<FfNote>("ff_notes");
        alice_notes
            .insert(&FfNote {
                id: None,
                content: "ragged content".to_string(),
                title: "ragged title".to_string(),
            })
            .execute()
            .await?;

        let ff_data = transport.fast_forward(bob.current_change_id()).await?;
        assert!(
            !ff_data.responses.is_empty(),
            "FF should have ragged changes"
        );
        let has_material = ff_data
            .responses
            .iter()
            .any(|r| !r.hashed_values.is_empty());
        assert!(
            has_material,
            "ragged change responses should carry hashed values"
        );

        bob.recover_via_fast_forward().await?;

        // Verify cache is populated directly from ragged FF — no select
        // needed. The `_users` table is re-warmed by `initialize_users`
        // inside FF recovery, which triggers a select on internal tables.
        // For app tables the ragged cache update should have landed the
        // row. Look for the row by iterating all cached rows.
        let cached_content = bob.with_state(|state| {
            state.cache.row_ids("ff_notes").into_iter().find_map(|id| {
                state
                    .cache
                    .get_row("ff_notes", id)
                    .and_then(|r| r.get("content").cloned())
            })
        });
        assert_eq!(
            cached_content.as_ref().and_then(|v| v.as_str()),
            Some("ragged content"),
            "ragged FF should populate cache with full hash-backed value before any select"
        );

        let bob_notes = bob.table::<FfNote>("ff_notes");
        let rows: Vec<FfNote> = bob_notes.select().all().await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content, "ragged content");
        assert_eq!(rows[0].title, "ragged title");

        Ok(())
    }

    #[tokio::test]
    async fn hash_backed_fast_forward_ragged_populates_cache_before_select() -> Result<()> {
        let schema = hash_backed_ff_schema();
        let transport = LocalTransport::new(std::slice::from_ref(&schema), None, Some(1000))
            .await
            .unwrap();
        let root = transport.get_root_hash().await?;
        let alice = Space::create(
            transport.clone(),
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let invite = alice.invite_user().await?;
        let bob = Space::join(
            transport.clone(),
            invite,
            hash_backed_ff_app_schema(schema.clone(), root),
        )
        .await?;

        let alice_notes = alice.table::<FfNote>("ff_notes");
        alice_notes
            .insert(&FfNote {
                id: None,
                content: "cache-before-select content".to_string(),
                title: "cache-before-select title".to_string(),
            })
            .execute()
            .await?;
        alice_notes
            .insert(&FfNote {
                id: None,
                content: "second row content".to_string(),
                title: "second row title".to_string(),
            })
            .execute()
            .await?;

        bob.recover_via_fast_forward().await?;

        // Inspect the cache BEFORE any select — ragged FF cache updates
        // should have resolved hash-backed values and inserted the rows.
        let cached_rows: Vec<(i64, String, String)> = bob.with_state(|state| {
            state
                .cache
                .row_ids("ff_notes")
                .into_iter()
                .filter_map(|id| {
                    let row = state.cache.get_row("ff_notes", id)?;
                    let content = row.get("content")?.as_str()?.to_string();
                    let title = row.get("title")?.as_str()?.to_string();
                    Some((id, content, title))
                })
                .collect()
        });
        assert_eq!(
            cached_rows.len(),
            2,
            "both ragged FF rows should be cached before select"
        );
        let contents: std::collections::BTreeSet<&str> =
            cached_rows.iter().map(|(_, c, _)| c.as_str()).collect();
        assert!(
            contents.contains("cache-before-select content"),
            "first row content should be in cache"
        );
        assert!(
            contents.contains("second row content"),
            "second row content should be in cache"
        );

        Ok(())
    }
}

/// Issue #212 regression tests: a mutation/key-rotation must only report
/// success once its *exact* submitted entry is proven incorporated on the
/// verified changelog chain. These tests drive an adversarial transport that
/// accepts the change on the honest backend but reports a *different*
/// (later) `change_id` than the one actually assigned — so a fast-forward
/// cannot prove the client's entry at the acknowledged position, and the SDK
/// must fail closed instead of returning the old false success.
#[cfg(test)]
mod issue212_completion_tests {
    use crate::local_transport::LocalTransport;
    use crate::schema::{ColumnType, SchemaBuilder};
    use crate::transport::{BroadcastReceiver, Transport};
    use crate::Space;
    use async_trait::async_trait;
    use encrypted_spaces_backend::access_control::AuthContext;
    use encrypted_spaces_backend::error::{Result, SdkError};
    use encrypted_spaces_backend::merk_storage::proofs::VerifiedRows;
    use encrypted_spaces_backend::query::Query;
    use encrypted_spaces_backend::schema::Schema;
    use encrypted_spaces_changelog_core::changelog::{Change, ChangeResponse, FastForwardData};
    use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
    use serde::{Deserialize, Serialize};
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Debug, Serialize, Deserialize)]
    struct Note {
        id: Option<i64>,
        title: String,
    }

    /// Transport wrapping an honest [`LocalTransport`]. When *armed*, the next
    /// `submit_change` is applied to the real backend but the returned
    /// `ChangeResponse.change_id` is bumped by one, modelling a server that
    /// lies about where the client's entry landed. The arm flag is shared
    /// across clones so a clone handed to `Space` is armed via the test's
    /// handle.
    #[derive(Clone)]
    struct AckSkewTransport {
        inner: LocalTransport,
        skew_armed: Arc<AtomicBool>,
    }

    impl AckSkewTransport {
        fn new(inner: LocalTransport) -> Self {
            Self {
                inner,
                skew_armed: Arc::new(AtomicBool::new(false)),
            }
        }

        /// Arm exactly one upcoming `submit_change` to misreport its change_id.
        fn arm(&self) {
            self.skew_armed.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl Transport for AckSkewTransport {
        async fn submit_change(
            &self,
            change: &Change,
            retention_proofs: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            let mut resp = self.inner.submit_change(change, retention_proofs).await?;
            if self.skew_armed.swap(false, Ordering::SeqCst) {
                // Claim a later position than the one actually assigned, so a
                // fast-forward cannot prove the exact entry at `resp.change_id`.
                resp.change_id += 1;
            }
            Ok(resp)
        }

        async fn fast_forward(&self, change_id: u32) -> Result<FastForwardData> {
            self.inner.fast_forward(change_id).await
        }

        async fn fast_forward_with_expected(
            &self,
            change_id: u32,
            expected_change_ids: &[u32],
        ) -> Result<FastForwardData> {
            self.inner
                .fast_forward_with_expected(change_id, expected_change_ids)
                .await
        }

        async fn select(
            &self,
            query: Query,
            commitment: &[u8; 32],
            schemas: &HashMap<String, Schema>,
        ) -> Result<VerifiedRows> {
            self.inner.select(query, commitment, schemas).await
        }

        fn as_any(&self) -> &dyn Any {
            // Delegate so the test-only `LocalTransport` downcast helpers
            // (create_table, baseline seeding, ...) resolve to the real inner
            // transport. The mutation path uses dynamic dispatch through this
            // wrapper, so the skew still applies.
            self.inner.as_any()
        }

        async fn fetch_my_key_delivery(&self) -> Result<Option<Vec<u8>>> {
            self.inner.fetch_my_key_delivery().await
        }

        async fn add_member(
            &self,
            request: InviteRequest,
            insert_change: &Change,
            retention_proofs: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            self.inner
                .add_member(request, insert_change, retention_proofs)
                .await
        }

        async fn remove_member(
            &self,
            request: RekeyRequest,
            remaining_uids: &[i64],
            delete_change: &Change,
            retention_proofs: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            self.inner
                .remove_member(request, remaining_uids, delete_change, retention_proofs)
                .await
        }

        async fn submit_retention(
            &self,
            change: &Change,
            retention_proofs: Vec<Vec<u8>>,
            rekey_request: Option<RekeyRequest>,
        ) -> Result<ChangeResponse> {
            self.inner
                .submit_retention(change, retention_proofs, rekey_request)
                .await
        }

        async fn authenticate(&self, auth_context: &AuthContext) -> Result<()> {
            self.inner.authenticate(auth_context).await
        }

        fn subscribe_broadcasts(&self) -> Result<BroadcastReceiver> {
            self.inner.subscribe_broadcasts()
        }

        async fn file_upload(&self, hash: &str, data: Vec<u8>) -> Result<()> {
            self.inner.file_upload(hash, data).await
        }

        async fn file_download(&self, hash: &str) -> Result<Vec<u8>> {
            self.inner.file_download(hash).await
        }
    }

    async fn make_space() -> (AckSkewTransport, Space) {
        let inner = LocalTransport::in_memory()
            .await
            .expect("in-memory transport");
        let transport = AckSkewTransport::new(inner);
        let space = Space::new(transport.clone()).await.expect("space");
        let schema = SchemaBuilder::new("notes")
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("title", ColumnType::String)
            .expect("title column")
            .plaintext()
            .index()
            .build()
            .expect("schema");
        space.create_table(&schema).await.expect("create_table");
        (transport, space)
    }

    /// Like [`make_space`] but also registers an `add_note` insert action on
    /// the `notes` table so the action-mutation surface can be exercised.
    async fn make_space_with_action() -> (AckSkewTransport, Space) {
        use encrypted_spaces_acl_types::{Action, ActionLeg};
        let (transport, space) = make_space().await;
        space
            .add_action(
                Action {
                    name: "add_note".into(),
                    legs: vec![ActionLeg::Insert {
                        table: "notes".into(),
                    }],
                    asserts: vec![],
                },
                None,
            )
            .await
            .expect("add_action");
        (transport, space)
    }

    fn assert_failed_closed<T: std::fmt::Debug>(res: Result<T>) {
        let err = res.expect_err("operation must fail closed when its entry cannot be proven");
        match err {
            SdkError::ValidationError(msg) => assert!(
                msg.contains("212") || msg.to_lowercase().contains("failing closed"),
                "expected an issue-#212 fail-closed validation error, got: {msg}"
            ),
            other => panic!("expected a fail-closed ValidationError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn accepted_update_with_misreported_change_id_fails_closed() {
        let (transport, space) = make_space().await;
        let notes = space.table::<Note>("notes");
        let id = notes
            .insert(&Note {
                id: None,
                title: "a".into(),
            })
            .execute()
            .await
            .expect("insert");

        // Honest update still works through the wrapper.
        let n = notes
            .update()
            .set("title", "b")
            .where_eq("id", id)
            .execute()
            .await
            .expect("honest update");
        assert_eq!(n, 1);

        transport.arm();
        let res = notes
            .update()
            .set("title", "c")
            .where_eq("id", id)
            .execute()
            .await;
        assert_failed_closed(res);
    }

    #[tokio::test]
    async fn accepted_delete_with_misreported_change_id_fails_closed() {
        let (transport, space) = make_space().await;
        let notes = space.table::<Note>("notes");
        let id = notes
            .insert(&Note {
                id: None,
                title: "a".into(),
            })
            .execute()
            .await
            .expect("insert");

        transport.arm();
        let res = notes.delete().where_eq("id", id).execute().await;
        assert_failed_closed(res);
    }

    #[tokio::test]
    async fn accepted_insert_with_misreported_change_id_fails_closed() {
        let (transport, space) = make_space().await;
        let notes = space.table::<Note>("notes");

        transport.arm();
        let res = notes
            .insert(&Note {
                id: None,
                title: "ghost".into(),
            })
            .execute()
            .await;
        assert_failed_closed(res);
    }

    #[tokio::test]
    async fn accepted_key_rotation_with_misreported_change_id_does_not_install_keys() {
        let (transport, space) = make_space().await;

        let kvf_before = space.with_state(|s| s.key_valid_from_change_id);
        let vk_before = {
            let km = space.key_manager.lock().await;
            serde_json::to_vec(km.auth_key_pair().verification_key()).expect("vk")
        };

        transport.arm();
        let res = space.rotate_user_keys().await.map(|_| ());
        assert_failed_closed(res);

        let kvf_after = space.with_state(|s| s.key_valid_from_change_id);
        assert_eq!(
            kvf_before, kvf_after,
            "key_valid_from_change_id must not advance on an unprovable rotation"
        );
        let vk_after = {
            let km = space.key_manager.lock().await;
            serde_json::to_vec(km.auth_key_pair().verification_key()).expect("vk")
        };
        assert_eq!(
            vk_before, vk_after,
            "the new auth key must not be installed on an unprovable rotation"
        );
    }

    #[tokio::test]
    async fn honest_mutations_still_succeed_through_wrapper() {
        let (_transport, space) = make_space().await;
        let notes = space.table::<Note>("notes");
        let id = notes
            .insert(&Note {
                id: None,
                title: "x".into(),
            })
            .execute()
            .await
            .expect("insert");
        let updated = notes
            .update()
            .set("title", "y")
            .where_eq("id", id)
            .execute()
            .await
            .expect("update");
        assert_eq!(updated, 1);
        let deleted = notes
            .delete()
            .where_eq("id", id)
            .execute()
            .await
            .expect("delete");
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    async fn accepted_action_with_misreported_change_id_fails_closed() {
        use encrypted_spaces_backend::query::QueryParam;
        let (transport, space) = make_space_with_action().await;

        // Honest action insert works through the wrapper.
        let id = space
            .call_insert_action(
                "add_note",
                vec![("title".to_string(), QueryParam::Text("honest".into()))],
            )
            .await
            .expect("honest action insert");
        assert!(id > 0);

        // Acknowledged-but-misreported action insert must fail closed: the
        // action path submits directly (no re-sign, to keep the baked
        // action-marker valid), so it routes through `complete_submitted` and
        // must refuse to report success when its exact entry isn't proven.
        transport.arm();
        let res = space
            .call_insert_action(
                "add_note",
                vec![("title".to_string(), QueryParam::Text("ghost".into()))],
            )
            .await;
        assert_failed_closed(res);
    }

    #[tokio::test]
    async fn ff_recovery_is_suppressed_while_an_apply_is_in_flight() {
        // Issue #212 (#4) deadlock guard: while an `apply_fast_forward_from_anchor`
        // is in flight (`ff_in_progress` set), a re-entrant recovery — e.g. a
        // deferred-verification table read that hits a stale select — must fail
        // fast with `FastForwardRequired` instead of blocking forever on the
        // non-reentrant `serialize_mutations` mutex.
        let (_transport, space) = make_space().await;
        space
            .ff_in_progress
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            space.recover_via_fast_forward(),
        )
        .await
        .expect("re-entrant recovery must return promptly, not deadlock");

        match res {
            Err(SdkError::FastForwardRequired { .. }) => {}
            other => panic!("expected FastForwardRequired suppression, got: {other:?}"),
        }

        // Once the in-flight apply finishes (flag cleared), recovery is allowed
        // again (here it is a no-op since the client is already current).
        space
            .ff_in_progress
            .store(false, std::sync::atomic::Ordering::SeqCst);
        space
            .recover_via_fast_forward()
            .await
            .expect("recovery permitted once no apply is in flight");
    }

    #[tokio::test]
    async fn signer_cannot_capture_anchor_while_fast_forward_holds_the_guard() {
        // Issue #212 (#4) observability: a concurrent signer must not read the
        // changelog-position anchor while a fast-forward apply holds the
        // `serialize_mutations` guard (the apply may have installed provisional,
        // not-yet-verified state). We hold the guard to stand in for an in-flight
        // apply and assert that building a change (which reads the anchor under
        // the guard) cannot make progress until the guard is released.
        let (_transport, space) = make_space().await;

        // Hold the guard, as `apply_fast_forward_from_anchor` does for its whole
        // duration.
        let guard = space.serialize_mutations.clone().lock_owned().await;

        let done = Arc::new(AtomicBool::new(false));
        let done_in_task = Arc::clone(&done);
        let space_in_task = space.clone();
        let handle = tokio::spawn(async move {
            // `insert(...).execute()` builds the change via `ChangeBuilder`,
            // whose `auth_state()` acquires `serialize_mutations` to read the
            // anchor — so this blocks until the test drops `guard`.
            let _ = space_in_task
                .table::<Note>("notes")
                .insert(&Note {
                    id: None,
                    title: "later".into(),
                })
                .execute()
                .await
                .expect("insert completes once the guard is released");
            done_in_task.store(true, Ordering::SeqCst);
        });

        // Give the task ample time to reach the guard; it must NOT complete
        // while we hold it. This is deterministic: the task genuinely cannot
        // acquire the mutex we hold.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !done.load(Ordering::SeqCst),
            "signer captured the anchor while fast-forward held the guard"
        );

        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(10), handle)
            .await
            .expect("signer must complete promptly after the guard is released")
            .expect("insert task panicked");
        assert!(done.load(Ordering::SeqCst));
    }
}
