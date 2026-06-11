use crate::cache::Cache;
use crate::SpaceKeyManager;
use crate::{DataCommitment, Space, SpaceId, Transport};
use encrypted_spaces_acl_types::Action;
use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::{
    error::{Result, SdkError},
    schema::Schema,
};
// `state` is a private module (`mod state;` in lib.rs), so `pub` items here
// can never escape the crate. Use `pub(crate)` to make the visibility intent
// explicit and consistent with PR #117.
pub(crate) use encrypted_spaces_changelog_core::changelog::{
    initial_clc_state, ChangelogEntry, ClcState,
};
use encrypted_spaces_changelog_core::mmr_tree::h_leaf;
#[cfg(test)]
use encrypted_spaces_ffproof::EXTEND_FF_ID;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Client-side state snapshot used for synchronization and proof verification.
#[derive(Serialize, Deserialize)]
pub(crate) struct State {
    pub(crate) auth_context: AuthContext,
    pub(crate) current_data_commitment: DataCommitment,
    pub(crate) initial_dc: DataCommitment,
    pub(crate) current_change_id: u32,
    pub(crate) my_last_change_id: u32,
    /// Per-user view of the most recently accepted `change_id` for each
    /// signing uid, used to enforce sigref-chain continuity on ragged
    /// (post-FF-proof) changes and on single broadcast changes. Mirrors
    /// the proven `sigref_map` that the FF guest threads across chunks,
    /// kept lightweight (no leaf hashes) for client-side use.
    ///
    /// Seeded from the FF proof's `range.sigref_map` after each
    /// successful fast-forward, and updated incrementally as each
    /// change (single or ragged) is accepted. Defaults to empty on
    /// restore from a legacy snapshot — `restore_internal` already
    /// drives `recover_via_fast_forward` immediately after restore,
    /// which repopulates the map before any broadcast listener starts.
    #[serde(default)]
    pub(crate) sigref_map: BTreeMap<u32, u32>,
    /// Timestamp high-water mark for the accepted changelog prefix. Mirrors
    /// the FF proof journal's timestamp HWM, but persisted in lightweight
    /// client state so proofless fast-forward tails can validate with the
    /// same relative freshness rule as proof mode.
    ///
    /// Seeded from verified FF proof output and updated incrementally after
    /// each accepted single or ragged change. Defaults to 0 for legacy
    /// snapshots; non-genesis snapshots missing this field must resync from
    /// genesis so the HWM can be reconstructed from proof output and tail
    /// replay.
    #[serde(default)]
    pub(crate) timestamp_hwm: u64,
    /// The change_id at which the current auth key became valid.
    /// Starts at 0 (for the initial key set during CreateSpace/InviteUser).
    /// Updated to the RefreshKeys change_id after each key rotation.
    pub(crate) key_valid_from_change_id: u32,
    pub(crate) table_schemas: HashMap<String, Schema>,
    /// App-defined actions registered with this Space.  Populated from
    /// the imported [`SchemaBundle`] during space init; consulted by
    /// the `call_*_action` entry points to look up which primitive op
    /// shape they're invoking.
    #[serde(default)]
    pub(crate) actions: HashMap<String, Action>,
    /// Current changelog commitment.
    /// Kept up-to-date for each change/FF proof.
    pub(crate) current_clc_state: ClcState,
    /// Locally-stored signed [`ChangelogEntry`] at `current_change_id`.
    /// Acts as the changelog anchor: on the next FF cycle the client
    /// uses this entry to verify `from_inclusion_proof`, ensuring the
    /// FF proof's `end_clc_state` actually extends this branch.
    ///
    /// `None` iff `current_change_id == 0`; the FF start-state checks
    /// already authenticate the initial changelog commitment.
    #[serde(default)]
    pub(crate) current_change_entry: Option<ChangelogEntry>,

    /// Trusted FF-proof guest image ID for this Space.  Persisted so a
    /// restored snapshot keeps the same trust bundle without callers
    /// having to re-supply it.  See [`crate::FfImageId`] for the
    /// rolling-upgrade caveat.
    #[serde(default)]
    pub(crate) ff_image_id: crate::FfImageId,

    /// In-flight local submissions awaiting cryptographic proof that their
    /// *exact* entry was incorporated, keyed by the acknowledged
    /// `change_id`. Each value records the journal leaf hash
    /// `h_leaf(entry.as_bytes())` of the submitted entry and whether it has
    /// been *discharged* (proven on the verified CLC chain) via a
    /// sequential append, a ragged fast-forward apply, a broadcast apply,
    /// or a fast-forward inclusion proof. The completion helper refuses to
    /// report success for a mutation whose pending entry is not discharged.
    /// Ephemeral: never serialized (in-flight only). See issue #212.
    #[serde(skip)]
    pub(crate) pending_local_changes: BTreeMap<u32, PendingLocalChange>,

    /// Ephemeral index-based cache of decrypted rows. Never serialized.
    #[serde(skip)]
    pub(crate) cache: Cache,
}

/// A local submission awaiting proof of incorporation. See
/// [`State::pending_local_changes`].
#[derive(Clone, Debug)]
pub(crate) struct PendingLocalChange {
    /// `h_leaf(entry.as_bytes())` of the exact submitted entry. Used to
    /// match the entry the client signed against the entry actually proven
    /// on the verified CLC chain, so a different (even validly signed)
    /// entry from the same user at the same `change_id` cannot discharge it.
    pub(crate) leaf_hash: [u8; 32],
    /// Set once the exact entry is proven incorporated on the verified
    /// chain. A mutation may only report success after this flips true.
    pub(crate) discharged: bool,
}

/// Discharge a pending local submission (issue #212) when the exact entry
/// bytes appended at `change_id` match the registered submission.
///
/// Matching is on the journal leaf hash `h_leaf(entry_bytes)`, so a different
/// — even validly signed — entry from the same user at the same `change_id`
/// can never discharge the wrong pending submission. Returns `true` iff a
/// pending entry was discharged by this call.
///
/// This is the single discharge predicate shared by every append path
/// (sequential, broadcast, ragged fast-forward), so broadcast-delivered
/// entries discharge through exactly the same check as locally-applied ones.
pub(crate) fn discharge_pending_local_change(
    pending: &mut BTreeMap<u32, PendingLocalChange>,
    change_id: u32,
    entry_bytes: &[u8],
) -> bool {
    if let Some(p) = pending.get_mut(&change_id) {
        let leaf_hash: [u8; 32] = h_leaf(entry_bytes).into();
        if p.leaf_hash == leaf_hash {
            p.discharged = true;
            return true;
        }
    }
    false
}

impl State {
    /// True when the restored snapshot is missing the FF anchor
    /// (`current_change_entry`), the per-user sigref chain (`sigref_map`), or
    /// the persisted timestamp HWM (`timestamp_hwm`).
    ///
    /// Three legacy-snapshot shapes need this:
    /// - pre-anchor-fix snapshots: `current_change_id > 0` but no anchor entry.
    /// - post-anchor-fix / pre-sigref-fix snapshots: anchor present but
    ///   `sigref_map` deserializes empty via `#[serde(default)]`.
    /// - post-sigref-fix / pre-timestamp-HWM snapshots: anchor and sigref map
    ///   are present but `timestamp_hwm` deserializes to 0.
    ///
    /// If `recover_via_fast_forward` happens to return a proofless ragged-only
    /// response, the proof seed step never runs. Resetting to genesis here
    /// forces a full re-fetch that re-seeds `sigref_map` and `timestamp_hwm`.
    pub(crate) fn needs_changelog_anchor_resync(&self) -> bool {
        self.current_change_id > 0
            && (self.current_change_entry.is_none()
                || self.sigref_map.is_empty()
                || self.timestamp_hwm == 0)
    }

    pub(crate) fn reset_changelog_anchor_to_genesis(&mut self) {
        self.current_change_id = 0;
        self.current_clc_state = initial_clc_state(&self.initial_dc);
        self.current_change_entry = None;
        // Any cached per-user sigref chain belongs to the discarded
        // anchor; the post-reset FF must re-seed it from the proof so
        // subsequent ragged changes validate against the right history.
        self.sigref_map.clear();
        self.timestamp_hwm = 0;
    }
}

#[derive(Serialize, Deserialize)]
struct SpaceSnapshot {
    #[serde(default)]
    space_id: Option<SpaceId>,
    state: State,
    #[serde(default)]
    key_manager: Option<SpaceKeyManager>,
}

impl Space {
    pub(crate) fn with_state<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        let state = self.state.lock().unwrap();
        f(&state)
    }

    pub(crate) fn with_state_mut<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let mut state = self.state.lock().unwrap();
        f(&mut state)
    }

    async fn build_snapshot_value(&self) -> Result<serde_json::Value> {
        // Serialize state while holding the lock to avoid cloning the key chain.
        let state_value = self
            .with_state(|state| serde_json::to_value(state))
            .map_err(|e| SdkError::SerializationError(e.to_string()))?;

        let km = self.key_manager.lock().await;
        let km_value =
            serde_json::to_value(&*km).map_err(|e| SdkError::SerializationError(e.to_string()))?;
        drop(km);

        let snapshot = serde_json::json!({
            "space_id": self.id,
            "state": state_value,
            "key_manager": km_value,
        });
        Ok(snapshot)
    }

    /// Export a serializable snapshot of this space's client-side state.
    ///
    /// The SDK does not persist snapshots itself — the caller is responsible
    /// for storing the returned value (e.g. on disk, in a keychain, or
    /// alongside app-level state) and supplying it to [`Space::restore`]
    /// on restart so the client can resume from the last known state
    /// after restart or crash.
    ///
    /// The returned value should be treated as opaque; its schema may change
    /// between SDK versions. Typical usage is to call this after meaningful
    /// state changes (e.g. after applying a batch of changes or before
    /// shutdown).
    pub async fn snapshot(&self) -> Result<serde_json::Value> {
        self.build_snapshot_value().await
    }

    /// Restore a [`Space`] from a previously exported [`Space::snapshot`] value.
    ///
    /// Mirrors the [`Space::create`] / [`Space::join`] lifecycle entry
    /// points: the caller provides a fresh `transport` so that
    /// subscriptions and other transport-level setup can be performed
    /// before state is restored.  The trusted FF-proof guest image ID
    /// rides along inside the snapshot, so callers don't need to
    /// re-supply it on restore.
    pub async fn restore(transport: impl Transport, snapshot: serde_json::Value) -> Result<Self> {
        let snapshot: SpaceSnapshot = serde_json::from_value(snapshot)
            .map_err(|e| SdkError::SerializationError(e.to_string()))?;

        let space_id = snapshot.space_id.unwrap_or_else(SpaceId::random);

        let key_manager = snapshot.key_manager.ok_or_else(|| {
            SdkError::SerializationError("snapshot is missing key_manager".to_string())
        })?;

        let transport: std::sync::Arc<dyn Transport> = std::sync::Arc::new(transport);
        Self::restore_internal(transport, space_id, snapshot.state, key_manager).await
    }

    /// Crate-internal accessor for the current data commitment, used
    /// by the SELECT path in [`crate::table`].  The corresponding
    /// `pub` accessor lives in [`crate::testing`] under the `testing`
    /// feature, so this `pub(crate)` definition is suppressed when
    /// that feature is enabled to avoid colliding with it.
    #[cfg(not(feature = "testing"))]
    pub(crate) fn current_data_commitment(&self) -> [u8; 32] {
        self.with_state(|state| state.current_data_commitment)
    }

    /// Get the authenticated user's UID.
    pub fn uid(&self) -> Option<u32> {
        self.with_state(|state| state.auth_context.uid.map(|uid| uid as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state(current_change_id: u32) -> State {
        let initial_dc = [0x11; 32];
        State {
            auth_context: AuthContext::anonymous(SpaceId::random()),
            current_data_commitment: [0x22; 32],
            initial_dc,
            current_change_id,
            my_last_change_id: current_change_id,
            sigref_map: BTreeMap::new(),
            timestamp_hwm: if current_change_id == 0 { 0 } else { 1_000 },
            key_valid_from_change_id: 0,
            table_schemas: HashMap::new(),
            actions: HashMap::new(),
            current_clc_state: initial_clc_state(&initial_dc),
            current_change_entry: None,
            ff_image_id: EXTEND_FF_ID,
            pending_local_changes: Default::default(),
            cache: Default::default(),
        }
    }

    #[test]
    fn state_deserializes_snapshots_without_current_change_entry() {
        let state = sample_state(7);
        let mut value = serde_json::to_value(&state).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("current_change_entry");

        let decoded: State = serde_json::from_value(value).unwrap();

        assert_eq!(decoded.current_change_id, 7);
        assert!(decoded.current_change_entry.is_none());
        assert!(decoded.needs_changelog_anchor_resync());
    }

    #[test]
    fn reset_changelog_anchor_to_genesis_keeps_data_commitment_for_cache_warmup() {
        let mut state = sample_state(7);
        let data_commitment = state.current_data_commitment;
        // Seed a stale per-user sigref entry that belongs to the
        // pre-reset anchor; the reset must drop it so the post-reset
        // FF can re-seed `sigref_map` cleanly.
        state.sigref_map.insert(42, 7);
        state.timestamp_hwm = 1_000;

        state.reset_changelog_anchor_to_genesis();

        assert_eq!(state.current_change_id, 0);
        assert_eq!(state.current_data_commitment, data_commitment);
        assert_eq!(
            state.current_clc_state,
            initial_clc_state(&state.initial_dc)
        );
        assert!(state.current_change_entry.is_none());
        assert!(
            state.sigref_map.is_empty(),
            "reset must clear sigref_map so post-reset FF re-seeds it"
        );
        assert_eq!(state.timestamp_hwm, 0);
    }

    #[test]
    fn needs_resync_when_sigref_map_missing_from_legacy_snapshot() {
        // A snapshot taken by a post-anchor-fix but pre-sigref-fix
        // client has a valid `current_change_entry` but no
        // `sigref_map`. `#[serde(default)]` would deserialize it to
        // empty, which would silently let the ragged loop reject every
        // signer with prior history if the next FF is proofless.
        // `needs_changelog_anchor_resync` must trip here so we
        // reset-to-genesis and re-fetch from scratch.
        let mut state = sample_state(7);
        state.current_change_entry = Some(ChangelogEntry::default());
        let mut value = serde_json::to_value(&state).unwrap();
        value.as_object_mut().unwrap().remove("sigref_map");

        let decoded: State = serde_json::from_value(value).unwrap();

        assert_eq!(decoded.current_change_id, 7);
        assert!(decoded.current_change_entry.is_some());
        assert!(decoded.sigref_map.is_empty());
        assert!(
            decoded.needs_changelog_anchor_resync(),
            "snapshot with anchor but no sigref_map must trigger anchor resync"
        );
    }

    // --- Issue #212: pending-local-change discharge predicate ---

    use encrypted_spaces_changelog_core::changelog::{ChangelogEntry, KvData, LogMessage, OpType};

    /// Build a distinct signed-ish entry. Varying `uid`/`sig_ref`/`value`
    /// changes the serialized bytes and therefore `h_leaf`.
    fn entry(uid: u32, sig_ref: u32, value: u8) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![KvData {
                    key: b"k".to_vec(),
                    value: vec![value; 8],
                }],
            },
            sig_ref,
            parent_clc: [0u8; 32],
            signature: vec![0xAB, 0xCD],
        }
    }

    fn pending_for(e: &ChangelogEntry) -> PendingLocalChange {
        let leaf_hash: [u8; 32] = h_leaf(&e.as_bytes()).into();
        PendingLocalChange {
            leaf_hash,
            discharged: false,
        }
    }

    #[test]
    fn discharge_marks_matching_pending() {
        let e = entry(7, 0, 0xAA);
        let mut pending = BTreeMap::new();
        pending.insert(5u32, pending_for(&e));

        let discharged = discharge_pending_local_change(&mut pending, 5, &e.as_bytes());

        assert!(
            discharged,
            "exact entry at the registered change_id discharges"
        );
        assert!(pending[&5].discharged);
    }

    #[test]
    fn discharge_ignores_wrong_entry_at_same_change_id() {
        // A different (even validly signed) entry from the *same user* at the
        // *same change_id* must not discharge the pending submission — only the
        // exact bytes we submitted may. Guards against a server incorporating a
        // different Alice entry at the acknowledged slot.
        let mine = entry(7, 0, 0xAA);
        let other_same_user = entry(7, 0, 0xBB);
        assert_ne!(mine.as_bytes(), other_same_user.as_bytes());

        let mut pending = BTreeMap::new();
        pending.insert(5u32, pending_for(&mine));

        let discharged =
            discharge_pending_local_change(&mut pending, 5, &other_same_user.as_bytes());

        assert!(!discharged, "a different entry must not discharge");
        assert!(
            !pending[&5].discharged,
            "pending must remain undischarged so the caller fails closed"
        );
    }

    #[test]
    fn discharge_ignores_unregistered_change_id() {
        let e = entry(7, 0, 0xAA);
        let mut pending = BTreeMap::new();
        pending.insert(5u32, pending_for(&e));

        // Same exact bytes, but applied at a different change_id than the one
        // the submission was acknowledged at.
        let discharged = discharge_pending_local_change(&mut pending, 6, &e.as_bytes());

        assert!(!discharged);
        assert!(!pending[&5].discharged);
    }

    #[test]
    fn discharge_is_noop_with_no_pending() {
        let e = entry(7, 0, 0xAA);
        let mut pending = BTreeMap::new();
        assert!(!discharge_pending_local_change(
            &mut pending,
            5,
            &e.as_bytes()
        ));
    }

    #[test]
    fn discharge_targets_only_matching_change_id_among_many() {
        // Two in-flight submissions; applying the exact bytes for one must
        // discharge only that one.
        let e5 = entry(7, 0, 0x01);
        let e6 = entry(7, 5, 0x02);
        let mut pending = BTreeMap::new();
        pending.insert(5u32, pending_for(&e5));
        pending.insert(6u32, pending_for(&e6));

        assert!(discharge_pending_local_change(
            &mut pending,
            6,
            &e6.as_bytes()
        ));
        assert!(!pending[&5].discharged, "the other pending stays untouched");
        assert!(pending[&6].discharged);
    }
    #[test]
    fn needs_resync_when_timestamp_hwm_missing_from_legacy_snapshot() {
        let mut state = sample_state(7);
        state.current_change_entry = Some(ChangelogEntry::default());
        state.sigref_map.insert(42, 7);
        let mut value = serde_json::to_value(&state).unwrap();
        value.as_object_mut().unwrap().remove("timestamp_hwm");

        let decoded: State = serde_json::from_value(value).unwrap();

        assert_eq!(decoded.current_change_id, 7);
        assert!(decoded.current_change_entry.is_some());
        assert!(!decoded.sigref_map.is_empty());
        assert_eq!(decoded.timestamp_hwm, 0);
        assert!(
            decoded.needs_changelog_anchor_resync(),
            "snapshot with anchor and sigref_map but no timestamp_hwm must trigger anchor resync"
        );
    }
}
