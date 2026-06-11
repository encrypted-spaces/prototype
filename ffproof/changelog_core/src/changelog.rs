use crate::mmr_tree::{h_init, h_leaf, InclusionProof, MmrTree, ProofCache, TreeHead};
use crate::time::{validate_timestamp_hwm, TIMESTAMP_HWM_TOLERANCE_SECONDS};
pub use risc0_zkvm::sha::Digest;

pub type Path = Vec<Vec<u8>>;
/// Side-channel map of `hashstore_hash(value) → value bytes` for hash-backed
/// column writes in a change. Merk stores only the 32-byte hash; the full
/// bytes travel alongside in this map. Recipients re-hash each value before
/// trusting it, so a peer can't ship `(signed_hash, garbage_value)` pairs.
///
/// On the wire the map collapses to `repeated bytes` (just the values);
/// receivers re-hash each one with `hashstore_hash` to rebuild the map.
pub type HashedValues = BTreeMap<[u8; 32], Vec<u8>>;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

///// Changelog Structures

#[cfg(test)]
pub(crate) const DEFAULT_UID: u32 = 3;
/// Maximum key length in bytes. Used to validate keys in `ChangelogEntry::new()`.
pub const MAX_KEY_LEN: usize = 64;
/// Maximum number of entries allowed in a single LogMessage.
pub const MAX_LOGMSG_ENTRIES: usize = 128;

#[derive(Debug)]
pub enum ChangelogError {
    Generic(String),
    KeyMismatch(String),
    /// ACL evaluation rejected the operation (rule returned false, rule
    /// evaluation errored, or a needed column was absent). Surfaced distinctly
    /// so the storage layer can map to `SdkError::AccessDenied`.
    AclDenied(String),
}

impl std::fmt::Display for ChangelogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangelogError::Generic(msg) => write!(f, "{msg}"),
            ChangelogError::KeyMismatch(msg) => write!(f, "Key mismatch: {msg}"),
            ChangelogError::AclDenied(msg) => write!(f, "ACL denied: {msg}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpType {
    Insert = 0,
    Update = 1,
    Delete = 2,
    ListInsert = 3,
    ListUpdate = 4,
    ListDelete = 5,
    CreateSpace = 6,
    /// Rotate a provisional user's keys and transition to full membership.
    /// Only allowed for provisional users targeting their own `_users` row.
    RefreshKeys = 7,
    /// Invite a new user: insert into `_users` + insert commitment into `_retention`.
    InviteUser = 8,
    /// Remove a user: delete from `_users` + insert new commitment into `_retention`.
    RemoveUser = 9,
    /// Extend the retention key chain: insert new D-key commitment into `_retention`.
    Extend = 10,
    /// Reduce (prune) old retention keys: mixed inserts/deletes in `_retention`.
    Reduce = 11,
    /// Standalone rekey: rotate group key and write new commitment into `_retention`.
    Rekey = 12,
    /// Append a new item to the tail of a list stored in the `_lists` table.
    ListAppend = 13,
    /// Action invocation: the signed entry carries an
    /// `action_marker_key()` kv at position 0 naming an action declared
    /// in authenticated state; the verifier dispatches each leg to the
    /// matching primitive op.
    Action = 14,
    /// Benchmark-only no-op: exercises the FF pipeline (changelog, MMR,
    /// sigref, pruned tree, overlay) without any table reads or writes.
    /// Rejected by the production server write path.
    Noop = 15,
}

type Time = u64;

pub const ROOT_TREE_PATH: &[u8] = b"/";

/// Log entry with structured reference and signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangelogEntry {
    pub timestamp: Time,
    pub uid: u32,           // The change author's UID
    pub parent_change: u32, // Change ID that this change applies to
    pub message: LogMessage,
    pub sig_ref: u32, // Change ID of the signer's previous entry (0 if the first)
    /// The changelog commitment (hash-chain link) of the parent change.
    pub parent_clc: [u8; 32],
    /// Signature over the entry bytes (with this field empty).
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// A (key, value) pair within a LogMessage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvData {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl KvData {
    /// Convert to the matching `BatchOp` for tracer proof steps.
    /// Uses the provided `key` (which may differ from `self.key` for
    /// insert ops where the proof key has the real row_id).
    pub fn to_batch_op(&self, key: &[u8]) -> crate::BatchOp {
        crate::BatchOp::Put {
            key: key.to_vec(),
            value: self.value.clone(),
        }
    }
}

/// Structured log message with data commitment.
/// For each column, the entry carries the stored value bytes. Hash-backed
/// columns carry the 32-byte hash reference selected by the schema.
/// `entries` has invariant len >= 1. Many ops use exactly one entry;
/// others, like deleting multiple rows from a table, have more.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogMessage {
    pub op_type: OpType,
    /// A binary encoding of a user-readable path to a tree, such as "/" for the main
    /// tree or "/lists" for a sub-tree that handles lists
    pub tree_path: Vec<u8>,
    /// A list of key-value pairs affected by this change
    pub entries: Vec<KvData>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeResponse {
    pub change_id: u32,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub pruned_merkle_tree: Vec<u8>,
    pub rows_affected: u64,
    #[serde(default)]
    pub hashed_values: HashedValues,
    #[serde(default)]
    pub accepted_at_server_time: Time,
}

/// A `ChangelogEntry` together with the side-channel `hash → value` map
/// covering every hash-backed column write in the entry. The two pieces
/// always travel together — the entry is what gets signed and verified,
/// the sidecar is the bytes that hash to the committed hashes — so we wrap
/// them in one type rather than threading `(entry, hashed_values)` tuples
/// through every API.
#[derive(Clone, Debug)]
pub struct Change {
    pub entry: ChangelogEntry,
    pub hashed_values: HashedValues,
}

impl Change {
    /// Build a `Change` from raw key/value pairs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        op_type: OpType,
        uid: u32,
        tree_path: &[u8],
        keys: &[&[u8]],
        values: &[&[u8]],
        parent_change: u32,
        user_previous_change: u32,
        parent_clc: [u8; 32],
    ) -> Result<Self, ChangelogError> {
        if keys.len() != values.len() {
            return Err(ChangelogError::Generic(format!(
                "keys and values must have the same length, got {} keys and {} values",
                keys.len(),
                values.len()
            )));
        }
        if keys.is_empty() {
            return Err(ChangelogError::Generic(
                "must provide at least one key-value pair".to_string(),
            ));
        }

        let mut entries = Vec::with_capacity(keys.len());
        for (key, val) in keys.iter().zip(values.iter()) {
            if key.len() > MAX_KEY_LEN {
                return Err(ChangelogError::Generic(format!(
                    "Key length is too long, got {} bytes, maximum is {MAX_KEY_LEN} bytes",
                    key.len()
                )));
            }
            let value = if op_type == OpType::Delete {
                vec![]
            } else {
                val.to_vec()
            };
            entries.push(KvData {
                key: key.to_vec(),
                value,
            });
        }

        Ok(Change {
            entry: ChangelogEntry {
                timestamp: ChangelogEntry::get_unix_timestamp(),
                parent_change,
                message: LogMessage {
                    op_type,
                    tree_path: tree_path.to_vec(),
                    entries,
                },
                uid,
                sig_ref: user_previous_change,
                parent_clc,
                signature: vec![],
            },
            hashed_values: HashedValues::new(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct FastForwardData {
    pub proof: Option<FastForwardProof>,
    pub changes: Vec<ChangelogEntry>,
    pub responses: Vec<ChangeResponse>,
    /// Server head after the returned proof/ragged changes were selected.
    pub server_head: Option<FastForwardServerHead>,
}

#[derive(Clone, Debug)]
pub struct FastForwardServerHead {
    pub change_id: u32,
    /// 16-byte prefix of the server's current CLC root. Just enough to
    /// detect divergence; intentionally too short to be adopted as an
    /// authoritative tree head.
    pub clc_prefix: [u8; 16],
    /// 16-byte prefix of the server's current data commitment.
    pub data_commitment_prefix: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct FastForwardProof {
    pub end_change_id: u32,
    pub proof: Vec<u8>,
    /// Signed changelog entries for each user's latest change (keyed by change_id).
    /// The verifier checks one signature per user using these entries.
    /// Populated by the server from its changelog using the proof's sigref_map.
    pub sigref_entries: BTreeMap<u32, ChangelogEntry>,
    /// Inclusion proof binding the client's prior position
    /// (`from_change_id` they sent in the FF request) to
    /// `end_clc_state` at `end_change_id`. `None` iff the request was
    /// `from_change_id == 0` — in that case the client's prior
    /// position is the initial changelog commitment, which the
    /// existing `start_dc == initial_dc` /
    /// `start_clc_state == initial_clc_state(initial_dc)` checks
    /// already authenticate. The client verifies the proof using its
    /// locally-stored `current_change_entry`. This proves the FF
    /// commitment extends the client's accepted branch.
    pub from_inclusion_proof: Option<InclusionProof>,
    /// The signed [`ChangelogEntry`] at `end_change_id` together with
    /// its inclusion proof against `end_clc_state`. Present only when
    /// the FF response has no ragged changes after the proof boundary;
    /// otherwise the last ragged change becomes the client's next
    /// changelog anchor.
    pub end_entry: Option<ChangelogEntry>,
    pub end_entry_inclusion_proof: Option<InclusionProof>,
    /// Inclusion proofs binding client-requested *expected local entries*
    /// (acknowledged `change_id` -> proof) to `end_clc_state`. Populated
    /// only for expected change_ids that fall inside the proven range
    /// `1..=end_change_id`; expected entries beyond the proof boundary are
    /// matched directly against the ragged `changes`/`responses`. Each
    /// proof's leaf is the client's own submitted entry, so the client
    /// verifies it with `h_leaf(entry.as_bytes())` and never trusts the
    /// server's claim that its exact change was incorporated. See issue #212.
    pub expected_inclusion_proofs: BTreeMap<u32, InclusionProof>,
}

/// Client/server-visible commitment to the changelog plus the
/// extension state needed to append the next entry.
///
/// Treat as opaque outside `changelog_core`, the details of the commiment
/// scheme are only relevant here.
pub type ClcState = TreeHead;

/// Build the initial `ClcState` for a fresh changelog seeded with
/// `initial_dc`. Equivalent to `ChangeLog::new(initial_dc).current_clc_state()`.
pub fn initial_clc_state(initial_dc: &[u8; 32]) -> ClcState {
    let mut tree = MmrTree::new();
    tree.initialize(initial_dc);
    tree.tree_head()
        .expect("tree must be non-empty after initialize")
}

fn inclusion_proof_cache_with_initial_leaf(initial_dc: &[u8; 32]) -> ProofCache {
    let mut cache = ProofCache::new();
    cache.extend_with_leaf(h_init(initial_dc));
    cache
}

fn build_inclusion_proof_cache(initial_dc: &[u8; 32], changes: &[ChangelogEntry]) -> ProofCache {
    let mut cache = inclusion_proof_cache_with_initial_leaf(initial_dc);
    for change in changes {
        cache.extend_with_leaf(h_leaf(&change.as_bytes()));
    }
    cache
}

fn inclusion_proof_cache_needs_rebuild(
    cache: Option<&ProofCache>,
    expected_leaves: u64,
    expected_root: Option<Digest>,
) -> bool {
    let (Some(cache), Some(expected_root)) = (cache, expected_root) else {
        return true;
    };

    if (cache.leaf_count() as u64) != expected_leaves {
        return true;
    }

    let leaf_count = cache.leaf_count();
    match cache.cached_subtree_root(0, leaf_count) {
        Some(cached) => cached != expected_root,
        None => true,
    }
}

/// The I/O data for a FastForward proof - identifies a range of changes.
/// The range always starts at change_id 0, we start at 0 and keep
/// extending the range of proven changes.
///
/// `start_clc_state` and `end_clc_state` are the MMR commitments
/// (`{ root, tree_size, peaks }`) at the chunk boundaries. Extension
/// chunks must satisfy `next.start_clc_state == previous.end_clc_state`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FastForwardRange {
    pub start_clc_state: ClcState,
    pub end_clc_state: ClcState,
    pub start_dc: Digest,
    pub end_dc: Digest,
    /// In final proof journals this is the absolute last proven change id.
    /// In the host-to-guest chunk input for recursive extensions, the same
    /// field carries the chunk length; the guest adds the previous proof's
    /// `end_change_id` before committing the journal output.
    pub end_change_id: u32,
    /// Per-user binding for the sigref chain. Keyed by `uid`; the value
    /// is `(latest_change_id, leaf_hash)` where `leaf_hash` is
    /// `h_leaf(entry_bytes)` of the changelog entry at
    /// `latest_change_id`. Threads across proof chunks; the verifier
    /// checks one signature per user against the same entry bytes the
    /// guest hashed, so a malicious server cannot serve a different
    /// (but genuinely signed) entry for signature verification than the
    /// one the FF proof actually processed.
    pub sigref_map: BTreeMap<u32, (u32, [u8; 32])>,
    /// Sliding window of the most recent changelog roots, used by the
    /// guest to validate each entry's `parent_clc`. Ordered ascending by
    /// `change_id`; length bounded by [`MAX_PARENT_DISTANCE`].
    ///
    /// In the journal (and `previous_io` for recursive extensions) this
    /// is the post-chunk state. The host does not populate it on the
    /// input `range`; the guest seeds the window from `previous_io`
    /// (or from `start_clc_state.root` for the first chunk) and emits
    /// the updated window in the journal.
    pub recent_roots: Vec<(u32, [u8; 32])>,
    /// High-water mark for change timestamps across the proven prefix.
    /// First chunks seed this to 0; extension chunks inherit the previous
    /// journal value and emit the post-chunk value.
    pub timestamp_hwm: Time,
}

impl FastForwardRange {
    pub fn as_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("Failed to serialize FastForwardRange")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<FastForwardRange, ChangelogError> {
        postcard::from_bytes(bytes)
            .map_err(|e| ChangelogError::Generic(format!("Deserialization error: {e}")))
    }

    pub fn set_from_bytes(&mut self, bytes: &[u8]) -> Result<(), ChangelogError> {
        let io = Self::from_bytes(bytes)?;
        *self = io;
        Ok(())
    }
}

/// A contiguous segment of changes in the same [`Space`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeLog {
    /// The current writer-side MMR state (peaks + tree_size).
    pub tree: MmrTree,
    /// `roots_by_change_id[0]` is the post-`initialize` root; index `k`
    /// is the root after appending real change `k`. Length is
    /// `changes.len() + 1`. Used to validate `parent_clc` against any
    /// historical change_id (32 B/change vs the full peaks list).
    pub roots_by_change_id: Vec<[u8; 32]>,
    /// Cached MMR head at `proven_up_to`. Becomes the `start_clc_state`
    /// of the next FF chunk and the `end_clc_state` shipped to clients
    /// alongside the FF proof. `None` iff `proven_up_to == 0`, in which
    /// case the head is derived from `initial_dc`.
    pub proven_clc_state: Option<ClcState>,
    /// The initial data commitment is the root of the tree after the schema
    ///  and initial data is populated, it's the first entry (position 0) in the MMR tree
    pub initial_dc: [u8; 32],
    pub changes: Vec<ChangelogEntry>,
    pub ff_proof: Vec<u8>,
    pub proven_up_to: usize, // ff_proof is a FF proof that changes[0..proven_up_to] are valid
    pub pruned_merkle_trees: Vec<PrunedMerkleTreeTriple>,
    /// In-memory acceleration cache for inclusion-proof generation.
    /// Pure cache: never serialised, fully reconstructible from
    /// `(initial_dc, changes)`. Lazily built on the first
    /// [`ChangeLog::prove_inclusion`] call and then maintained
    /// incrementally on every [`ChangeLog::add_change`] (O(log n) hashes
    /// per append). If reset (e.g. after deserialisation), the next
    /// proof rebuilds it in O(n log n) hashes one-time.
    #[serde(skip)]
    inclusion_proof_cache: Option<ProofCache>,
    /// Similar to `inclusion_proof_cache` but limited to the current FF-proven range.
    #[serde(skip)]
    ff_inclusion_proof_cache: Option<ProofCache>,
}

/// A serialized pruned Merk tree plus the roots it advances between.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrunedMerkleTreeTriple {
    pruned_merkle_tree: Vec<u8>,
    old_root: [u8; 32],
    new_root: [u8; 32],
}

/// A logical view over a contiguous suffix of a [`ChangeLog`], handed to
/// the FF prover. Carries matched slices of `changes` and `pruned_merkle_trees`
/// plus the source changelog's `initial_dc`. Deliberately not a
/// [`ChangeLog`]: it would be impossible to satisfy `validate_mmr_state`
/// without replaying the prefix it omits, and the prover supplies the
/// correct `start_clc_state` separately.
#[derive(Clone, Debug)]
pub struct ChangeLogTail {
    pub initial_dc: [u8; 32],
    pub changes: Vec<ChangelogEntry>,
    pub pruned_merkle_trees: Vec<PrunedMerkleTreeTriple>,
}

impl ChangeLogTail {
    pub fn num_changes(&self) -> u32 {
        self.changes.len() as u32
    }
}

/////// Implementation

/// Convert Path to slash-separated bytes directly
pub fn flatten_path(path: &Path) -> Vec<u8> {
    let mut path_bytes = Vec::new();
    path_bytes.push(b'/');
    for (i, segment) in path.iter().enumerate() {
        if i > 0 {
            path_bytes.push(b'/');
        }
        path_bytes.extend_from_slice(segment);
    }
    path_bytes
}

/// Convert slash-separated bytes back to Path
pub fn parse_path(path_bytes: &[u8]) -> Result<Path, ChangelogError> {
    if path_bytes.is_empty() {
        return Err(ChangelogError::Generic("Empty path".to_string()));
    }
    if path_bytes[0] != b'/' {
        return Err(ChangelogError::Generic(
            "Path must start with '/'".to_string(),
        ));
    }
    // Just "/" means empty path (root)
    if path_bytes.len() == 1 {
        return Ok(vec![]);
    }
    let segments: Vec<Vec<u8>> = path_bytes[1..]
        .split(|&b| b == b'/')
        .map(|segment| segment.to_vec())
        .collect();
    Ok(segments)
}

pub fn get_table_name(path_bytes: &[u8]) -> Result<String, ChangelogError> {
    let path_parsed = parse_path(path_bytes)?;
    if path_parsed.len() < 2 {
        return Err(ChangelogError::Generic(
            "Paths containing a table name must have length at least 2, /table_name/rows"
                .to_string(),
        ));
    }
    if path_parsed[path_parsed.len() - 1] != b"rows" {
        return Err(ChangelogError::Generic(
            "Paths containing a table name must end with 'rows'".to_string(),
        ));
    }
    std::str::from_utf8(&path_parsed[path_parsed.len() - 2])
        .map(|s| s.to_string())
        .map_err(|e| ChangelogError::Generic(format!("Error decoding table name; {e:?}")))
}

impl OpType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OpType::Insert),
            1 => Some(OpType::Update),
            2 => Some(OpType::Delete),
            3 => Some(OpType::ListInsert),
            4 => Some(OpType::ListUpdate),
            5 => Some(OpType::ListDelete),
            6 => Some(OpType::CreateSpace),
            7 => Some(OpType::RefreshKeys),
            8 => Some(OpType::InviteUser),
            9 => Some(OpType::RemoveUser),
            10 => Some(OpType::Extend),
            11 => Some(OpType::Reduce),
            12 => Some(OpType::Rekey),
            13 => Some(OpType::ListAppend),
            14 => Some(OpType::Action),
            15 => Some(OpType::Noop),
            _ => None,
        }
    }
}

impl LogMessage {
    pub fn as_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("Failed to serialize LogMessage")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        postcard::from_bytes(bytes).map_err(|_| "Failed to deserialize LogMessage")
    }
}

impl ChangelogEntry {
    pub fn get_unix_timestamp() -> u64 {
        use instant::SystemTime;
        use std::time::UNIX_EPOCH;

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Creates a new ChangelogEntry with the specified parameters.
    /// Called by clients when making a change.
    /// # Arguments:
    /// * `op_type` - The type of operation being logged, see OpType.
    /// * `uid` - User ID of the change author
    /// * `tree_path` - The path to the tree this key is relevant to
    /// * `keys` - Keys to be operated on (parallel with `values`)
    /// * `values` - Value data for each key (can have arbitrary length, always hashed internally)
    /// * `parent_change` - The ID of the most recent change when this change was created
    /// * `user_previous_change` - The author's previous change (or zero if their first)
    /// * `parent_clc` - The changelog commitment of the parent change
    ///
    /// Returns just the entry; tests/benches that don't ship a sidecar
    /// (because the entry's value bytes are all inline) use this. The
    /// SDK and server use [`Change::new`] instead so the matching
    /// hash → value sidecar is built in the same pass.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        op_type: OpType,
        uid: u32,
        tree_path: &[u8],
        keys: &[&[u8]],
        values: &[&[u8]],
        parent_change: u32,
        user_previous_change: u32,
        parent_clc: [u8; 32],
    ) -> Result<Self, ChangelogError> {
        Change::new(
            op_type,
            uid,
            tree_path,
            keys,
            values,
            parent_change,
            user_previous_change,
            parent_clc,
        )
        .map(|change| change.entry)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("Failed to serialize ChangelogEntry")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChangelogError> {
        let (entry, trailing) = postcard::take_from_bytes(bytes).map_err(|e| {
            ChangelogError::Generic(format!("Failed to deserialize ChangelogEntry: {e}"))
        })?;

        if !trailing.is_empty() {
            return Err(ChangelogError::Generic(format!(
                "Failed to deserialize ChangelogEntry: {} trailing bytes",
                trailing.len()
            )));
        }

        Ok(entry)
    }

    pub fn pretty_print(&self) -> String {
        let path_str = std::str::from_utf8(&self.message.tree_path).unwrap_or("<invalid utf8>");

        let entries_str: Vec<String> = self
            .message
            .entries
            .iter()
            .map(|e| {
                let data_str = format!("value: {}", hex::encode(&e.value));
                format!("(key: {}, {})", hex::encode(&e.key), data_str)
            })
            .collect();

        format!(
            "ChangelogEntry {{\n  timestamp: {},\n  uid: {},\n  parent_change: {},\n  sig_ref: {},\n  op_type: {:?},\n  tree_path: \"{}\",\n  entries: [{}]\n}}",
            self.timestamp,
            self.uid,
            self.parent_change,
            self.sig_ref,
            self.message.op_type,
            path_str,
            entries_str.join(", ")
        )
    }
}

impl Default for ChangelogEntry {
    fn default() -> Self {
        ChangelogEntry {
            timestamp: 0,
            parent_change: 0,
            uid: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![KvData {
                    key: vec![],
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "<unknown panic>".to_string()
    }
}

struct PrunedTreeReader<'a> {
    tree: &'a merk::Node,
}

impl<'a> PrunedTreeReader<'a> {
    fn new(tree: &'a merk::Node) -> Self {
        Self { tree }
    }
}

impl crate::ops::OpReader for PrunedTreeReader<'_> {
    fn read(&mut self, op: crate::ReadOp) -> Result<crate::ProvenRead, ChangelogError> {
        read_from_pruned_tree(self.tree, op)
    }
}

fn read_from_pruned_tree(
    tree: &merk::Node,
    op: crate::ReadOp,
) -> Result<crate::ProvenRead, ChangelogError> {
    let results = match &op {
        crate::ReadOp::Key(key) => match ffproof_tracer_shared::lookup_value_verified(tree, key) {
            merk::GetResult::Found(value) => vec![(key.clone(), value)],
            merk::GetResult::NotFound => vec![],
            merk::GetResult::Pruned => {
                return Err(ChangelogError::Generic(format!(
                    "verify_proof: pruned tree witness is missing key {}",
                    hex::encode(key)
                )));
            }
        },
        crate::ReadOp::Prefix(prefix) => {
            let end = crate::prefix_successor(prefix);
            crate::collect_range(tree, prefix, end.as_deref())
        }
        crate::ReadOp::Range { start, end } => {
            crate::collect_range(tree, start, Some(end.as_slice()))
        }
    };
    Ok(crate::ProvenRead { op, results })
}

fn flatten_write_steps(
    result: crate::ops::OpVerifyResult,
) -> Result<Vec<crate::BatchOp>, ChangelogError> {
    let mut writes = Vec::new();
    for step in result.write_steps {
        match step {
            crate::TraceStep::Write(ops) => writes.extend(ops),
            crate::TraceStep::Read(_) => {
                return Err(ChangelogError::Generic(
                    "verify_proof: extract_and_validate emitted a Read in write_steps".to_string(),
                ));
            }
        }
    }
    Ok(writes)
}

impl ChangeLog {
    pub fn new(initial_data_commitment: &[u8; 32]) -> Self {
        let mut tree = MmrTree::new();
        tree.initialize(initial_data_commitment);
        let initial_root: [u8; 32] = tree
            .root()
            .expect("tree must be non-empty after initialize")
            .into();
        Self {
            tree,
            roots_by_change_id: vec![initial_root],
            proven_clc_state: None,
            initial_dc: *initial_data_commitment,
            changes: vec![],
            ff_proof: vec![],
            proven_up_to: 0,
            pruned_merkle_trees: vec![],
            inclusion_proof_cache: None,
            ff_inclusion_proof_cache: None,
        }
    }

    pub fn num_changes(&self) -> u32 {
        self.changes.len() as u32
    }

    pub fn validate_mmr_state(&self) -> Result<(), ChangelogError> {
        let expected_roots_len = self
            .changes
            .len()
            .checked_add(1)
            .ok_or_else(|| ChangelogError::Generic("ChangeLog length overflow".to_string()))?;
        if self.roots_by_change_id.len() != expected_roots_len {
            return Err(ChangelogError::Generic(format!(
                "ChangeLog root cache has length {}, expected {} for {} changes",
                self.roots_by_change_id.len(),
                expected_roots_len,
                self.changes.len()
            )));
        }
        if self.pruned_merkle_trees.len() != self.changes.len() {
            return Err(ChangelogError::Generic(format!(
                "ChangeLog pruned tree witness cache has length {}, expected {}",
                self.pruned_merkle_trees.len(),
                self.changes.len()
            )));
        }
        if self.proven_up_to > self.changes.len() {
            return Err(ChangelogError::Generic(format!(
                "ChangeLog proven_up_to {} exceeds changes length {}",
                self.proven_up_to,
                self.changes.len()
            )));
        }

        let mut replay_tree = MmrTree::new();
        replay_tree.initialize(&self.initial_dc);
        let initial_root: [u8; 32] = replay_tree
            .root()
            .expect("tree must be non-empty after initialize")
            .into();
        if self.roots_by_change_id[0] != initial_root {
            return Err(ChangelogError::Generic(
                "ChangeLog initial root does not match MmrTree::initialize(initial_dc)".to_string(),
            ));
        }

        // Track the head at proven_up_to as we replay, so we can
        // cross-check the cached `proven_clc_state`.
        let mut replay_head_at_proven: Option<ClcState> = None;

        for (idx, change) in self.changes.iter().enumerate() {
            replay_tree.append(&change.as_bytes());
            let replayed_root: [u8; 32] = replay_tree
                .root()
                .expect("tree must be non-empty after append")
                .into();
            let cached_root = self.roots_by_change_id[idx + 1];
            if cached_root != replayed_root {
                return Err(ChangelogError::Generic(format!(
                    "ChangeLog root at change_id {} does not match replayed entries",
                    idx + 1
                )));
            }
            if idx + 1 == self.proven_up_to {
                replay_head_at_proven = Some(
                    replay_tree
                        .tree_head()
                        .expect("tree must be non-empty after append"),
                );
            }
        }

        let expected_live_head = replay_tree
            .tree_head()
            .expect("tree must be non-empty after replay");
        let live_head = self.tree.tree_head().ok_or_else(|| {
            ChangelogError::Generic("ChangeLog live MMR tree is malformed".to_string())
        })?;
        if live_head != expected_live_head {
            return Err(ChangelogError::Generic(
                "ChangeLog live MMR tree does not match replayed entries".to_string(),
            ));
        }

        match (&self.proven_clc_state, &replay_head_at_proven) {
            (None, None) => {}
            (Some(cached), Some(expected)) if cached == expected => {}
            (Some(_), None) => {
                return Err(ChangelogError::Generic(
                    "ChangeLog has proven_clc_state cached but proven_up_to == 0".to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(ChangelogError::Generic(format!(
                    "ChangeLog is missing proven_clc_state for proven_up_to={}",
                    self.proven_up_to
                )));
            }
            _ => {
                return Err(ChangelogError::Generic(format!(
                    "ChangeLog proven_clc_state does not match replayed head at proven_up_to={}",
                    self.proven_up_to
                )));
            }
        }

        Ok(())
    }

    /// Root of the changelog after `change_id` real changes have been
    /// applied. `change_id == 0` returns the post-`initialize` root
    /// (the initial DC bound into the synthetic leaf at MMR position 0).
    pub fn root_at(&self, change_id: u32) -> Option<[u8; 32]> {
        self.roots_by_change_id.get(change_id as usize).copied()
    }

    /// `ClcState` (full peaks list) at MMR position 0: the post-
    /// `initialize` head, derived from `initial_dc`.
    pub fn initial_clc_state(&self) -> ClcState {
        initial_clc_state(&self.initial_dc)
    }

    /// Cached `ClcState` at `proven_up_to`. `None` while
    /// `proven_up_to == 0` (the head is then [`Self::initial_clc_state`]).
    pub fn proven_clc_state(&self) -> Option<ClcState> {
        self.proven_clc_state.clone()
    }

    /// Current writer-side `ClcState` (after the latest change).
    pub fn current_clc_state(&self) -> ClcState {
        self.tree
            .tree_head()
            .expect("ChangeLog tree is always initialized")
    }

    /// Current MMR root (after the latest change).
    pub fn current_root(&self) -> [u8; 32] {
        self.current_clc_state().root.into()
    }

    /// Verify root progression + pruned tree witness for a single change by
    /// re-running the op-specific `extract_and_validate` directly against
    /// the witness, then applying E&V's writes and checking the resulting
    /// root. Returns the per-op batch the server applied.
    pub fn verify_proof_and_validate(
        change: &ChangelogEntry,
        pruned_merkle_tree: &[u8],
        old_root: &[u8; 32],
        new_root: &[u8; 32],
        current_change_id: usize,
    ) -> Result<Vec<crate::BatchOp>, ChangelogError> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::verify_proof_and_validate_inner(
                change,
                pruned_merkle_tree,
                old_root,
                new_root,
                current_change_id,
            )
        }))
        .map_err(|payload| {
            ChangelogError::Generic(format!(
                "verify_proof: pruned tree witness verification panicked: {}",
                panic_payload_to_string(payload)
            ))
        })?
    }

    fn verify_proof_and_validate_inner(
        change: &ChangelogEntry,
        pruned_merkle_tree: &[u8],
        old_root: &[u8; 32],
        new_root: &[u8; 32],
        current_change_id: usize,
    ) -> Result<Vec<crate::BatchOp>, ChangelogError> {
        let pruned_tree = postcard::from_bytes::<crate::PrunedMerkleTree>(pruned_merkle_tree)
            .map_err(|e| {
                ChangelogError::Generic(format!(
                    "verify_proof: pruned tree proof deserialize failed: {e}"
                ))
            })?;

        if !validate_parent_change(change.parent_change, current_change_id) {
            return Err(ChangelogError::Generic(format!(
                "verify_proof: invalid parent_change={} for current_change_id={current_change_id}",
                change.parent_change
            )));
        }

        let mut tree = crate::pruned_to_merk(pruned_tree).ok_or_else(|| {
            ChangelogError::Generic("verify_proof: pruned tree witness is empty".to_string())
        })?;
        tree.commit();

        if tree.hash() != *old_root {
            return Err(ChangelogError::Generic(
                "verify_proof: start root mismatch".to_string(),
            ));
        }

        let mut reader = PrunedTreeReader::new(&tree);
        let ctx = crate::ops::OpContext::for_change_id(current_change_id);
        let op_result = crate::ops::dispatch_extract_and_validate(change, &mut reader, &ctx)?;
        let writes = flatten_write_steps(op_result)?;

        let mut maybe_tree = crate::apply_batch(Some(tree), &writes, merk::PanicSource {});
        let computed_end = match maybe_tree.as_mut() {
            Some(tree) => {
                tree.commit();
                tree.hash()
            }
            None => [0u8; 32],
        };
        if computed_end != *new_root {
            return Err(ChangelogError::Generic(
                "verify_proof: end root mismatch".to_string(),
            ));
        }

        Ok(writes)
    }

    // Add a new change.
    // Returns the assigned change_id (1-indexed).
    pub fn add_change(
        &mut self,
        change: &ChangelogEntry,
        pruned_merkle_tree: &[u8],
        old_root: &[u8; 32],
        new_root: &[u8; 32],
    ) -> Result<u32, ChangelogError> {
        // current_change_id is 1-indexed: this change becomes change #(len+1).
        let current_change_id = self.changes.len() + 1;
        Self::verify_proof_and_validate(
            change,
            pruned_merkle_tree,
            old_root,
            new_root,
            current_change_id,
        )?;

        let pruned_merkle_tree = PrunedMerkleTreeTriple {
            pruned_merkle_tree: pruned_merkle_tree.to_vec(),
            old_root: *old_root,
            new_root: *new_root,
        };

        self.tree.append(&change.as_bytes());
        let new_root: [u8; 32] = self
            .tree
            .root()
            .expect("tree must be non-empty after append")
            .into();
        self.roots_by_change_id.push(new_root);
        // Keep the inclusion-proof cache in sync if it has been built.
        // O(log n) hashes; no-op if the cache hasn't been materialised
        // yet (it'll be built lazily on the first proof request).
        if let Some(cache) = self.inclusion_proof_cache.as_mut() {
            cache.extend_with_leaf(h_leaf(&change.as_bytes()));
        }
        self.changes.push(change.clone());
        self.pruned_merkle_trees.push(pruned_merkle_tree);

        Ok(self.changes.len() as u32)
    }

    /// Generate an MMR inclusion proof for `change_id`.
    ///
    /// `change_id` is the MMR leaf index: position 0 is the synthetic
    /// initial leaf carrying `initial_dc`, and position `k` (for
    /// `k >= 1`) is the (k-1)-th real change in `changes`. Returns
    /// `None` when `change_id` is out of range (i.e. exceeds
    /// `changes.len()`).
    ///
    /// The first call lazily builds an in-memory proof cache from
    /// `(initial_dc, changes)` in O(n log n) hashes; subsequent calls
    /// are O(log n) lookups with zero hashing. The cache is maintained
    /// incrementally on every [`ChangeLog::add_change`] (O(log n) per
    /// append) and is never serialised.
    pub fn prove_inclusion(&mut self, change_id: u32) -> Option<InclusionProof> {
        // tree_size = initial leaf + real changes; range-check before
        // touching the cache so callers get a clean `None` for OOB.
        let total_leaves = u32::try_from(self.changes.len().checked_add(1)?).ok()?;
        if change_id >= total_leaves {
            return None;
        }
        self.ensure_inclusion_proof_cache_built();
        self.inclusion_proof_cache
            .as_ref()
            .expect("inclusion_proof_cache built above")
            .prove(change_id)
    }

    /// Build the inclusion-proof cache from `(initial_dc, changes)` if it
    /// hasn't been built, has the wrong leaf count, or has gone
    /// content-stale (e.g. due to an in-place mutation of the `pub
    /// changes` field that bypassed [`ChangeLog::add_change`]).
    /// Idempotent and inexpensive when already current — the
    /// content check is a single `HashMap` lookup and a digest compare.
    fn ensure_inclusion_proof_cache_built(&mut self) {
        // tree_size = changes.len() + 1 (initial leaf + real changes).
        let expected_leaves = (self.changes.len() as u64) + 1;
        let live_root = self.tree.root();
        let needs_rebuild = inclusion_proof_cache_needs_rebuild(
            self.inclusion_proof_cache.as_ref(),
            expected_leaves,
            live_root,
        );
        if !needs_rebuild {
            return;
        }
        self.inclusion_proof_cache =
            Some(build_inclusion_proof_cache(&self.initial_dc, &self.changes));
    }

    /// Prove that `change_id` is included in the current FF-proven
    /// range. The resulting proof covers the prefix through
    /// `proven_up_to` and verifies against [`Self::proven_clc_state`]
    /// (or [`Self::initial_clc_state`] when `proven_up_to == 0`).
    ///
    /// Used by the FF transport to bind a client's prior position
    /// (`from_change_id`) and the FF-proof end position
    /// (`end_change_id == proven_up_to`) into the FF response so the
    /// client can detect branch substitutions at FF time. Returns
    /// `None` when `change_id > proven_up_to`.
    ///
    /// First call after reload (or on a fresh `ChangeLog`) lazily
    /// builds the FF inclusion-proof cache from
    /// `(initial_dc, changes[0..proven_up_to])` in O(p log p) hashes;
    /// subsequent calls are O(log p) lookups with zero hashing. The
    /// cache is maintained incrementally inside
    /// [`ChangeLog::set_ff_proof`] (O((new - old) * log p) per FF
    /// boundary advance).
    pub fn prove_included_in_ff_range(&mut self, change_id: u32) -> Option<InclusionProof> {
        let ff_range_leaves = u32::try_from(self.proven_up_to.checked_add(1)?).ok()?;
        if change_id >= ff_range_leaves {
            return None;
        }
        self.ensure_ff_inclusion_proof_cache_built();
        self.ff_inclusion_proof_cache
            .as_ref()
            .expect("ff_inclusion_proof_cache built above")
            .prove(change_id)
    }

    /// Build the inclusion-proof cache for the current FF-proven range from
    /// `(initial_dc, changes[0..proven_up_to])` if it hasn't been built,
    /// has the wrong leaf count, or has gone content-stale. Idempotent
    /// and inexpensive when already current.
    fn ensure_ff_inclusion_proof_cache_built(&mut self) {
        let expected_leaves = (self.proven_up_to as u64) + 1;
        // Root for the FF-proven range: explicit cache when `proven_up_to > 0`,
        // otherwise derived from initial_dc.
        let ff_range_root = self
            .proven_clc_state
            .as_ref()
            .map(|h| h.root)
            .unwrap_or_else(|| initial_clc_state(&self.initial_dc).root);
        let needs_rebuild = inclusion_proof_cache_needs_rebuild(
            self.ff_inclusion_proof_cache.as_ref(),
            expected_leaves,
            Some(ff_range_root),
        );
        if !needs_rebuild {
            return;
        }
        self.ff_inclusion_proof_cache = Some(build_inclusion_proof_cache(
            &self.initial_dc,
            &self.changes[..self.proven_up_to],
        ));
    }

    pub fn get_number_unproven_changes(&self) -> usize {
        assert!(self.proven_up_to <= self.changes.len());

        self.changes.len() - self.proven_up_to
    }

    pub fn get_unproven_changes(&self) -> Vec<ChangelogEntry> {
        self.changes[self.proven_up_to..].to_vec()
    }

    /// Set the FF proof after it's been generated externally (e.g., by prove_ff in prover.rs)
    /// This avoids circular dependencies between changelog_core and ffproof crates.
    ///
    /// Advances `proven_clc_state` by replaying the newly-proven entries
    /// on top of the previous snapshot (or the post-`initialize` head if
    /// `proven_up_to` was 0). The replay is O((new - old) * log N) and
    /// runs only at FF-proof boundaries.
    ///
    /// `new_proven_up_to` must be strictly greater than the current
    /// `proven_up_to`: `set_ff_proof` is the only path that advances the
    /// proven boundary, and re-storing a proof at the same position has
    /// no defined meaning.
    ///
    /// # Arguments
    /// * `proof_bytes` - The serialized FFProof
    /// * `new_proven_up_to` - The new value for proven_up_to (typically self.changes.len())
    pub fn set_ff_proof(&mut self, proof_bytes: Vec<u8>, new_proven_up_to: usize) {
        assert!(
            new_proven_up_to <= self.changes.len(),
            "new_proven_up_to ({}) cannot exceed changes.len() ({})",
            new_proven_up_to,
            self.changes.len()
        );
        assert!(
            new_proven_up_to > self.proven_up_to,
            "new_proven_up_to ({}) must strictly advance proven_up_to ({})",
            new_proven_up_to,
            self.proven_up_to
        );

        let mut head = self
            .proven_clc_state
            .clone()
            .unwrap_or_else(|| initial_clc_state(&self.initial_dc));
        for change in &self.changes[self.proven_up_to..new_proven_up_to] {
            head.append(&change.as_bytes());
        }
        self.proven_clc_state = Some(head);

        // Mirror the head update on the FF inclusion-proof cache:
        // initialise from the synthetic initial leaf if absent (i.e.
        // first FF chunk; previous `proven_up_to == 0`), then extend
        // with each newly-proven entry. O((new - old) * log n) hashes.
        // The cache then covers `new_proven_up_to + 1` leaves and
        // can answer inclusion proofs for any `change_id` in
        // `[0, new_proven_up_to]` against `proven_clc_state`.
        let mut ff_range_idx = self
            .ff_inclusion_proof_cache
            .take()
            .unwrap_or_else(|| inclusion_proof_cache_with_initial_leaf(&self.initial_dc));
        for change in &self.changes[self.proven_up_to..new_proven_up_to] {
            ff_range_idx.extend_with_leaf(h_leaf(&change.as_bytes()));
        }
        self.ff_inclusion_proof_cache = Some(ff_range_idx);

        self.ff_proof = proof_bytes;
        self.proven_up_to = new_proven_up_to;
    }

    /// Get the current FF proof bytes, if any
    pub fn get_ff_proof(&self) -> Option<&[u8]> {
        if self.ff_proof.is_empty() {
            None
        } else {
            Some(&self.ff_proof)
        }
    }

    /// Get a logical tail of the changelog starting from `start_idx`,
    /// suitable for feeding to the FF prover. The returned
    /// [`ChangeLogTail`] holds matched slices of `changes` and
    /// `pruned_merkle_trees`; it deliberately does not pretend to be a
    /// self-consistent [`ChangeLog`] — callers (the FF prover) supply the
    /// correct `start_clc_state` separately.
    pub fn get_tail(&self, start_idx: usize) -> ChangeLogTail {
        assert!(
            start_idx <= self.changes.len(),
            "start_idx ({}) cannot exceed changes.len() ({})",
            start_idx,
            self.changes.len()
        );

        ChangeLogTail {
            initial_dc: self.initial_dc,
            changes: self.changes[start_idx..].to_vec(),
            pruned_merkle_trees: self.pruned_merkle_trees[start_idx..].to_vec(),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("Failed to serialize ChangeLog")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChangelogError> {
        let changelog: Self = postcard::from_bytes(bytes).map_err(|e| {
            ChangelogError::Generic(format!("Failed to deserialize ChangeLog: {e}"))
        })?;
        changelog.validate_mmr_state()?;
        Ok(changelog)
    }
}

/// Maximum distance, in changes, between an entry's `parent_change`
/// and its own `current_change_id`. Enforced identically by:
///
/// - The FF guest (`verify_op_sequence` / [`validate_parent_change`]).
/// - The server submission path (`backend/server/src/db.rs`).
/// - The client SDK pre-sign / retry-on-stale logic.
///
/// One constant, one source of truth: a divergence between these three
/// would either accept entries the FF proof later rejects (server too
/// lax) or reject legitimate entries (server/client too strict).
///
/// The window also bounds the per-chunk `recent_roots` journal payload
/// in [`FastForwardRange`] at `MAX_PARENT_DISTANCE * 36` bytes.
pub const MAX_PARENT_DISTANCE: u32 = 10;

/// Sanity check on `parent_change`: every change must reference a
/// strictly earlier change_id (or `0` for the very first change), AND
/// must be at most [`MAX_PARENT_DISTANCE`] changes behind
/// `current_change_id`.
///
/// The window check matches the FF-proof side (sliding `recent_roots`
/// window) and the server submission side, so an entry that fails this
/// check would also fail proof verification, and vice versa.
pub fn validate_parent_change(parent_change: u32, current_change_id: usize) -> bool {
    let in_bounds = if current_change_id == 1 {
        parent_change == 0
    } else {
        (parent_change as usize) < current_change_id
    };
    if !in_bounds {
        return false;
    }
    let distance = current_change_id.saturating_sub(parent_change as usize);
    distance <= MAX_PARENT_DISTANCE as usize
}

/// Validate one entry's `parent_clc` against the proven root for its
/// `parent_change`. The caller maintains `recent_roots` as a sliding
/// window of `(change_id, root)` pairs covering the legal window.
///
/// Returns `true` if the entry's `parent_clc` matches the root recorded
/// for `entry.parent_change`. Returns `false` if the lookup fails (the
/// window does not contain a root for `parent_change`) or the root
/// disagrees with the signed `parent_clc`.
///
/// A `false` return here typically indicates either a malicious prover
/// (signed `parent_clc` doesn't match the proven chain — see issue 30)
/// or a stale entry that slipped past `validate_parent_change`.
pub fn validate_parent_clc(
    parent_change: u32,
    parent_clc: &[u8; 32],
    recent_roots: &[(u32, [u8; 32])],
) -> bool {
    match recent_roots.iter().find(|(cid, _)| *cid == parent_change) {
        Some((_, root)) => {
            if root != parent_clc {
                println!(
                    "parent_clc mismatch: parent_change={parent_change}, claimed={}, expected={}",
                    hex::encode(parent_clc),
                    hex::encode(root)
                );
                false
            } else {
                true
            }
        }
        None => {
            println!(
                "parent_clc lookup failed: no root in window for parent_change={parent_change} \
                 (window has {} entries)",
                recent_roots.len()
            );
            false
        }
    }
}

/// Validate one step of the sigref chain for a single change.
/// Returns `true` if valid, `false` if the chain is broken.
/// On success, updates `sigref_map[uid] = (current_change_id, entry_hash)`.
///
/// `entry_hash` is the domain-tagged leaf hash of the change's entry
/// bytes (`h_leaf(entry_bytes)`). Committing it in the journal lets
/// downstream verifiers confirm that the entry they signature-check is
/// the same one the FF guest processed.
///
/// This is the FF-guest variant: it owns the full
/// `(change_id, entry_hash)` map and advances it on success. The
/// single-step, caller-driven counterpart used by the server and SDK at
/// submission time is [`check_sigref_continuity`]; both encode the same
/// invariant.
pub fn validate_sigref(
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    uid: u32,
    sig_ref: u32,
    current_change_id: u32,
    entry_hash: [u8; 32],
) -> bool {
    match sigref_map.get(&uid) {
        Some(&(prev_change_id, _)) => {
            if sig_ref != prev_change_id {
                println!(
                    "Sigref chain broken at change {current_change_id}: \
                     uid={uid}, expected sig_ref={prev_change_id}, got sig_ref={sig_ref}"
                );
                return false;
            }
        }
        None => {
            if sig_ref != 0 {
                println!(
                    "Sigref chain broken at change {current_change_id}: \
                     uid={uid} has no prior change, expected sig_ref=0, got sig_ref={sig_ref}"
                );
                return false;
            }
        }
    }
    sigref_map.insert(uid, (current_change_id, entry_hash));
    true
}

/// Enforce the sigref-chain invariant for a single change against a
/// caller-supplied `expected_sig_ref`.
///
/// `expected_sig_ref` is the change_id of the signer's previous accepted
/// change, or `0` if the signer has never written before. A fresh user
/// must have `sig_ref == 0`; every subsequent change by the same user
/// must point at that user's previously accepted change_id.
///
/// This is the single-step, caller-driven counterpart to
/// [`validate_sigref`]: callers maintain their own `uid -> last_change_id`
/// view (the server's `SpaceState::sigref_map`, the SDK's
/// `ChangelogState::sigref_map`) and use this helper before mutating
/// state. Closes the post-FF / pre-next-FF window where the per-user
/// chain is otherwise only checked inside the FF guest (issue #30).
pub fn check_sigref_continuity(
    change: &ChangelogEntry,
    expected_sig_ref: u32,
) -> Result<(), ChangelogError> {
    if change.sig_ref != expected_sig_ref {
        return Err(ChangelogError::Generic(format!(
            "Sigref chain broken for uid {}: expected sig_ref={expected_sig_ref}, got {}",
            change.uid, change.sig_ref
        )));
    }
    Ok(())
}

/// Verify a sequence of changes using a pruned tree witness.
///
/// # Arguments
/// * `entries` - Serialized `ChangelogEntry` bytes, one per change in the chunk
/// * `range` - The FastForwardRange identifying the range of changes
/// * `pruned_tree_bytes` - Postcard-serialized `PrunedMerkleTree` covering all changes
/// * `start_change_id` - The absolute change ID of the first change in this batch
///   (0 for the first proof, `previous_io.end_change_id` for subsequent proofs)
/// * `sigref_map` - Per-user sigref state, threaded across recursive chunks
/// * `recent_roots` - Sliding window of recent `(change_id, root)` pairs, used
///   to validate each entry's `parent_clc`. Threaded across recursive chunks.
///   For first chunks (`start_change_id == 0`), the caller passes an empty
///   `Vec` and the guest seeds with `(0, start_clc_state.root)`. For
///   extension chunks, the caller passes `previous_io.recent_roots`, whose
///   last entry must be `(start_change_id, start_clc_state.root)`.
/// * `timestamp_hwm` - Timestamp high-water mark threaded across recursive chunks.
#[allow(clippy::too_many_arguments)]
pub fn verify_op_sequence(
    entries: &[Vec<u8>],
    range: &FastForwardRange,
    pruned_tree_bytes: &[u8],
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
) -> bool {
    verify_op_sequence_inner(
        &VecEntryBytes(entries),
        range,
        pruned_tree_bytes,
        start_change_id,
        sigref_map,
        recent_roots,
        timestamp_hwm,
    )
}

// ─── Bench-timing infrastructure ─────────────────────────────────────────────

#[cfg(feature = "bench-timing")]
#[derive(Default, serde::Serialize, serde::Deserialize, Debug)]
pub struct VerificationLoopTimings {
    pub value_cache_check_cycles: u64,
    pub pruned_tree_cycles: u64,
    pub pruned_tree_decode_cycles: u64,
    pub pruned_tree_rebuild_cycles: u64,
    pub pruned_tree_commit_cycles: u64,
    pub pruned_tree_root_check_cycles: u64,
    pub entry_decode_cycles: u64,
    pub sigref_parent_cycles: u64,
    pub extract_validate_cycles: u64,
    pub reader_read_cycles: u64,
    pub reader_read_ops: u64,
    pub reader_read_key_ops: u64,
    pub reader_read_range_ops: u64,
    pub reader_read_prefix_ops: u64,
    pub write_prepare_cycles: u64,
    pub overlay_apply_cycles: u64,
    pub normalize_cycles: u64,
    pub final_replay_cycles: u64,
    pub table_sorted_cycles: u64,
    pub table_key_parse_cycles: u64,
    pub table_id_cycles: u64,
    pub table_user_access_cycles: u64,
    pub table_schema_cycles: u64,
    pub table_row_presence_cycles: u64,
    pub table_acl_load_cycles: u64,
    pub table_acl_value_cycles: u64,
    pub table_acl_eval_cycles: u64,
    pub table_value_encode_cycles: u64,
    pub table_index_cycles: u64,
    pub table_batch_build_cycles: u64,
}

#[cfg(feature = "bench-timing")]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct FastForwardJournal {
    pub output: FastForwardRange,
    pub guest_deserialize_cycles: u64,
    pub guest_recursive_verify_cycles: u64,
    pub loop_timings: VerificationLoopTimings,
}

#[cfg(feature = "bench-timing")]
struct TimedPrunedTreeReader<'a> {
    inner: PrunedTreeReader<'a>,
    cycle_count: fn() -> u64,
    read_cycles: u64,
    read_ops: u64,
    key_ops: u64,
    range_ops: u64,
    prefix_ops: u64,
}

#[cfg(feature = "bench-timing")]
impl<'a> TimedPrunedTreeReader<'a> {
    fn new(tree: &'a merk::Node, cycle_count: fn() -> u64) -> Self {
        Self {
            inner: PrunedTreeReader::new(tree),
            cycle_count,
            read_cycles: 0,
            read_ops: 0,
            key_ops: 0,
            range_ops: 0,
            prefix_ops: 0,
        }
    }

    fn drain_into(&self, timings: &mut VerificationLoopTimings) {
        timings.reader_read_cycles += self.read_cycles;
        timings.reader_read_ops += self.read_ops;
        timings.reader_read_key_ops += self.key_ops;
        timings.reader_read_range_ops += self.range_ops;
        timings.reader_read_prefix_ops += self.prefix_ops;
    }
}

#[cfg(feature = "bench-timing")]
impl crate::ops::OpReader for TimedPrunedTreeReader<'_> {
    fn read(&mut self, op: crate::ReadOp) -> Result<crate::ProvenRead, ChangelogError> {
        self.read_ops += 1;
        match &op {
            crate::ReadOp::Key(_) => self.key_ops += 1,
            crate::ReadOp::Range { .. } => self.range_ops += 1,
            crate::ReadOp::Prefix(_) => self.prefix_ops += 1,
        }
        let t0 = (self.cycle_count)();
        let result = self.inner.read(op);
        let t1 = (self.cycle_count)();
        self.read_cycles += t1 - t0;
        result
    }
}

#[cfg(feature = "bench-timing")]
/// Verify a sequence while collecting cycle timings.
///
/// `pruned_tree_bytes` must be encoded with `encode_pruned_compact`; the
/// non-flat pure verifier keeps using postcard-encoded `PrunedMerkleTree` bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_op_sequence_timed(
    entries: &[Vec<u8>],
    range: &FastForwardRange,
    pruned_tree_bytes: &[u8],
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
    cycle_count: fn() -> u64,
) -> (bool, VerificationLoopTimings) {
    verify_op_sequence_timed_inner(
        &VecEntryBytes(entries),
        range,
        pruned_tree_bytes,
        start_change_id,
        sigref_map,
        recent_roots,
        timestamp_hwm,
        cycle_count,
    )
}

impl ChangeResponse {
    pub fn to_bytes(responses: &Vec<ChangeResponse>) -> Vec<u8> {
        postcard::to_allocvec(responses).expect("Failed to serialize Vec<ChangeResponse>")
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Vec<ChangeResponse>, &'static str> {
        postcard::from_bytes(bytes).map_err(|_| "Failed to deserialize Vec<ChangeResponse>")
    }
}

// ─── Flat entry byte blob ───────────────────────────────────────────────────

pub struct FlatEntryBytes<'a> {
    bytes: &'a [u8],
    entry_ends: &'a [u32],
}

impl<'a> FlatEntryBytes<'a> {
    pub fn new(bytes: &'a [u8], entry_ends: &'a [u32]) -> Result<Self, ChangelogError> {
        let mut prev: u32 = 0;
        for (i, &end) in entry_ends.iter().enumerate() {
            if end < prev {
                return Err(ChangelogError::Generic(format!(
                    "FlatEntryBytes: non-monotonic offset at index {i}: {end} < {prev}"
                )));
            }
            prev = end;
        }
        if let Some(&last) = entry_ends.last() {
            if last as usize != bytes.len() {
                return Err(ChangelogError::Generic(format!(
                    "FlatEntryBytes: last offset {} != bytes.len() {}",
                    last,
                    bytes.len()
                )));
            }
        } else if !bytes.is_empty() {
            return Err(ChangelogError::Generic(
                "FlatEntryBytes: no offsets but non-empty bytes".to_string(),
            ));
        }
        Ok(Self { bytes, entry_ends })
    }

    pub fn len(&self) -> usize {
        self.entry_ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entry_ends.is_empty()
    }

    pub fn entry(&self, index: usize) -> Option<&'a [u8]> {
        if index >= self.entry_ends.len() {
            return None;
        }
        let start = if index == 0 {
            0
        } else {
            self.entry_ends[index - 1] as usize
        };
        let end = self.entry_ends[index] as usize;
        Some(&self.bytes[start..end])
    }
}

trait EntryByteSequence {
    fn len(&self) -> usize;
    fn entry(&self, index: usize) -> Option<&[u8]>;
}

struct VecEntryBytes<'a>(&'a [Vec<u8>]);

impl EntryByteSequence for VecEntryBytes<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn entry(&self, index: usize) -> Option<&[u8]> {
        self.0.get(index).map(|v| v.as_slice())
    }
}

impl EntryByteSequence for FlatEntryBytes<'_> {
    fn len(&self) -> usize {
        self.len()
    }
    fn entry(&self, index: usize) -> Option<&[u8]> {
        self.entry(index)
    }
}

// ─── Fast ChangelogEntry decoder ────────────────────────────────────────────

struct EntryDecoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> EntryDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ChangelogError> {
        if self.offset + len > self.input.len() {
            return Err(ChangelogError::Generic(
                "EntryDecoder: unexpected end of input".to_string(),
            ));
        }
        let slice = &self.input[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    fn read_varint_u32(&mut self) -> Result<u32, ChangelogError> {
        let mut result: u32 = 0;
        let mut shift: u32 = 0;
        loop {
            if self.offset >= self.input.len() {
                return Err(ChangelogError::Generic(
                    "EntryDecoder: varint extends past end of input".to_string(),
                ));
            }
            let byte = self.input[self.offset];
            self.offset += 1;
            result |= ((byte & 0x7F) as u32) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 35 {
                return Err(ChangelogError::Generic(
                    "EntryDecoder: varint too long for u32".to_string(),
                ));
            }
        }
    }

    fn read_varint_u64(&mut self) -> Result<u64, ChangelogError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if self.offset >= self.input.len() {
                return Err(ChangelogError::Generic(
                    "EntryDecoder: varint extends past end of input".to_string(),
                ));
            }
            let byte = self.input[self.offset];
            self.offset += 1;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 70 {
                return Err(ChangelogError::Generic(
                    "EntryDecoder: varint too long for u64".to_string(),
                ));
            }
        }
    }

    fn read_len(&mut self) -> Result<usize, ChangelogError> {
        let v = self.read_varint_u32()?;
        Ok(v as usize)
    }

    fn read_vec_u8(&mut self) -> Result<Vec<u8>, ChangelogError> {
        let len = self.read_len()?;
        let data = self.take(len)?;
        Ok(data.to_vec())
    }

    fn skip_vec_u8(&mut self) -> Result<(), ChangelogError> {
        let len = self.read_len()?;
        let _ = self.take(len)?;
        Ok(())
    }

    fn read_array_32(&mut self) -> Result<[u8; 32], ChangelogError> {
        let data = self.take(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(data);
        Ok(arr)
    }

    fn finish(self) -> Result<(), ChangelogError> {
        if self.offset != self.input.len() {
            return Err(ChangelogError::Generic(format!(
                "EntryDecoder: {} trailing bytes",
                self.input.len() - self.offset,
            )));
        }
        Ok(())
    }
}

impl ChangelogEntry {
    pub fn from_bytes_for_verification(bytes: &[u8]) -> Result<Self, ChangelogError> {
        Self::decode_from_bytes(bytes, false)
    }

    fn decode_from_bytes(bytes: &[u8], include_signature: bool) -> Result<Self, ChangelogError> {
        let mut d = EntryDecoder::new(bytes);

        let timestamp = d.read_varint_u64()?;
        let uid = d.read_varint_u32()?;
        let parent_change = d.read_varint_u32()?;

        // message.op_type: enum variant index
        let op_type_u32 = d.read_varint_u32()?;
        if op_type_u32 > u8::MAX as u32 {
            return Err(ChangelogError::Generic(format!(
                "OpType variant {op_type_u32} out of range"
            )));
        }
        let op_type = OpType::from_u8(op_type_u32 as u8).ok_or_else(|| {
            ChangelogError::Generic(format!("Unknown OpType variant: {op_type_u32}"))
        })?;

        // message.tree_path
        let tree_path = d.read_vec_u8()?;

        // message.entries: Vec<KvData>
        let entries_len = d.read_len()?;
        let mut entries = Vec::with_capacity(entries_len);
        for _ in 0..entries_len {
            let key = d.read_vec_u8()?;
            let value = d.read_vec_u8()?;
            entries.push(KvData { key, value });
        }

        let sig_ref = d.read_varint_u32()?;
        let parent_clc = d.read_array_32()?;

        let signature = if include_signature {
            d.read_vec_u8()?
        } else {
            d.skip_vec_u8()?;
            Vec::new()
        };

        d.finish()?;

        Ok(ChangelogEntry {
            timestamp,
            uid,
            parent_change,
            message: LogMessage {
                op_type,
                tree_path,
                entries,
            },
            sig_ref,
            parent_clc,
            signature,
        })
    }
}

// ─── Internal verify helper using EntryByteSequence ─────────────────────────

fn verify_op_sequence_inner(
    entries: &dyn EntryByteSequence,
    range: &FastForwardRange,
    pruned_tree_bytes: &[u8],
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
) -> bool {
    verify_op_sequence_with_tree(
        entries,
        range,
        decode_postcard_pruned_tree(pruned_tree_bytes),
        start_change_id,
        sigref_map,
        recent_roots,
        timestamp_hwm,
    )
}

fn decode_postcard_pruned_tree(pruned_tree_bytes: &[u8]) -> Option<merk::Node> {
    let pruned_tree: crate::PrunedMerkleTree = match postcard::from_bytes(pruned_tree_bytes) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to deserialize pruned tree: {:?}", e);
            return None;
        }
    };

    match crate::pruned_to_merk(pruned_tree) {
        Some(t) => Some(t),
        None => {
            println!("Failed to verify: pruned tree is empty");
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_op_sequence_with_tree(
    entries: &dyn EntryByteSequence,
    range: &FastForwardRange,
    tree: Option<merk::Node>,
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
) -> bool {
    use merk::PanicSource;

    let Some(mut tree) = tree else {
        return false;
    };

    let start_idx: u32 = 0;
    let end_idx = range.end_change_id;
    let start_dc = range.start_dc;
    let end_dc = range.end_dc;
    let start_dc_bytes: [u8; 32] = start_dc.as_bytes().try_into().unwrap();
    let end_dc_bytes: [u8; 32] = end_dc.as_bytes().try_into().unwrap();

    if !range.start_clc_state.verify_for_change_id(start_change_id) {
        println!(
            "FastForwardRange.start_clc_state is inconsistent with start_change_id={}",
            start_change_id
        );
        return false;
    }
    if start_change_id == 0 && range.start_clc_state != initial_clc_state(&start_dc_bytes) {
        println!("FastForwardRange.start_clc_state does not match MmrTree::initialize(start_dc)");
        return false;
    }

    // Sanity-check and setup the recent_roots sliding window. The last entry
    // must always be `(start_change_id, start_clc_state.root)`: in first
    // chunks the guest pushes it on an empty seed; in extension chunks
    // the previous proof's output already ends with this pair.
    let start_root: [u8; 32] = range.start_clc_state.root.as_bytes().try_into().unwrap();
    match recent_roots.last().copied() {
        Some((last_cid, last_root)) => {
            if last_cid != start_change_id || last_root != start_root {
                println!(
                    "recent_roots last entry ({last_cid}) does not match start_change_id \
                     ({start_change_id}) or start_clc_state.root"
                );
                return false;
            }
        }
        None => {
            if start_change_id != 0 {
                println!(
                    "recent_roots must be non-empty for extension chunks \
                     (start_change_id={start_change_id})"
                );
                return false;
            }
            recent_roots.push((0, start_root));
        }
    }

    let chunk_len: u32 = entries.len().try_into().unwrap();
    assert!(start_idx < end_idx);
    assert!(start_idx < chunk_len);
    assert!(end_idx <= chunk_len);

    let expected_end_tree_size = range
        .start_clc_state
        .tree_size
        .checked_add(chunk_len)
        .expect("tree_size overflow");
    if !range
        .end_clc_state
        .verify_for_tree_size(expected_end_tree_size)
    {
        println!(
            "FastForwardRange.end_clc_state is inconsistent: tree_size {} != start ({}) + chunk_len ({}), or peaks/root malformed",
            range.end_clc_state.tree_size, range.start_clc_state.tree_size, chunk_len
        );
        return false;
    }

    tree.commit();
    if tree.hash() != start_dc_bytes {
        println!("Failed to verify: computed start root does not match");
        return false;
    }

    let mut working_tree = MmrTree {
        peaks: range.start_clc_state.peaks.clone(),
        tree_size: range.start_clc_state.tree_size,
    };

    let mut ctx = crate::ops::OpContext::for_change_sequence();

    for i in (start_idx as usize)..(end_idx as usize) {
        let current_change_id = start_change_id as usize + i + 1;

        let e_i = entries.entry(i).expect("entry index out of bounds");
        let leaf_hash = working_tree.append(e_i);

        let entry_i = match ChangelogEntry::from_bytes_for_verification(e_i) {
            Ok(m) => m,
            Err(e) => {
                println!("Failed to verify changes; Changelog entry didn't parse {e:?}");
                return false;
            }
        };

        if !validate_timestamp_hwm(entry_i.timestamp, timestamp_hwm) {
            println!(
                "Failed to verify changes; entry {current_change_id} timestamp {} is older than HWM {} by more than {TIMESTAMP_HWM_TOLERANCE_SECONDS}s",
                entry_i.timestamp, *timestamp_hwm
            );
            return false;
        }

        if !validate_sigref(
            sigref_map,
            entry_i.uid,
            entry_i.sig_ref,
            current_change_id as u32,
            (*leaf_hash.as_bytes())
                .try_into()
                .expect("digest is 32 bytes"),
        ) {
            return false;
        }

        if !validate_parent_change(entry_i.parent_change, current_change_id) {
            println!(
                "Failed to verify changes; entry {current_change_id} has invalid \
                 parent_change={} (current_change_id={current_change_id}, \
                 MAX_PARENT_DISTANCE={MAX_PARENT_DISTANCE})",
                entry_i.parent_change
            );
            return false;
        }

        // Validate parent_clc against the sliding window. This binds the
        // signed entry to the proven chain prefix; without it a malicious
        // server could splice signed entries from a divergent fork into
        // the proven chain
        if !validate_parent_clc(entry_i.parent_change, &entry_i.parent_clc, recent_roots) {
            println!(
                "Failed to verify changes; entry {current_change_id} has invalid \
                 parent_clc for parent_change={}",
                entry_i.parent_change
            );
            return false;
        }

        let mut reader = PrunedTreeReader::new(&tree);
        ctx.begin_change(current_change_id);
        let op_result = match crate::ops::dispatch_extract_and_validate(&entry_i, &mut reader, &ctx)
        {
            Ok(r) => r,
            Err(e) => {
                println!("Op validation failed at entry {current_change_id}: {e}");
                return false;
            }
        };

        let writes = match flatten_write_steps(op_result) {
            Ok(w) => w,
            Err(e) => {
                println!("Op at entry {current_change_id} produced invalid writes: {e}");
                return false;
            }
        };
        let maybe_tree = crate::apply_batch(Some(tree), &writes, PanicSource {});
        tree = match maybe_tree {
            Some(t) => t,
            None => {
                println!("Tree became empty after entry {current_change_id}");
                return false;
            }
        };

        ctx.finish_change(entry_i.message.op_type);

        // Push the post-append root into the sliding window, then prune
        // from the front so the window holds at most MAX_PARENT_DISTANCE
        // entries.
        let root_after: [u8; 32] = working_tree
            .root()
            .expect("working_tree non-empty after append")
            .as_bytes()
            .try_into()
            .expect("digest is 32 bytes");
        recent_roots.push((current_change_id as u32, root_after));
        while recent_roots.len() > MAX_PARENT_DISTANCE as usize {
            recent_roots.remove(0);
        }
    }

    tree.commit();
    if tree.hash() != end_dc_bytes {
        println!("Failed to verify changes; ending data root does not match");
        return false;
    }

    let computed_end = working_tree
        .tree_head()
        .expect("working tree must be non-empty after replay");
    if computed_end != range.end_clc_state {
        println!("Failed to verify changes; ending tree head does not match replay");
        return false;
    }

    true
}

/// Verify flat entry bytes with compact pruned witness bytes.
///
/// This is the production guest input shape. `pruned_tree_bytes` must be
/// encoded with `encode_pruned_compact`.
#[allow(clippy::too_many_arguments)]
pub fn verify_op_sequence_flat(
    entries: FlatEntryBytes<'_>,
    range: &FastForwardRange,
    pruned_tree_bytes: &[u8],
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
) -> bool {
    verify_op_sequence_compact_inner(
        &entries,
        range,
        pruned_tree_bytes,
        start_change_id,
        sigref_map,
        recent_roots,
        timestamp_hwm,
    )
}

fn decode_compact_pruned_tree(pruned_tree_bytes: &[u8]) -> Option<merk::Node> {
    match crate::decode_pruned_compact_to_merk(pruned_tree_bytes) {
        Ok(Some(t)) => Some(t),
        Ok(None) => {
            println!("Failed to verify: pruned tree is empty");
            None
        }
        Err(e) => {
            println!("Failed to decode compact pruned tree into Merk: {:?}", e);
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_op_sequence_compact_inner(
    entries: &dyn EntryByteSequence,
    range: &FastForwardRange,
    pruned_tree_bytes: &[u8],
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
) -> bool {
    verify_op_sequence_with_tree(
        entries,
        range,
        decode_compact_pruned_tree(pruned_tree_bytes),
        start_change_id,
        sigref_map,
        recent_roots,
        timestamp_hwm,
    )
}

// ─── Timed flat verification loop ──────────────────────────────────────────

#[cfg(feature = "bench-timing")]
#[allow(clippy::too_many_arguments)]
fn verify_op_sequence_timed_inner(
    entries: &dyn EntryByteSequence,
    range: &FastForwardRange,
    pruned_tree_bytes: &[u8],
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
    cycle_count: fn() -> u64,
) -> (bool, VerificationLoopTimings) {
    use merk::PanicSource;

    let mut timings = VerificationLoopTimings::default();

    let start_idx: u32 = 0;
    let end_idx = range.end_change_id;
    let start_dc = range.start_dc;
    let end_dc = range.end_dc;
    let start_dc_bytes: [u8; 32] = start_dc.as_bytes().try_into().unwrap();
    let end_dc_bytes: [u8; 32] = end_dc.as_bytes().try_into().unwrap();

    if !range.start_clc_state.verify_for_change_id(start_change_id) {
        println!(
            "FastForwardRange.start_clc_state is inconsistent with start_change_id={}",
            start_change_id
        );
        return (false, timings);
    }
    if start_change_id == 0 && range.start_clc_state != initial_clc_state(&start_dc_bytes) {
        println!("FastForwardRange.start_clc_state does not match MmrTree::initialize(start_dc)");
        return (false, timings);
    }

    // Seed / sanity-check the recent_roots sliding window. The last entry
    // must always be `(start_change_id, start_clc_state.root)`: in first
    // chunks the guest pushes it on an empty seed; in extension chunks
    // the previous proof's output already ends with this pair.
    let start_root: [u8; 32] = range.start_clc_state.root.as_bytes().try_into().unwrap();
    match recent_roots.last().copied() {
        Some((last_cid, last_root)) => {
            if last_cid != start_change_id || last_root != start_root {
                println!(
                    "recent_roots last entry ({last_cid}) does not match start_change_id \
                     ({start_change_id}) or start_clc_state.root"
                );
                return (false, timings);
            }
        }
        None => {
            if start_change_id != 0 {
                println!(
                    "recent_roots must be non-empty for extension chunks \
                     (start_change_id={start_change_id})"
                );
                return (false, timings);
            }
            recent_roots.push((0, start_root));
        }
    }

    let chunk_len: u32 = entries.len().try_into().unwrap();
    assert!(start_idx < end_idx);
    assert!(start_idx < chunk_len);
    assert!(end_idx <= chunk_len);

    let expected_end_tree_size = range
        .start_clc_state
        .tree_size
        .checked_add(chunk_len)
        .expect("tree_size overflow");
    if !range
        .end_clc_state
        .verify_for_tree_size(expected_end_tree_size)
    {
        println!(
            "FastForwardRange.end_clc_state is inconsistent: tree_size {} != start ({}) + chunk_len ({}), or peaks/root malformed",
            range.end_clc_state.tree_size, range.start_clc_state.tree_size, chunk_len
        );
        return (false, timings);
    }

    let pruned_tree_t0 = cycle_count();

    let t0 = cycle_count();
    let mut tree = match crate::decode_pruned_compact_to_merk(pruned_tree_bytes) {
        Ok(Some(t)) => t,
        Ok(None) => {
            println!("Failed to verify: pruned tree is empty");
            return (false, timings);
        }
        Err(e) => {
            println!("Failed to decode compact pruned tree into Merk: {:?}", e);
            return (false, timings);
        }
    };
    timings.pruned_tree_decode_cycles = cycle_count() - t0;

    let t0 = cycle_count();
    tree.commit();
    timings.pruned_tree_commit_cycles = cycle_count() - t0;

    let t0 = cycle_count();
    let start_root_matches = tree.hash() == start_dc_bytes;
    timings.pruned_tree_root_check_cycles = cycle_count() - t0;
    timings.pruned_tree_cycles = cycle_count() - pruned_tree_t0;
    if !start_root_matches {
        println!("Failed to verify: computed start root does not match");
        return (false, timings);
    }

    let mut working_tree = MmrTree {
        peaks: range.start_clc_state.peaks.clone(),
        tree_size: range.start_clc_state.tree_size,
    };

    let mut ctx = crate::ops::OpContext::for_change_sequence();

    for i in (start_idx as usize)..(end_idx as usize) {
        let current_change_id = start_change_id as usize + i + 1;

        let e_i = entries.entry(i).expect("entry index out of bounds");
        let leaf_hash = working_tree.append(e_i);

        let t0 = cycle_count();
        let entry_i = match ChangelogEntry::from_bytes_for_verification(e_i) {
            Ok(m) => m,
            Err(e) => {
                println!("Failed to verify changes; Changelog entry didn't parse {e:?}");
                return (false, timings);
            }
        };
        timings.entry_decode_cycles += cycle_count() - t0;

        if !validate_timestamp_hwm(entry_i.timestamp, timestamp_hwm) {
            println!(
                "Failed to verify changes; entry {current_change_id} timestamp {} is older than HWM {} by more than {TIMESTAMP_HWM_TOLERANCE_SECONDS}s",
                entry_i.timestamp, *timestamp_hwm
            );
            return (false, timings);
        }

        let t0 = cycle_count();
        if !validate_sigref(
            sigref_map,
            entry_i.uid,
            entry_i.sig_ref,
            current_change_id as u32,
            (*leaf_hash.as_bytes())
                .try_into()
                .expect("digest is 32 bytes"),
        ) {
            return (false, timings);
        }

        if !validate_parent_change(entry_i.parent_change, current_change_id) {
            println!(
                "Failed to verify changes; entry {current_change_id} has invalid \
                 parent_change={} (current_change_id={current_change_id})",
                entry_i.parent_change
            );
            return (false, timings);
        }

        // Validate parent_clc against the sliding window. This binds the
        // signed entry to the proven chain prefix; without it a malicious
        // server could splice signed entries from a divergent fork into
        // the proven chain.
        if !validate_parent_clc(entry_i.parent_change, &entry_i.parent_clc, recent_roots) {
            println!(
                "Failed to verify changes; entry {current_change_id} has invalid \
                 parent_clc for parent_change={}",
                entry_i.parent_change
            );
            return (false, timings);
        }
        timings.sigref_parent_cycles += cycle_count() - t0;

        let mut reader = TimedPrunedTreeReader::new(&tree, cycle_count);
        ctx.begin_change(current_change_id);

        let t0 = cycle_count();
        let op_result = match crate::ops::dispatch_extract_and_validate(&entry_i, &mut reader, &ctx)
        {
            Ok(r) => r,
            Err(e) => {
                println!("Op validation failed at entry {current_change_id}: {e}");
                return (false, timings);
            }
        };
        timings.extract_validate_cycles += cycle_count() - t0;
        reader.drain_into(&mut timings);

        let t0 = cycle_count();
        let writes = match flatten_write_steps(op_result) {
            Ok(w) => w,
            Err(e) => {
                println!("Op at entry {current_change_id} produced invalid writes: {e}");
                return (false, timings);
            }
        };
        timings.write_prepare_cycles += cycle_count() - t0;

        let t0 = cycle_count();
        let maybe_tree = crate::apply_batch(Some(tree), &writes, PanicSource {});
        tree = match maybe_tree {
            Some(t) => t,
            None => {
                println!("Tree became empty after entry {current_change_id}");
                return (false, timings);
            }
        };
        timings.overlay_apply_cycles += cycle_count() - t0;

        ctx.finish_change(entry_i.message.op_type);

        // Push the post-append root into the sliding window, then prune
        // from the front so the window holds at most MAX_PARENT_DISTANCE
        // entries.
        let root_after: [u8; 32] = working_tree
            .root()
            .expect("working_tree non-empty after append")
            .as_bytes()
            .try_into()
            .expect("digest is 32 bytes");
        recent_roots.push((current_change_id as u32, root_after));
        while recent_roots.len() > MAX_PARENT_DISTANCE as usize {
            recent_roots.remove(0);
        }
    }

    let t0 = cycle_count();
    tree.commit();
    if tree.hash() != end_dc_bytes {
        println!("Failed to verify changes; ending data root does not match");
        return (false, timings);
    }

    let computed_end = working_tree
        .tree_head()
        .expect("working tree must be non-empty after replay");
    if computed_end != range.end_clc_state {
        println!("Failed to verify changes; ending tree head does not match replay");
        return (false, timings);
    }
    timings.final_replay_cycles = cycle_count() - t0;

    (true, timings)
}

#[cfg(feature = "bench-timing")]
#[allow(clippy::too_many_arguments)]
pub fn verify_op_sequence_timed_flat(
    entries: FlatEntryBytes<'_>,
    range: &FastForwardRange,
    pruned_tree_bytes: &[u8],
    start_change_id: u32,
    sigref_map: &mut BTreeMap<u32, (u32, [u8; 32])>,
    recent_roots: &mut Vec<(u32, [u8; 32])>,
    timestamp_hwm: &mut u64,
    cycle_count: fn() -> u64,
) -> (bool, VerificationLoopTimings) {
    verify_op_sequence_timed_inner(
        &entries,
        range,
        pruned_tree_bytes,
        start_change_id,
        sigref_map,
        recent_roots,
        timestamp_hwm,
        cycle_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr_tree::{h_leaf, MmrTree};

    #[test]
    fn changelog_entry_rejects_trailing_bytes_that_change_clc_commitment() {
        let mut entry = ChangelogEntry::new(
            OpType::Insert,
            DEFAULT_UID,
            ROOT_TREE_PATH,
            &[b"key"],
            &[b"value"],
            0,
            0,
            [0u8; 32],
        )
        .expect("valid changelog entry");
        entry.timestamp = 1;
        entry.signature = b"test signature bytes".to_vec();

        let canonical_bytes = entry.as_bytes();
        let mut trailing_bytes = canonical_bytes.clone();
        trailing_bytes.extend_from_slice(b"uncommitted trailing bytes");

        let decoded_with_trailing = ChangelogEntry::from_bytes(&trailing_bytes);
        assert!(
            decoded_with_trailing.is_err(),
            "the signed semantic entry and raw-byte CLC cannot diverge"
        );

        // The MMR leaf hash commits to raw bytes, so trailing bytes
        // produce a different leaf hash (and therefore a different root).
        let canonical_leaf = h_leaf(&canonical_bytes);
        let trailing_leaf = h_leaf(&trailing_bytes);
        assert_ne!(
            canonical_leaf, trailing_leaf,
            "MMR leaf hashes are over raw bytes, so trailing bytes produce a different leaf"
        );
    }

    #[test]
    fn changelog_mmr_state_accepts_fresh_changelog() {
        let changelog = ChangeLog::new(&[0x11; 32]);
        assert!(changelog.validate_mmr_state().is_ok());
    }

    #[test]
    fn changelog_mmr_state_rejects_unbound_initial_head() {
        let mut changelog = ChangeLog::new(&[0x11; 32]);
        let mut other_tree = MmrTree::new();
        other_tree.initialize(&[0x22; 32]);
        let other_root: [u8; 32] = other_tree.root().unwrap().into();
        changelog.roots_by_change_id[0] = other_root;

        let err = changelog.validate_mmr_state().unwrap_err().to_string();
        assert!(err.contains("initial root"), "unexpected error: {err}");
    }

    #[test]
    fn changelog_mmr_state_rejects_cached_head_not_matching_entries() {
        let initial_dc = [0x33; 32];
        let mut changelog = ChangeLog::new(&initial_dc);
        let mut change = ChangelogEntry::new(
            OpType::Insert,
            DEFAULT_UID,
            ROOT_TREE_PATH,
            &[b"key"],
            &[b"value"],
            0,
            0,
            changelog.current_root(),
        )
        .expect("valid changelog entry");
        change.timestamp = 1;

        changelog.tree.append(&change.as_bytes());
        changelog
            .roots_by_change_id
            .push(changelog.tree.root().unwrap().into());
        changelog.changes.push(change);
        changelog.pruned_merkle_trees.push(PrunedMerkleTreeTriple {
            pruned_merkle_tree: vec![],
            old_root: [0u8; 32],
            new_root: [1u8; 32],
        });
        assert!(changelog.validate_mmr_state().is_ok());

        let mut other_tree = MmrTree::new();
        other_tree.initialize(&initial_dc);
        other_tree.append(b"different entry bytes");
        changelog.roots_by_change_id[1] = other_tree.root().unwrap().into();

        let err = changelog.validate_mmr_state().unwrap_err().to_string();
        assert!(err.contains("replayed entries"), "unexpected error: {err}");
    }

    #[test]
    fn verify_op_sequence_rejects_initial_head_not_bound_to_start_dc() {
        let mut wrong_tree = MmrTree::new();
        wrong_tree.initialize(&[0x44; 32]);
        let range = FastForwardRange {
            start_clc_state: wrong_tree.tree_head().unwrap(),
            end_clc_state: ClcState::default(),
            start_dc: [0x55; 32].into(),
            end_dc: [0x66; 32].into(),
            end_change_id: 0,
            sigref_map: BTreeMap::new(),
            recent_roots: Vec::new(),
            timestamp_hwm: 0,
        };

        let mut timestamp_hwm = 0;
        assert!(!verify_op_sequence(
            &[],
            &range,
            &[],
            0,
            &mut BTreeMap::new(),
            &mut Vec::new(),
            &mut timestamp_hwm,
        ));
    }

    #[test]
    fn kvdata_to_batch_op_value() {
        let kv = KvData {
            key: b"placeholder".to_vec(),
            value: b"42".to_vec(),
        };
        let op = kv.to_batch_op(b"real_key");
        match op {
            crate::BatchOp::Put { key, value } => {
                assert_eq!(key, b"real_key");
                assert_eq!(value, b"42");
            }
            other => panic!("Expected Put, got: {other:?}"),
        }
    }

    #[test]
    fn sigref_chain_validation_rejects_wrong_sigref() {
        let mut map = BTreeMap::new();
        let uid = 1;
        let hash_a = [0xA1; 32];
        let hash_b = [0xA2; 32];
        let hash_c = [0xA3; 32];

        // First change: sig_ref=0 (no prior change) → should pass
        assert!(validate_sigref(&mut map, uid, 0, 1, hash_a));
        assert_eq!(map[&uid], (1, hash_a));

        // Second change: sig_ref=1 (correct, points to change 1) → should pass
        assert!(validate_sigref(&mut map, uid, 1, 2, hash_b));
        assert_eq!(map[&uid], (2, hash_b));

        // Third change: sig_ref=999 (WRONG, should be 2) → must reject
        assert!(!validate_sigref(&mut map, uid, 999, 3, hash_c));
        // Map should still point to change 2 (not updated on failure)
        assert_eq!(map[&uid], (2, hash_b));

        // Third change with correct sig_ref=2 → should pass
        assert!(validate_sigref(&mut map, uid, 2, 3, hash_c));
        assert_eq!(map[&uid], (3, hash_c));
    }

    #[test]
    fn sigref_rejects_nonzero_for_first_change() {
        let mut map = BTreeMap::new();
        // First-ever change claims sig_ref=5 (should be 0) → must reject
        assert!(!validate_sigref(&mut map, 42, 5, 1, [0u8; 32]));
        assert!(!map.contains_key(&42));
    }

    #[test]
    fn sigref_tracks_multiple_users_independently() {
        let mut map = BTreeMap::new();
        let h = |b: u8| [b; 32];

        // User A's first change
        assert!(validate_sigref(&mut map, 10, 0, 1, h(0xA1)));
        // User B's first change
        assert!(validate_sigref(&mut map, 11, 0, 2, h(0xB1)));
        // User A's second change (sig_ref=1)
        assert!(validate_sigref(&mut map, 10, 1, 3, h(0xA2)));
        // User B's second change (sig_ref=2)
        assert!(validate_sigref(&mut map, 11, 2, 4, h(0xB2)));
        // User A's third change (sig_ref=3)
        assert!(validate_sigref(&mut map, 10, 3, 5, h(0xA3)));

        assert_eq!(map[&10], (5, h(0xA3)));
        assert_eq!(map[&11], (4, h(0xB2)));

        // Cross-user contamination: User B with A's change_id should fail
        assert!(!validate_sigref(&mut map, 11, 5, 6, h(0xB3)));
    }

    /// Each new change for a user updates the stored entry hash; the
    /// previous user's hash is replaced (not retained alongside).
    #[test]
    fn sigref_updates_entry_hash_on_each_change() {
        let mut map = BTreeMap::new();
        let uid = 7;

        assert!(validate_sigref(&mut map, uid, 0, 1, [0x11; 32]));
        assert_eq!(map[&uid], (1, [0x11; 32]));

        assert!(validate_sigref(&mut map, uid, 1, 2, [0x22; 32]));
        assert_eq!(map[&uid], (2, [0x22; 32]));
        assert_eq!(map.len(), 1, "still one entry per uid");
    }

    // -------------------------------------------------------------------
    // validate_parent_change / validate_parent_clc sliding-window tests
    // -------------------------------------------------------------------

    #[test]
    fn validate_parent_change_first_change_requires_zero() {
        assert!(validate_parent_change(0, 1));
        for bad in [1u32, 2, 100] {
            assert!(
                !validate_parent_change(bad, 1),
                "first change must have parent_change==0, got {bad}"
            );
        }
    }

    #[test]
    fn validate_parent_change_in_window() {
        let current = 50usize;
        // parent_change anywhere in [current - W, current - 1] is OK
        for p in (current - MAX_PARENT_DISTANCE as usize)..current {
            assert!(
                validate_parent_change(p as u32, current),
                "expected in-window parent_change={p} to be accepted at current={current}"
            );
        }
    }

    #[test]
    fn validate_parent_change_rejects_self_and_future() {
        assert!(!validate_parent_change(50, 50));
        assert!(!validate_parent_change(51, 50));
        assert!(!validate_parent_change(u32::MAX, 50));
    }

    #[test]
    fn validate_parent_change_rejects_too_old() {
        let current = 100usize;
        let too_old = current - MAX_PARENT_DISTANCE as usize - 1;
        assert!(
            !validate_parent_change(too_old as u32, current),
            "parent_change {too_old} should be too old at current={current}"
        );
        assert!(!validate_parent_change(0, current));
    }

    #[test]
    fn validate_parent_change_zero_allowed_only_within_window() {
        // parent_change == 0 has distance == current_change_id. So it is
        // only valid for current_change_id <= W.
        for current in 1..=(MAX_PARENT_DISTANCE as usize) {
            assert!(
                validate_parent_change(0, current),
                "parent_change=0 should be valid at current={current}"
            );
        }
        // current_change_id == W + 1 would give distance W+1 > W, reject.
        assert!(!validate_parent_change(0, MAX_PARENT_DISTANCE as usize + 1));
    }

    #[test]
    fn validate_parent_clc_accepts_matching_root() {
        let root = [0x42u8; 32];
        let window = vec![(0, [0x00; 32]), (1, [0x11; 32]), (5, root)];
        assert!(validate_parent_clc(5, &root, &window));
    }

    #[test]
    fn validate_parent_clc_rejects_root_mismatch() {
        let actual_root = [0x42u8; 32];
        let claimed_root = [0x99u8; 32];
        let window = vec![(0, [0x00; 32]), (5, actual_root)];
        assert!(!validate_parent_clc(5, &claimed_root, &window));
    }

    #[test]
    fn validate_parent_clc_rejects_missing_change_id() {
        let window = vec![(1, [0x11; 32]), (2, [0x22; 32]), (3, [0x33; 32])];
        // parent_change=0 falls outside the window
        assert!(!validate_parent_clc(0, &[0; 32], &window));
        // parent_change=5 falls outside the window
        assert!(!validate_parent_clc(5, &[0; 32], &window));
    }

    #[test]
    fn validate_parent_clc_accepts_zero_change_id() {
        let init_root = [0x77u8; 32];
        let window = vec![(0, init_root)];
        assert!(validate_parent_clc(0, &init_root, &window));
    }

    // -------------------------------------------------------------------
    // Cross-component consistency: every place that reads
    // MAX_PARENT_DISTANCE must observe the same value. We check the
    // server and SDK paths in a separate integration test; here we just
    // pin the value to catch accidental edits.
    // -------------------------------------------------------------------
    #[test]
    fn max_parent_distance_is_reasonable() {
        // The window must allow at least one in-flight predecessor and
        // be small enough to keep the FF-journal `recent_roots` payload
        // bounded.
        const _: () = assert!(MAX_PARENT_DISTANCE >= 1);
        const _: () = assert!(MAX_PARENT_DISTANCE <= 64);
    }

    // -------------------------------------------------------------------
    // Inclusion-proof cache tests.
    // -------------------------------------------------------------------

    /// Mimic the writer-side state changes that `add_change` makes,
    /// without going through signature/proof validation. Pushes
    /// the entry into `tree`, `roots_by_change_id`, and `changes`, and
    /// — crucially — keeps the `inclusion_proof_cache` cache in sync if it's
    /// already been built. This is the same invariant `add_change` is
    /// expected to maintain on the production path.
    fn push_test_change(changelog: &mut ChangeLog, key: &[u8], val: &[u8]) {
        let change = ChangelogEntry::new(
            OpType::Insert,
            DEFAULT_UID,
            ROOT_TREE_PATH,
            &[key],
            &[val],
            0,
            0,
            changelog.current_root(),
        )
        .expect("valid changelog entry");
        let bytes = change.as_bytes();
        changelog.tree.append(&bytes);
        let new_root: [u8; 32] = changelog.tree.root().unwrap().into();
        changelog.roots_by_change_id.push(new_root);
        if let Some(idx) = changelog.inclusion_proof_cache.as_mut() {
            idx.extend_with_leaf(h_leaf(&bytes));
        }
        changelog.changes.push(change);
    }

    /// Lazy build path: a freshly-constructed changelog has no cache;
    /// the first `prove_inclusion` call materialises it and produces a
    /// proof that verifies against the live tree head.
    #[test]
    fn prove_inclusion_lazy_build_proves_initial_leaf() {
        let initial_dc = [0x77; 32];
        let mut changelog = ChangeLog::new(&initial_dc);
        // Cache is empty before the first proof.
        assert!(changelog.inclusion_proof_cache.is_none());

        let proof = changelog.prove_inclusion(0).expect("initial leaf");
        assert!(
            changelog.inclusion_proof_cache.is_some(),
            "cache must be built"
        );

        let head = changelog.tree.tree_head().unwrap();
        assert!(crate::mmr_tree::verify_with_leaf_hash(
            &head,
            &proof,
            h_init(&initial_dc),
        ));
    }

    /// After several appends through the test harness (which mirrors
    /// `add_change`'s side effects), every leaf must be provable and
    /// every proof must verify against the live head.
    #[test]
    fn prove_inclusion_covers_every_leaf_after_appends() {
        let initial_dc = [0x88; 32];
        let mut changelog = ChangeLog::new(&initial_dc);

        // Trigger the cache early so subsequent appends maintain it
        // incrementally — this exercises the `add_change` hot path.
        let _ = changelog.prove_inclusion(0).unwrap();

        for k in 0..10u32 {
            push_test_change(&mut changelog, &k.to_le_bytes(), format!("v{k}").as_bytes());
        }

        let head = changelog.tree.tree_head().unwrap();
        // Initial leaf at index 0.
        let p0 = changelog.prove_inclusion(0).unwrap();
        assert!(crate::mmr_tree::verify_with_leaf_hash(
            &head,
            &p0,
            h_init(&initial_dc),
        ));
        // Real changes at indices 1..=10.
        for (k, change) in changelog.changes.clone().iter().enumerate() {
            let i = (k + 1) as u32;
            let proof = changelog.prove_inclusion(i).unwrap();
            assert!(
                crate::mmr_tree::verify(&head, &proof, &change.as_bytes()),
                "proof failed for change_id={i}"
            );
        }
        // Out-of-range request must return None, not panic.
        assert!(changelog.prove_inclusion(11).is_none());
    }

    /// The cache must NOT travel through serde — a postcard
    /// round-trip drops it and the next `prove_inclusion` call must
    /// transparently rebuild it and still produce verifying proofs.
    #[test]
    fn prove_inclusion_rebuilds_cache_after_serde_roundtrip() {
        let initial_dc = [0x99; 32];
        let mut changelog = ChangeLog::new(&initial_dc);
        for k in 0..5u32 {
            push_test_change(&mut changelog, &k.to_le_bytes(), b"v");
        }
        // Build the cache.
        let _ = changelog.prove_inclusion(3).unwrap();
        assert!(changelog.inclusion_proof_cache.is_some());

        // Round-trip: cache must be dropped.
        let bytes = postcard::to_allocvec(&changelog).unwrap();
        let mut decoded: ChangeLog = postcard::from_bytes(&bytes).unwrap();
        assert!(
            decoded.inclusion_proof_cache.is_none(),
            "cache must not be serialised"
        );

        // Lazy rebuild on next proof.
        let head = decoded.tree.tree_head().unwrap();
        let proof = decoded.prove_inclusion(3).unwrap();
        assert!(decoded.inclusion_proof_cache.is_some());
        assert!(crate::mmr_tree::verify(
            &head,
            &proof,
            &decoded.changes[2].as_bytes()
        ));
    }

    /// `prove_inclusion` against an out-of-range change_id must return
    /// `None` cleanly (no panic, no cache corruption).
    #[test]
    fn prove_inclusion_rejects_out_of_range() {
        let mut changelog = ChangeLog::new(&[0xAA; 32]);
        push_test_change(&mut changelog, b"k", b"v");
        // tree_size = 2 (initial + 1 real); valid indices 0,1.
        assert!(changelog.prove_inclusion(0).is_some());
        assert!(changelog.prove_inclusion(1).is_some());
        assert!(changelog.prove_inclusion(2).is_none());
        assert!(changelog.prove_inclusion(u32::MAX).is_none());
    }

    /// Cache coherence: a length-preserving in-place mutation of
    /// `changes` (which bypasses `add_change` and the cache update
    /// hook) must trigger a rebuild on the next proof — otherwise
    /// `prove_inclusion` would return a proof valid against the *old*
    /// root, not the live `tree.root()`.
    #[test]
    fn prove_inclusion_rebuilds_on_in_place_change_mutation() {
        let mut changelog = ChangeLog::new(&[0xBB; 32]);
        for k in 0..4u32 {
            push_test_change(&mut changelog, &k.to_le_bytes(), b"v");
        }
        // Build the cache.
        let _ = changelog.prove_inclusion(2).unwrap();

        // Mutate change[1] in place AND the live MMR (so they stay
        // self-consistent). The cache, however, still reflects the
        // pre-mutation tree — rebuild detection must catch this.
        let new_change = ChangelogEntry::new(
            OpType::Insert,
            DEFAULT_UID,
            ROOT_TREE_PATH,
            &[b"replaced"],
            &[b"replaced"],
            0,
            0,
            changelog.roots_by_change_id[1],
        )
        .expect("valid changelog entry");
        // Rebuild the live tree from scratch with the substituted change.
        let mut new_tree = MmrTree::new();
        new_tree.initialize(&changelog.initial_dc);
        let mut new_roots = vec![changelog.roots_by_change_id[0]];
        let mut new_changes = changelog.changes.clone();
        new_changes[1] = new_change;
        for c in &new_changes {
            new_tree.append(&c.as_bytes());
            new_roots.push(new_tree.root().unwrap().into());
        }
        changelog.tree = new_tree;
        changelog.changes = new_changes;
        changelog.roots_by_change_id = new_roots;
        // inclusion_proof_cache is stale: same length, different content.

        let head = changelog.tree.tree_head().unwrap();
        let proof = changelog.prove_inclusion(2).unwrap();
        // Must verify against the *new* head, not the old one.
        assert!(crate::mmr_tree::verify(
            &head,
            &proof,
            &changelog.changes[1].as_bytes()
        ));
    }

    // -------------------------------------------------------------------
    // Proven-snapshot inclusion proof tests for FF branch continuity.
    // -------------------------------------------------------------------

    /// `prove_included_in_ff_range` must answer against the cached
    /// snapshot at `proven_up_to`, not the live tree head. The
    /// resulting proof verifies against `proven_clc_state` for every
    /// leaf in `[0, proven_up_to]` and rejects out-of-range indices.
    #[test]
    fn prove_included_in_ff_range_verifies_against_proven_head() {
        let initial_dc = [0x33; 32];
        let mut changelog = ChangeLog::new(&initial_dc);
        // Append 5 changes total, freeze proof at proven_up_to == 3.
        for k in 0..5u32 {
            push_test_change(&mut changelog, &k.to_le_bytes(), b"v");
        }
        changelog.set_ff_proof(vec![0xDE, 0xAD, 0xBE, 0xEF], 3);
        let proven_head = changelog.proven_clc_state().expect("proven head");

        // Initial leaf at index 0.
        let p0 = changelog.prove_included_in_ff_range(0).unwrap();
        assert!(crate::mmr_tree::verify_with_leaf_hash(
            &proven_head,
            &p0,
            h_init(&initial_dc),
        ));
        // Real changes at indices 1..=3 — the proven leaves.
        for i in 1..=3u32 {
            let proof = changelog.prove_included_in_ff_range(i).unwrap();
            assert!(
                crate::mmr_tree::verify(
                    &proven_head,
                    &proof,
                    &changelog.changes[(i - 1) as usize].as_bytes()
                ),
                "proof failed for change_id={i} against proven head"
            );
        }
        // Indices past proven_up_to are not in the snapshot.
        assert!(changelog.prove_included_in_ff_range(4).is_none());
        assert!(changelog.prove_included_in_ff_range(5).is_none());
    }

    /// An inclusion proof generated against branch A's proven head
    /// must not verify when the supplied leaf hash comes from a
    /// different branch entry at the same index.
    #[test]
    fn proven_inclusion_rejects_substituted_leaf() {
        let initial_dc = [0x44; 32];
        let mut changelog_a = ChangeLog::new(&initial_dc);
        for k in 0..3u32 {
            push_test_change(&mut changelog_a, &k.to_le_bytes(), b"branchA");
        }
        changelog_a.set_ff_proof(vec![0x01], 3);
        let head_a = changelog_a.proven_clc_state().unwrap();

        // Build a parallel branch B sharing the same initial_dc but
        // with different entries.
        let mut changelog_b = ChangeLog::new(&initial_dc);
        for k in 0..3u32 {
            push_test_change(&mut changelog_b, &k.to_le_bytes(), b"branchB");
        }
        // Sanity: branches diverge at change_id 1 onward.
        assert_ne!(
            changelog_a.changes[1].as_bytes(),
            changelog_b.changes[1].as_bytes()
        );

        // A's proof at index 2, paired with B's leaf at index 2 (the
        // "client's stored anchor") must fail to verify against A's
        // proven head — even though the index matches.
        let proof = changelog_a.prove_included_in_ff_range(2).unwrap();
        let b_leaf_hash = h_leaf(&changelog_b.changes[1].as_bytes());
        assert!(
            !crate::mmr_tree::verify_with_leaf_hash(&head_a, &proof, b_leaf_hash),
            "branch-substitution defense failed: A's proof verified B's leaf"
        );

        // Control: A's proof + A's own leaf still verifies.
        let a_leaf_hash = h_leaf(&changelog_a.changes[1].as_bytes());
        assert!(crate::mmr_tree::verify_with_leaf_hash(
            &head_a,
            &proof,
            a_leaf_hash,
        ));
    }

    /// Incremental advance: a second `set_ff_proof` call must extend
    /// the FF inclusion-proof cache in place (not rebuild), so proofs for the
    /// newly-proven leaves verify against the updated proven head.
    #[test]
    fn proven_inclusion_advances_with_set_ff_proof() {
        let initial_dc = [0x55; 32];
        let mut changelog = ChangeLog::new(&initial_dc);
        for k in 0..6u32 {
            push_test_change(&mut changelog, &k.to_le_bytes(), b"v");
        }
        changelog.set_ff_proof(vec![0x01], 2);
        let head_1 = changelog.proven_clc_state().unwrap();
        let p_1 = changelog.prove_included_in_ff_range(2).unwrap();
        assert!(crate::mmr_tree::verify(
            &head_1,
            &p_1,
            &changelog.changes[1].as_bytes()
        ));
        // Cache entry for the new boundary is not available until the FF proof advances.
        assert!(changelog.prove_included_in_ff_range(3).is_none());

        // Advance.
        changelog.set_ff_proof(vec![0x02], 5);
        let head_2 = changelog.proven_clc_state().unwrap();
        assert_ne!(head_1.root, head_2.root, "proven head must advance");
        // Now proofs at indices 0..=5 verify against the new head.
        for i in 0..=5u32 {
            let proof = changelog.prove_included_in_ff_range(i).unwrap();
            let ok = if i == 0 {
                crate::mmr_tree::verify_with_leaf_hash(&head_2, &proof, h_init(&initial_dc))
            } else {
                crate::mmr_tree::verify(
                    &head_2,
                    &proof,
                    &changelog.changes[(i - 1) as usize].as_bytes(),
                )
            };
            assert!(ok, "advanced proof failed at change_id={i}");
        }
        assert!(changelog.prove_included_in_ff_range(6).is_none());
    }

    /// The FF inclusion-proof cache must NOT be serialised but must
    /// rebuild lazily from `(initial_dc, changes[0..proven_up_to])`
    /// on the next call after deserialisation.
    #[test]
    fn ff_range_inclusion_rebuilds_after_serde_roundtrip() {
        let initial_dc = [0x66; 32];
        let mut changelog = ChangeLog::new(&initial_dc);
        for k in 0..4u32 {
            push_test_change(&mut changelog, &k.to_le_bytes(), b"v");
        }
        changelog.set_ff_proof(vec![0xAA], 3);
        assert!(changelog.ff_inclusion_proof_cache.is_some());

        let bytes = postcard::to_allocvec(&changelog).unwrap();
        let mut decoded: ChangeLog = postcard::from_bytes(&bytes).unwrap();
        assert!(
            decoded.ff_inclusion_proof_cache.is_none(),
            "FF inclusion-proof cache must not be serialised"
        );

        let head = decoded.proven_clc_state().unwrap();
        let proof = decoded.prove_included_in_ff_range(2).unwrap();
        assert!(decoded.ff_inclusion_proof_cache.is_some());
        assert!(crate::mmr_tree::verify(
            &head,
            &proof,
            &decoded.changes[1].as_bytes()
        ));
    }

    #[test]
    fn changelog_entry_from_bytes_matches_postcard_wire_format() {
        // Normal entry with inline Value
        let entry1 = ChangelogEntry {
            timestamp: 1234567890,
            uid: 42,
            parent_change: 10,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: b"/".to_vec(),
                entries: vec![
                    KvData {
                        key: b"key1".to_vec(),
                        value: b"value1".to_vec(),
                    },
                    KvData {
                        key: b"key2".to_vec(),
                        value: b"value2".to_vec(),
                    },
                ],
            },
            sig_ref: 5,
            parent_clc: [0xAA; 32],
            signature: b"test_signature".to_vec(),
        };

        // Entry with hash value (stored as raw bytes)
        let entry2 = ChangelogEntry {
            timestamp: 9999,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Update,
                tree_path: b"/".to_vec(),
                entries: vec![KvData {
                    key: b"col".to_vec(),
                    value: [0xBB; 32].to_vec(),
                }],
            },
            sig_ref: 0,
            parent_clc: [0x00; 32],
            signature: vec![1, 2, 3, 4],
        };

        // Noop entry with empty entries
        let entry3 = ChangelogEntry {
            timestamp: 100,
            uid: 3,
            parent_change: 1,
            message: LogMessage {
                op_type: OpType::Noop,
                tree_path: b"/".to_vec(),
                entries: vec![],
            },
            sig_ref: 0,
            parent_clc: [0xCC; 32],
            signature: b"noop_sig".to_vec(),
        };

        // Entry with non-empty signature bytes
        let entry4 = ChangelogEntry {
            timestamp: 0,
            uid: 0,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Delete,
                tree_path: b"/sub".to_vec(),
                entries: vec![KvData {
                    key: b"k".to_vec(),
                    value: vec![],
                }],
            },
            sig_ref: 0,
            parent_clc: [0; 32],
            signature: vec![0xFF; 64],
        };

        for (label, entry) in [
            ("inline_value", &entry1),
            ("hash_value", &entry2),
            ("noop", &entry3),
            ("nonempty_sig", &entry4),
        ] {
            let bytes = entry.as_bytes();

            // Full decode (with signature) must round-trip
            let decoded_full = ChangelogEntry::from_bytes(&bytes)
                .unwrap_or_else(|e| panic!("{label}: from_bytes failed: {e}"));
            assert_eq!(
                decoded_full.as_bytes(),
                bytes,
                "{label}: full decode round-trip mismatch"
            );

            // Custom decoder (decode_from_bytes with include_signature=true) must match
            let decoded_custom = ChangelogEntry::decode_from_bytes(&bytes, true)
                .unwrap_or_else(|e| panic!("{label}: decode_from_bytes(true) failed: {e}"));
            assert_eq!(
                decoded_custom.as_bytes(),
                bytes,
                "{label}: custom decoder round-trip mismatch"
            );

            // Verification decoder (skip signature) must preserve all fields except signature
            let decoded_verif = ChangelogEntry::from_bytes_for_verification(&bytes)
                .unwrap_or_else(|e| panic!("{label}: from_bytes_for_verification failed: {e}"));
            assert_eq!(
                decoded_verif.timestamp, entry.timestamp,
                "{label}: timestamp"
            );
            assert_eq!(decoded_verif.uid, entry.uid, "{label}: uid");
            assert_eq!(
                decoded_verif.parent_change, entry.parent_change,
                "{label}: parent_change"
            );
            assert_eq!(
                decoded_verif.message.op_type, entry.message.op_type,
                "{label}: op_type"
            );
            assert_eq!(
                decoded_verif.message.tree_path, entry.message.tree_path,
                "{label}: tree_path"
            );
            assert_eq!(
                decoded_verif.message.entries, entry.message.entries,
                "{label}: entries"
            );
            assert_eq!(decoded_verif.sig_ref, entry.sig_ref, "{label}: sig_ref");
            assert_eq!(
                decoded_verif.parent_clc, entry.parent_clc,
                "{label}: parent_clc"
            );
            assert!(
                decoded_verif.signature.is_empty(),
                "{label}: verification decode should skip signature"
            );
        }
    }

    #[test]
    fn flat_entry_bytes_basic() {
        let e1 = b"hello";
        let e2 = b"world!";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(e1);
        bytes.extend_from_slice(e2);
        let ends = vec![5u32, 11u32];

        let flat = FlatEntryBytes::new(&bytes, &ends).unwrap();
        assert_eq!(flat.len(), 2);
        assert!(!flat.is_empty());
        assert_eq!(flat.entry(0).unwrap(), b"hello");
        assert_eq!(flat.entry(1).unwrap(), b"world!");
        assert!(flat.entry(2).is_none());
    }

    #[test]
    fn flat_entry_bytes_empty() {
        let flat = FlatEntryBytes::new(&[], &[]).unwrap();
        assert_eq!(flat.len(), 0);
        assert!(flat.is_empty());
        assert!(flat.entry(0).is_none());
    }

    #[test]
    fn flat_entry_bytes_rejects_non_monotonic() {
        let bytes = vec![0u8; 10];
        let ends = vec![5u32, 3u32]; // non-monotonic
        assert!(FlatEntryBytes::new(&bytes, &ends).is_err());
    }

    #[test]
    fn flat_entry_bytes_rejects_wrong_length() {
        let bytes = vec![0u8; 10];
        let ends = vec![5u32, 8u32]; // last offset != bytes.len()
        assert!(FlatEntryBytes::new(&bytes, &ends).is_err());
    }

    #[test]
    fn custom_decoder_rejects_invalid_op_type() {
        // Build a valid entry, then corrupt the op_type field in the serialized bytes.
        let entry = ChangelogEntry {
            timestamp: 1,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert, // variant 0
                tree_path: b"/".to_vec(),
                entries: vec![],
            },
            sig_ref: 0,
            parent_clc: [0; 32],
            signature: vec![],
        };
        let mut bytes = entry.as_bytes();

        // The wire layout is: timestamp(varint), uid(varint), parent_change(varint),
        // op_type(varint), ... Find the op_type byte. timestamp=1 (1 byte),
        // uid=1 (1 byte), parent_change=0 (1 byte), so op_type is at offset 3.
        // Set it to an unknown variant (e.g., 99).
        bytes[3] = 99;
        assert!(
            ChangelogEntry::from_bytes_for_verification(&bytes).is_err(),
            "should reject unknown op_type variant 99"
        );

        // Test the truncation case: a u32 value > 255 encoded as a varint.
        // 256 in LEB128 is [0x80, 0x02]. Replace the single byte at offset 3.
        let mut bytes2 = entry.as_bytes();
        bytes2[3] = 0x80; // first byte of varint 256
        bytes2.insert(4, 0x02); // second byte of varint 256
        assert!(
            ChangelogEntry::from_bytes_for_verification(&bytes2).is_err(),
            "should reject op_type variant 256 (out of u8 range)"
        );
    }
}
