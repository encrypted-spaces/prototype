//! Shared types and logic for ffproof_tracer host and guest.

mod trace_verify;
pub use trace_verify::{verify_trace, TracerProof, VerifyTraceError};

use merk::{kv_hash, Child, Fetch, GetResult, Hasher, Node, Op, Walker};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════
// Batch operations
// ═══════════════════════════════════════════════════════════════════════════

/// Batch operation with variable-length key/value
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum BatchOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

impl BatchOp {
    pub fn key(&self) -> &[u8] {
        match self {
            BatchOp::Put { key, .. } => key,
            BatchOp::Delete { key } => key,
        }
    }

    pub fn to_merk_op(&self) -> Op {
        match self {
            BatchOp::Put { value, .. } => Op::Put(value.clone()),
            BatchOp::Delete { .. } => Op::Delete,
        }
    }

    /// Convert to merk BatchEntry (key, Op) tuple
    pub fn to_merk_batch_entry(&self) -> (Vec<u8>, Op) {
        (self.key().to_vec(), self.to_merk_op())
    }
}

/// Apply batch with deduplication and sorting.
/// Last-write-wins for duplicate keys.
/// Deletes of non-existent keys are passed to merk (handled as no-ops).
pub fn apply_batch<S: Fetch + Clone + Send>(
    tree: Option<Node>,
    ops: &[BatchOp],
    source: S,
) -> Option<Node> {
    // Dedupe: last-write-wins
    let mut deduped: BTreeMap<Vec<u8>, &BatchOp> = BTreeMap::new();
    for op in ops {
        deduped.insert(op.key().to_vec(), op);
    }

    // Convert to merk batch (BTreeMap iteration is sorted)
    #[allow(unused_mut)] // mut needed for apply_in_place on zkvm
    let mut batch: Vec<_> = deduped
        .into_iter()
        .map(|(k, op)| (k, op.to_merk_op()))
        .collect();

    if batch.is_empty() {
        return tree;
    }

    // Apply via Walker — use in-place mutation in the zkVM (no COW needed),
    // COW path on the host (where snapshots may exist).
    #[cfg(target_os = "zkvm")]
    {
        let mut walker = Walker::new(tree?, source);
        walker
            .apply_in_place(&mut batch)
            .expect("apply_in_place failed");
        Some(walker.into_inner())
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        let maybe_walker = tree.map(|t| Walker::new(t, source.clone()));
        let (result, _deleted) =
            Walker::apply_cow_owned(maybe_walker, batch, source).expect("apply_to failed");
        result
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Read operations and trace steps
// ═══════════════════════════════════════════════════════════════════════════

/// A read query
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReadOp {
    /// Read a single key
    Key(Vec<u8>),
    /// Read all keys matching a prefix
    Prefix(Vec<u8>),
    /// Read all keys in range [start, end)
    Range { start: Vec<u8>, end: Vec<u8> },
}

/// A read query with optional results.
///
/// Results are not serialized (they're derived from the pruned tree during
/// verification via `get_unverified_reads()`). Code that needs results
/// (e.g. op validators) must populate this field before use.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProvenRead {
    pub op: ReadOp,
    /// Key-value pairs found. Empty = non-inclusion proof.
    /// Skipped during serialization; populated from the pruned tree at verification time.
    #[serde(skip, default)]
    pub results: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A step in the trace
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TraceStep {
    Read(Vec<ProvenRead>),
    Write(Vec<BatchOp>),
}

/// An input step before tracing (reads don't have results yet)
#[derive(Clone, Debug)]
pub enum InputStep {
    Read(Vec<ReadOp>),
    Write(Vec<BatchOp>),
}

/// Compute the exclusive end bound for a prefix scan.
/// Increments the rightmost non-0xFF byte. Returns None if all bytes are 0xFF
/// (meaning the prefix has no upper bound).
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(&last) = end.last() {
        if last < 0xFF {
            *end.last_mut().unwrap() += 1;
            return Some(end);
        }
        end.pop();
    }
    None
}

/// BST range traversal on a merk Node, collecting key-value pairs where
/// key >= start and (end is None or key < end).
///
/// Defense-in-depth: verifies `kv_hash(key, value) == node.kv_hash()` at every
/// in-range node. Panics on mismatch.
///
/// Panics if any node on the traversal path is a Reference link (pruned).
pub fn collect_range(tree: &Node, start: &[u8], end: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut results = Vec::new();
    collect_range_recursive(tree, start, end, &mut results);
    results
}

fn collect_range_recursive(
    tree: &Node,
    start: &[u8],
    end: Option<&[u8]>,
    results: &mut Vec<(Vec<u8>, Vec<u8>)>,
) {
    let key = tree.key();

    // Go left if node's key > start (there may be in-range keys to the left)
    if key > start {
        if let Some(child) = tree.child_ref(true) {
            match child {
                Child::Resident(child) => collect_range_recursive(child, start, end, results),
                Child::Pruned(_) => panic!(
                    "Pruned node encountered during range traversal (left child of key {})",
                    hex::encode(key)
                ),
            }
        }
    }

    // Collect this node if in range, after verifying kv_hash binding.
    if key >= start && (end.is_none() || key < end.unwrap()) {
        let value = tree.value();
        let expected_kv = kv_hash::<Hasher>(key, value).expect("kv_hash computation failed");
        let stored_kv = *tree.kv_hash();
        if expected_kv != stored_kv {
            panic!("kv_hash mismatch on range read at key {}", hex::encode(key));
        }
        results.push((key.to_vec(), value.to_vec()));
    }

    // Go right if end is None or node's key < end (there may be in-range keys to the right)
    if end.is_none() || key < end.unwrap() {
        if let Some(child) = tree.child_ref(false) {
            match child {
                Child::Resident(child) => collect_range_recursive(child, start, end, results),
                Child::Pruned(_) => panic!(
                    "Pruned node encountered during range traversal (right child of key {})",
                    hex::encode(key)
                ),
            }
        }
    }
}

/// Look up a key in a merk Node, returning the value AND verifying that
/// `kv_hash(key, value) == node.kv_hash()`.
pub fn lookup_value_verified(tree: &Node, key: &[u8]) -> GetResult {
    use std::cmp::Ordering;
    match key.cmp(tree.key()) {
        Ordering::Equal => {
            let value = tree.value();
            let expected_kv = kv_hash::<Hasher>(key, value).expect("kv_hash computation failed");
            let stored_kv = *tree.kv_hash();
            if expected_kv != stored_kv {
                panic!("kv_hash mismatch on key read at {}", hex::encode(key));
            }
            GetResult::Found(value.to_vec())
        }
        Ordering::Less => match tree.child_ref(true) {
            None => GetResult::NotFound,
            Some(Child::Resident(child)) => lookup_value_verified(child, key),
            Some(Child::Pruned(_)) => GetResult::Pruned,
        },
        Ordering::Greater => match tree.child_ref(false) {
            None => GetResult::NotFound,
            Some(Child::Resident(child)) => lookup_value_verified(child, key),
            Some(Child::Pruned(_)) => GetResult::Pruned,
        },
    }
}

/// Per-step read results: one ProvenRead (with results populated) per read in the step.
pub type ReadResults = Vec<ProvenRead>;

/// Extract read results directly from a PrunedMerkleTree BST,
/// without converting to a merk Node. Uses BST key lookups and
/// range traversals — no SHA-256.
///
/// **Test-only**: production verification goes through [`extract_reads`]
/// against a reconstructed merk Node (which has its own `kv_hash`-binding
/// defense). Kept as an alternative implementation used by tests that
/// want to exercise the PrunedMerkleTree-direct path with its panic guards.
#[cfg(test)]
pub fn extract_reads_pruned(root: &PrunedMerkleTree, reads: &[ProvenRead]) -> ReadResults {
    let mut all_results = Vec::with_capacity(reads.len());
    for proven_read in reads {
        let results = match &proven_read.op {
            ReadOp::Key(key) => match root.get_value(key) {
                Some(value) => vec![(key.clone(), value.to_vec())],
                None => vec![],
            },
            ReadOp::Prefix(prefix) => {
                let end = prefix_successor(prefix);
                root.collect_range(prefix, end.as_deref())
            }
            ReadOp::Range { start, end } => root.collect_range(start, Some(end)),
        };
        all_results.push(ProvenRead {
            op: proven_read.op.clone(),
            results,
        });
    }
    all_results
}

/// Extract read results from a root-verified tree.
/// The tree's root hash was already validated against the commitment in Stage 1
/// of verify_trace, so results are trustworthy by construction.
///
/// Defense-in-depth: every consumed (key, value) pair is checked against the
/// node's stored `kv_hash`.
///
/// Panics if a required node is pruned (missing from the pruned tree),
/// or if a consumed node's `kv_hash` does not bind the returned value.
pub fn extract_reads(tree: &Node, reads: &[ProvenRead]) -> ReadResults {
    let mut all_results = Vec::with_capacity(reads.len());
    for proven_read in reads {
        let results = match &proven_read.op {
            ReadOp::Key(key) => match lookup_value_verified(tree, key) {
                GetResult::Found(value) => vec![(key.clone(), value)],
                GetResult::NotFound => vec![],
                GetResult::Pruned => {
                    panic!(
                        "Pruned node encountered during key read for {}",
                        hex::encode(key)
                    );
                }
            },
            ReadOp::Prefix(prefix) => {
                let end = prefix_successor(prefix);
                collect_range(tree, prefix, end.as_deref())
            }
            ReadOp::Range { start, end } => collect_range(tree, start, Some(end.as_slice())),
        };
        all_results.push(ProvenRead {
            op: proven_read.op.clone(),
            results,
        });
    }
    all_results
}

// ═══════════════════════════════════════════════════════════════════════════
// Pruned tree serialization (host → guest)
// ═══════════════════════════════════════════════════════════════════════════

/// Pruned tree node. Accessed subtrees are Full; untouched subtrees are Pruned.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PrunedMerkleTree {
    /// No node at this position (empty child slot)
    Empty,

    /// Pruned subtree - only hash retained, not accessed during ops
    Pruned {
        key: Vec<u8>,
        hash: [u8; 32],
        child_heights: (u8, u8), // Exact (left, right) heights for correct balance factor
    },

    /// Full node - was accessed during ops. The full value is carried so Merk's
    /// key/value commitment can be recomputed directly.
    Full {
        key: Vec<u8>,
        value: Vec<u8>,
        left: Box<PrunedMerkleTree>,
        right: Box<PrunedMerkleTree>,
    },
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrunedMerkleTreeStats {
    pub full_nodes: usize,
    pub pruned_nodes: usize,
    pub empty_slots: usize,
    pub full_key_bytes: usize,
    pub full_value_bytes: usize,
    pub pruned_key_bytes: usize,
    pub max_depth: usize,
}

impl PrunedMerkleTree {
    pub fn stats(&self) -> PrunedMerkleTreeStats {
        let mut stats = PrunedMerkleTreeStats::default();
        self.accumulate_stats(1, &mut stats);
        stats
    }

    fn accumulate_stats(&self, depth: usize, stats: &mut PrunedMerkleTreeStats) {
        match self {
            PrunedMerkleTree::Empty => {
                stats.empty_slots += 1;
            }
            PrunedMerkleTree::Pruned { key, .. } => {
                stats.pruned_nodes += 1;
                stats.pruned_key_bytes += key.len();
                stats.max_depth = stats.max_depth.max(depth);
            }
            PrunedMerkleTree::Full {
                key,
                value,
                left,
                right,
            } => {
                stats.full_nodes += 1;
                stats.full_key_bytes += key.len();
                stats.full_value_bytes += value.len();
                stats.max_depth = stats.max_depth.max(depth);
                left.accumulate_stats(depth + 1, stats);
                right.accumulate_stats(depth + 1, stats);
            }
        }
    }

    /// Count Full nodes in this tree.
    pub fn count_full(&self) -> usize {
        match self {
            PrunedMerkleTree::Empty | PrunedMerkleTree::Pruned { .. } => 0,
            PrunedMerkleTree::Full { left, right, .. } => {
                1 + left.count_full() + right.count_full()
            }
        }
    }

    /// Count Pruned nodes in this tree
    pub fn count_pruned(&self) -> usize {
        match self {
            PrunedMerkleTree::Empty => 0,
            PrunedMerkleTree::Pruned { .. } => 1,
            PrunedMerkleTree::Full { left, right, .. } => {
                left.count_pruned() + right.count_pruned()
            }
        }
    }

    /// Look up a key in the BST. Returns the value if found in a Full node.
    /// Returns None if the key is absent. Panics if the search path hits a
    /// Pruned node (the pruned tree is incomplete for this query).
    ///
    /// **Test-only**: production verification reads through the merk Node
    /// path in [`extract_reads`]. This method is retained for tests of
    /// [`extract_reads_pruned`].
    #[cfg(test)]
    pub fn get_value(&self, target: &[u8]) -> Option<&[u8]> {
        match self {
            PrunedMerkleTree::Empty => None,
            PrunedMerkleTree::Pruned { key, .. } => {
                panic!(
                    "Pruned node encountered during key lookup for {} at node {}",
                    hex::encode(target),
                    hex::encode(key),
                );
            }
            PrunedMerkleTree::Full {
                key,
                value,
                left,
                right,
            } => {
                if target == key.as_slice() {
                    Some(value)
                } else if target < key.as_slice() {
                    left.get_value(target)
                } else {
                    right.get_value(target)
                }
            }
        }
    }

    /// Collect all key-value pairs in [start, end) by BST in-order traversal.
    /// If end is None, collects all keys >= start.
    /// Panics if the traversal path hits a Pruned node.
    ///
    /// **Test-only**: production reads go through [`collect_range`] on the
    /// reconstructed merk Node.
    #[cfg(test)]
    pub fn collect_range(&self, start: &[u8], end: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut results = Vec::new();
        self.collect_range_inner(start, end, &mut results);
        results
    }

    #[cfg(test)]
    fn collect_range_inner(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        results: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) {
        match self {
            PrunedMerkleTree::Empty => {}
            PrunedMerkleTree::Pruned { key, .. } => {
                panic!(
                    "Pruned node on range traversal path at key {}",
                    hex::encode(key),
                );
            }
            PrunedMerkleTree::Full {
                key,
                value,
                left,
                right,
            } => {
                // Go left if there may be in-range keys
                if key.as_slice() > start {
                    left.collect_range_inner(start, end, results);
                }
                // Collect this node if in range
                if key.as_slice() >= start && (end.is_none() || key.as_slice() < end.unwrap()) {
                    results.push((key.clone(), value.clone()));
                }
                // Go right if there may be in-range keys
                if end.is_none() || key.as_slice() < end.unwrap() {
                    right.collect_range_inner(start, end, results);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Guest utilities: PrunedMerkleTree → merk Node conversion
// ═══════════════════════════════════════════════════════════════════════════

/// Construct a pruned child from the pruned-tree metadata.
pub fn pruned_child(key: Vec<u8>, hash: [u8; 32], child_heights: (u8, u8)) -> Child {
    Child::pruned(key, hash, child_heights)
}

/// Convert PrunedMerkleTree to Option<Child> for use as a child
pub fn pruned_to_child(node: PrunedMerkleTree) -> Option<Child> {
    match node {
        PrunedMerkleTree::Empty => None,

        PrunedMerkleTree::Pruned {
            key,
            hash,
            child_heights,
        } => {
            // Pruned nodes keep only the child metadata needed for hash and balance checks.
            Some(pruned_child(key, hash, child_heights))
        }

        PrunedMerkleTree::Full {
            key,
            value,
            left,
            right,
        } => {
            // Full nodes become resident children (hash needs recomputation on commit)
            let tree = pruned_to_merk_inner(key, value, *left, *right);
            Some(Child::Resident(tree))
        }
    }
}

/// Convert Full node's data into a merk Node
fn pruned_to_merk_inner(
    key: Vec<u8>,
    value: Vec<u8>,
    left: PrunedMerkleTree,
    right: PrunedMerkleTree,
) -> Node {
    let left_child = pruned_to_child(left);
    let right_child = pruned_to_child(right);
    // Recompute kv_hash from key+value (not stored in PrunedMerkleTree)
    let kv_hash = kv_hash::<Hasher>(&key, &value).expect("kv_hash computation failed");
    Node::from_fields(key, value, kv_hash, left_child, right_child)
}

/// Convert root PrunedMerkleTree to merk Node
pub fn pruned_to_merk(node: PrunedMerkleTree) -> Option<Node> {
    match node {
        PrunedMerkleTree::Empty => None,
        PrunedMerkleTree::Pruned { .. } => {
            panic!("Root cannot be Pruned - must have at least the root as Full");
        }
        PrunedMerkleTree::Full {
            key,
            value,
            left,
            right,
        } => Some(pruned_to_merk_inner(key, value, *left, *right)),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Guest utilities: compact PrunedMerkleTree witness → merk Node direct decode
// ═══════════════════════════════════════════════════════════════════════════

const PRUNED_WITNESS_EMPTY: u8 = 0;
const PRUNED_WITNESS_PRUNED: u8 = 1;
const PRUNED_WITNESS_FULL: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrunedWitnessDecodeError {
    UnexpectedEof,
    TrailingBytes { at: usize, len: usize },
    InvalidTag(u8),
    LengthOverflow,
    RootPruned,
    KvHashFailed,
}

impl fmt::Display for PrunedWitnessDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrunedWitnessDecodeError::UnexpectedEof => {
                formatter.write_str("unexpected end of pruned witness")
            }
            PrunedWitnessDecodeError::TrailingBytes { at, len } => {
                write!(
                    formatter,
                    "trailing bytes in pruned witness at offset {at} of {len}"
                )
            }
            PrunedWitnessDecodeError::InvalidTag(tag) => {
                write!(formatter, "invalid pruned witness tag {tag}")
            }
            PrunedWitnessDecodeError::LengthOverflow => {
                formatter.write_str("pruned witness length overflow")
            }
            PrunedWitnessDecodeError::RootPruned => {
                formatter.write_str("root pruned witness node cannot be pruned")
            }
            PrunedWitnessDecodeError::KvHashFailed => {
                formatter.write_str("kv_hash computation failed")
            }
        }
    }
}

/// Encode a pruned tree as a compact preorder witness for FF guest input.
///
/// Full nodes still carry key/value bytes, and compact decoding recomputes
/// `kv_hash(key, value)` before the verifier checks the committed root.
pub fn encode_pruned_compact(tree: &PrunedMerkleTree) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_pruned_compact_inner(tree, &mut bytes);
    bytes
}

fn encode_pruned_compact_inner(tree: &PrunedMerkleTree, out: &mut Vec<u8>) {
    match tree {
        PrunedMerkleTree::Empty => {
            out.push(PRUNED_WITNESS_EMPTY);
        }
        PrunedMerkleTree::Pruned {
            key,
            hash,
            child_heights,
        } => {
            out.push(PRUNED_WITNESS_PRUNED);
            write_compact_bytes(key, out);
            out.extend_from_slice(hash);
            out.push(child_heights.0);
            out.push(child_heights.1);
        }
        PrunedMerkleTree::Full {
            key,
            value,
            left,
            right,
        } => {
            out.push(PRUNED_WITNESS_FULL);
            write_compact_bytes(key, out);
            write_compact_bytes(value, out);
            encode_pruned_compact_inner(left, out);
            encode_pruned_compact_inner(right, out);
        }
    }
}

fn write_compact_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    let len = u32::try_from(bytes.len()).expect("compact pruned witness field exceeds u32");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

pub fn decode_pruned_compact_to_merk(
    bytes: &[u8],
) -> Result<Option<Node>, PrunedWitnessDecodeError> {
    let mut decoder = PrunedWitnessDecoder { bytes, pos: 0 };
    let root = decoder.decode_root()?;
    if decoder.pos != decoder.bytes.len() {
        return Err(PrunedWitnessDecodeError::TrailingBytes {
            at: decoder.pos,
            len: decoder.bytes.len(),
        });
    }
    Ok(root)
}

struct PrunedWitnessDecoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PrunedWitnessDecoder<'a> {
    fn decode_root(&mut self) -> Result<Option<Node>, PrunedWitnessDecodeError> {
        match self.read_u8()? {
            PRUNED_WITNESS_EMPTY => Ok(None),
            PRUNED_WITNESS_PRUNED => Err(PrunedWitnessDecodeError::RootPruned),
            PRUNED_WITNESS_FULL => self.decode_full_node().map(Some),
            tag => Err(PrunedWitnessDecodeError::InvalidTag(tag)),
        }
    }

    fn decode_child(&mut self) -> Result<Option<Child>, PrunedWitnessDecodeError> {
        match self.read_u8()? {
            PRUNED_WITNESS_EMPTY => Ok(None),
            PRUNED_WITNESS_PRUNED => self.decode_pruned_child().map(Some),
            PRUNED_WITNESS_FULL => self.decode_full_node().map(Child::Resident).map(Some),
            tag => Err(PrunedWitnessDecodeError::InvalidTag(tag)),
        }
    }

    fn decode_pruned_child(&mut self) -> Result<Child, PrunedWitnessDecodeError> {
        let key = self.read_vec()?;
        let hash = self.read_hash()?;
        let left_height = self.read_u8()?;
        let right_height = self.read_u8()?;
        Ok(Child::pruned(key, hash, (left_height, right_height)))
    }

    fn decode_full_node(&mut self) -> Result<Node, PrunedWitnessDecodeError> {
        let key = self.read_vec()?;
        let value = self.read_vec()?;
        let left = self.decode_child()?;
        let right = self.decode_child()?;
        let kv_hash =
            kv_hash::<Hasher>(&key, &value).map_err(|_| PrunedWitnessDecodeError::KvHashFailed)?;
        Ok(Node::from_fields(key, value, kv_hash, left, right))
    }

    fn read_u8(&mut self) -> Result<u8, PrunedWitnessDecodeError> {
        let byte = *self
            .bytes
            .get(self.pos)
            .ok_or(PrunedWitnessDecodeError::UnexpectedEof)?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_u32_le(&mut self) -> Result<u32, PrunedWitnessDecodeError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, PrunedWitnessDecodeError> {
        let len = self.read_u32_le()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_hash(&mut self) -> Result<[u8; 32], PrunedWitnessDecodeError> {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(self.read_exact(32)?);
        Ok(hash)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], PrunedWitnessDecodeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(PrunedWitnessDecodeError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(PrunedWitnessDecodeError::UnexpectedEof);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_op_key() {
        let put = BatchOp::Put {
            key: vec![1u8; 16],
            value: vec![2u8; 32],
        };
        let del = BatchOp::Delete { key: vec![3u8; 16] };

        assert_eq!(put.key(), &[1u8; 16]);
        assert_eq!(del.key(), &[3u8; 16]);
    }

    #[test]
    fn test_pruned_node_counts() {
        let tree = PrunedMerkleTree::Full {
            key: vec![0u8; 16],
            value: vec![0u8; 32],
            left: Box::new(PrunedMerkleTree::Pruned {
                key: vec![1u8; 16],
                hash: [0u8; 32],
                child_heights: (0, 0),
            }),
            right: Box::new(PrunedMerkleTree::Full {
                key: vec![2u8; 16],
                value: vec![0u8; 32],
                left: Box::new(PrunedMerkleTree::Empty),
                right: Box::new(PrunedMerkleTree::Empty),
            }),
        };

        assert_eq!(tree.count_full(), 2);
        assert_eq!(tree.count_pruned(), 1);
    }

    #[test]
    fn test_variable_length_keys() {
        // Test that variable-length keys work correctly
        let short_key = BatchOp::Put {
            key: vec![1, 2, 3],
            value: vec![10, 20],
        };
        let long_key = BatchOp::Put {
            key: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ],
            value: vec![100; 100],
        };

        assert_eq!(short_key.key().len(), 3);
        assert_eq!(long_key.key().len(), 20);
    }

    /// Build a 5-node BST for testing:
    ///       cc
    ///      /  \
    ///    bb    dd
    ///   /        \
    ///  aa         ee
    fn make_test_pruned_tree() -> PrunedMerkleTree {
        PrunedMerkleTree::Full {
            key: b"cc".to_vec(),
            value: b"val_cc".to_vec(),
            left: Box::new(PrunedMerkleTree::Full {
                key: b"bb".to_vec(),
                value: b"val_bb".to_vec(),
                left: Box::new(PrunedMerkleTree::Full {
                    key: b"aa".to_vec(),
                    value: b"val_aa".to_vec(),
                    left: Box::new(PrunedMerkleTree::Empty),
                    right: Box::new(PrunedMerkleTree::Empty),
                }),
                right: Box::new(PrunedMerkleTree::Empty),
            }),
            right: Box::new(PrunedMerkleTree::Full {
                key: b"dd".to_vec(),
                value: b"val_dd".to_vec(),
                left: Box::new(PrunedMerkleTree::Empty),
                right: Box::new(PrunedMerkleTree::Full {
                    key: b"ee".to_vec(),
                    value: b"val_ee".to_vec(),
                    left: Box::new(PrunedMerkleTree::Empty),
                    right: Box::new(PrunedMerkleTree::Empty),
                }),
            }),
        }
    }

    #[test]
    fn test_compact_pruned_witness_roundtrip() {
        let tree = make_test_pruned_tree();
        let bytes = encode_pruned_compact(&tree);

        let mut decoded = decode_pruned_compact_to_merk(&bytes)
            .expect("decode compact witness")
            .expect("decoded tree");
        decoded.commit();

        let mut expected = pruned_to_merk(tree).expect("expected tree");
        expected.commit();

        assert_eq!(decoded.hash(), expected.hash());
        assert_eq!(decoded.key(), expected.key());
        assert_eq!(decoded.child_heights(), expected.child_heights());
    }

    #[test]
    fn test_pruned_get_value() {
        let tree = make_test_pruned_tree();

        // Find existing keys
        assert_eq!(tree.get_value(b"aa"), Some(b"val_aa".as_slice()));
        assert_eq!(tree.get_value(b"bb"), Some(b"val_bb".as_slice()));
        assert_eq!(tree.get_value(b"cc"), Some(b"val_cc".as_slice()));
        assert_eq!(tree.get_value(b"dd"), Some(b"val_dd".as_slice()));
        assert_eq!(tree.get_value(b"ee"), Some(b"val_ee".as_slice()));

        // Missing keys return None
        assert_eq!(tree.get_value(b"ab"), None);
        assert_eq!(tree.get_value(b"ff"), None);
        assert_eq!(tree.get_value(b"a"), None);
    }

    #[test]
    fn test_pruned_collect_range() {
        let tree = make_test_pruned_tree();

        // Full range (no end bound)
        let all = tree.collect_range(b"aa", None);
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].0, b"aa");
        assert_eq!(all[4].0, b"ee");

        // Partial range [bb, dd)
        let mid = tree.collect_range(b"bb", Some(b"dd"));
        assert_eq!(mid.len(), 2);
        assert_eq!(mid[0].0, b"bb");
        assert_eq!(mid[1].0, b"cc");

        // Range matching nothing
        let empty = tree.collect_range(b"ff", Some(b"gg"));
        assert!(empty.is_empty());

        // Single-element range [cc, cd)
        let single = tree.collect_range(b"cc", Some(b"cd"));
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].0, b"cc");
    }

    #[test]
    fn test_extract_reads_pruned() {
        let tree = make_test_pruned_tree();

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(b"bb".to_vec()),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(b"zz".to_vec()), // missing
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Range {
                    start: b"cc".to_vec(),
                    end: b"ee".to_vec(),
                },
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Prefix(b"d".to_vec()),
                results: vec![],
            },
        ];

        let results = extract_reads_pruned(&tree, &reads);
        assert_eq!(results.len(), 4);

        // Key "bb" found
        assert_eq!(
            results[0].results,
            vec![(b"bb".to_vec(), b"val_bb".to_vec())]
        );
        // Key "zz" not found
        assert!(results[1].results.is_empty());
        // Range [cc, ee) → cc, dd
        assert_eq!(results[2].results.len(), 2);
        assert_eq!(results[2].results[0].0, b"cc");
        assert_eq!(results[2].results[1].0, b"dd");
        // Prefix "d" → dd
        assert_eq!(results[3].results.len(), 1);
        assert_eq!(results[3].results[0].0, b"dd");
    }

    #[test]
    #[should_panic(expected = "Pruned node encountered during key lookup")]
    fn test_pruned_get_value_panics_on_pruned() {
        let tree = PrunedMerkleTree::Full {
            key: b"cc".to_vec(),
            value: b"val_cc".to_vec(),
            left: Box::new(PrunedMerkleTree::Pruned {
                key: b"bb".to_vec(),
                hash: [0u8; 32],
                child_heights: (0, 0),
            }),
            right: Box::new(PrunedMerkleTree::Empty),
        };
        // Should panic — search path goes left through pruned node
        tree.get_value(b"aa");
    }

    #[test]
    #[should_panic(expected = "Pruned node on range traversal")]
    fn test_pruned_collect_range_panics_on_pruned() {
        let tree = PrunedMerkleTree::Full {
            key: b"cc".to_vec(),
            value: b"val_cc".to_vec(),
            left: Box::new(PrunedMerkleTree::Pruned {
                key: b"bb".to_vec(),
                hash: [0u8; 32],
                child_heights: (0, 0),
            }),
            right: Box::new(PrunedMerkleTree::Empty),
        };
        // Should panic — range traversal goes left through pruned node
        tree.collect_range(b"aa", Some(b"dd"));
    }
}
