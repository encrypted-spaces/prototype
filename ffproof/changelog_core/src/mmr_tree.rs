//! # Append-Only Merkle Log
//!
//! A left-balanced binary Merkle tree (a Merkle Mountain Range / MMR) used
//! as the Changelog Commitment (CLC). The construction follows the Merkle
//! Tree Hash defined in RFC 6962 §2.1, with one extension (a third leaf
//! domain tag) described below.
//!
//! ## Structure
//! Leaves are appended one at a time. The committed shape is a
//! *left-balanced* binary Merkle tree: the left subtree of the root is
//! always the largest perfect binary tree that fits, and the right subtree
//! is the rest, recursively. Equivalently, the tree is a Merkle Mountain
//! Range of perfect-binary peaks whose heights are the bit positions of
//! `tree_size`. For example, `tree_size = 11 = 0b1011` has peaks of heights
//! 3, 1, 0 (sizes 8, 2, 1) folded into a single root.
//!
//! ## State carried by the writer
//! * `peaks`: the root hashes of the current peaks, ordered tallest first.
//! * `tree_size`: the leaf count (RFC 6962 terminology).
//!
//! `peaks.len() == tree_size.count_ones()`, i.e. `O(log tree_size)` hashes.
//!
//! ## Hashing & domain separation
//! SHA-256 with one-byte tags:
//! ```text
//!   real leaf:      H(0x00 || entry_bytes)
//!   internal node:  H(0x01 || left_hash || right_hash)
//!   initial leaf: H(0x02 || initial_dc_bytes)
//! ```
//! The first two tags are the RFC 6962 §2.1 leaf/internal tags; the third
//! is added here for a synthetic *initial* leaf appended at index 0
//! before any real entries. The initial leaf binds an initial value
//! (the changelog's initial digest commitment) into every future root,
//! and its distinct tag guarantees it can never collide with a real leaf.
//!
//! Tags prevent leaf/internal/initial confusion (RFC 6962 §2.1: "this
//! domain separation is required to give second preimage resistance").
//!
//! ## Empty tree
//! RFC 6962 defines `MTH({}) = SHA-256("")`. This implementation
//! deliberately returns `None` from [`MmrTree::root`] for an empty tree: in
//! the intended workflow a writer always calls [`MmrTree::initialize`]
//! before any real append, so the empty tree is never observed as a live
//! commitment.
//!
//! ## Security notes (see RFC 6962 §7)
//! * The commitment is the pair `(root, tree_size)`. `tree_size` MUST be
//!   published alongside `root`; verifiers MUST cross-check the proof's
//!   declared `tree_size` against the trusted [`TreeHead`] (this is done
//!   in [`verify_with_leaf_hash`]).
//! * Domain tags prevent the standard "internal-hash-as-leaf" second-
//!   preimage attack regardless of entry contents: an attacker cannot
//!   present a 33-byte string of the form `0x01 || L || R` as a leaf,
//!   because real leaves are tagged `0x00`.
//! * Consistency proofs between two `tree_size` values (RFC 6962 §2.1.2)
//!   are *not* implemented here; they are a latent extension that is not
//!   currently required by callers.
//!
//! ## Operations & costs
//! * [`MmrTree::append`] / [`MmrTree::initialize`]: amortized O(1), worst
//!   case O(log tree_size) hashes.
//! * [`MmrTree::root`] / [`MmrTree::tree_head`]: O(log tree_size).
//! * [`prove`] / [`prove_from_leaf_hashes`]: O(n log n) — they build a
//!   [`ProofCache`] internally and discard it. Callers expecting many
//!   proofs against an evolving leaf list should keep a long-lived
//!   [`ProofCache`], extend it incrementally as leaves are added
//!   ([`ProofCache::extend_with_leaf`], O(log n) per extension), and
//!   call [`ProofCache::prove`] (O(log n) per proof, zero hashes).
//! * [`verify`] / [`verify_with_leaf_hash`]: O(log tree_size), stateless.

#![allow(dead_code)]

use std::collections::HashMap;

use risc0_zkvm::sha::{Digest, Impl, Sha256};
use serde::{Deserialize, Serialize};

pub const TAG_LEAF: u8 = 0x00;
pub const TAG_NODE: u8 = 0x01;
pub const TAG_INIT: u8 = 0x02;

/// Maximum supported leaf count.
///
/// The choice is **arbitrary**: it caps `tree_size` at `u32::MAX` (~4.3 B
/// leaves), which is comfortably enough for any realistic application of
/// this tree. The cap exists primarily so that verifiers can put an
/// upper bound on the size of an inclusion proof they will accept (at
/// most `MAX_INCLUSION_PROOF_SIBLINGS = 32` sibling hashes, i.e.
/// `⌈log₂ MAX_TREE_SIZE⌉`) without having to allow proof sizes that
/// could blow up the verifier's resource budget. Encoding `tree_size` as
/// `u32` makes that bound a property of the type system rather than a
/// runtime check.
pub const MAX_TREE_SIZE: u32 = u32::MAX;
pub const MAX_INCLUSION_PROOF_SIBLINGS: usize = u32::BITS as usize;

const DIGEST_BYTES: usize = 32;

/// Hash a real changelog entry leaf: `H(0x00 || entry_bytes)`.
pub fn h_leaf(data: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(TAG_LEAF);
    buf.extend_from_slice(data);
    *Impl::hash_bytes(&buf)
}

/// Hash the synthetic initial leaf: `H(0x02 || initial_dc_bytes)`.
///
/// Distinct from `h_leaf` so the initial leaf can never collide with a
/// real `ChangelogEntry` leaf.
pub fn h_init(data: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(TAG_INIT);
    buf.extend_from_slice(data);
    *Impl::hash_bytes(&buf)
}

/// Hash an internal node: `H(0x01 || left_hash || right_hash)`.
pub fn h_node(left: &Digest, right: &Digest) -> Digest {
    #[cfg(test)]
    tests::H_NODE_CALLS.with(|c| c.set(c.get() + 1));
    let mut buf = Vec::with_capacity(1 + 2 * DIGEST_BYTES);
    buf.push(TAG_NODE);
    buf.extend_from_slice(left.as_bytes());
    buf.extend_from_slice(right.as_bytes());
    *Impl::hash_bytes(&buf)
}

// ---------------------------------------------------------------------------
// Writer state
// ---------------------------------------------------------------------------

/// Mutable writer-side state: just the peak hashes (tallest first) and the
/// leaf count.
///
/// Invariants:
/// * `peaks.len() == tree_size.count_ones()`
/// * The i-th peak (from the left in the final tree) covers a subtree of
///   size `2^k` where `k` is the position of the i-th set bit of
///   `tree_size`, scanned from the most significant bit down.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrTree {
    /// Peak hashes ordered from tallest to shortest peak.
    pub peaks: Vec<Digest>,
    /// Total leaf count (RFC 6962 `tree_size`), including the initial
    /// leaf when present. Bounded by [`MAX_TREE_SIZE`] = `u32::MAX`.
    pub tree_size: u32,
}

impl MmrTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append the synthetic initial leaf carrying `initial_dc`. Must be
    /// called exactly once on an empty tree; afterwards `tree_size == 1`
    /// and the (sole) peak is `H(0x02 || initial_dc)`.
    pub fn initialize(&mut self, initial_dc: &[u8]) {
        assert_eq!(
            self.tree_size, 0,
            "initialize called on non-empty tree (tree_size={})",
            self.tree_size
        );
        assert!(
            self.peaks.is_empty(),
            "initialize called with non-empty peaks on an empty tree"
        );
        self.append_hash(h_init(initial_dc));
    }

    /// Append one real changelog entry. The leaf hash is `H(0x00 || entry)`.
    /// O(log tree_size) worst case, O(1) amortized.
    ///
    /// Returns the domain-tagged leaf hash that was folded into the peaks
    /// so callers that already need it (e.g. the FF guest binding entry
    /// bytes into the proven sigref map) don't have to re-hash.
    pub fn append(&mut self, entry: &[u8]) -> Digest {
        assert!(
            self.tree_size > 0,
            "append called before initialize; call MmrTree::initialize first"
        );
        let leaf_hash = h_leaf(entry);
        self.append_hash(leaf_hash);
        leaf_hash
    }

    fn append_hash(&mut self, leaf_hash: Digest) {
        assert!(
            writer_state_is_well_formed(self.tree_size, &self.peaks),
            "MMR writer state is malformed before append"
        );
        assert!(
            self.tree_size < MAX_TREE_SIZE,
            "MMR tree_size exceeds maximum supported leaves ({MAX_TREE_SIZE})"
        );
        let mut carry = leaf_hash;
        // Merge with each trailing peak of equal height: the number of
        // merges is exactly the number of trailing 1-bits of the *current*
        // tree_size.
        let mut k = self.tree_size;
        while k & 1 == 1 {
            let left = self
                .peaks
                .pop()
                .expect("peak invariant: trailing 1-bits require a matching peak");
            carry = h_node(&left, &carry);
            k >>= 1;
        }
        self.peaks.push(carry);
        // Guarded above by `tree_size < MAX_TREE_SIZE`, so this addition
        // cannot overflow `u32`. We use the panicking `+` (rather than
        // `wrapping_add`) so any future weakening of that invariant is
        // caught loudly instead of silently corrupting the commitment.
        self.tree_size += 1;
    }

    /// Compute the single root by folding peaks shortest-to-tallest:
    /// `root = h(P_tallest, h(P_next, h(..., P_shortest)))`.
    /// Returns `None` for an empty (un-initialized) tree.
    pub fn root(&self) -> Option<Digest> {
        if !writer_state_is_well_formed(self.tree_size, &self.peaks) {
            return None;
        }
        fold_peaks(&self.peaks)
    }

    /// Borrow a `TreeHead` snapshot of the current state. Returns `None`
    /// for an empty tree.
    pub fn tree_head(&self) -> Option<TreeHead> {
        Some(TreeHead {
            root: self.root()?,
            tree_size: self.tree_size,
            peaks: self.peaks.clone(),
        })
    }

    /// `popcount(tree_size)` — also the length of `peaks`.
    pub fn peak_count(&self) -> u32 {
        self.tree_size.count_ones()
    }
}

fn fold_peaks(peaks: &[Digest]) -> Option<Digest> {
    let mut it = peaks.iter().rev(); // shortest first
    let mut acc = *it.next()?;
    for p in it {
        acc = h_node(p, &acc);
    }
    Some(acc)
}

fn is_supported_live_tree_size(tree_size: u32) -> bool {
    // The upper bound (MAX_TREE_SIZE = u32::MAX) is enforced by the type;
    // we only need to exclude the empty tree here.
    tree_size != 0
}

fn peak_count_matches(tree_size: u32, peaks: &[Digest]) -> bool {
    match u32::try_from(peaks.len()) {
        Ok(peak_count) => peak_count == tree_size.count_ones(),
        Err(_) => false,
    }
}

fn writer_state_is_well_formed(tree_size: u32, peaks: &[Digest]) -> bool {
    if tree_size == 0 {
        return peaks.is_empty();
    }
    is_supported_live_tree_size(tree_size) && peak_count_matches(tree_size, peaks)
}

fn tree_head_parts_are_well_formed(tree_size: u32, peaks: &[Digest], root: Digest) -> bool {
    is_supported_live_tree_size(tree_size)
        && peak_count_matches(tree_size, peaks)
        && fold_peaks(peaks) == Some(root)
}

// ---------------------------------------------------------------------------
// TreeHead — serialisable commitment shipped on FF proof endpoints.
// ---------------------------------------------------------------------------

/// Serialisable MMR commitment. `peaks.len() == tree_size.count_ones()`
/// (which is `≤ ⌈log₂ tree_size⌉`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHead {
    pub root: Digest,
    /// Total leaf count. Bounded by [`MAX_TREE_SIZE`] = `u32::MAX`.
    pub tree_size: u32,
    pub peaks: Vec<Digest>,
}

impl TreeHead {
    fn is_well_formed(&self) -> bool {
        tree_head_parts_are_well_formed(self.tree_size, &self.peaks, self.root)
    }

    /// Verify this head is internally consistent and has exactly
    /// `expected_tree_size` leaves.
    pub fn verify_for_tree_size(&self, expected_tree_size: u32) -> bool {
        self.tree_size == expected_tree_size
            && tree_head_parts_are_well_formed(self.tree_size, &self.peaks, self.root)
    }

    /// Verify this head is internally consistent and corresponds to the CLC
    /// state after `change_id` real changes. The synthetic initial leaf makes
    /// `tree_size == change_id + 1`. Returns `false` if `change_id + 1`
    /// would overflow `u32` (i.e. `change_id == u32::MAX`), since such a
    /// state cannot exist within `MAX_TREE_SIZE`.
    pub fn verify_for_change_id(&self, change_id: u32) -> bool {
        match change_id.checked_add(1) {
            Some(expected) => self.verify_for_tree_size(expected),
            None => false,
        }
    }

    /// Append `entry` into this head if it is a valid, initialized head.
    /// Returns `false` and leaves `self` unchanged if validation fails.
    /// O(log tree_size) worst case.
    pub fn try_append(&mut self, entry: &[u8]) -> bool {
        if !self.is_well_formed() || self.tree_size == MAX_TREE_SIZE {
            return false;
        }
        let mut tree = MmrTree {
            peaks: self.peaks.clone(),
            tree_size: self.tree_size,
        };
        tree.append(entry);
        *self = tree
            .rooted_head()
            .expect("valid non-empty head after append");
        true
    }

    /// Append `entry` into this head, mutating it in place.
    /// Panics if the head is invalid or uninitialized; use
    /// [`TreeHead::try_append`] at fallible protocol boundaries.
    /// O(log tree_size) worst case.
    pub fn append(&mut self, entry: &[u8]) {
        assert!(
            self.try_append(entry),
            "TreeHead::append called on invalid or uninitialized head"
        );
    }
}

impl MmrTree {
    fn rooted_head(&self) -> Option<TreeHead> {
        Some(TreeHead {
            root: self.root()?,
            tree_size: self.tree_size,
            peaks: self.peaks.clone(),
        })
    }
}

impl From<&MmrTree> for Option<TreeHead> {
    fn from(tree: &MmrTree) -> Self {
        tree.tree_head()
    }
}

// ---------------------------------------------------------------------------
// Inclusion proofs
// ---------------------------------------------------------------------------

/// Inclusion proof: sibling hashes from the leaf up to the root, plus the
/// leaf index `i` and the `tree_size` the proof was generated against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Leaf index. Bounded by `tree_size`, hence by [`MAX_TREE_SIZE`].
    pub i: u32,
    /// Tree size the proof was generated against. Bounded by
    /// [`MAX_TREE_SIZE`] = `u32::MAX`.
    pub tree_size: u32,
    /// Sibling hashes ordered leaf -> root.
    pub siblings: Vec<Digest>,
}

/// Precomputed cache of every subtree-root hash in a left-balanced
/// Merkle tree, allowing O(log n) inclusion-proof generation.
///
/// **Maintenance model.** The cache is built incrementally — one
/// [`ProofCache::extend_with_leaf`] call per leaf, costing O(log n)
/// hashes per extension (the same merge cascade [`MmrTree::append`]
/// performs). After `n` extensions the cache holds every `(lo, hi)`
/// subtree-range hash that the left-balanced recursion can produce for
/// `D[0..n]`. [`ProofCache::prove`] then reads sibling subtree roots
/// out of the cache: O(log n) lookups and zero hashing per proof.
///
/// **Pure cache.** The cache is fully reconstructible from the
/// underlying leaf list and is intended to be skipped during
/// serialisation. Callers that drop and reload the cache pay an O(n)
/// rebuild on the next proof.
///
/// **Memory.** The cache stores up to one digest per `(lo, hi)` range
/// ever produced by the recursion across every prefix `D[0..k]`,
/// `1 <= k <= n`. Each extension inserts at most `1 + (trailing 1-bits
/// of old leaf_count)` entries, so the total entry count is `O(n)`.
#[derive(Default, Clone, Debug)]
pub struct ProofCache {
    leaf_count: u32,
    /// Map from a half-open leaf range `(lo, hi)` (with `0 <= lo < hi
    /// <= leaf_count`) to the Merkle root of `D[lo..hi]` under the
    /// left-balanced split rule.
    nodes: HashMap<(u32, u32), Digest>,
}

impl ProofCache {
    /// Empty cache covering zero leaves. Use [`ProofCache::extend_with_leaf`]
    /// to grow it; pre-tagged leaf digests (i.e. [`h_leaf`] / [`h_init`]
    /// outputs) must be supplied — the cache does no domain tagging of
    /// its own.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the cache from a full leaf-hash list by extending one leaf
    /// at a time. O(n log n) hashes total (n × O(log n) per extension);
    /// internally identical to calling [`ProofCache::extend_with_leaf`]
    /// in a loop. Returns `None` if `leaf_hashes.len() > MAX_TREE_SIZE`.
    pub fn from_leaf_hashes(leaf_hashes: &[Digest]) -> Option<Self> {
        u32::try_from(leaf_hashes.len()).ok()?;
        let mut cache = Self::new();
        for h in leaf_hashes {
            cache.extend_with_leaf(*h);
        }
        Some(cache)
    }

    /// Number of leaves the cache currently covers.
    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    /// True iff the cache covers zero leaves.
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// Look up the cached Merkle root of `D[lo..hi]`. Returns `None` if
    /// the range is not present in the cache. Intended for callers that
    /// need to validate the cache against an externally-tracked root
    /// (e.g. the live MMR head) before trusting it for proof
    /// generation.
    pub fn cached_subtree_root(&self, lo: u32, hi: u32) -> Option<Digest> {
        self.nodes.get(&(lo, hi)).copied()
    }

    /// Extend the cache by one leaf. `leaf_hash` MUST already be domain-
    /// tagged (use [`h_leaf`] for real entries or [`h_init`] for the
    /// synthetic initial leaf) — the cache never hashes the raw bytes.
    ///
    /// O(log n) hashes and O(log n) `HashMap` inserts per extension.
    /// Walks the right spine of the new tree `D[0..n+1]` and inserts a
    /// cache entry for every range `(lo, n+1)` produced by the
    /// recursion. These are exactly the new internal nodes that appear
    /// in the left-balanced tree on `n+1` leaves; their left children
    /// are spine left-subtrees of `(0, n+1)`, which by the
    /// left-balanced split rule are perfect (power-of-two-sized)
    /// subtrees and therefore already cached from earlier extensions.
    ///
    /// # Panics
    /// If extending would exceed [`MAX_TREE_SIZE`].
    pub fn extend_with_leaf(&mut self, leaf_hash: Digest) {
        assert!(
            self.leaf_count < MAX_TREE_SIZE,
            "ProofCache leaf_count would exceed MAX_TREE_SIZE ({MAX_TREE_SIZE})"
        );
        let n = self.leaf_count;
        let new_size = n + 1;

        // (n, n+1) is the singleton leaf range.
        self.nodes.insert((n, new_size), leaf_hash);

        // Collect the right-spine left-subtree ranges of (0, n+1),
        // root-first. Each (left_lo, left_mid) is the *left* child at
        // some level of the recursion; we then descend into the right
        // child and repeat. The recursion terminates when the right
        // child is the singleton (n, n+1).
        //
        // By the left-balanced split rule, each such left subtree has
        // size = largest_pow2_less_than(remaining_span), which is a
        // perfect power of two. Perfect subtrees are inserted exactly
        // once (when their right edge is first appended) and persist
        // forever, so every spine left-subtree is guaranteed to be in
        // the cache.
        let mut spine: Vec<(u32, u32)> = Vec::new();
        let mut lo = 0u32;
        let hi = new_size;
        while hi - lo > 1 {
            let span = (hi - lo) as usize;
            let k = largest_pow2_less_than(span) as u32;
            let mid = lo + k;
            spine.push((lo, mid));
            lo = mid;
        }
        debug_assert_eq!(lo, n, "right spine must terminate at the new leaf");

        // Compute hashes bottom-up, materialising one new (left_lo,
        // n+1) range per spine level.
        let mut cur_hash = leaf_hash;
        for (left_lo, left_mid) in spine.iter().rev() {
            let left_hash = *self.nodes.get(&(*left_lo, *left_mid)).expect(
                "ProofCache invariant: spine left-subtree must be cached \
                     (perfect subtrees never expire)",
            );
            cur_hash = h_node(&left_hash, &cur_hash);
            self.nodes.insert((*left_lo, new_size), cur_hash);
        }

        // Guarded above by `leaf_count < MAX_TREE_SIZE`.
        self.leaf_count = new_size;
    }

    /// Generate an inclusion proof for leaf index `i`. O(log n) lookups
    /// and zero hashing. Returns `None` if `i >= leaf_count`.
    pub fn prove(&self, i: u32) -> Option<InclusionProof> {
        let (proof, _ops) = self.prove_inner(i)?;
        Some(proof)
    }

    /// Internal proof routine that also returns the number of inner-loop
    /// iterations performed (one lookup + one half-tree decision per
    /// iteration). Used by tests to assert that proof generation does
    /// O(log n) work; not part of the public API surface.
    fn prove_inner(&self, i: u32) -> Option<(InclusionProof, usize)> {
        if i >= self.leaf_count {
            return None;
        }
        let mut siblings = Vec::new();
        let mut lo = 0u32;
        let mut hi = self.leaf_count;
        let mut ops = 0usize;
        // Walk root-to-leaf, reading the sibling subtree's cached root
        // at each step. The path length is ⌈log₂ leaf_count⌉, capped by
        // MAX_INCLUSION_PROOF_SIBLINGS (= 32 for u32 sizes), so this
        // loop runs O(log n) times and each iteration does O(1) work.
        while hi - lo > 1 {
            ops += 1;
            let span = (hi - lo) as usize;
            let k = largest_pow2_less_than(span) as u32;
            let mid = lo + k;
            let sibling = if i < mid {
                let sib = *self
                    .nodes
                    .get(&(mid, hi))
                    .expect("ProofCache invariant: sibling subtree was cached at build time");
                hi = mid;
                sib
            } else {
                let sib = *self
                    .nodes
                    .get(&(lo, mid))
                    .expect("ProofCache invariant: sibling subtree was cached at build time");
                lo = mid;
                sib
            };
            siblings.push(sibling);
        }
        // Reverse so the proof is ordered leaf -> root, matching the
        // `InclusionProof` contract that `verify_with_leaf_hash` expects.
        siblings.reverse();
        Some((
            InclusionProof {
                i,
                tree_size: self.leaf_count,
                siblings,
            },
            ops,
        ))
    }
}

/// Generate an inclusion proof for leaf index `i` from the full leaf-hash
/// list. Builds a transient [`ProofCache`] (O(n log n) hashes total) and
/// queries it (O(log n)); for repeated proofs against an evolving leaf
/// list, prefer maintaining a long-lived [`ProofCache`] and calling
/// [`ProofCache::extend_with_leaf`] / [`ProofCache::prove`] directly.
pub fn prove_from_leaf_hashes(leaf_hashes: &[Digest], i: u32) -> Option<InclusionProof> {
    let n: u32 = u32::try_from(leaf_hashes.len()).ok()?;
    if i >= n {
        return None;
    }
    ProofCache::from_leaf_hashes(leaf_hashes)?.prove(i)
}

/// Convenience wrapper that hashes raw entry bytes (real leaves only).
/// Initialize leaves must be hashed via [`h_init`] first and passed to
/// [`prove_from_leaf_hashes`].
pub fn prove(entries: &[Vec<u8>], i: u32) -> Option<InclusionProof> {
    let hashes: Vec<Digest> = entries.iter().map(|e| h_leaf(e)).collect();
    prove_from_leaf_hashes(&hashes, i)
}

/// Compute the root of `hashes[lo..hi]` using the left-balanced split rule.
/// Used by tests as an independent reference for [`MmrTree::root`] and
/// [`ProofCache`]; production code uses [`MmrTree::root`] (peak fold) or
/// [`ProofCache::from_leaf_hashes`] instead.
fn subtree_root(hashes: &[Digest], lo: usize, hi: usize) -> Digest {
    let len = hi - lo;
    debug_assert!(len >= 1);
    if len == 1 {
        return hashes[lo];
    }
    let k = largest_pow2_less_than(len);
    let left = subtree_root(hashes, lo, lo + k);
    let right = subtree_root(hashes, lo + k, hi);
    h_node(&left, &right)
}

fn largest_pow2_less_than(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << (usize::BITS as usize - 1 - (n - 1).leading_zeros() as usize)
}

fn proof_directions(
    tree_size: u32,
    i: u32,
) -> Option<([bool; MAX_INCLUSION_PROOF_SIBLINGS], usize)> {
    if !is_supported_live_tree_size(tree_size) || i >= tree_size {
        return None;
    }

    let mut directions = [false; MAX_INCLUSION_PROOF_SIBLINGS];
    let mut direction_count = 0usize;
    let mut lo = 0u32;
    let mut hi = tree_size;
    while hi - lo > 1 {
        if direction_count == MAX_INCLUSION_PROOF_SIBLINGS {
            return None;
        }
        let span = (hi - lo) as usize;
        let k = largest_pow2_less_than(span) as u32;
        let mid = lo + k;
        if i < mid {
            directions[direction_count] = true;
            hi = mid;
        } else {
            directions[direction_count] = false;
            lo = mid;
        }
        direction_count += 1;
    }
    Some((directions, direction_count))
}

/// Verify an inclusion proof against an expected `TreeHead`.
/// Stateless and O(log tree_size).
///
/// `leaf_hash` is the already-domain-tagged leaf digest (use [`h_leaf`] for
/// real entries or [`h_init`] for the initial leaf).
pub fn verify_with_leaf_hash(head: &TreeHead, proof: &InclusionProof, leaf_hash: Digest) -> bool {
    if !head.is_well_formed() {
        return false;
    }
    if proof.tree_size != head.tree_size {
        return false;
    }
    if proof.siblings.len() > MAX_INCLUSION_PROOF_SIBLINGS {
        return false;
    }
    let Some((directions, direction_count)) = proof_directions(proof.tree_size, proof.i) else {
        return false;
    };
    if direction_count != proof.siblings.len() {
        return false;
    }

    let mut acc = leaf_hash;
    // Apply siblings bottom-up (proof order is leaf -> root, matching
    // `directions` reversed: deepest decision was made last).
    for (sib, on_left) in proof
        .siblings
        .iter()
        .zip(directions[..direction_count].iter().rev())
    {
        acc = if *on_left {
            h_node(&acc, sib)
        } else {
            h_node(sib, &acc)
        };
    }
    acc == head.root
}

/// Convenience wrapper that hashes raw entry bytes as a real leaf.
pub fn verify(head: &TreeHead, proof: &InclusionProof, entry: &[u8]) -> bool {
    verify_with_leaf_hash(head, proof, h_leaf(entry))
}

// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Thread-local counter incremented inside `h_node` (test builds only).
    // Lets tests assert that proof generation off a precomputed
    // `ProofCache` performs *zero* hashing, which is the actual
    // runtime-cost claim we want to lock in.
    thread_local! {
        pub(super) static H_NODE_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    fn h_node_calls() -> usize {
        H_NODE_CALLS.with(|c| c.get())
    }

    /// Independent reference for the RFC 6962 audit path. Recursively
    /// builds the path leaf -> root by re-hashing every sibling subtree
    /// from raw leaf hashes — i.e. the previous O(n)-per-call algorithm.
    /// Used only by tests to cross-check `ProofCache::prove`.
    fn reference_path(
        hashes: &[Digest],
        lo: usize,
        hi: usize,
        target: usize,
        out: &mut Vec<Digest>,
    ) {
        let len = hi - lo;
        if len == 1 {
            return;
        }
        let k = largest_pow2_less_than(len);
        let mid = lo + k;
        if target < mid {
            reference_path(hashes, lo, mid, target, out);
            out.push(subtree_root(hashes, mid, hi));
        } else {
            reference_path(hashes, mid, hi, target, out);
            out.push(subtree_root(hashes, lo, mid));
        }
    }

    fn entries(n: u32) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("entry-{i}").into_bytes()).collect()
    }

    /// Build the leaf-hash list for an MMR with a initial leaf at
    /// position 0 and `real_entries` afterwards.
    fn leaves_with_init(initial_dc: &[u8], real_entries: &[Vec<u8>]) -> Vec<Digest> {
        let mut hs = Vec::with_capacity(1 + real_entries.len());
        hs.push(h_init(initial_dc));
        hs.extend(real_entries.iter().map(|e| h_leaf(e)));
        hs
    }

    fn append_raw_entry(tree: &mut MmrTree, entry: &[u8]) {
        tree.append_hash(h_leaf(entry));
    }

    #[test]
    fn append_matches_full_recompute() {
        for n in 0u32..=33 {
            let es = entries(n);
            let mut tree = MmrTree::new();
            for e in &es {
                append_raw_entry(&mut tree, e);
            }
            assert_eq!(tree.tree_size, n);
            assert_eq!(tree.peaks.len() as u32, n.count_ones());
            match tree.root() {
                None => assert_eq!(n, 0),
                Some(r) => {
                    let hs: Vec<Digest> = es.iter().map(|e| h_leaf(e)).collect();
                    assert_eq!(r, subtree_root(&hs, 0, n as usize));
                }
            }
        }
    }

    #[test]
    fn proofs_round_trip_for_every_index() {
        for n in 1u32..=33 {
            let es = entries(n);
            let mut tree = MmrTree::new();
            for e in &es {
                append_raw_entry(&mut tree, e);
            }
            let head = tree.tree_head().unwrap();
            assert!(head.verify_for_tree_size(n));
            for i in 0..n {
                let p = prove(&es, i).unwrap();
                assert!(verify(&head, &p, &es[i as usize]), "n={n} i={i}");
                // Tampered leaf must fail.
                assert!(!verify(&head, &p, b"nope"));
                // Wrong index must fail.
                let mut bad = p.clone();
                bad.i = (i + 1) % n;
                if bad.i != p.i {
                    assert!(!verify(&head, &bad, &es[i as usize]));
                }
            }
        }
    }

    #[test]
    fn initialize_yields_tree_size_one() {
        let mut tree = MmrTree::new();
        tree.initialize(b"initial-dc");
        assert_eq!(tree.tree_size, 1);
        assert_eq!(tree.peaks.len(), 1);
        assert_eq!(tree.root().unwrap(), h_init(b"initial-dc"));
    }

    #[test]
    #[should_panic(expected = "initialize called on non-empty tree")]
    fn initialize_twice_panics() {
        let mut tree = MmrTree::new();
        tree.initialize(b"initial-dc");
        tree.initialize(b"again");
    }

    #[test]
    #[should_panic(expected = "append called before initialize")]
    fn append_before_initialize_panics() {
        let mut tree = MmrTree::new();
        tree.append(b"entry");
    }

    #[test]
    fn initialize_disjoint_from_real_leaf() {
        // Same bytes hashed under different domain tags must not collide.
        assert_ne!(h_leaf(b"x"), h_init(b"x"));
        assert_ne!(
            h_leaf(b"x").as_bytes(),
            h_node(&Digest::default(), &Digest::default()).as_bytes()
        );
    }

    /// `tree_size == change_id + 1` invariant: the initial leaf occupies
    /// MMR position 0, and real change `k` lives at MMR leaf position `k`.
    #[test]
    fn tree_size_equals_change_id_plus_one() {
        let mut tree = MmrTree::new();
        tree.initialize(b"initial-dc");
        // After initialize: current_change_id == 0 + tree_size == 1.
        assert_eq!(tree.tree_size, 1);

        for change_id in 1u32..=20 {
            tree.append(format!("change-{change_id}").as_bytes());
            assert_eq!(tree.tree_size, change_id + 1, "change_id={change_id}");
        }
    }

    /// `roots_by_change_id[k]` must equal the live root after appending
    /// the k-th real change (with initialize at index 0).
    #[test]
    fn roots_by_change_id_matches_live_root() {
        let initial_dc = b"initial-dc";
        let real = entries(10);

        let mut tree = MmrTree::new();
        tree.initialize(initial_dc);
        let mut roots_by_change_id: Vec<Digest> = vec![tree.root().unwrap()];
        for e in &real {
            tree.append(e);
            roots_by_change_id.push(tree.root().unwrap());
        }
        assert_eq!(roots_by_change_id.len(), real.len() + 1);

        // Cross-check: each historical root recovered from the leaf list.
        let mut leaf_hashes = vec![h_init(initial_dc)];
        for (k, e) in real.iter().enumerate() {
            leaf_hashes.push(h_leaf(e));
            let len = leaf_hashes.len();
            let r = subtree_root(&leaf_hashes, 0, len);
            assert_eq!(roots_by_change_id[k + 1], r, "change_id={}", k + 1);
        }
    }

    /// Inclusion proofs against an MMR that includes the initial leaf.
    #[test]
    fn inclusion_proofs_with_init() {
        let initial_dc = b"initial-dc";
        for n_real in 0u32..=20 {
            let real = entries(n_real);
            let mut tree = MmrTree::new();
            tree.initialize(initial_dc);
            for e in &real {
                tree.append(e);
            }
            let head = tree.tree_head().unwrap();
            let leaf_hashes = leaves_with_init(initial_dc, &real);

            // Initial leaf must be provable at index 0.
            let p0 = prove_from_leaf_hashes(&leaf_hashes, 0).unwrap();
            assert!(
                verify_with_leaf_hash(&head, &p0, h_init(initial_dc)),
                "initialize inclusion failed at n_real={n_real}"
            );
            // Real leaves at positions 1..=n_real.
            for (k, e) in real.iter().enumerate() {
                let i = (k + 1) as u32;
                let p = prove_from_leaf_hashes(&leaf_hashes, i).unwrap();
                assert!(verify(&head, &p, e), "n_real={n_real} change_id={}", k + 1);
            }
        }
    }

    #[test]
    fn tree_head_validation_detects_tampering() {
        let mut tree = MmrTree::new();
        tree.initialize(b"dc");
        for e in entries(7).iter() {
            tree.append(e);
        }
        let head = tree.tree_head().unwrap();
        assert!(head.verify_for_change_id(7));

        // Wrong root.
        let mut bad = head.clone();
        bad.root = Digest::default();
        assert!(!bad.verify_for_change_id(7));

        // Peak count mismatch.
        let mut bad = head.clone();
        bad.peaks.pop();
        assert!(!bad.verify_for_change_id(7));

        // Tampered peak.
        let mut bad = head.clone();
        bad.peaks[0] = Digest::default();
        assert!(!bad.verify_for_change_id(7));
    }

    #[test]
    fn tree_head_validation_rejects_empty_and_wrong_expected_size() {
        assert!(!TreeHead::default().verify_for_tree_size(0));

        let mut tree = MmrTree::new();
        tree.initialize(b"dc");
        tree.append(b"entry-1");
        tree.append(b"entry-2");
        let head = tree.tree_head().unwrap();

        assert!(head.verify_for_change_id(2));
        assert!(head.verify_for_tree_size(3));
        assert!(!head.verify_for_change_id(4));
        assert!(!head.verify_for_tree_size(5));

        let mut relabeled = head.clone();
        relabeled.tree_size = 5;
        assert!(!relabeled.verify_for_tree_size(head.tree_size));
        assert!(!relabeled.verify_for_change_id(2));
    }

    #[test]
    fn tree_head_append_matches_tree_append() {
        let mut tree = MmrTree::new();
        tree.initialize(b"dc");
        let mut head = tree.tree_head().unwrap();
        for (k, e) in entries(15).iter().enumerate() {
            tree.append(e);
            head.append(e);
            assert_eq!(head, tree.tree_head().unwrap(), "step {k}");
        }
    }

    #[test]
    fn tree_head_try_append_rejects_invalid_heads_without_mutating() {
        let mut tree = MmrTree::new();
        tree.initialize(b"dc");
        let head = tree.tree_head().unwrap();

        let mut bad = head.clone();
        bad.root = Digest::default();
        let original = bad.clone();
        assert!(!bad.try_append(b"entry"));
        assert_eq!(bad, original);

        let mut empty = TreeHead::default();
        let original = empty.clone();
        assert!(!empty.try_append(b"entry"));
        assert_eq!(empty, original);
    }

    #[test]
    #[should_panic(expected = "TreeHead::append called on invalid or uninitialized head")]
    fn tree_head_append_invalid_panics() {
        TreeHead::default().append(b"entry");
    }

    /// `verify_for_change_id(u32::MAX)` would require `tree_size ==
    /// u32::MAX + 1`, which overflows; the API must reject this rather
    /// than panicking.
    #[test]
    fn verify_for_change_id_rejects_overflow() {
        let mut tree = MmrTree::new();
        tree.initialize(b"dc");
        let head = tree.tree_head().unwrap();
        assert!(!head.verify_for_change_id(u32::MAX));
    }

    #[test]
    fn verify_rejects_proof_against_wrong_tree_size() {
        let es = entries(8);
        let mut tree = MmrTree::new();
        for e in &es {
            append_raw_entry(&mut tree, e);
        }
        let head = tree.tree_head().unwrap();
        let mut p = prove(&es, 3).unwrap();
        // Wrong tree_size declared in the proof.
        p.tree_size = head.tree_size + 1;
        assert!(!verify(&head, &p, &es[3]));
    }

    #[test]
    fn verify_rejects_index_out_of_range() {
        let es = entries(4);
        let mut tree = MmrTree::new();
        for e in &es {
            append_raw_entry(&mut tree, e);
        }
        let head = tree.tree_head().unwrap();
        let bad = InclusionProof {
            i: 4, // == tree_size
            tree_size: head.tree_size,
            siblings: vec![],
        };
        assert!(!verify(&head, &bad, &es[0]));
    }

    #[test]
    fn verify_rejects_oversized_sibling_vector() {
        let es = entries(1);
        let mut tree = MmrTree::new();
        append_raw_entry(&mut tree, &es[0]);
        let head = tree.tree_head().unwrap();
        let bad = InclusionProof {
            i: 0,
            tree_size: head.tree_size,
            siblings: vec![Digest::default(); MAX_INCLUSION_PROOF_SIBLINGS + 1],
        };
        assert!(!verify(&head, &bad, &es[0]));
    }

    /// Mutating any sibling in a valid proof must invalidate it.
    #[test]
    fn tampered_sibling_rejected() {
        let es = entries(13);
        let mut tree = MmrTree::new();
        for e in &es {
            append_raw_entry(&mut tree, e);
        }
        let head = tree.tree_head().unwrap();
        for i in 0..es.len() as u32 {
            let p = prove(&es, i).unwrap();
            for s in 0..p.siblings.len() {
                let mut bad = p.clone();
                let mut bytes: [u8; 32] = bad.siblings[s].as_bytes().try_into().unwrap();
                bytes[0] ^= 0xff;
                bad.siblings[s] = Digest::from(bytes);
                assert!(
                    !verify(&head, &bad, &es[i as usize]),
                    "i={i} sibling={s} still verified"
                );
            }
        }
    }

    /// Serde round-trip via postcard for the on-wire `TreeHead`.
    #[test]
    fn tree_head_postcard_roundtrip() {
        let mut tree = MmrTree::new();
        tree.initialize(b"dc");
        for e in entries(11).iter() {
            tree.append(e);
        }
        let head = tree.tree_head().unwrap();
        let bytes = postcard::to_allocvec(&head).unwrap();
        let decoded: TreeHead = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(head, decoded);
        assert!(decoded.verify_for_change_id(11));
    }

    // ---------------------------------------------------------------------
    // RFC 6962 \u00a72.1.3 worked example: 7 leaves d0..d6.
    //
    //               hash
    //              /    \
    //             k      l
    //            / \    / \
    //           g   h  i   j
    //          /\  /\  /\  |
    //          a b c d e f d6
    //          ||  ||  ||
    //          d0 d1 d2 d3 d4 d5
    //
    //   PATH(0, D[7]) = [b, h, l]
    //   PATH(3, D[7]) = [c, g, l]
    //   PATH(4, D[7]) = [f, j, k]
    //   PATH(6, D[7]) = [i, k]
    // ---------------------------------------------------------------------
    fn rfc_leaves() -> Vec<Vec<u8>> {
        (0..7u8).map(|i| vec![i]).collect()
    }

    fn rfc_leaf_hashes() -> Vec<Digest> {
        rfc_leaves().iter().map(|l| h_leaf(l)).collect()
    }

    #[test]
    fn rfc6962_root_matches_recursive_definition() {
        let leaves = rfc_leaves();
        let hs = rfc_leaf_hashes();

        // Manually compute the RFC 6962 MTH for D[7].
        let a = hs[0];
        let b = hs[1];
        let c = hs[2];
        let d = hs[3];
        let e = hs[4];
        let f = hs[5];
        let d6 = hs[6];
        let g = h_node(&a, &b);
        let h = h_node(&c, &d);
        let i = h_node(&e, &f);
        let j = d6;
        let k = h_node(&g, &h);
        let l = h_node(&i, &j);
        let expected_root = h_node(&k, &l);

        // Via MmrTree::append.
        let mut tree = MmrTree::new();
        for leaf in &leaves {
            append_raw_entry(&mut tree, leaf);
        }
        assert_eq!(tree.root().unwrap(), expected_root);
        // Via subtree_root.
        assert_eq!(subtree_root(&hs, 0, hs.len()), expected_root);
    }

    #[test]
    fn rfc6962_audit_paths_match_specification() {
        let leaves = rfc_leaves();
        let hs = rfc_leaf_hashes();

        let a = hs[0];
        let b = hs[1];
        let c = hs[2];
        let d = hs[3];
        let e = hs[4];
        let f = hs[5];
        let d6 = hs[6];
        let g = h_node(&a, &b);
        let h = h_node(&c, &d);
        let i = h_node(&e, &f);
        let j = d6;
        let k = h_node(&g, &h);
        let l = h_node(&i, &j);

        // PATH(0, D[7]) = [b, h, l]
        let p0 = prove(&leaves, 0).unwrap();
        assert_eq!(p0.siblings, vec![b, h, l]);
        // PATH(3, D[7]) = [c, g, l]
        let p3 = prove(&leaves, 3).unwrap();
        assert_eq!(p3.siblings, vec![c, g, l]);
        // PATH(4, D[7]) = [f, j, k]
        let p4 = prove(&leaves, 4).unwrap();
        assert_eq!(p4.siblings, vec![f, j, k]);
        // PATH(6, D[7]) = [i, k]
        let p6 = prove(&leaves, 6).unwrap();
        assert_eq!(p6.siblings, vec![i, k]);
    }

    /// Second-preimage / "internal-hash-as-leaf" attack: an attacker knows
    /// an internal node hash (call it `g = H(0x01 || a || b)`) and tries to
    /// pass it off as a leaf in a smaller tree whose root happens to equal
    /// the larger tree's root. The 0x00/0x01 domain separation makes this
    /// impossible; assert it explicitly.
    #[test]
    fn internal_hash_cannot_be_passed_as_leaf() {
        // Build a 4-leaf tree.
        let four = entries(4);
        let mut tree = MmrTree::new();
        for e in &four {
            append_raw_entry(&mut tree, e);
        }
        let head4 = tree.tree_head().unwrap();
        let hs = rfc_leaf_hashes(); // unrelated; just to obtain Digests.

        // Imagine an attacker constructs a fake 1-leaf "proof" claiming the
        // 4-leaf root is `H(0x00 || x)` for some x. They cannot produce
        // such an x in poly time (preimage resistance), but more
        // structurally: any single-leaf proof has an empty sibling list and
        // verify recomputes acc = h_leaf(x) and compares to head.root.
        let fake = InclusionProof {
            i: 0,
            tree_size: 1,
            siblings: vec![],
        };
        // Wrong tree_size is rejected up front.
        assert!(!verify_with_leaf_hash(&head4, &fake, hs[0]));
        // Even feeding the *internal* hash bytes as a candidate leaf
        // pre-image fails: the verifier hashes them under the leaf tag.
        let internal_hash_bytes: [u8; 32] = h_node(&hs[0], &hs[1]).as_bytes().try_into().unwrap();
        let mut tree1 = MmrTree::new();
        append_raw_entry(&mut tree1, &internal_hash_bytes);
        let head1 = tree1.tree_head().unwrap();
        // Verifier rebuilds H(0x00 || internal_hash_bytes) which is
        // *different* from H(0x01 || a || b), so head1.root != any
        // internal node of the 4-leaf tree.
        assert_ne!(head1.root, head4.root);
    }

    /// Boundary tree sizes around powers of two (1, 2, 3, ..., 17, 32, 33).
    #[test]
    fn boundary_tree_sizes_round_trip() {
        for &n in &[1u32, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65] {
            let es = entries(n);
            let mut tree = MmrTree::new();
            for e in &es {
                append_raw_entry(&mut tree, e);
            }
            let head = tree.tree_head().unwrap();
            assert!(head.verify_for_tree_size(n), "tree_head invalid at n={n}");
            for i in 0..n {
                let p = prove(&es, i).unwrap();
                assert!(verify(&head, &p, &es[i as usize]), "n={n} i={i}");
            }
        }
    }

    /// Deterministic randomised fuzz: any single-byte mutation of the
    /// proof's serialised form must invalidate it.
    #[test]
    fn random_proof_bitflips_rejected() {
        // Tiny LCG so the test is hermetic and fast.
        let mut state: u64 = 0xdead_beef_cafe_f00d;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let n = 24u32;
        let es = entries(n);
        let mut tree = MmrTree::new();
        for e in &es {
            append_raw_entry(&mut tree, e);
        }
        let head = tree.tree_head().unwrap();

        for _ in 0..200 {
            let i = (next() % u64::from(n)) as u32;
            let p = prove(&es, i).unwrap();
            let ser = postcard::to_allocvec(&p).unwrap();
            // Pick a random byte and flip a random bit.
            let pos = (next() as usize) % ser.len();
            let bit = (next() as u8) & 0x07;
            let mut bad = ser.clone();
            bad[pos] ^= 1u8 << bit;
            // Either deserialisation fails or the resulting proof fails to
            // verify. Both outcomes are acceptable.
            match postcard::from_bytes::<InclusionProof>(&bad) {
                Err(_) => {}
                Ok(decoded) => {
                    assert!(
                        !verify(&head, &decoded, &es[i as usize]),
                        "bit-flipped proof verified: i={i} pos={pos} bit={bit}"
                    );
                }
            }
        }
    }

    /// `ProofCache::prove` performs O(log n) work — at most ⌈log₂ n⌉
    /// inner-loop iterations and, crucially, **zero hash invocations**
    /// (siblings are read out of the precomputed cache). The build
    /// step is O(n) hashes but is amortised across all proofs against
    /// the same leaf list.
    ///
    /// We assert both bounds: the loop-iteration bound proves the path
    /// length is logarithmic, and the `h_node`-call counter proves
    /// each iteration does O(1) work — together these rule out any
    /// O(n) hashing fallback.
    #[test]
    fn proof_cache_prove_is_logarithmic() {
        fn ceil_log2(n: u32) -> usize {
            // ⌈log₂ n⌉ for n >= 1, with ceil_log2(1) == 0.
            (u32::BITS - n.saturating_sub(1).leading_zeros()) as usize
        }

        for &n in &[
            1u32, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 1024, 4096, 100_000,
        ] {
            let leaf_hashes: Vec<Digest> = (0..n).map(|i| h_leaf(&i.to_le_bytes())).collect();
            let cache = ProofCache::from_leaf_hashes(&leaf_hashes).unwrap();
            let max_ops = ceil_log2(n);

            // Sample indices including the boundaries (worst-case
            // asymmetric paths in a left-balanced tree).
            let mut indices = vec![0u32, n - 1];
            if n >= 2 {
                indices.push(n / 2);
            }
            if n >= 4 {
                indices.push(n / 2 - 1);
                indices.push(n / 2 + 1);
            }

            for &i in &indices {
                let hashes_before = h_node_calls();
                let (proof, ops) = cache.prove_inner(i).unwrap();
                let hashes_used = h_node_calls() - hashes_before;

                assert_eq!(
                    hashes_used, 0,
                    "n={n} i={i}: ProofCache::prove must not hash; \
                     observed {hashes_used} h_node calls"
                );
                assert!(
                    ops <= max_ops,
                    "n={n} i={i}: prove did {ops} iterations, exceeds ⌈log₂ n⌉ = {max_ops}"
                );
                assert_eq!(
                    proof.siblings.len(),
                    ops,
                    "siblings length must match loop iterations (one sibling per step)"
                );
                // Hard cap from the verifier-side bound.
                assert!(proof.siblings.len() <= MAX_INCLUSION_PROOF_SIBLINGS);
            }
        }
    }

    /// `ProofCache::prove` must produce identical proofs to an
    /// *independent* reference implementation that re-hashes every
    /// sibling subtree from scratch (the prior O(n) algorithm). This
    /// guards against the cache and the query walk silently agreeing
    /// on a wrong split rule.
    #[test]
    fn proof_cache_matches_reference_proofs() {
        for n in 1u32..=33 {
            let es = entries(n);
            let hs: Vec<Digest> = es.iter().map(|e| h_leaf(e)).collect();
            let cache = ProofCache::from_leaf_hashes(&hs).unwrap();
            for i in 0..n {
                let from_cache = cache.prove(i).unwrap();
                let mut reference_siblings = Vec::new();
                reference_path(&hs, 0, n as usize, i as usize, &mut reference_siblings);
                assert_eq!(
                    from_cache.siblings, reference_siblings,
                    "siblings disagree at n={n} i={i}"
                );
                assert_eq!(from_cache.i, i);
                assert_eq!(from_cache.tree_size, n);
            }
        }
    }

    /// Building incrementally with [`ProofCache::extend_with_leaf`]
    /// must yield a cache that proves identically to the batch
    /// [`ProofCache::from_leaf_hashes`] path. Also asserts that each
    /// extension does at most ⌈log₂(k+1)⌉ hash invocations (one per
    /// right-spine level of the new tree), establishing the
    /// O(log n)-per-extension cost bound.
    #[test]
    fn proof_cache_incremental_matches_batch_and_is_logarithmic() {
        for n in 1u32..=200 {
            let es = entries(n);
            let hs: Vec<Digest> = es.iter().map(|e| h_leaf(e)).collect();
            let batch = ProofCache::from_leaf_hashes(&hs).unwrap();

            let mut incremental = ProofCache::new();
            for (k, h) in hs.iter().enumerate() {
                let before = h_node_calls();
                incremental.extend_with_leaf(*h);
                let used = h_node_calls() - before;
                // Right-spine depth of (0, k+1) = ⌈log₂(k+1)⌉.
                let new_size = (k + 1) as u32;
                let max_hashes = (u32::BITS - new_size.saturating_sub(1).leading_zeros()) as usize;
                assert!(
                    used <= max_hashes,
                    "extend_with_leaf at k={k} did {used} hashes (max {max_hashes})"
                );
            }
            assert_eq!(incremental.leaf_count(), n);
            assert_eq!(incremental.leaf_count(), batch.leaf_count());

            // Proofs must match across every leaf index. (We don't
            // compare cache contents directly: the incremental path
            // accumulates "stale" intermediate-prefix entries that the
            // batch path never produces, but neither cache contains
            // contradictory entries.)
            for i in 0..n {
                assert_eq!(incremental.prove(i), batch.prove(i), "n={n} i={i}");
            }
        }
    }

    /// Sanity check that an incrementally-built `ProofCache` agrees
    /// with the live `MmrTree` root after the same sequence of
    /// appends, including the synthetic initial leaf.
    #[test]
    fn proof_cache_incremental_with_init_round_trip() {
        let initial_dc = b"initial-dc";
        for n_real in 0u32..=20 {
            let real = entries(n_real);
            let mut tree = MmrTree::new();
            tree.initialize(initial_dc);

            let mut cache = ProofCache::new();
            cache.extend_with_leaf(h_init(initial_dc));
            for e in &real {
                tree.append(e);
                cache.extend_with_leaf(h_leaf(e));
            }
            let head = tree.tree_head().unwrap();

            // Initial leaf provable.
            let p0 = cache.prove(0).unwrap();
            assert!(verify_with_leaf_hash(&head, &p0, h_init(initial_dc)));
            // Real leaves provable at positions 1..=n_real with zero
            // hash work during proof generation.
            for (k, e) in real.iter().enumerate() {
                let i = (k + 1) as u32;
                let before = h_node_calls();
                let p = cache.prove(i).unwrap();
                assert_eq!(
                    h_node_calls() - before,
                    0,
                    "ProofCache::prove must not hash"
                );
                assert!(verify(&head, &p, e), "n_real={n_real} i={i}");
            }
        }
    }
}
