//! Backend selection and the shared read vocabulary for the prove/verify
//! seams.
//!
//! The tree, tracer, and proof machinery all live in `merk` now; this crate
//! picks the backend module the workspace builds against and re-exports the
//! handful of names the seams use. A checkpoint is a [`Tree`] clone (O(1)
//! copy-on-write on the host): clone the live tree to get an immutable
//! snapshot, hand `&Tree` to [`TraceRecorder::new`] to record a trace against
//! it.
//!
//! [`ReadOp`] and [`ProvenRead`] stay local (rather than merk's equivalents)
//! because they are serialized on the select/store proof wire.

pub use backend::{TraceRecorder, TraceReplayer, Tree, WriteOp};
// MRT is the default backend; the `avl` feature selects the AVL tree instead.
#[cfg(feature = "avl")]
pub use merk::avl as backend;
#[cfg(not(feature = "avl"))]
pub use merk::mrt as backend;
pub use merk::tracer::{TraceReader, TraceWriter};

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// Read operations
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
/// Results are not serialized (the verifier derives them by replaying the
/// declared reads against the authenticated trace). Code that needs results
/// (e.g. op validators) must populate this field before use.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProvenRead {
    pub op: ReadOp,
    /// Key-value pairs found. Empty = non-inclusion proof.
    /// Skipped during serialization; populated by replaying against the
    /// authenticated trace at verification time.
    #[serde(skip, default)]
    pub results: Vec<(Vec<u8>, Vec<u8>)>,
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

/// Per-step read results: one ProvenRead (with results populated) per read in the step.
pub type ReadResults = Vec<ProvenRead>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_successor() {
        assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(&[0x01, 0xFF]), Some(vec![0x02]));
        assert_eq!(prefix_successor(&[0xFF, 0xFF]), None);
        assert_eq!(prefix_successor(b""), None);
    }
}
