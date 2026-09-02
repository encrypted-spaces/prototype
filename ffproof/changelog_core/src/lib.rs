// Core modules (merk-only)
pub mod changelog;
pub mod mmr_tree;
pub mod ops;
pub mod time;

// Re-export key construction from storage-encoding
pub use encrypted_spaces_storage_encoding::encode_column_names;
pub use encrypted_spaces_storage_encoding::keys::{
    acl_only_via_actions_key, acl_rule_key, row_prefix, schema_columns_key, users_row_key,
    LISTS_TABLE, RETENTION_TABLE, USERS_TABLE,
};

// Re-export merk hash test for zkVM verification
pub use merk::zkvm_hash_tests;

pub use ffproof_tracer_shared::{prefix_successor, ProvenRead, ReadOp, ReadResults};
// merk's traced-handle seam types used by the verify path (`changelog`) and the
// ops' write vocabulary. `WriteOp` replaces the old `BatchOp` on the live op/seam path;
// `TraceReplayer` + `TraceReader`/`TraceWriter` drive verification.
pub use ffproof_tracer_shared::{TraceReader, TraceReplayer, TraceWriter, WriteOp};

/// The single `OpReader` adapter over a merk traced handle, shared by the
/// prove (`prover.rs`), verify (`changelog.rs`), and storage (`proofs.rs`) seams.
pub use changelog::HandleReader;
