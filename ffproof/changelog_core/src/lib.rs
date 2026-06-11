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

// Optional: trace proof helpers
pub use ffproof_tracer::trace_prove::{create_trace, create_trace_full};
pub use ffproof_tracer_shared::{
    apply_batch, collect_range, decode_pruned_compact_to_merk, encode_pruned_compact,
    prefix_successor, pruned_to_merk, verify_trace, BatchOp, InputStep, ProvenRead,
    PrunedMerkleTree, PrunedMerkleTreeStats, PrunedWitnessDecodeError, ReadOp, ReadResults,
    TraceStep, TracerProof, VerifyTraceError,
};
