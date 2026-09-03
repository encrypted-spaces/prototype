//! Client-side key/value cache for SDK SELECT and write paths.
//!
//! A [`KvCache`] holds two kinds of authenticated knowledge anchored to a
//! single state commitment:
//!
//! - **Point entries** — authenticated key/value presences.
//! - **Coverage intervals** — half-open byte ranges within which every key is
//!   known. A missing point inside coverage is
//!   authenticated absence; outside coverage means "unknown — ask the
//!   server".
//!
//! `KvCache::try_select` plans via the backend's `determine_query_strategy`,
//! checks coverage of the byte ranges the planned query would touch, and runs
//! `execute_query` against an internal `RowReadSource` view of the cache on a
//! hit. SDK helpers in [`helpers`] convert verified write batches into the
//! [`CacheUpdate`] the cache splices alongside an anchor advance.
//!
//! Lives inside the SDK rather than as its own crate so it can read SDK
//! schema state directly without ceremony.

use encrypted_spaces_backend::error::Result as SdkResult;
use encrypted_spaces_crypto::encryption::FieldType;

use crate::DataCommitment;

pub mod cache;
pub mod coverage_store;
pub mod helpers;

#[cfg(test)]
mod proptests;

pub use cache::{CacheResult, CacheUpdate, KvCache};
pub use helpers::{cache_update_from_writes, new_row_id_for_table};

/// Synchronous encrypted-field resolver used during cache-hit materialization.
///
/// The production implementation is `SyncDecryptContext` in `sync_decrypt.rs`.
/// The cache core only needs this narrow contract: anchor checking and
/// converting one encrypted stored string into stored plaintext bytes.
pub(crate) trait SyncDecryptResolver {
    fn anchor(&self) -> DataCommitment;

    fn decrypt_column_bytes(&self, encoded: &str, field_type: &FieldType) -> SdkResult<Vec<u8>>;
}
