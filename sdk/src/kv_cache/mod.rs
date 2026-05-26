//! Client-side key/value cache for SDK SELECT and write paths.
//!
//! A [`KvCache`] holds two kinds of authenticated knowledge anchored to a
//! single state commitment:
//!
//! - **Point entries** — a key's exact value, or its proven absence.
//! - **Coverage intervals** — half-open byte ranges within which every key's
//!   presence or absence is known. A missing point inside coverage is
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

pub mod cache;
pub mod coverage_store;
pub mod helpers;

pub use cache::{CacheResult, CacheUpdate, CacheWrite, KvCache};
pub use coverage_store::CoverageStore;
pub use helpers::{cache_update_from_writes, new_row_id_for_table};
