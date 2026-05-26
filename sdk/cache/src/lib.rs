//! Client-side key/value cache for SDK SELECT and write paths.
//!
//! A `KvCache` holds two kinds of authenticated knowledge anchored to a
//! single state commitment:
//!
//! - **Point entries** — a key's exact value, or its proven absence.
//! - **Coverage intervals** — half-open byte ranges within which every key's
//!   presence or absence is known. A missing point inside coverage is
//!   authenticated absence; outside coverage it means "unknown — ask the
//!   server".
//!
//! `KvCache` implements [`encrypted_spaces_backend::merk_storage::RowReadSource`]
//! so the backend's `execute_query` runs unchanged against cached state. The
//! cache itself decides hit-vs-miss by checking coverage of the byte ranges
//! a planned query would touch.

pub mod coverage_store;
pub mod kv_cache;

pub use coverage_store::CoverageStore;
pub use kv_cache::{CacheResult, CacheUpdate, CacheWrite, KvCache};
