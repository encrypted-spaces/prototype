//! Library entry point for the Tauri demo crate.
//!
//! Modules are exposed so that:
//! - `main.rs` (the Tauri binary) wires them into command handlers, and
//! - the sibling `encrypted-spaces-demo-test-harness` crate
//!   ([`demos/tauri/test-harness`](../../test-harness/)) drives the same
//!   business logic against an in-process `LocalTransport` for scripted
//!   and fuzzed scenarios.
//!
//! The transport-generic modules (`chat`, `tasks`, `calendar`, `notes`,
//! `files`) work over any `encrypted_spaces_sdk::Transport`. The
//! `state`, `commands`, and `broadcast` modules are tied to
//! `WebSocketTransport` and are only useful inside the Tauri binary.

pub mod broadcast;
pub mod calendar;
pub mod chat;
pub mod commands;
pub mod files;
pub mod notes;
pub mod state;
pub mod tasks;

include!(concat!(env!("OUT_DIR"), "/sdk_codegen.rs"));

/// Application schema bytes, embedded from `demos/tauri/app_schema.kdl`.
///
/// Re-exported so the test-harness crate can bootstrap a `LocalTransport`
/// whose tables match the production server's schema without duplicating
/// the file include.
pub const APP_SCHEMA_BYTES: &[u8] = include_bytes!("../../app_schema.kdl");
