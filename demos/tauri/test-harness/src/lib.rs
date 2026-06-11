//! Multi-actor test harness for the Tauri demo.
//!
//! The harness drives the same business logic the Tauri commands wrap
//! (the `chat`, `tasks`, `calendar`, `notes`, `files` modules of the
//! [`encrypted_spaces_demo`] crate) against an in-process `LocalTransport`,
//! so scripted and randomised scenarios run headless and deterministically.
//!
//! It lives in its own crate (separate from `encrypted-spaces-demo`) so the
//! demo binary stays minimal and the harness is clearly optional — anyone
//! using the demo as a starting point can drop this directory entirely.
//!
//! Available submodules:
//! - [`actor`]   — per-user [`Actor`] handle (a `Space` + bookkeeping).
//! - [`action`]  — the [`Action`] enum and JSON-serialisable [`Scenario`].
//! - [`runner`]  — [`Runner`] that executes a [`Scenario`] against a [`World`].
//! - [`world`]   — shared [`World`] (one `LocalTransport` + many `Actor`s).
//! - [`fuzz`]    — seeded random generator producing [`Scenario`]s.
//!
//! Quick start (Rust):
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! use encrypted_spaces_demo_test_harness::{Action, Runner, Scenario};
//! let scenario = Scenario::new(vec![
//!     ("alice".into(), Action::CreateSpace { channel: "general".into() }),
//!     ("alice".into(), Action::Invite { invitee: "bob".into() }),
//!     ("bob".into(),   Action::Join   { from: "alice".into(), channel: "general".into() }),
//!     ("alice".into(), Action::SendMessage { text: "hi".into() }),
//!     ("bob".into(),   Action::AddTask { title: "milestone 1".into() }),
//! ]);
//! let mut runner = Runner::new().await?;
//! runner.execute(&scenario).await?;
//! # Ok(()) }
//! ```

pub mod action;
pub mod actor;
pub mod fuzz;
pub mod runner;
pub mod world;

pub use action::{Action, Scenario, Step};
pub use actor::Actor;
pub use fuzz::{FuzzConfig, FuzzGenerator};
pub use runner::{FailureReport, Runner, RunnerError};
pub use world::World;

use std::cell::Cell;

thread_local! {
    static CURRENT_STEP_INDEX: Cell<usize> = const { Cell::new(0) };
}

/// Index of the step the [`Runner`] is currently executing. Set by
/// [`Runner::execute_step`] before each dispatch and read by panic hooks
/// (see `bin/harness.rs`) so a panic during a fuzz run reports the failing
/// step alongside the seed that produced it.
pub fn current_step_index() -> usize {
    CURRENT_STEP_INDEX.with(|c| c.get())
}

pub fn set_current_step_index(i: usize) {
    CURRENT_STEP_INDEX.with(|c| c.set(i));
}
