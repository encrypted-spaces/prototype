//! `demo-harness` — orchestrate scripted and fuzzed scenarios for the Tauri demo.
//!
//! Run with:
//!     cargo run -p encrypted-spaces-demo --features harness --bin demo-harness -- <subcommand>
//!
//! Subcommands:
//!   demo                        Run the built-in Alice/Bob/Charlie scenario.
//!   replay <file.json>          Execute a saved Scenario.
//!   fuzz [--seed N --steps M]   Generate and execute a random scenario.
//!   gen [--seed N --steps M]    Print a random scenario as JSON without running it.

use std::cell::Cell;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use encrypted_spaces_demo_test_harness::{
    current_step_index, Action, FuzzConfig, FuzzGenerator, Runner, Scenario,
};

thread_local! {
    static CURRENT_SEED: Cell<u64> = const { Cell::new(0) };
}

/// Install a panic hook that prepends the active fuzz seed and the index of
/// the step the [`Runner`] was executing when the panic fired. Borrowed from
/// `sdk_fuzzer/src/main.rs` so the harness fuzzer leaves the same kind of
/// breadcrumb for unreproducible panics that don't go through the
/// [`Runner`]'s `FailureReport` path.
fn install_fuzz_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let seed = CURRENT_SEED.with(|c| c.get());
        let step_index = current_step_index();
        eprintln!("FUZZ FAIL seed={seed} step_index={step_index}");
        prev(info);
    }));
}

#[derive(Parser)]
#[command(
    name = "demo-harness",
    about = "Orchestrate scripted and fuzzed scenarios"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Print every executed step.
    #[arg(long, global = true)]
    verbose: bool,

    /// Disable the post-step `sync_all`. Stresses eventual consistency.
    #[arg(long, global = true)]
    no_auto_sync: bool,

    /// On failure, write a `FailureReport` (the successful prefix, the
    /// failing step, and the error chain) here as JSON. Defaults to
    /// `<TMP>/demo-harness-failure.json`. Pass an empty string to disable.
    #[arg(long, global = true)]
    dump_failure: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a built-in canned scenario (Alice creates, invites Bob & Charlie,
    /// chat / tasks / calendar / notes are all exercised).
    Demo,

    /// Replay a previously saved scenario JSON.
    Replay { file: PathBuf },

    /// Generate and execute a random scenario.
    Fuzz {
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value_t = 50)]
        steps: usize,
        #[arg(long, default_value_t = 4)]
        actors: usize,
        /// Save the scenario before running so failures can be replayed.
        /// Defaults to `<TMP>/demo-harness-fuzz-seed-<SEED>.json`. Pass an
        /// empty string to disable.
        #[arg(long)]
        save: Option<String>,
    },

    /// Generate a random scenario and print it as JSON to stdout (no run).
    Gen {
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value_t = 50)]
        steps: usize,
        #[arg(long, default_value_t = 4)]
        actors: usize,
    },
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "warn"),
    )
    .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> ExitCode {
    let auto_sync = !cli.no_auto_sync;
    let verbose = cli.verbose;
    let dump_failure = resolve_optional_path(cli.dump_failure.clone(), || {
        std::env::temp_dir().join("demo-harness-failure.json")
    });

    match cli.cmd {
        Cmd::Demo => match run_scenario(builtin_scenario(), auto_sync, verbose, dump_failure).await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail("demo", e),
        },
        Cmd::Replay { file } => {
            let bytes = match std::fs::read(&file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("read {}: {e}", file.display());
                    return ExitCode::FAILURE;
                }
            };
            let scenario: Scenario = match serde_json::from_slice(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("parse {}: {e}", file.display());
                    return ExitCode::FAILURE;
                }
            };
            match run_scenario(scenario, auto_sync, verbose, dump_failure).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail("replay", e),
            }
        }
        Cmd::Fuzz {
            seed,
            steps,
            actors,
            save,
        } => {
            install_fuzz_panic_hook();
            CURRENT_SEED.with(|c| c.set(seed));
            let scenario = FuzzGenerator::new(FuzzConfig {
                max_actors: actors.max(1),
                min_actors: 2.min(actors.max(1)),
                steps,
                seed,
                ..Default::default()
            })
            .generate();

            // Default to a tempdir path keyed by seed so re-runs overwrite
            // predictably and failures are always recoverable.
            let save_path = resolve_optional_path(save, || {
                std::env::temp_dir().join(format!("demo-harness-fuzz-seed-{seed}.json"))
            });
            if let Some(path) = save_path.as_ref() {
                match std::fs::write(path, scenario.to_json().unwrap()) {
                    Ok(()) => eprintln!("[harness] scenario saved to {}", path.display()),
                    Err(e) => eprintln!(
                        "[harness] warning: could not save scenario to {}: {e}",
                        path.display()
                    ),
                }
            }

            match run_scenario(scenario, auto_sync, verbose, dump_failure).await {
                Ok(()) => {
                    println!("fuzz seed={seed} steps={steps} actors={actors}: OK");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("fuzz seed={seed} steps={steps} actors={actors}: FAIL");
                    if let Some(path) = save_path.as_ref() {
                        eprintln!("(replay with: demo-harness replay {})", path.display());
                    }
                    fail("fuzz", e)
                }
            }
        }
        Cmd::Gen {
            seed,
            steps,
            actors,
        } => {
            let scenario = FuzzGenerator::new(FuzzConfig {
                max_actors: actors.max(1),
                min_actors: 2.min(actors.max(1)),
                steps,
                seed,
                ..Default::default()
            })
            .generate();
            println!("{}", scenario.to_json().unwrap());
            ExitCode::SUCCESS
        }
    }
}

/// Resolve an optional CLI path argument:
/// - `None` (flag not passed)              -> use `default()`.
/// - `Some("")` (explicit opt-out)        -> `None`.
/// - `Some(path)` (explicit override)       -> that path.
fn resolve_optional_path(
    arg: Option<String>,
    default: impl FnOnce() -> PathBuf,
) -> Option<PathBuf> {
    match arg {
        None => Some(default()),
        Some(s) if s.is_empty() => None,
        Some(s) => Some(PathBuf::from(s)),
    }
}

async fn run_scenario(
    scenario: Scenario,
    auto_sync: bool,
    verbose: bool,
    dump_failure: Option<PathBuf>,
) -> anyhow::Result<()> {
    let mut runner = Runner::new().await?;
    runner.auto_sync = auto_sync;
    runner.failure_dump_path = dump_failure;

    if verbose {
        for (i, step) in scenario.steps.iter().enumerate() {
            println!("[{i:03}] {} -> {}", step.actor, step.action.label());
        }
    }

    runner.execute(&scenario).await?;
    println!(
        "OK: executed {} step(s), {} actor(s)",
        runner.trace.len(),
        runner.world.actor_names().len()
    );
    Ok(())
}

fn fail(label: &str, e: impl std::fmt::Display) -> ExitCode {
    eprintln!("{label}: {e}");
    ExitCode::FAILURE
}

/// Built-in scenario covering the user's narrative example:
/// Alice creates → invites Bob → Bob joins → Alice chats "hi" →
/// Bob adds task → Alice adds calendar event → Bob invites Charlie → ...
fn builtin_scenario() -> Scenario {
    Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        ("alice".into(), Action::SendMessage { text: "hi".into() }),
        (
            "bob".into(),
            Action::AddTask {
                title: "milestone 1".into(),
            },
        ),
        (
            "alice".into(),
            Action::AddCalendarEvent {
                start_time: 1_700_000_000,
                end_time: 1_700_003_600,
                title: "dev meeting".into(),
                description: "weekly sync".into(),
            },
        ),
        (
            "bob".into(),
            Action::Invite {
                invitee: "charlie".into(),
            },
        ),
        (
            "charlie".into(),
            Action::Join {
                from: "bob".into(),
                channel: "general".into(),
            },
        ),
        (
            "charlie".into(),
            Action::SendMessage {
                text: "👋 hello".into(),
            },
        ),
        (
            "alice".into(),
            Action::ReplyToLast {
                text: "welcome charlie".into(),
            },
        ),
        (
            "bob".into(),
            Action::ToggleReactionOnLast {
                emoji: "tada".into(),
            },
        ),
        (
            "alice".into(),
            Action::NotesInsert {
                pos: 0,
                text: "Project plan:\n".into(),
            },
        ),
        (
            "bob".into(),
            Action::NotesInsert {
                pos: 14,
                text: "- ship MVE\n".into(),
            },
        ),
        ("bob".into(), Action::ToggleLastTask),
        (
            "alice".into(),
            Action::EditLastMessage {
                text: "hello team".into(),
            },
        ),
    ])
}
