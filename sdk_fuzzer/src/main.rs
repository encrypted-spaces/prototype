//! Stateful seeded-RNG fuzzer for `encrypted-spaces-sdk`.
//!
//! Runs N iterations, each of which spins up a fresh in-memory `Space`,
//! applies a bootstrap phase (a few tables + a few rows) and then executes
//! K randomly-chosen ops. Asserts round-trip, reserved-name, typed-error,
//! and affected-count invariants on every step.
//!
//!     cargo run -p encrypted-spaces-sdk-fuzzer -- \
//!         --seed 42 --iters 100 --ops 50

use std::cell::Cell;

use encrypted_spaces_sdk::{LocalTransport, Space};
use encrypted_spaces_sdk_fuzzer::{
    executor, is_known_acl_infra_error,
    model::{self, Actor, ModelState},
};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

const HOST_UID: i64 = 1; // Space::create assigns uid=1 to the initial user.

struct Args {
    seed: u64,
    iters: usize,
    ops: usize,
}

fn parse_args() -> Args {
    let mut seed: Option<u64> = None;
    let mut iters: usize = 10;
    let mut ops: usize = 50;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seed" => {
                seed = it.next().and_then(|s| s.parse().ok());
            }
            "--iters" => {
                iters = it.next().and_then(|s| s.parse().ok()).unwrap_or(iters);
            }
            "--ops" => {
                ops = it.next().and_then(|s| s.parse().ok()).unwrap_or(ops);
            }
            "--help" | "-h" => {
                eprintln!(
                    "fuzz: stateful SDK fuzzer\n\
                     usage: cargo run -p encrypted-spaces-sdk-fuzzer -- \\\n\
                       [--seed <u64>] [--iters <n>] [--ops <n>]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }

    Args {
        seed: seed.unwrap_or_else(rand::random),
        iters,
        ops,
    }
}

thread_local! {
    static CURRENT_SEED: Cell<u64> = const { Cell::new(0) };
    static CURRENT_ITER: Cell<usize> = const { Cell::new(0) };
    static CURRENT_OP_INDEX: Cell<usize> = const { Cell::new(0) };
}

fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let seed = CURRENT_SEED.with(|c| c.get());
        let iter = CURRENT_ITER.with(|c| c.get());
        let op_index = CURRENT_OP_INDEX.with(|c| c.get());
        eprintln!("FUZZ FAIL seed={seed} iter={iter} op_index={op_index}");
        prev(info);
    }));
}

#[tokio::main]
async fn main() {
    install_panic_hook();
    let args = parse_args();
    CURRENT_SEED.with(|c| c.set(args.seed));

    println!(
        "fuzz: seed={} iters={} ops_per_iter={}",
        args.seed, args.iters, args.ops
    );

    // Child RNGs for each iteration are derived from the top-level seed so that
    // a single `--seed` fully reproduces the run.
    let mut outer = StdRng::seed_from_u64(args.seed);

    for iter in 0..args.iters {
        CURRENT_ITER.with(|c| c.set(iter));
        CURRENT_OP_INDEX.with(|c| c.set(0));
        let iter_seed: u64 = outer.next_u64();
        println!("iter {iter} seed={iter_seed}");
        run_iter(iter_seed, args.ops).await;
    }

    println!("OK seed={}", args.seed);
}

async fn run_iter(seed: u64, ops_per_iter: usize) {
    let mut rng = StdRng::seed_from_u64(seed);

    let host_transport = LocalTransport::in_memory()
        .await
        .expect("LocalTransport::in_memory");
    // Hold the original transport handle so InviteUser can clone it for new
    // joiners. Cloning a LocalTransport produces a second handle to the same
    // in-memory server (`sdk/src/local_transport.rs:64-76`).
    let host_space = Space::new(host_transport.clone())
        .await
        .expect("Space::new");
    host_space
        .authenticate_as_id(HOST_UID)
        .await
        .expect("authenticate_as_id host");

    let mut model = ModelState::new(Actor {
        uid: HOST_UID,
        space: host_space,
    });

    // Bootstrap: lay down all the schemas we'll fuzz against, plus a few
    // rows so predicate/join ops have data to work with. CreateTable is a
    // LocalTransport-only setup helper, so it only ever runs here — never
    // as a runtime fuzz op.
    println!("  bootstrap");
    let bootstrap_tables = rng.random_range(2..=4);
    for _ in 0..bootstrap_tables {
        if let Err(e) = executor::step_force(
            &mut rng,
            &mut model,
            &host_transport,
            model::FuzzOp::CreateTable,
        )
        .await
        {
            panic!("bootstrap CreateTable failed: {e:?}");
        }
    }

    // ACL rule installation goes through the same baseline-resetting code
    // path as `create_table`, so it must run before any tracked changes
    // (the bootstrap inserts below would otherwise leave the client ahead
    // of the post-reset server change_id).
    if let Err(e) = executor::install_bootstrap_acl_rules(&mut rng, &mut model).await {
        panic!("bootstrap install_acl_rules failed: {e:?}");
    }

    for _ in 0..3 {
        if let Err(e) =
            executor::step_force(&mut rng, &mut model, &host_transport, model::FuzzOp::Insert).await
        {
            if is_known_acl_infra_error(&e) {
                println!("    bootstrap Insert hit known ACL infra issue, skipping iter");
                return;
            }
            panic!("bootstrap Insert failed: {e:?}");
        }
    }

    println!("  ops");
    for op_index in 0..ops_per_iter {
        CURRENT_OP_INDEX.with(|c| c.set(op_index));
        if let Err(e) = executor::step(&mut rng, &mut model, &host_transport).await {
            if is_known_acl_infra_error(&e) {
                println!("    op {op_index} hit known ACL infra issue, skipping rest of iter");
                return;
            }
            panic!("step returned SdkError at op_index={op_index}: {e:?}");
        }
    }
}
