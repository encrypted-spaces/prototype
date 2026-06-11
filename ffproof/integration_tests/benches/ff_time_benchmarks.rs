//! Wall-clock time benchmarks for the realistic FF workloads.
//!
//! What each "iteration" of these benchmarks does — **carefully**:
//!   1. Builds a fresh `Space`.
//!   2. Applies the entire 100-change (or 1000-change) sequence.
//!   3. Calls the Risc0 prover **once** to produce a single FF proof
//!      covering all of those changes in one shot.
//!   4. Records the wall-clock duration of step (3) only.
//!
//! So the Criterion `time:` output is the **total per-proof time**, not
//! per-change. Divide by the change count for amortized per-change cost.
//!
//! Because real proof generation is deterministic and very slow, each
//! workload is proved **once** during the bench and the resulting
//! `Duration` is cached for Criterion's resample loop.
//!
//! Workloads:
//! - `ff_time/table_100`         — 1 × `apply_table_sequence` (100 changes)
//! - `ff_time/table_1000`        — 10 × `apply_table_sequence` (1000 changes)
//! - `ff_time/list_100`          — 1 × `apply_list_sequence` (100 changes)
//! - `ff_time/list_1000`         — 10 × `apply_list_sequence` (1000 changes)
//! - `ff_time/groth16_compress`  — Groth16 compression of the 100-change
//!   table receipt (≈ workload-independent)
//!
//! Run (real GPU proofs):
//!   cargo bench -p encrypted-spaces-ff-test --bench ff_time_benchmarks \
//!     --features real-proofs,cuda
//!
//! Without `real-proofs` the prover runs in `RISC0_DEV_MODE=1` (fake/mock
//! proofs) and the numbers are meaningless for real cost analysis. The
//! `groth16_compress` bench cannot produce a real Groth16 proof in dev
//! mode and will be skipped with a warning.

#[path = "ff_common/mod.rs"]
mod ff_common;

use criterion::{criterion_group, criterion_main, Criterion};
use ff_common::{
    apply_list_sequence, apply_table_sequence, compress_to_groth16, init_state_and_space,
    last_receipt, prove_pending_changes,
};
use std::time::Duration;

#[derive(Clone, Copy)]
enum Workload {
    Table,
    List,
}

/// Run `repeats` × the chosen sequence inside a fresh space, prove once,
/// and report the cached wall-clock duration.
fn bench_prove(c: &mut Criterion, bench_name: &str, workload: Workload, repeats: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut cached: Option<Duration> = None;

    c.bench_function(bench_name, |b| {
        b.iter_custom(|iters| {
            let elapsed = *cached.get_or_insert_with(|| {
                rt.block_on(async {
                    let (state, space) = init_state_and_space().await;
                    let mut total_changes = 0usize;
                    for _ in 0..repeats {
                        total_changes += match workload {
                            Workload::Table => apply_table_sequence(&space).await,
                            Workload::List => apply_list_sequence(&space).await,
                        };
                    }
                    let r = prove_pending_changes(&state).await;
                    let secs = r.elapsed.as_secs_f64();
                    let khz = if secs > 0.0 {
                        (r.cycles as f64) / secs / 1_000.0
                    } else {
                        0.0
                    };
                    eprintln!(
                        "  [{bench_name}] single proof of {total_changes} changes: \
                         prove_time={:.2?}, cycles={}, throughput={:.2} kHz, \
                         per_change={:.2?}",
                        r.elapsed,
                        r.cycles,
                        khz,
                        r.elapsed / total_changes as u32,
                    );
                    r.elapsed
                })
            });
            elapsed.saturating_mul(iters as u32)
        });
    });
}

fn bench_groth16_compress(c: &mut Criterion) {
    let bench_name = "ff_time/groth16_compress";

    // Skip if we know we're in dev mode — compress would either no-op or
    // produce a fake proof, which isn't what this bench is for.
    if std::env::var("RISC0_DEV_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        eprintln!(
            "  [{bench_name}] SKIPPED: RISC0_DEV_MODE=1 — run with \
             --features real-proofs,cuda for a meaningful Groth16 number."
        );
        return;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut cached: Option<Duration> = None;

    c.bench_function(bench_name, |b| {
        b.iter_custom(|iters| {
            let elapsed = *cached.get_or_insert_with(|| {
                rt.block_on(async {
                    // Use the 100-change table workload as a stand-in. The
                    // Groth16 compress cost is essentially independent of
                    // the inner receipt's contents.
                    let (state, space) = init_state_and_space().await;
                    let _ = apply_table_sequence(&space).await;
                    let prove = prove_pending_changes(&state).await;
                    let receipt = last_receipt(&state).await;
                    eprintln!(
                        "  [{bench_name}] inner-proof time={:.2?} ({} cycles) — \
                         now compressing to Groth16…",
                        prove.elapsed, prove.cycles
                    );
                    let (compress_time, seal_size) = compress_to_groth16(&receipt);
                    eprintln!(
                        "  [{bench_name}] groth16 compress time={:.2?}, \
                         groth16 seal size={} bytes",
                        compress_time, seal_size
                    );
                    compress_time
                })
            });
            elapsed.saturating_mul(iters as u32)
        });
    });
}

fn bench_table_100(c: &mut Criterion) {
    bench_prove(c, "ff_time/table_100", Workload::Table, 1);
}
fn bench_table_1000(c: &mut Criterion) {
    bench_prove(c, "ff_time/table_1000", Workload::Table, 10);
}
fn bench_list_100(c: &mut Criterion) {
    bench_prove(c, "ff_time/list_100", Workload::List, 1);
}
fn bench_list_1000(c: &mut Criterion) {
    bench_prove(c, "ff_time/list_1000", Workload::List, 10);
}

fn time_criterion() -> Criterion {
    std::env::set_var("RUST_LOG", "error");
    std::env::set_var("RISC0_GUEST_LOGFILE", "/dev/null");

    Criterion::default()
        // Cached, deterministic measurement → minimum samples.
        .sample_size(10)
        .nresamples(10)
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(1))
        .significance_level(0.0001)
        .noise_threshold(1.0)
}

criterion_group! {
    name = ff_time_benchmarks;
    config = time_criterion();
    targets =
        bench_table_100,
        bench_table_1000,
        bench_list_100,
        bench_list_1000,
        bench_groth16_compress
}

criterion_main!(ff_time_benchmarks);
