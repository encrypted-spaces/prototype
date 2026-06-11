//! ffproof_tracer host: Load fixture, trace operations, run RISC0 prover.

use clap::Parser;
use ffproof_tracer::json_loader::load_from_file;
use ffproof_tracer::trace_prove::{create_trace, verify_trace};
use ffproof_tracer_methods::{BENCH_TRACER_ELF, BENCH_TRACER_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

#[derive(Parser)]
#[command(name = "ff-bench-tracer")]
#[command(about = "Benchmark exact-traced pruned Merk operations in RISC0")]
struct Args {
    /// Path to input fixture JSON file
    #[arg(short, long)]
    input: Option<String>,

    /// Enable debug output (node counts, timing)
    #[arg(long, default_value = "false")]
    debug: bool,
}

const DEFAULT_FIXTURE: &str = "test_fixtures/insert_1.json";

fn main() {
    let args = Args::parse();

    let input = args.input.unwrap_or_else(|| {
        println!(
            "No input specified, using default: `{DEFAULT_FIXTURE}`.  Use --input to specify a different input"
        );
        DEFAULT_FIXTURE.to_string()
    });

    // Tracer CLI always uses dev mode (standalone tool, not gated by feature flag).
    std::env::set_var("RISC0_DEV_MODE", "1");
    std::env::set_var("RISC0_INFO", "1");
    std::env::set_var("RUST_LOG", "info");

    let (full_tree, steps) = load_from_file(&input);

    // Create trace (step-based processing handles both modes)
    let traced_fixture = create_trace(&full_tree, &steps);

    // Verify trace (panics on failure)
    verify_trace(&traced_fixture).expect("trace verification failed");

    if args.debug {
        let full_count = traced_fixture.pruned_tree.count_full();
        let pruned_count = traced_fixture.pruned_tree.count_pruned();
        println!(
            "Pruned tree: {} Full nodes, {} Pruned nodes",
            full_count, pruned_count
        );
    }

    let fixture_bytes =
        postcard::to_allocvec(&traced_fixture).expect("Failed to serialize fixture");
    println!("Fixture size: {} bytes", fixture_bytes.len());

    let env = ExecutorEnv::builder()
        .write(&fixture_bytes.len())
        .expect("write len failed")
        .write_slice(&fixture_bytes)
        .build()
        .expect("Failed to build executor env");

    let prover = default_prover();
    println!("\nRunning RISC0 prover...");

    let start_time = std::time::Instant::now();
    let proof_info = prover.prove(env, BENCH_TRACER_ELF).expect("prove failed");
    let prove_duration = start_time.elapsed();

    let receipt = proof_info.receipt;
    receipt
        .verify(BENCH_TRACER_ID)
        .expect("receipt verify failed");

    let (start_root, end_root, stage1_cycles): ([u8; 32], [u8; 32], u64) =
        receipt.journal.decode().expect("decode journal failed");

    println!("\n=== Results ===");
    println!("Start root: {}", hex::encode(start_root));
    println!("End root: {}", hex::encode(end_root));
    println!("\nStage 1 (load + verify start): {stage1_cycles} cycles");
    println!("Total user cycles: {}", proof_info.stats.user_cycles);
    println!(
        "Cycles per step: {}",
        proof_info.stats.user_cycles / (steps.len() as u64)
    );
    let stage2_cycles = proof_info.stats.user_cycles.saturating_sub(stage1_cycles);
    println!("Stage 2 (steps + verify end): {stage2_cycles} cycles");
    println!("\nProving time: {prove_duration:?}");
    println!("Receipt size: {} bytes", receipt.seal_size());
}
