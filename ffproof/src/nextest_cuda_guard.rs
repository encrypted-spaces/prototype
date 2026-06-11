//! Abort the test binary at startup if we detect we're running under
//! `cargo-nextest` with the `cuda` feature enabled.
//!
//! Background: the test machine has a single GPU. Each real-proof prover
//! invocation peaks at ~3.5 GB of CUDA allocation, so any parallel
//! execution OOMs. Plain `cargo test` passes `--test-threads=1` per
//! integration-test binary by default, but `nextest` parallelizes
//! aggressively across both binaries and tests. Rather than try to
//! enumerate every test that touches the prover, we just refuse to
//! run under nextest whenever the `cuda` feature was compiled in.
//!
//! `nextest` sets `NEXTEST=1` in the environment of every test
//! process it spawns (and also `NEXTEST_RUN_ID`, `NEXTEST_EXECUTION_*`,
//! etc.). We check both to be defensive.
//!
//! To run these tests, use:
//!     cargo test --features real-proofs,cuda
//! or pin the parallelism explicitly:
//!     cargo nextest run --features real-proofs,cuda --test-threads=1

#[ctor::ctor(unsafe)]
fn refuse_nextest_with_cuda() {
    if std::env::var_os("NEXTEST").is_some() || std::env::var_os("NEXTEST_RUN_ID").is_some() {
        eprintln!(
            "\n\
            ────────────────────────────────────────────────────────────────\n\
            encrypted-spaces-ffproof: refusing to run under cargo-nextest with\n\
            the `cuda` feature enabled.\n\
            \n\
            Our test machine has one GPU; nextest parallelizes tests across\n\
            binaries which causes CUDA out-of-memory failures.\n\
            \n\
            Use `cargo test --features real-proofs,cuda` instead, or\n\
            `cargo nextest run --features real-proofs,cuda --test-threads=1`.\n\
            ────────────────────────────────────────────────────────────────\n"
        );
        std::process::exit(2);
    }
}
