pub mod common;

#[cfg(feature = "verify")]
pub mod verifier;

// Proving module — only available when `prove` is enabled.  Disabled
// for wasm builds because the guest-binary methods crates aren't built
// for wasm targets.
#[cfg(all(not(target_arch = "wasm32"), feature = "prove"))]
pub mod prover;

// Abort at startup if running under cargo-nextest with cuda enabled
// (single-GPU machines fail with parallel proving due to memory limits). See module docs.
#[cfg(all(feature = "cuda", not(target_arch = "wasm32")))]
mod nextest_cuda_guard;

/// RISC0 image ID of the FF-proof guest binary in this build.
///
/// Re-exported from `encrypted-spaces-ffproof-methods` so callers (the
/// codegen, in-tree tests, prover-side benches) can verify receipts
/// against the binary that produced them without duplicating the
/// methods crate dependency.  Production apps should bake this
/// constant in at app build time via `sdk_codegen::FF_GUEST_IMAGE_ID`
/// rather than pulling it from the SDK at runtime.
///
/// Only available when the `prove` feature is enabled; verify-only
/// consumers (the SDK) don't see it.
#[cfg(all(not(target_arch = "wasm32"), feature = "prove"))]
pub use encrypted_spaces_ffproof_methods::EXTEND_FF_ID;

#[cfg(all(not(target_arch = "wasm32"), feature = "prove"))]
pub use encrypted_spaces_ffproof_methods::HASH_TEST_ELF;

/// Ensure the RISC0 proof mode environment variable is configured.
///
/// By default (without the `real-proofs` feature), this sets
/// `RISC0_DEV_MODE=1` so that proving and verification use fast fake
/// proofs.  Enable the `real-proofs` feature for actual cryptographic
/// proofs.
///
/// An explicit `RISC0_DEV_MODE` env var always takes precedence.
pub fn ensure_risc0_proof_mode() {
    #[cfg(not(feature = "real-proofs"))]
    {
        if std::env::var("RISC0_DEV_MODE").is_err() {
            // SAFETY: called early, before multi-threaded proving begins.
            unsafe { std::env::set_var("RISC0_DEV_MODE", "1") };
        }
    }
}
