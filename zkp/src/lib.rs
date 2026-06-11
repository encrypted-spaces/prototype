extern crate alloc;

/// Demos and benchmarks.
pub mod demo;

/// Algebraic encodings for the key material.
pub mod mve;
/// Poseidon2 configuration.
pub(crate) mod poseidon2;

/// Proofs for hash preimage
pub(crate) mod hash_preimage;
/// Proofs for key derivations and key encryption.
pub mod transitions;
