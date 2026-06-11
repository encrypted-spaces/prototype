//! SimpleLine2: storage-native key retention with lazy client key resolution.
//!
//! This module implements the SimpleLine2 retention algorithm over key-value
//! `Storage`. Public retention state is stored canonically in storage; only
//! secret local state (the current HGK) is held on `SimpleLine2SpaceKey`.

mod proof;
mod space_key;
mod stark_proofs;
mod store;

#[cfg(test)]
mod tests;

pub use proof::{
    DefaultDerivation, DeleteKeysProofInput, DeleteKeysSurvivor, DeleteKeysVerifyInput,
    ExtendProofInput, ExtendVerifyInput, NoProver, RekeyProofInput, RekeyVerifyInput,
    SimpleLine2Proofs, SimpleLine2RuntimeProver, VecProofs,
};
pub use space_key::SimpleLine2SpaceKey;
pub use stark_proofs::StarkProver;

/// Default prover type selected at compile time.
///
/// `real-proofs` feature on (default) → [`StarkProver`] (real STARK proof bytes).
/// `real-proofs` feature off → [`NoProver`] (fast, empty proof bytes).
#[cfg(feature = "real-proofs")]
pub type DefaultProver = StarkProver;

#[cfg(not(feature = "real-proofs"))]
pub type DefaultProver = NoProver;
