//! Hash permutation backends for relation proofs.
//!
//! Each backend supplies a concrete permutation, AIR adapter, and security
//! profile wiring used by [`crate::relation::PreparedRelation`].

#[cfg(feature = "keccak256")]
pub mod keccak;
#[cfg(feature = "poseidon2")]
pub mod poseidon2;
