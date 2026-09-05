//! STARK proofs for simple hash-preimage relations.
//!
//! `spongefish-stark` allows to prove permutation statements via Plonky3 STARK proofs.
//!
//! Use cases include proving preimage of one or more hash invocations, while
//! revealing only the selected public outputs, inputs, or linear equations over them.
//! It can be useful for hash-based constructions such as commitments, encryption,
//! and Merkle-style structures.
//!
//! A relation can express that private inputs hash to a public commitment,
//! that values reused across hash calls are equal, or that linked hash invocations
//! form a larger computation such as a path or node update.
//!
//! The [`relation`] module provides the proving layer. Callers describe the
//! symbolic statement with `spongefish_circuit`'s
//! `PermutationInstanceBuilder`, provide matching private values with
//! `PermutationWitnessBuilder`, then use [`relation::PreparedRelation`] to
//! prove and verify the statement. The crate supplies ready-made
//! backends in [`permutation`] for Poseidon2 and Keccak-f[1600]; each backend
//! implements [`HashRelationBackend`] by bundling the Plonky3 configuration,
//! the hash AIR, and the executable permutation.
//!
//! # Lookup relation structure
//!
//! The relation uses three global lookups over `(variable id, value)` tuples.
//! The hash AIR proves each permutation and emits tuples. `in-out` balances
//! repeated private variables, so reused `FieldVar`s have one value.
//! `public-vars` matches public occurrences against declared assignments.
//! `linear-constraints` links a separate linear AIR, which checks sums locally,
//! back to the same hash values. Together they compose hash validity, public
//! openings, equality reuse, and linear relations.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{StarkGenericConfig, Val};
use spongefish::Permutation;
use spongefish_circuit::permutation::{PermutationWitness, QueryAnswerPair};

pub mod air;
pub mod ff;
mod hiding;
pub mod permutation;
pub mod relation;
pub mod rng;
pub mod security_profile;

#[cfg(test)]
mod tests;

pub type RelationField<B, const WIDTH: usize> = Val<<B as HashRelationBackend<WIDTH>>::Config>;
pub type RelationChallenge<B, const WIDTH: usize> =
    <<B as HashRelationBackend<WIDTH>>::Config as StarkGenericConfig>::Challenge;

/// Adapter bridging logical hash invocations to a STARK relation.
///
/// The relation layer only needs the logical `input` and `output` lanes for one
/// hash invocation. Implementations define the backend-specific local `Frame`
/// needed to recover that pair. For simple chips, this may be a single row; for
/// multi-row chips such as Keccak, it may be a wider window over the trace.
pub trait RelationArithmetization<F, const WIDTH: usize>: Clone {
    /// Backend-defined local trace view required to recover one hash invocation.
    type Frame<'a, Var>
    where
        Self: 'a,
        Var: 'a;

    /// Width of the main trace used by the inner hash AIR.
    fn main_width(&self) -> usize;

    /// Number of rows used to realize one logical hash invocation.
    fn trace_rows_per_invocation(&self) -> usize {
        1
    }

    /// Evaluate the inner hash AIR constraints over the provided builder.
    fn eval<AB>(&self, builder: &mut AB)
    where
        AB: AirBuilder<F = F>;

    /// Return the number of periodic columns used by the inner hash AIR.
    fn num_periodic_columns(&self) -> usize {
        0
    }

    /// Return the public periodic-column data used by the inner hash AIR.
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        Vec::new()
    }

    /// Wrap a backend-specific symbolic row into the frame used by
    /// [`Self::invocation`].
    fn row_frame<'a, Var>(&self, row: &'a [Var]) -> Self::Frame<'a, Var>;

    /// Build a concrete main trace from a witness trace of logical invocations.
    fn build_trace(&self, witness: &PermutationWitness<F, WIDTH>) -> RowMajorMatrix<F>;

    /// Project one backend-specific invocation frame into its logical input and
    /// output expressions.
    fn invocation<AB>(&self, frame: &Self::Frame<'_, AB::Var>) -> QueryAnswerPair<AB::Expr, WIDTH>
    where
        AB: AirBuilder<F = F>;

    /// Selector for whether the current row should contribute to the outer
    /// relation lookups. Single-row chips return `1`; multi-row chips can gate
    /// lookups to their export/final row. The relation layer constrains the
    /// returned expression to be boolean.
    fn lookup_selector<AB>(&self, _frame: &Self::Frame<'_, AB::Var>) -> AB::Expr
    where
        AB: AirBuilder<F = F>,
    {
        AB::Expr::ONE
    }
}

/// Backend for a hash relation.
///
/// A backend preset bundles: the proof configuration, the hash AIR adapter, and the executable
/// permutation. Instance and witness builders stay explicit: callers create the symbolic statement
/// scope separately and pass [`Self::permutation`] to the witness builder.
pub trait HashRelationBackend<const WIDTH: usize>: Clone {
    /// AIR configuration (the security profile)
    type Config: StarkGenericConfig;
    /// The AIR itself
    type Air: RelationArithmetization<Val<Self::Config>, WIDTH> + Sync + Clone;
    /// The permutation function
    type Permutation: Permutation<WIDTH, U = Val<Self::Config>> + Clone;

    /// Build the prover-side STARK config with fresh private zero-knowledge randomness.
    fn prover_config(&self) -> Self::Config;

    /// Build the verifier-side STARK config.
    ///
    /// Plonky3's current config type stores a full PCS value, and this crate's hiding PCS
    /// includes an RNG field used only by prover-side hiding methods. Verification does not
    /// consume that RNG. Implementations may therefore use a fixed placeholder seed here; it is
    /// only needed to construct the type, not to reconstruct prover randomness.
    fn verifier_config(&self) -> Self::Config;

    /// Return the security parameters used by the prover and verifier configs.
    ///
    /// Implementations must return the parameters used by both
    /// [`Self::prover_config`] and [`Self::verifier_config`]. Prepared relations
    /// reject a backend whose parameters differ from those used at preparation.
    fn security_parameters(&self) -> security_profile::SecurityParameters;

    /// Return the minimum trace height required by this backend's hiding PCS.
    fn hiding_trace_height(&self) -> usize
    where
        <Self::Config as StarkGenericConfig>::Challenge:
            p3_field::BasedVectorSpace<Val<Self::Config>>,
    {
        hiding::min_trace_height::<Self::Config>(self.security_parameters())
    }

    /// Return the AIR matching the permutation function.
    ///
    /// The AIR adapter can be used to build traces and evaluate the
    /// backend-specific constraints for each logical invocation.
    fn air(&self) -> Self::Air;

    /// Return the permutation function.
    ///
    /// Callers pass this to [`PermutationWitnessBuilder`] and can also use it
    /// directly to compute expected outputs.
    fn permutation(&self) -> Self::Permutation;
}
