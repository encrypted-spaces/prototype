//! STARK relation for permutation-evaluation circuits.
//!
//! # Assumptions
//!
//! The relation layer encodes symbolic [`FieldVar`] identifiers and lookup
//! multiplicities as base-field elements with `F::from_usize`.
//!
//! Soundness assumes these integers do not overflow:
//! every variable identifier used by the instance, and every
//! multiplicity computed for the `in-out`, `public-vars`, and
//! `linear-constraints` lookups, must be strictly smaller than the field
//! characteristic. Equivalently, relation sizes must stay below the modulus of
//! the backend field.
//!
//! Plonky3 0.6 additionally requires the global LogUp query budget to satisfy
//! `sum_i count_weight_i * trace_height_i < p`. This layer derives tight
//! per-lane weights from verifier-known multiplicity columns and constrains
//! every dynamic selector to be boolean. The Plonky3 batch prover and verifier
//! both enforce the resulting weighted-height bound.
//!

use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpressionExt, WindowAccess};
use p3_batch_stark::{BatchProof, ProverData, StarkInstance};
use p3_field::{
    integers::QuotientMap, Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField,
};
use p3_lookup::{Count, InteractionBuilder, Lookups};
use p3_matrix::{
    dense::{DenseMatrix, RowMajorMatrix},
    Matrix,
};
use p3_uni_stark::StarkGenericConfig;
use spongefish::{Permutation, Unit, VerificationError, VerificationResult};
use spongefish_circuit::{
    allocator::FieldVar,
    permutation::{
        LinearConstraints, PermutationInstance, PermutationInstanceBuilder, PermutationWitness,
        PermutationWitnessBuilder, QueryAnswerPair,
    },
};

use crate::security_profile::SecurityParameters;
use crate::{HashRelationBackend, RelationArithmetization, RelationChallenge, RelationField};

// --------------------------------------
// Constants for the protocol
// --------------------------------------

/// The first lookup, checking that outputs re-appear as inputs.
pub const IO_LOOKUP_NAME: &str = "in-out";
/// The second lookup, checking that public variables are correctly assigned.
pub const PUB_LOOKUP_NAME: &str = "public-vars";
/// The third lookup, checking linear relations between inputs and outputs.
pub const LIN_LOOKUP_NAME: &str = "linear-constraints";

/// Default supported maximum number of terms in one linear equation.
pub const MAX_LINEAR_WIDTH: usize = 16;

// ----------------------------------
// AIR columns for the hash relation
// ----------------------------------

type LinearConstraintsInstance<F> = LinearConstraints<FieldVar, F>;
type LinearConstraintsWitness<F> = LinearConstraints<F, F>;
type PreparedRelationAir<B, const WIDTH: usize> = HashRelationAir<
    <B as HashRelationBackend<WIDTH>>::Air,
    RelationField<B, WIDTH>,
    WIDTH,
    MAX_LINEAR_WIDTH,
>;
type PreparedRelationTrace<B, const WIDTH: usize> = DenseMatrix<RelationField<B, WIDTH>>;

/// The (preprocessed, public) lookup columns.
#[repr(C)]
struct LookupCols<T, const WIDTH: usize> {
    /// The input wires
    input_vars: [T; WIDTH],
    /// The output wires
    output_vars: [T; WIDTH],
    /// How many times an output will appear.
    output_multiplicities: [T; WIDTH],
    /// How many times an input will appear.
    input_multiplicities: [T; WIDTH],
    /// The input wires that are public.
    input_public: [T; WIDTH],
    /// The input wires that are public.
    output_public: [T; WIDTH],
    /// The
    input_linear_constraints: [T; WIDTH],
    output_linear_constraints: [T; WIDTH],
}

#[repr(C)]
struct PublicLookupCols<T> {
    var: T,
    val: T,
    multiplicity: T,
}

#[repr(C)]
struct LinearConstraintCols<T, const LIN_WIDTH: usize> {
    linear_combination: [T; LIN_WIDTH],
}

#[repr(C)]
struct LinearConstraintPreprocessedCols<T, const LIN_WIDTH: usize> {
    linear_coefficients: [T; LIN_WIDTH],
    linear_vars: [T; LIN_WIDTH],
    image_value: T,
    linear_multiplicities: [T; LIN_WIDTH],
}

#[derive(Clone)]
struct MultiplicityColumns<F, const WIDTH: usize> {
    inputs: Vec<[F; WIDTH]>,
    outputs: Vec<[F; WIDTH]>,
    input_count_bounds: [u32; WIDTH],
    output_count_bounds: [u32; WIDTH],
}

/// Number of field elements in [`LookupCols`]
const fn num_lookup_cols<const WIDTH: usize>() -> usize {
    size_of::<LookupCols<u8, WIDTH>>()
}

/// Number of field elements in [`PublicLookupCols`]
const fn num_public_lookup_cols() -> usize {
    size_of::<PublicLookupCols<u8>>()
}

/// Number of field elements in [`LinearConstraintCols`]
const fn num_linear_main_cols<const LIN_WIDTH: usize>() -> usize {
    size_of::<LinearConstraintCols<u8, LIN_WIDTH>>()
}

/// Number of field elements in [`LinearConstraintPreprocessedCols`]
const fn num_linear_preprocessed_cols<const LIN_WIDTH: usize>() -> usize {
    size_of::<LinearConstraintPreprocessedCols<u8, LIN_WIDTH>>()
}

//------------------------------
// AIRs for the hash relation
// -----------------------------

/// AIR for hash preimage relations.
#[derive(Clone)]
struct HashLookupAir<H, F, const WIDTH: usize, const LIN_WIDTH: usize> {
    hash: H,
    instance: PermutationInstance<F, WIDTH>,
    public_multiplicities: Vec<Option<usize>>,
    public_input_count_bounds: [u32; WIDTH],
    public_output_count_bounds: [u32; WIDTH],
    io_multiplicities: MultiplicityColumns<F, WIDTH>,
    linear_multiplicities: MultiplicityColumns<F, WIDTH>,
    trace_len: usize,
}

/// AIR for public-variables lookup tables.
#[derive(Clone)]
struct PublicVarLookupAir<F, const WIDTH: usize> {
    instance: PermutationInstance<F, WIDTH>,
    trace_len: usize,
}

/// AIR for linear-equations.
#[derive(Clone)]
struct LinearConstraintsAir<F, const WIDTH: usize, const LIN_WIDTH: usize> {
    constraints: LinearConstraintsInstance<F>,
    trace_len: usize,
    active_width: usize,
}

/// Combined AIR for the generic relation.
///
/// TODO: `Linear` can be any AIR that talks about variables.
#[derive(Clone)]
enum HashRelationAir<H, F, const WIDTH: usize, const LIN_WIDTH: usize> {
    Hash(Box<HashLookupAir<H, F, WIDTH, LIN_WIDTH>>),
    Public(PublicVarLookupAir<F, WIDTH>),
    Linear(LinearConstraintsAir<F, WIDTH, LIN_WIDTH>),
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> HashLookupAir<H, F, WIDTH, LIN_WIDTH>
where
    F: Field + Unit + PartialEq,
{
    fn new(
        hash: H,
        instance: PermutationInstance<F, WIDTH>,
        linear_constraints: LinearConstraintsInstance<F>,
        trace_len: usize,
    ) -> Self {
        let public_multiplicities = public_multiplicities(&instance);
        let (public_input_count_bounds, public_output_count_bounds) =
            public_lookup_count_bounds(instance.constraints().as_ref(), &public_multiplicities);
        let io_multiplicities = hash_equality_multiplicities::<F, WIDTH>(
            instance.constraints().as_ref(),
            instance.vars_count,
            &public_multiplicities,
        );
        let linear_multiplicities = linear_lookup_multiplicities::<F, WIDTH>(
            instance.constraints().as_ref(),
            &lin_multiplicities(&linear_constraints),
        );
        Self {
            hash,
            instance,
            public_multiplicities,
            public_input_count_bounds,
            public_output_count_bounds,
            io_multiplicities,
            linear_multiplicities,
            trace_len,
        }
    }
}

impl<F, const WIDTH: usize> PublicVarLookupAir<F, WIDTH> {
    fn new(instance: PermutationInstance<F, WIDTH>, trace_len: usize) -> Self {
        assert!(trace_len.is_power_of_two());
        Self {
            instance,
            trace_len,
        }
    }
}

impl<F, const WIDTH: usize, const LIN_WIDTH: usize> LinearConstraintsAir<F, WIDTH, LIN_WIDTH> {
    fn new(
        constraints: LinearConstraintsInstance<F>,
        trace_len: usize,
        active_width: usize,
    ) -> Self {
        assert!(trace_len.is_power_of_two());
        assert!(constraints.as_ref().len() <= trace_len);
        assert!(active_width <= LIN_WIDTH);
        Self {
            constraints,
            trace_len,
            active_width,
        }
    }
}

// ----------------------------------------
// Relation definition and implementation
// ----------------------------------------

/// The (padded) hash relation ready to be proven.
pub struct PreparedRelation<B: HashRelationBackend<WIDTH>, const WIDTH: usize> {
    hash: B::Air,
    permutation: B::Permutation,
    security_parameters: SecurityParameters,
    instance: PermutationInstance<RelationField<B, { WIDTH }>, WIDTH>,
    linear_constraints: LinearConstraintsInstance<RelationField<B, { WIDTH }>>,
    linear_width: usize,
    original_constraints_len: usize,
    hash_log_len: usize,
    public_log_len: usize,
    linear_log_len: usize,
}

pub struct PreparedWitness<B: HashRelationBackend<WIDTH>, const WIDTH: usize> {
    witness: PermutationWitness<RelationField<B, { WIDTH }>, WIDTH>,
}

impl<B, const WIDTH: usize> PreparedRelation<B, WIDTH>
where
    B: HashRelationBackend<{ WIDTH }>,
    RelationField<B, { WIDTH }>: PrimeField + Unit + PartialEq + Send + Sync,
    RelationChallenge<B, { WIDTH }>: BasedVectorSpace<RelationField<B, { WIDTH }>>,
    SymbolicExpressionExt<RelationField<B, { WIDTH }>, RelationChallenge<B, { WIDTH }>>:
        Algebra<RelationChallenge<B, { WIDTH }>>,
{
    pub fn new(
        backend: &B,
        instance: &PermutationInstanceBuilder<RelationField<B, { WIDTH }>, WIDTH>,
    ) -> Self {
        Self::new_with_min_trace_height(backend, instance, 1)
    }

    /// Prepare a relation whose hash, public, and linear traces have at least
    /// the backend's PCS hiding minimum and `min_trace_height` rows.
    ///
    /// The caller-supplied minimum can raise but cannot weaken the backend's
    /// profile-derived hiding requirement. It must be a non-zero power of two,
    /// and both the prover and verifier must construct the relation with the same
    /// value. Symbolic permutation rows are padded here, and
    /// [`Self::prepare_witness`] adds the matching concrete rows to the witness.
    pub fn new_with_min_trace_height(
        backend: &B,
        instance: &PermutationInstanceBuilder<RelationField<B, { WIDTH }>, WIDTH>,
        min_trace_height: usize,
    ) -> Self {
        assert!(
            min_trace_height.is_power_of_two(),
            "minimum trace height must be a non-zero power of two"
        );
        let security_parameters = backend.security_parameters();
        let hiding_trace_height = crate::hiding::min_trace_height::<B::Config>(security_parameters);
        let min_trace_height = min_trace_height.max(hiding_trace_height);
        let hash = backend.air();
        let permutation = backend.permutation();
        let mut instance = instance.snapshot();
        let original_constraints_len = instance.constraints().as_ref().len();
        let linear_width = max_linear_width(instance.linear_constraints());
        assert!(
            linear_width <= MAX_LINEAR_WIDTH,
            "linear equation width {linear_width} exceeds supported maximum {MAX_LINEAR_WIDTH}",
        );
        let linear_constraints =
            pad_instance_linear_constraints(instance.linear_constraints.clone(), MAX_LINEAR_WIDTH);
        let hash_logical_len = hash_logical_target_len(&hash, &instance, min_trace_height);
        pad_instance_permutations(&mut instance, hash_logical_len);
        // The hash AIR height is counted in trace rows, not logical hash invocations.
        let hash_log_len = (instance.constraints().as_ref().len()
            * hash.trace_rows_per_invocation())
        .next_power_of_two()
        .max(min_trace_height)
        .trailing_zeros() as usize;
        // The public lookup AIR is sized by the public-variable table, independently of hash rows.
        let public_log_len = instance
            .public_vars()
            .len()
            .next_power_of_two()
            .max(min_trace_height)
            .trailing_zeros() as usize;
        // The linear lookup AIR is always present, even when the linear relation is empty.
        let linear_log_len = linear_constraints
            .as_ref()
            .len()
            .next_power_of_two()
            .max(min_trace_height)
            .trailing_zeros() as usize;

        Self {
            hash,
            permutation,
            security_parameters,
            instance,
            linear_constraints,
            linear_width,
            original_constraints_len,
            hash_log_len,
            public_log_len,
            linear_log_len,
        }
    }

    pub fn prepare_witness(
        &self,
        witness: &PermutationWitnessBuilder<B::Permutation, WIDTH>,
    ) -> PreparedWitness<B, WIDTH> {
        let witness_len = witness.trace().as_ref().len();
        assert_eq!(
            witness_len, self.original_constraints_len,
            "instance/witness permutation count mismatch: instance has {}, witness has {}",
            self.original_constraints_len, witness_len,
        );
        let mut witness = witness.snapshot();
        witness.linear_constraints =
            pad_witness_linear_constraints(witness.linear_constraints, MAX_LINEAR_WIDTH);
        pad_witness_permutations(&mut witness, &self.permutation, self.num_constraints());

        PreparedWitness { witness }
    }

    /// Return the public weighted-height sum used by Plonky3's LogUp
    /// multiplicity soundness check.
    ///
    /// This is exposed so production relation shapes can pin their concrete
    /// headroom below the field characteristic in regression tests. Plonky3's
    /// same-bus packing preserves total count weight, so the unpacked symbolic
    /// interactions used here produce the same sum checked during proving.
    pub fn logup_weighted_height_sum(&self) -> u128 {
        let trace_heights = [
            1usize << self.hash_log_len,
            1usize << self.public_log_len,
            1usize << self.linear_log_len,
        ];
        self.build_airs()
            .iter()
            .zip(trace_heights)
            .fold(0u128, |sum, (air, height)| {
                let lookups = Lookups::<RelationField<B, { WIDTH }>>::from_air::<
                    RelationChallenge<B, { WIDTH }>,
                    _,
                >(air);
                sum.saturating_add(
                    u128::from(lookups.total_count_weight()).saturating_mul(height as u128),
                )
            })
    }

    /// Generate a STARK proof that the witness satisfies this hash relation.
    pub fn prove(&self, backend: &B, witness: &PreparedWitness<B, WIDTH>) -> Vec<u8>
    where
        p3_uni_stark::Domain<B::Config>: Send + Sync,
        <B::Config as StarkGenericConfig>::Pcs: Sync,
        <<B::Config as StarkGenericConfig>::Pcs as p3_commit::Pcs<
            RelationChallenge<B, { WIDTH }>,
            <B::Config as StarkGenericConfig>::Challenger,
        >>::ProverData: Sync,
        <<B::Config as StarkGenericConfig>::Pcs as p3_commit::Pcs<
            RelationChallenge<B, { WIDTH }>,
            <B::Config as StarkGenericConfig>::Challenger,
        >>::Commitment: Sync,
    {
        assert_eq!(
            backend.security_parameters(),
            self.security_parameters,
            "prepared relation security parameters do not match proving backend",
        );
        assert_eq!(
            witness.witness.trace().as_ref().len(),
            self.num_constraints(),
            "prepared witness trace length does not match prepared relation",
        );

        let (airs, traces) = self.generate_trace_rows(witness);
        let log_degrees = self.trace_degree_bits();
        assert_eq!(
            trace_degree_bits(&traces),
            log_degrees,
            "generated trace degrees do not match prepared relation",
        );
        let config = backend.prover_config();
        for trace in &traces {
            crate::hiding::assert_safe_trace_height::<B::Config>(
                &config,
                self.security_parameters,
                trace.height(),
            );
        }
        // Transparent preprocessed commitments are public verifier-recomputed data, so they use the
        // deterministic verifier config. Witness-bearing commitments below use fresh prover config.
        let preprocessing_config = backend.verifier_config();
        let log_ext_degrees = log_ext_degrees(&log_degrees, &config);
        let prover_data =
            ProverData::from_airs_and_degrees(&preprocessing_config, &airs, &log_ext_degrees);
        #[cfg(debug_assertions)]
        for (air, lookups) in airs.iter().zip(&prover_data.common.lookups) {
            crate::hiding::debug_assert_air_row_window(
                air,
                !lookups.is_empty(),
                <p3_lookup::InteractionSymbolicBuilder<
                    RelationField<B, { WIDTH }>,
                    RelationChallenge<B, { WIDTH }>,
                > as p3_air::AirBuilder>::WINDOW,
            );
        }
        let publics = vec![Vec::new(); airs.len()];
        let trace_refs = traces.iter().collect::<Vec<_>>();
        let instances = StarkInstance::new_multiple(&airs, &trace_refs, &publics);
        let proof = p3_batch_stark::prove_batch(&config, &instances, &prover_data);
        postcard::to_allocvec(&proof).expect("proof serialization should succeed")
    }

    /// Verify a STARK proof against this relation and backend.
    pub fn verify(&self, backend: &B, proof_bytes: &[u8]) -> VerificationResult<()> {
        if backend.security_parameters() != self.security_parameters {
            return Err(VerificationError);
        }
        let config = backend.verifier_config();
        let proof: BatchProof<B::Config> =
            postcard::from_bytes(proof_bytes).map_err(|_| VerificationError)?;
        let expected_degree_bits = log_ext_degrees(&self.trace_degree_bits(), &config);
        if proof.degree_bits != expected_degree_bits {
            return Err(VerificationError);
        }
        let airs = self.build_airs();
        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &proof.degree_bits);
        let publics = vec![Vec::new(); airs.len()];
        p3_batch_stark::verify_batch(&config, &airs, &proof, &publics, &prover_data.common)
            .map_err(|_| VerificationError)
    }

    fn build_airs(&self) -> Vec<PreparedRelationAir<B, WIDTH>> {
        let hash_air =
            HashLookupAir::<B::Air, RelationField<B, { WIDTH }>, WIDTH, MAX_LINEAR_WIDTH>::new(
                self.hash.clone(),
                self.instance.clone(),
                self.linear_constraints.clone(),
                1usize << self.hash_log_len,
            );
        vec![
            HashRelationAir::Hash(Box::new(hash_air)),
            HashRelationAir::Public(PublicVarLookupAir::new(
                self.instance.clone(),
                1usize << self.public_log_len,
            )),
            HashRelationAir::Linear(LinearConstraintsAir::<
                RelationField<B, { WIDTH }>,
                WIDTH,
                MAX_LINEAR_WIDTH,
            >::new(
                self.linear_constraints.clone(),
                1usize << self.linear_log_len,
                self.linear_width,
            )),
        ]
    }

    fn num_constraints(&self) -> usize {
        self.instance.constraints().as_ref().len()
    }

    fn trace_degree_bits(&self) -> Vec<usize> {
        vec![self.hash_log_len, self.public_log_len, self.linear_log_len]
    }

    fn generate_trace_rows(
        &self,
        witness: &PreparedWitness<B, WIDTH>,
    ) -> (
        Vec<PreparedRelationAir<B, WIDTH>>,
        Vec<PreparedRelationTrace<B, WIDTH>>,
    ) {
        let hash_trace = self.hash.build_trace(&witness.witness);
        let trace = pad_dense_matrix_to_height(hash_trace, 1usize << self.hash_log_len);
        let public_trace = build_public_lookup_main_trace::<RelationField<B, { WIDTH }>>(
            1usize << self.public_log_len,
        );
        let airs = self.build_airs();
        let mut traces = vec![trace, public_trace];
        traces.push(build_linear_constraints_trace::<
            RelationField<B, { WIDTH }>,
            MAX_LINEAR_WIDTH,
        >(
            &witness.witness.linear_constraints,
            1usize << self.linear_log_len,
        ));

        (airs, traces)
    }
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> BaseAir<F>
    for HashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    H: RelationArithmetization<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        match self {
            Self::Hash(air) => <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as BaseAir<F>>::width(air),
            Self::Public(air) => <PublicVarLookupAir<F, WIDTH> as BaseAir<F>>::width(air),
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as BaseAir<F>>::width(air)
            }
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as BaseAir<F>>::preprocessed_trace(air)
            }
            Self::Public(air) => {
                <PublicVarLookupAir<F, WIDTH> as BaseAir<F>>::preprocessed_trace(air)
            }
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as BaseAir<F>>::preprocessed_trace(air)
            }
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as BaseAir<F>>::preprocessed_width(air)
            }
            Self::Public(air) => {
                <PublicVarLookupAir<F, WIDTH> as BaseAir<F>>::preprocessed_width(air)
            }
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as BaseAir<F>>::preprocessed_width(air)
            }
        }
    }

    fn num_periodic_columns(&self) -> usize {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as BaseAir<F>>::num_periodic_columns(air)
            }
            Self::Public(_) | Self::Linear(_) => 0,
        }
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as BaseAir<F>>::periodic_columns(air)
            }
            Self::Public(_) | Self::Linear(_) => Vec::new(),
        }
    }
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> BaseAir<F>
    for HashLookupAir<H, F, WIDTH, LIN_WIDTH>
where
    H: RelationArithmetization<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        self.hash.main_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let input_outputs = self.instance.constraints();
        let output_count = input_outputs.as_ref().len();
        let rows_per_invocation = self.hash.trace_rows_per_invocation();
        let unpadded_rows = output_count * rows_per_invocation;
        let mut ptrace = DenseMatrix::new(
            vec![<F as PrimeCharacteristicRing>::ZERO; num_lookup_cols::<WIDTH>() * self.trace_len],
            num_lookup_cols::<WIDTH>(),
        );

        for (row_idx, column) in ptrace.rows_mut().take(unpadded_rows).enumerate() {
            let pair_idx = row_idx / rows_per_invocation;
            let pair = &input_outputs.as_ref()[pair_idx];
            let output_mult = self.io_multiplicities.outputs[pair_idx];
            let input_mult = self.io_multiplicities.inputs[pair_idx];
            let linear_input = self.linear_multiplicities.inputs[pair_idx];
            let linear_output = self.linear_multiplicities.outputs[pair_idx];
            let lookup: &mut LookupCols<F, WIDTH> = column.borrow_mut();
            lookup.input_public = pair
                .input
                .map(|var| F::from_bool(self.public_multiplicities[var.index()].is_some()));
            lookup.output_public = pair
                .output
                .map(|var| F::from_bool(self.public_multiplicities[var.index()].is_some()));
            lookup.input_vars = pair
                .input
                .map(|var| field_from_usize_checked::<F>(var.index()));
            lookup.output_vars = pair
                .output
                .map(|var| field_from_usize_checked::<F>(var.index()));
            lookup.output_multiplicities = output_mult;
            lookup.input_multiplicities = input_mult;
            lookup.input_linear_constraints = linear_input;
            lookup.output_linear_constraints = linear_output;
        }

        Some(ptrace)
    }

    fn preprocessed_width(&self) -> usize {
        num_lookup_cols::<WIDTH>()
    }

    fn num_periodic_columns(&self) -> usize {
        self.hash.num_periodic_columns()
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        self.hash.periodic_columns()
    }
}

impl<F, const WIDTH: usize> BaseAir<F> for PublicVarLookupAir<F, WIDTH>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        1
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(build_public_lookup_table_trace(
            &self.instance,
            self.trace_len,
        ))
    }

    fn preprocessed_width(&self) -> usize {
        num_public_lookup_cols()
    }
}

impl<F, const WIDTH: usize, const LIN_WIDTH: usize> BaseAir<F>
    for LinearConstraintsAir<F, WIDTH, LIN_WIDTH>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        num_linear_main_cols::<LIN_WIDTH>()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(build_lin_lookup_trace::<F, LIN_WIDTH>(
            &self.constraints,
            self.trace_len,
        ))
    }

    fn preprocessed_width(&self) -> usize {
        num_linear_preprocessed_cols::<LIN_WIDTH>()
    }
}

impl<AB, H, F, const WIDTH: usize, const LIN_WIDTH: usize> Air<AB>
    for HashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    AB: InteractionBuilder + AirBuilder<F = F>,
    H: RelationArithmetization<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as Air<AB>>::eval(air, builder)
            }
            Self::Public(air) => <PublicVarLookupAir<F, WIDTH> as Air<AB>>::eval(air, builder),
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as Air<AB>>::eval(air, builder)
            }
        }
    }
}

impl<AB, H, F, const WIDTH: usize, const LIN_WIDTH: usize> Air<AB>
    for HashLookupAir<H, F, WIDTH, LIN_WIDTH>
where
    AB: InteractionBuilder + AirBuilder<F = F>,
    H: RelationArithmetization<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        self.hash.eval(builder);

        let main = builder.main();
        let row = main.current_slice();
        let frame = self.hash.row_frame(row);
        let invocation = self.hash.invocation::<AB>(&frame);
        let selector = self.hash.lookup_selector::<AB>(&frame);
        builder.assert_bool(selector.clone());
        let (
            input_vars,
            output_vars,
            output_multiplicities,
            input_multiplicities,
            input_public,
            output_public,
            input_linear_constraints,
            output_linear_constraints,
        ) = {
            let preprocessed = builder.preprocessed();
            let lookup_row = preprocessed.current_slice();
            let lookup_column: &LookupCols<_, WIDTH> = lookup_row.borrow();
            (
                lookup_column.input_vars,
                lookup_column.output_vars,
                lookup_column.output_multiplicities,
                lookup_column.input_multiplicities,
                lookup_column.input_public,
                lookup_column.output_public,
                lookup_column.input_linear_constraints,
                lookup_column.output_linear_constraints,
            )
        };

        for i in 0..WIDTH {
            let input = invocation.input[i].clone();
            let output = invocation.output[i].clone();
            let input_var = input_vars[i];
            let output_var = output_vars[i];
            let input_multiplicity: AB::Expr = input_multiplicities[i].into();
            let output_multiplicity: AB::Expr = output_multiplicities[i].into();
            let input_public: AB::Expr = input_public[i].into();
            let output_public: AB::Expr = output_public[i].into();
            let input_linear: AB::Expr = input_linear_constraints[i].into();
            let output_linear: AB::Expr = output_linear_constraints[i].into();

            let input_count_bound = self.io_multiplicities.input_count_bounds[i];
            if input_count_bound != 0 {
                builder.push_interaction(
                    IO_LOOKUP_NAME,
                    [input_var.into(), input.clone()],
                    Count::bounded(selector.clone() * input_multiplicity, input_count_bound),
                );
            }
            let output_count_bound = self.io_multiplicities.output_count_bounds[i];
            if output_count_bound != 0 {
                builder.push_interaction(
                    IO_LOOKUP_NAME,
                    [output_var.into(), output.clone()],
                    Count::bounded(selector.clone() * output_multiplicity, output_count_bound),
                );
            }

            if self.public_output_count_bounds[i] != 0 {
                builder.push_interaction(
                    PUB_LOOKUP_NAME,
                    [output_var.into(), output.clone()],
                    Count::bounded(selector.clone() * output_public, 1),
                );
            }
            if self.public_input_count_bounds[i] != 0 {
                builder.push_interaction(
                    PUB_LOOKUP_NAME,
                    [input_var.into(), input.clone()],
                    Count::bounded(selector.clone() * input_public, 1),
                );
            }

            let input_count_bound = self.linear_multiplicities.input_count_bounds[i];
            if input_count_bound != 0 {
                builder.push_interaction(
                    LIN_LOOKUP_NAME,
                    [input_var.into(), input],
                    Count::bounded(selector.clone() * input_linear, input_count_bound),
                );
            }
            let output_count_bound = self.linear_multiplicities.output_count_bounds[i];
            if output_count_bound != 0 {
                builder.push_interaction(
                    LIN_LOOKUP_NAME,
                    [output_var.into(), output],
                    Count::bounded(selector.clone() * output_linear, output_count_bound),
                );
            }
        }
    }
}

impl<AB, F, const WIDTH: usize> Air<AB> for PublicVarLookupAir<F, WIDTH>
where
    AB: InteractionBuilder + AirBuilder<F = F>,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        let (var, val, multiplicity) = {
            let preprocessed = builder.preprocessed();
            let row = preprocessed.current_slice();
            let public_column: &PublicLookupCols<_> = row.borrow();
            (
                public_column.var,
                public_column.val,
                public_column.multiplicity,
            )
        };
        let multiplicity: AB::Expr = multiplicity.into();
        builder.push_interaction(
            PUB_LOOKUP_NAME,
            [var.into(), val.into()],
            Count::provided(-multiplicity),
        );
    }
}

impl<AB, F, const WIDTH: usize, const LIN_WIDTH: usize> Air<AB>
    for LinearConstraintsAir<F, WIDTH, LIN_WIDTH>
where
    AB: InteractionBuilder + AirBuilder<F = F>,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        let linear_combination = {
            let main = builder.main();
            let local: &LinearConstraintCols<_, LIN_WIDTH> = main.current_slice().borrow();
            local.linear_combination
        };
        let (linear_coefficients, linear_vars, image_value, linear_multiplicities) = {
            let preprocessed = builder.preprocessed();
            let prep: &LinearConstraintPreprocessedCols<_, LIN_WIDTH> =
                preprocessed.current_slice().borrow();
            (
                prep.linear_coefficients,
                prep.linear_vars,
                prep.image_value,
                prep.linear_multiplicities,
            )
        };
        let mut sum = AB::Expr::ZERO;
        for i in 0..LIN_WIDTH {
            sum += linear_coefficients[i] * linear_combination[i];
        }
        builder.assert_eq(sum, image_value);
        for i in 0..self.active_width {
            let multiplicity: AB::Expr = linear_multiplicities[i].into();
            builder.push_interaction(
                LIN_LOOKUP_NAME,
                [linear_vars[i].into(), linear_combination[i].into()],
                Count::provided(-multiplicity),
            );
        }
    }
}

fn build_public_lookup_table_trace<F, const WIDTH: usize>(
    instance: &PermutationInstance<F, WIDTH>,
    trace_len: usize,
) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    let public_multiplicities = public_multiplicities(instance);
    let public_vars = instance.public_vars();
    let width = num_public_lookup_cols();
    assert!(trace_len.is_power_of_two());
    assert!(public_vars.len() <= trace_len);
    let mut values = vec![<F as PrimeCharacteristicRing>::ZERO; width * trace_len];

    for (row_idx, (var, val)) in public_vars.iter().enumerate() {
        let multiplicity = public_multiplicities[var.index()].unwrap_or(0);
        let offset = row_idx * width;
        values[offset] = field_from_usize_checked::<F>(var.index());
        values[offset + 1] = *val;
        values[offset + 2] = field_from_usize_checked::<F>(multiplicity);
    }

    DenseMatrix::new(values, width)
}

fn build_public_lookup_main_trace<F>(trace_len: usize) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    assert!(trace_len.is_power_of_two());
    DenseMatrix::new(vec![<F as PrimeCharacteristicRing>::ZERO; trace_len], 1)
}

fn build_lin_lookup_trace<F, const LIN_WIDTH: usize>(
    lc: &LinearConstraintsInstance<F>,
    trace_len: usize,
) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    let constraints_len = lc.as_ref().len();
    let width = num_linear_preprocessed_cols::<LIN_WIDTH>();
    assert!(trace_len.is_power_of_two());
    assert!(constraints_len <= trace_len);
    let mut values = vec![<F as PrimeCharacteristicRing>::ZERO; width * trace_len];

    for (row_idx, equation) in lc.as_ref().iter().enumerate() {
        let linear_coefficients = core::array::from_fn(|i| equation.linear_combination[i].0);
        let linear_vars = core::array::from_fn(|i| {
            let (coeff, var) = equation.linear_combination[i];
            if coeff == <F as PrimeCharacteristicRing>::ZERO {
                FieldVar::ZERO
            } else {
                var
            }
        });
        let linear_multiplicities = core::array::from_fn(|i| {
            if equation.linear_combination[i].0 == <F as PrimeCharacteristicRing>::ZERO {
                <F as PrimeCharacteristicRing>::ZERO
            } else {
                <F as PrimeCharacteristicRing>::ONE
            }
        });
        let offset = row_idx * width;
        let row = &mut values[offset..offset + width];
        let column: &mut LinearConstraintPreprocessedCols<F, LIN_WIDTH> = row.borrow_mut();
        column.linear_coefficients = linear_coefficients;
        column.linear_vars = linear_vars.map(|var| field_from_usize_checked::<F>(var.index()));
        column.image_value = equation.image;
        column.linear_multiplicities = linear_multiplicities;
    }

    DenseMatrix::new(values, width)
}

fn build_linear_constraints_trace<F, const LIN_WIDTH: usize>(
    lc: &LinearConstraintsWitness<F>,
    trace_len: usize,
) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    let constraints_len = lc.as_ref().len();
    let width = num_linear_main_cols::<LIN_WIDTH>();
    assert!(trace_len.is_power_of_two());
    assert!(constraints_len <= trace_len);
    let mut values = vec![<F as PrimeCharacteristicRing>::ZERO; width * trace_len];

    for (row_idx, equation) in lc.as_ref().iter().enumerate() {
        let linear_values = core::array::from_fn(|i| equation.linear_combination[i].1);
        let offset = row_idx * width;
        let row = &mut values[offset..offset + width];
        let column: &mut LinearConstraintCols<F, LIN_WIDTH> = row.borrow_mut();
        column.linear_combination = linear_values;
    }

    DenseMatrix::new(values, width)
}

//-----------------------------------------------------
// Lookup helpers: compute multiplicities of each term
// ---------------------------------------------------
//
// The lookup will need to know the number of repetitions of each term
// These helper functions help computing them.

fn hash_equality_multiplicities<F, const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    vars_count: usize,
    public_multiplicities: &[Option<usize>],
) -> MultiplicityColumns<F, WIDTH>
where
    F: PrimeCharacteristicRing,
{
    let mut counts = vec![0usize; vars_count];
    for pair in constraints {
        for var in pair.input.iter().chain(pair.output.iter()) {
            if public_multiplicities[var.index()].is_none() {
                counts[var.index()] += 1;
            }
        }
    }

    let mut seen = vec![0usize; vars_count];
    let mut input_multiplicities = Vec::with_capacity(constraints.len());
    let mut output_multiplicities = Vec::with_capacity(constraints.len());
    let mut input_count_bounds = [0; WIDTH];
    let mut output_count_bounds = [0; WIDTH];

    for pair in constraints {
        let input = core::array::from_fn(|i| {
            let (multiplicity, bound) =
                hash_equality_multiplicity::<F>(pair.input[i], &counts, &mut seen);
            input_count_bounds[i] = input_count_bounds[i].max(bound);
            multiplicity
        });
        let output = core::array::from_fn(|i| {
            let (multiplicity, bound) =
                hash_equality_multiplicity::<F>(pair.output[i], &counts, &mut seen);
            output_count_bounds[i] = output_count_bounds[i].max(bound);
            multiplicity
        });
        input_multiplicities.push(input);
        output_multiplicities.push(output);
    }

    debug_assert_eq!(seen, counts);
    MultiplicityColumns {
        inputs: input_multiplicities,
        outputs: output_multiplicities,
        input_count_bounds,
        output_count_bounds,
    }
}

fn hash_equality_multiplicity<F>(var: FieldVar, counts: &[usize], seen: &mut [usize]) -> (F, u32)
where
    F: PrimeCharacteristicRing,
{
    let count = counts[var.index()];
    if count == 0 {
        return (<F as PrimeCharacteristicRing>::ZERO, 0);
    }
    let seen_count = &mut seen[var.index()];
    if count == 1 {
        *seen_count += 1;
        return (<F as PrimeCharacteristicRing>::ZERO, 0);
    }
    let (multiplicity, magnitude) = if *seen_count == 0 {
        (field_from_usize_checked::<F>(count - 1), count - 1)
    } else {
        (-<F as PrimeCharacteristicRing>::ONE, 1)
    };
    *seen_count += 1;
    (multiplicity, count_bound_checked(magnitude))
}

fn linear_lookup_multiplicities<F, const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    linear_counts: &[Option<usize>],
) -> MultiplicityColumns<F, WIDTH>
where
    F: PrimeCharacteristicRing,
{
    let mut remaining = linear_counts
        .iter()
        .map(|count| count.unwrap_or(0))
        .collect::<Vec<_>>();
    let mut input_multiplicities = Vec::with_capacity(constraints.len());
    let mut output_multiplicities = Vec::with_capacity(constraints.len());
    let mut input_count_bounds = [0; WIDTH];
    let mut output_count_bounds = [0; WIDTH];

    for pair in constraints {
        let mut input_counts = [<F as PrimeCharacteristicRing>::ZERO; WIDTH];
        let mut output_counts = [<F as PrimeCharacteristicRing>::ZERO; WIDTH];

        for (i, (slot, var)) in input_counts.iter_mut().zip(pair.input.iter()).enumerate() {
            let count = remaining.get_mut(var.index()).map_or(0, core::mem::take);
            *slot = field_from_usize_checked::<F>(count);
            input_count_bounds[i] = input_count_bounds[i].max(count_bound_checked(count));
        }
        for (i, (slot, var)) in output_counts.iter_mut().zip(pair.output.iter()).enumerate() {
            let count = remaining.get_mut(var.index()).map_or(0, core::mem::take);
            *slot = field_from_usize_checked::<F>(count);
            output_count_bounds[i] = output_count_bounds[i].max(count_bound_checked(count));
        }

        input_multiplicities.push(input_counts);
        output_multiplicities.push(output_counts);
    }

    debug_assert!(remaining.into_iter().all(|count| count == 0));
    MultiplicityColumns {
        inputs: input_multiplicities,
        outputs: output_multiplicities,
        input_count_bounds,
        output_count_bounds,
    }
}

fn count_bound_checked(value: usize) -> u32 {
    u32::try_from(value).expect("lookup multiplicity exceeds the supported u32 bound")
}

fn public_multiplicities<F, const WIDTH: usize>(
    instance: &PermutationInstance<F, WIDTH>,
) -> Vec<Option<usize>>
where
    F: Field + Unit + PartialEq,
{
    let public = instance.public_vars();
    let mut mult = vec![None; instance.vars_count];

    for (var, _) in public.iter() {
        mult[var.index()] = Some(0);
    }

    for var in instance
        .constraints()
        .as_ref()
        .iter()
        .flat_map(|pair| pair.input.iter().chain(pair.output.iter()))
    {
        mult[var.index()] = mult[var.index()].map(|count| count + 1);
    }

    mult
}

fn public_lookup_count_bounds<const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    public_multiplicities: &[Option<usize>],
) -> ([u32; WIDTH], [u32; WIDTH]) {
    let mut input_bounds = [0; WIDTH];
    let mut output_bounds = [0; WIDTH];

    for pair in constraints {
        for (i, var) in pair.input.iter().enumerate() {
            input_bounds[i] |= u32::from(public_multiplicities[var.index()].is_some());
        }
        for (i, var) in pair.output.iter().enumerate() {
            output_bounds[i] |= u32::from(public_multiplicities[var.index()].is_some());
        }
    }

    (input_bounds, output_bounds)
}

fn lin_multiplicities<F>(lc: &LinearConstraintsInstance<F>) -> Vec<Option<usize>>
where
    F: Field + Unit + PartialEq,
{
    let vars_count = lc
        .as_ref()
        .iter()
        .flat_map(|equation| {
            equation
                .linear_combination
                .iter()
                .filter_map(|(coeff, var)| {
                    (*coeff != <F as PrimeCharacteristicRing>::ZERO).then_some(var.index())
                })
        })
        .max()
        .map(|max_var| max_var + 1)
        .unwrap_or(0);
    let mut mult = vec![None; vars_count];

    for equation in lc.as_ref() {
        for (coeff, var) in &equation.linear_combination {
            if *coeff != <F as PrimeCharacteristicRing>::ZERO {
                mult[var.index()] = Some(mult[var.index()].unwrap_or(0) + 1);
            }
        }
    }

    mult
}

fn max_linear_width<T, U>(lc: &LinearConstraints<T, U>) -> usize {
    lc.as_ref()
        .iter()
        .map(|equation| equation.linear_combination.len())
        .max()
        .unwrap_or(0)
}

/// Convert a usize to a field element, and panic if there's an oveflow.
///
/// `FieldVar`, as a wire identifier does not guarantee its associated usize
/// can be represented in a single field element. We make sure of that here.
fn field_from_usize_checked<F: PrimeCharacteristicRing>(value: usize) -> F {
    let value = <F::PrimeSubfield as QuotientMap<usize>>::from_canonical_checked(value)
        .expect("value must be smaller than the field characteristic");
    F::from_prime_subfield(value)
}

//-----------------------
// Trace length helpers
// ----------------------

fn pad_instance_linear_constraints<F>(
    mut lc: LinearConstraintsInstance<F>,
    width: usize,
) -> LinearConstraintsInstance<F>
where
    F: PrimeCharacteristicRing,
{
    for equation in &mut lc.equations {
        equation.linear_combination.resize(
            width,
            (<F as PrimeCharacteristicRing>::ZERO, FieldVar::ZERO),
        );
    }
    lc
}

fn pad_witness_linear_constraints<F>(
    mut lc: LinearConstraintsWitness<F>,
    width: usize,
) -> LinearConstraintsWitness<F>
where
    F: PrimeCharacteristicRing,
{
    for equation in &mut lc.equations {
        equation.linear_combination.resize(
            width,
            (
                <F as PrimeCharacteristicRing>::ZERO,
                <F as PrimeCharacteristicRing>::ZERO,
            ),
        );
    }
    lc
}

fn hash_logical_target_len<H, F, const WIDTH: usize>(
    hash: &H,
    instance: &PermutationInstance<F, WIDTH>,
    min_trace_height: usize,
) -> usize
where
    H: RelationArithmetization<F, WIDTH>,
    F: Field + Unit + PartialEq,
{
    let rows_per_invocation = hash.trace_rows_per_invocation();
    let mut target_len = instance
        .constraints()
        .as_ref()
        .len()
        .next_power_of_two()
        .max(1);
    while (target_len * rows_per_invocation)
        .next_power_of_two()
        .max(1)
        < min_trace_height
    {
        target_len *= 2;
    }
    target_len
}

fn pad_witness_permutations<F, P, const WIDTH: usize>(
    witness: &mut PermutationWitness<F, WIDTH>,
    permutation: &P,
    target_len: usize,
) where
    F: Field + Unit + PartialEq,
    P: Permutation<WIDTH, U = F>,
{
    let witness_len = witness.trace.len();
    assert!(target_len.is_power_of_two());
    assert!(witness_len <= target_len);

    let zero_input = core::array::from_fn(|_| <F as PrimeCharacteristicRing>::ZERO);
    let zero_output = permutation.permute(&zero_input);
    witness.trace.reserve(target_len - witness_len);
    for _ in witness_len..target_len {
        witness
            .trace
            .push(QueryAnswerPair::new(zero_input, zero_output));
    }
}

fn pad_instance_permutations<F, const WIDTH: usize>(
    instance: &mut PermutationInstance<F, WIDTH>,
    target_len: usize,
) where
    F: Field + Unit + PartialEq,
{
    let current_len = instance.query_answers.len();
    assert!(target_len.is_power_of_two());
    assert!(current_len <= target_len);
    instance.query_answers.reserve(target_len - current_len);
    for _ in 0..(target_len - current_len) {
        let output = core::array::from_fn(|_| {
            let var = FieldVar::try_from_index(instance.vars_count)
                .expect("variable count exceeds SpongeFish FieldVar maximum");
            instance.vars_count += 1;
            var
        });
        instance
            .query_answers
            .push(QueryAnswerPair::new([FieldVar::ZERO; WIDTH], output));
    }
}

fn trace_degree_bits<T: Clone + Send + Sync>(traces: &[DenseMatrix<T>]) -> Vec<usize> {
    traces
        .iter()
        .map(|trace| {
            let trace_height = trace.height();
            assert!(trace_height.is_power_of_two());
            trace_height.trailing_zeros() as usize
        })
        .collect()
}

fn log_ext_degrees<SC: StarkGenericConfig>(log_degrees: &[usize], config: &SC) -> Vec<usize> {
    log_degrees
        .iter()
        .map(|&degree| degree + config.is_zk())
        .collect()
}

fn pad_dense_matrix_to_height<T: Clone + Default + Send + Sync>(
    mut matrix: DenseMatrix<T>,
    target_height: usize,
) -> DenseMatrix<T> {
    let width = matrix.width;
    let current_height = matrix.values.len() / width;
    if current_height < target_height {
        matrix.values.resize_with(target_height * width, T::default);
    }
    DenseMatrix::new(matrix.values, width)
}

// Trace rows are stored as flat `[T]` slices, but the AIR code is easier to
// read against typed column structs. This macro wires up `Borrow` and
// `BorrowMut` by reinterpreting one row slice as the corresponding `#[repr(C)]`
// column type. Callers must keep the slice length and layout in sync with the
// struct definition; the debug assertions catch mismatches while testing.
macro_rules! impl_borrow_for_column {
    ($ty:ident $(, const $const_name:ident : $const_ty:ty)*) => {
        impl<T, $(const $const_name: $const_ty,)*> core::borrow::Borrow<$ty<T, $($const_name,)*>>
            for [T]
        {
            fn borrow(&self) -> &$ty<T, $($const_name,)*> {
                let (prefix, columns, suffix) =
                    unsafe { self.align_to::<$ty<T, $($const_name,)*>>() };
                debug_assert!(prefix.is_empty());
                debug_assert!(suffix.is_empty());
                debug_assert_eq!(columns.len(), 1);
                &columns[0]
            }
        }

        impl<T, $(const $const_name: $const_ty,)*> core::borrow::BorrowMut<$ty<T, $($const_name,)*>>
            for [T]
        {
            fn borrow_mut(&mut self) -> &mut $ty<T, $($const_name,)*> {
                let (prefix, columns, suffix) =
                    unsafe { self.align_to_mut::<$ty<T, $($const_name,)*>>() };
                debug_assert!(prefix.is_empty());
                debug_assert!(suffix.is_empty());
                debug_assert_eq!(columns.len(), 1);
                &mut columns[0]
            }
        }
    };
}

impl_borrow_for_column!(LookupCols, const WIDTH: usize);
impl_borrow_for_column!(PublicLookupCols);
impl_borrow_for_column!(LinearConstraintCols, const LIN_WIDTH: usize);
impl_borrow_for_column!(LinearConstraintPreprocessedCols, const LIN_WIDTH: usize);

#[cfg(all(test, feature = "p3-koala-bear"))]
mod tests {
    use super::*;
    use crate::{ff::KoalaBearChallenge, permutation::poseidon2::KoalaBearPoseidon2_16HashAir};
    use p3_air::AirLayout;
    use p3_koala_bear::KoalaBear;
    use p3_lookup::{InteractionSymbolicBuilder, Lookups};

    const SELECTOR_TEST_WIDTH: usize = 1;

    #[derive(Clone)]
    struct PeriodicSelectorAir;

    impl RelationArithmetization<KoalaBear, SELECTOR_TEST_WIDTH> for PeriodicSelectorAir {
        type Frame<'a, Var>
            = &'a [Var]
        where
            Self: 'a,
            Var: 'a;

        fn main_width(&self) -> usize {
            3
        }

        fn eval<AB>(&self, _builder: &mut AB)
        where
            AB: AirBuilder<F = KoalaBear>,
        {
        }

        fn num_periodic_columns(&self) -> usize {
            1
        }

        fn periodic_columns(&self) -> Vec<Vec<KoalaBear>> {
            vec![vec![
                <KoalaBear as PrimeCharacteristicRing>::ZERO,
                <KoalaBear as PrimeCharacteristicRing>::ONE,
            ]]
        }

        fn row_frame<'a, Var>(&self, row: &'a [Var]) -> Self::Frame<'a, Var> {
            row
        }

        fn build_trace(
            &self,
            _witness: &PermutationWitness<KoalaBear, SELECTOR_TEST_WIDTH>,
        ) -> RowMajorMatrix<KoalaBear> {
            unreachable!("symbolic adapter test does not build a concrete trace")
        }

        fn invocation<AB>(
            &self,
            frame: &Self::Frame<'_, AB::Var>,
        ) -> QueryAnswerPair<AB::Expr, SELECTOR_TEST_WIDTH>
        where
            AB: AirBuilder<F = KoalaBear>,
        {
            QueryAnswerPair::new([frame[0].into()], [frame[1].into()])
        }

        fn lookup_selector<AB>(&self, frame: &Self::Frame<'_, AB::Var>) -> AB::Expr
        where
            AB: AirBuilder<F = KoalaBear>,
        {
            frame[2].into()
        }
    }

    #[test]
    fn hash_air_forwards_periodic_columns_and_constrains_selector() {
        let instance = PermutationInstanceBuilder::<KoalaBear, SELECTOR_TEST_WIDTH>::new();
        let _ = instance.allocate_permutation(&[FieldVar::ZERO; SELECTOR_TEST_WIDTH]);
        let instance = instance.snapshot();
        let linear_constraints =
            pad_instance_linear_constraints(instance.linear_constraints.clone(), MAX_LINEAR_WIDTH);
        let air = HashLookupAir::<_, _, SELECTOR_TEST_WIDTH, MAX_LINEAR_WIDTH>::new(
            PeriodicSelectorAir,
            instance,
            linear_constraints,
            1,
        );

        assert_eq!(air.num_periodic_columns(), 1);
        assert_eq!(
            air.periodic_columns(),
            vec![vec![
                <KoalaBear as PrimeCharacteristicRing>::ZERO,
                <KoalaBear as PrimeCharacteristicRing>::ONE,
            ]]
        );

        let relation_air = HashRelationAir::Hash(Box::new(air.clone()));
        assert_eq!(relation_air.num_periodic_columns(), 1);
        assert_eq!(
            relation_air.periodic_columns(),
            vec![vec![
                <KoalaBear as PrimeCharacteristicRing>::ZERO,
                <KoalaBear as PrimeCharacteristicRing>::ONE,
            ]]
        );

        let mut builder = InteractionSymbolicBuilder::<KoalaBear, KoalaBearChallenge>::new(
            AirLayout::from_air(&air),
        );
        air.eval(&mut builder);
        let constraints = builder.base_constraints();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].degree_multiple(), 2);
    }

    #[test]
    fn hash_count_bounds_are_tight_per_interaction() {
        const WIDTH: usize = 16;
        const NUM_PERMUTATIONS: usize = 2_048;

        let mut next_var = 1;
        let constraints = (0..NUM_PERMUTATIONS)
            .map(|_| {
                let output = core::array::from_fn(|_| {
                    let var = FieldVar::try_from_index(next_var).unwrap();
                    next_var += 1;
                    var
                });
                QueryAnswerPair::new([FieldVar::ZERO; WIDTH], output)
            })
            .collect::<Vec<_>>();
        let public_multiplicities = vec![None; next_var];

        let multiplicities = hash_equality_multiplicities::<KoalaBear, WIDTH>(
            &constraints,
            next_var,
            &public_multiplicities,
        );

        assert_eq!(
            multiplicities.input_count_bounds[0],
            u32::try_from(NUM_PERMUTATIONS * WIDTH - 1).unwrap()
        );
        assert!(multiplicities.input_count_bounds[1..]
            .iter()
            .all(|&bound| bound == 1));
        assert!(multiplicities
            .output_count_bounds
            .iter()
            .all(|&bound| bound == 0));
    }

    #[test]
    fn zero_bound_lanes_do_not_create_interactions() {
        const WIDTH: usize = 16;

        let instance = PermutationInstanceBuilder::<KoalaBear, WIDTH>::new();
        let _ = instance.allocate_permutation(&[FieldVar::ZERO; WIDTH]);
        let instance = instance.snapshot();
        let linear_constraints =
            pad_instance_linear_constraints(instance.linear_constraints.clone(), MAX_LINEAR_WIDTH);
        let air = HashLookupAir::<_, _, WIDTH, MAX_LINEAR_WIDTH>::new(
            KoalaBearPoseidon2_16HashAir::default(),
            instance,
            linear_constraints,
            1,
        );

        let lookups = Lookups::from_air::<KoalaBearChallenge, _>(&air);

        assert_eq!(lookups.len(), WIDTH);
        assert!(lookups
            .iter()
            .all(|lookup| lookup.kind == p3_lookup::Kind::Global(PUB_LOOKUP_NAME.into())));
    }
}
