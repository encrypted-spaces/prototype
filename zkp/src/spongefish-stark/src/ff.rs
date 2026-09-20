#![allow(dead_code)]

/// Defines field-specific STARK config aliases and constructors, wiring challenge fields, MMCS, PCS, challenger, and profile-derived prover/verifier configs.
macro_rules! define_field_config {
    (
        $config:ident,
        $field:ty,
        $challenge_ty:ty,
        $challenge:ident,
        $transcript_hash:ident,
        $transcript_compress:ident,
        $val_mmcs:ident,
        $challenge_mmcs:ident,
        $challenger:ident,
        $dft:ident,
        $pcs:ident,
        $stark_config:ident,
    ) => {
        #[derive(Clone, Copy, Default)]
        pub struct $config<P>(core::marker::PhantomData<P>)
        where
            P: crate::security_profile::SecurityProfile;

        pub type $challenge = $challenge_ty;
        pub type $transcript_hash = $crate::ff::StarkFieldHash;
        pub type $transcript_compress = $crate::ff::StarkCompress;
        pub type $val_mmcs = p3_merkle_tree::MerkleTreeHidingMmcs<
            [$field; p3_keccak::VECTOR_LEN],
            [u64; p3_keccak::VECTOR_LEN],
            $transcript_hash,
            $transcript_compress,
            $crate::rng::ChaChaCsrng,
            2,
            4,
            4,
        >;
        pub type $challenge_mmcs = p3_commit::ExtensionMmcs<$field, $challenge, $val_mmcs>;
        pub type $challenger = p3_challenger::SerializingChallenger32<
            $field,
            p3_challenger::HashChallenger<u8, $crate::ff::StarkByteHash, 32>,
        >;
        pub type $dft = p3_dft::Radix2DFTSmallBatch<$field>;
        pub type $pcs = p3_fri::HidingFriPcs<
            $field,
            $dft,
            $val_mmcs,
            $challenge_mmcs,
            $crate::rng::ChaChaCsrng,
        >;
        pub type $stark_config = p3_uni_stark::StarkConfig<$pcs, $challenge, $challenger>;

        impl<P> $config<P>
        where
            P: crate::security_profile::SecurityProfile,
        {
            /// Return the conservative number of base-field constraints exposed by the
            /// profile's direct, quotient-derived shifted, and out-of-domain openings.
            pub fn hiding_revealed_base_field_constraints() -> usize {
                $crate::hiding::revealed_base_field_constraints::<$stark_config>(
                    P::security_parameters(),
                )
            }

            /// Return the minimum power-of-two trace height required for hiding.
            pub fn hiding_trace_height() -> usize {
                $crate::hiding::min_trace_height::<$stark_config>(P::security_parameters())
            }

            /// Normalize a logical trace height to a power of two satisfying
            /// this profile's PCS hiding minimum.
            pub fn normalized_trace_height(trace_height: usize) -> usize {
                $crate::hiding::normalized_trace_height::<$stark_config>(
                    P::security_parameters(),
                    trace_height,
                )
            }

            /// Prepare a logical AIR using an explicit padding contract and a
            /// padded height satisfying this profile's PCS hiding minimum.
            pub fn prepare_air<'a, A>(
                air: &'a A,
                logical_trace_height: usize,
                padding: $crate::air::AirTracePadding,
            ) -> $crate::air::PreparedAir<'a, A>
            where
                A: p3_air::BaseAir<$field>,
            {
                #[cfg(debug_assertions)]
                $crate::hiding::debug_assert_air_row_window(
                    air,
                    false,
                    <p3_air::SymbolicAirBuilder<$field> as p3_air::AirBuilder>::WINDOW,
                );
                let trace_height = Self::normalized_trace_height(logical_trace_height);
                $crate::air::PreparedAir::new(
                    air,
                    logical_trace_height,
                    trace_height,
                    padding,
                )
            }

            pub fn prover_config() -> $stark_config {
                Self::prover_config_with_security_parameters(P::security_parameters())
            }

            pub fn prover_config_with_security_parameters(
                security_parameters: $crate::security_profile::SecurityParameters,
            ) -> $stark_config {
                $crate::ff::stark_config!(
                    $crate::rng::ChaChaCsrng::from_entropy(),
                    $crate::rng::ChaChaCsrng::from_entropy(),
                    security_parameters,
                    $val_mmcs,
                    $challenge_mmcs,
                    $pcs,
                    $dft,
                    $challenger,
                    $stark_config,
                )
            }

            pub fn verifier_config() -> $stark_config {
                Self::verifier_config_with_security_parameters(P::security_parameters())
            }

            pub fn verifier_config_with_security_parameters(
                security_parameters: crate::security_profile::SecurityParameters,
            ) -> $stark_config {
                $crate::ff::stark_config!(
                    $crate::rng::ChaChaCsrng::from_seed_u64($crate::ff::PLACEHOLDER_MMCS_SEED),
                    $crate::rng::ChaChaCsrng::from_seed_u64($crate::ff::PLACEHOLDER_PCS_SEED),
                    security_parameters,
                    $val_mmcs,
                    $challenge_mmcs,
                    $pcs,
                    $dft,
                    $challenger,
                    $stark_config,
                )
            }

            /// Prove an AIR using this profile's PCS hiding requirements.
            #[allow(clippy::multiple_bound_locations)] // cfg is not supported on where predicates.
            pub fn prove_air<
                #[cfg(debug_assertions)] A: for<'a> p3_air::Air<
                    p3_air::DebugConstraintBuilder<'a, $field>,
                >,
                #[cfg(not(debug_assertions))] A,
            >(
                air: &A,
                trace: p3_matrix::dense::RowMajorMatrix<$field>,
                public_values: &[$field],
            ) -> alloc::vec::Vec<u8>
            where
                A: p3_air::Air<p3_air::SymbolicAirBuilder<$field>>
                    + for<'a> p3_air::Air<
                        p3_uni_stark::ProverConstraintFolder<'a, $stark_config>,
                    >,
            {
                use p3_matrix::Matrix;

                #[cfg(debug_assertions)]
                $crate::hiding::debug_assert_air_row_window(
                    air,
                    false,
                    <p3_air::SymbolicAirBuilder<$field> as p3_air::AirBuilder>::WINDOW,
                );
                let trace_height = trace.height();
                let degree_bits = trace_height.trailing_zeros() as usize;
                let preprocessing_config = Self::verifier_config();
                let config = Self::prover_config();
                $crate::hiding::assert_safe_trace_height(
                    &config,
                    P::security_parameters(),
                    trace_height,
                );
                let preprocessed =
                    p3_uni_stark::setup_preprocessed(&preprocessing_config, air, degree_bits);
                let proof = p3_uni_stark::prove_with_preprocessed(
                    &config,
                    air,
                    trace,
                    public_values,
                    preprocessed.as_ref().map(|(prover_data, _)| prover_data),
                );

                postcard::to_allocvec(&proof).expect("proof serialization should succeed")
            }

            /// Prove a prepared AIR and require its generated main trace to
            /// match the profile-derived padded height.
            #[allow(clippy::multiple_bound_locations)] // cfg is not supported on where predicates.
            pub fn prove_prepared_air<
                #[cfg(debug_assertions)] A: for<'a> p3_air::Air<
                    p3_air::DebugConstraintBuilder<'a, $field>,
                >,
                #[cfg(not(debug_assertions))] A,
            >(
                air: &$crate::air::PreparedAir<'_, A>,
                trace: p3_matrix::dense::RowMajorMatrix<$field>,
                public_values: &[$field],
            ) -> alloc::vec::Vec<u8>
            where
                A: p3_air::Air<p3_air::SymbolicAirBuilder<$field>>
                    + for<'a> p3_air::Air<
                        p3_uni_stark::ProverConstraintFolder<'a, $stark_config>,
                    >,
            {
                use p3_matrix::Matrix;

                assert_eq!(
                    trace.height(),
                    air.trace_height(),
                    "main trace height must equal the prepared padded height"
                );
                Self::prove_air(air, trace, public_values)
            }

            /// Verify a serialized AIR proof and bind its degree exactly to the
            /// statement-derived trace height.
            pub fn verify_air<A>(
                air: &A,
                proof_bytes: &[u8],
                expected_trace_height: usize,
                public_values: &[$field],
            ) -> spongefish::VerificationResult<()>
            where
                A: p3_air::Air<p3_air::SymbolicAirBuilder<$field>>
                    + for<'a> p3_air::Air<
                        p3_uni_stark::ProverConstraintFolder<'a, $stark_config>,
                    >
                    + for<'a> p3_air::Air<
                        p3_uni_stark::VerifierConstraintFolder<'a, $stark_config>,
                    >,
            {
                let config = Self::verifier_config();
                let proof: p3_uni_stark::Proof<$stark_config> =
                    postcard::from_bytes(proof_bytes).map_err(|_| spongefish::VerificationError)?;
                let degree_bits = $crate::hiding::validated_statement_degree_bits(
                    &config,
                    P::security_parameters(),
                    proof.degree_bits,
                    expected_trace_height,
                )
                .ok_or(spongefish::VerificationError)?;
                let preprocessed = p3_uni_stark::setup_preprocessed(&config, air, degree_bits);
                p3_uni_stark::verify_with_preprocessed(
                    &config,
                    air,
                    &proof,
                    public_values,
                    preprocessed.as_ref().map(|(_, verifier_key)| verifier_key),
                )
                .map_err(|_| spongefish::VerificationError)
            }

            /// Verify a prepared AIR proof against its profile-derived exact degree.
            pub fn verify_prepared_air<A>(
                air: &$crate::air::PreparedAir<'_, A>,
                proof_bytes: &[u8],
                public_values: &[$field],
            ) -> spongefish::VerificationResult<()>
            where
                A: p3_air::Air<p3_air::SymbolicAirBuilder<$field>>
                    + for<'a> p3_air::Air<
                        p3_uni_stark::ProverConstraintFolder<'a, $stark_config>,
                    >
                    + for<'a> p3_air::Air<
                        p3_uni_stark::VerifierConstraintFolder<'a, $stark_config>,
                    >,
            {
                Self::verify_air(air, proof_bytes, air.trace_height(), public_values)
            }
        }
    };
}

#[cfg(feature = "p3-baby-bear")]
define_field_config!(
    BabyBearConfig,
    p3_baby_bear::BabyBear,
    p3_field::extension::BinomialExtensionField<p3_baby_bear::BabyBear, 5>,
    BabyBearChallenge,
    BabyBearTranscriptHash,
    BabyBearTranscriptCompress,
    BabyBearValMmcs,
    BabyBearChallengeMmcs,
    BabyBearChallenger,
    BabyBearDft,
    BabyBearPcs,
    BabyBearStarkConfig,
);

// XXX. We would like KoalaBear to have a quintic extension too.
// This is currently not possible since its respective Algebra<Challenge> impl is missing.
#[cfg(feature = "p3-koala-bear")]
define_field_config!(
    KoalaBearConfig,
    p3_koala_bear::KoalaBear,
    p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
    KoalaBearChallenge,
    KoalaBearTranscriptHash,
    KoalaBearTranscriptCompress,
    KoalaBearValMmcs,
    KoalaBearChallengeMmcs,
    KoalaBearChallenger,
    KoalaBearDft,
    KoalaBearPcs,
    KoalaBearStarkConfig,
);

use p3_keccak::{Keccak256Hash, KeccakF};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};

pub(crate) use crate::rng::{PLACEHOLDER_MMCS_SEED, PLACEHOLDER_PCS_SEED};

pub type StarkByteHash = Keccak256Hash;
pub type StarkU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
pub type StarkFieldHash = SerializingHasher<StarkU64Hash>;
pub type StarkCompress = CompressionFunctionFromHasher<StarkU64Hash, 2, 4>;

/// Builds a concrete STARK config from RNGs, security parameters, MMCS/PCS types, DFT, challenger, and optional hiding codeword count.
macro_rules! stark_config {
    (
        $mmcs_rng:expr,
        $pcs_rng:expr,
        $security_parameters:expr,
        $val_mmcs:ty,
        $challenge_mmcs:ty,
        $pcs:ty,
        $dft:ty,
        $challenger:ty,
        $stark_config:ty,
    ) => {{
        let hiding_random_codewords = <<$stark_config as p3_uni_stark::StarkGenericConfig>::Challenge as p3_field::BasedVectorSpace<p3_uni_stark::Val<$stark_config>>>::DIMENSION;
        $crate::ff::stark_config!(
            $mmcs_rng,
            $pcs_rng,
            $security_parameters,
            hiding_random_codewords,
            $val_mmcs,
            $challenge_mmcs,
            $pcs,
            $dft,
            $challenger,
            $stark_config,
        )
    }};
    (
        $mmcs_rng:expr,
        $pcs_rng:expr,
        $security_parameters:expr,
        $hiding_random_codewords:expr,
        $val_mmcs:ty,
        $challenge_mmcs:ty,
        $pcs:ty,
        $dft:ty,
        $challenger:ty,
        $stark_config:ty,
    ) => {{
        let byte_hash = $crate::ff::StarkByteHash {};
        let u64_hash = $crate::ff::StarkU64Hash::new(p3_keccak::KeccakF {});
        let hash = $crate::ff::StarkFieldHash::new(u64_hash);
        let compress = $crate::ff::StarkCompress::new(u64_hash);
        let val_mmcs = <$val_mmcs>::new(hash, compress, 0, $mmcs_rng);
        let challenge_mmcs = <$challenge_mmcs>::new(val_mmcs.clone());
        let fri_params = $security_parameters.fri_params_zk(challenge_mmcs);
        let pcs = <$pcs>::new(
            <$dft>::default(),
            val_mmcs,
            fri_params,
            $hiding_random_codewords,
            $pcs_rng,
        );
        let challenger = <$challenger>::from_hasher(alloc::vec::Vec::new(), byte_hash);
        <$stark_config>::new(pcs, challenger)
    }};
}

pub(crate) use stark_config;
