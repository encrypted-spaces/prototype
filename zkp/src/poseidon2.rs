//! Poseidon constants and proof helpers using the `encrypted_spaces_crypto` configuration.
use encrypted_spaces_crypto::P2_16_CONFIG;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols};

pub type KoalaBearPoseidon2_16Air = Poseidon2Air<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    { P2_16_CONFIG.width },
    { P2_16_CONFIG.sbox_degree },
    { P2_16_CONFIG.sbox_registers },
    { P2_16_CONFIG.half_full_rounds },
    { P2_16_CONFIG.partial_rounds },
>;

pub type KoalaBearPoseidon2_16Cols<T> = Poseidon2Cols<
    T,
    { P2_16_CONFIG.width },
    { P2_16_CONFIG.sbox_degree },
    { P2_16_CONFIG.sbox_registers },
    { P2_16_CONFIG.half_full_rounds },
    { P2_16_CONFIG.partial_rounds },
>;

pub type KoalaBearPoseidon2_16RoundConstants = p3_poseidon2_air::RoundConstants<
    KoalaBear,
    { P2_16_CONFIG.width },
    { P2_16_CONFIG.half_full_rounds },
    { P2_16_CONFIG.partial_rounds },
>;

pub fn poseidon_round_constants() -> KoalaBearPoseidon2_16RoundConstants {
    p3_poseidon2_air::RoundConstants::new(
        p3_koala_bear::KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        p3_koala_bear::KOALABEAR_POSEIDON2_RC_16_INTERNAL,
        p3_koala_bear::KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

pub fn generate_poseidon2_16_trace(
    inputs: &[[KoalaBear; P2_16_CONFIG.width]],
    constants: &KoalaBearPoseidon2_16RoundConstants,
    extra_capacity_bits: usize,
) -> RowMajorMatrix<KoalaBear> {
    p3_poseidon2_air::generate_trace_rows::<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        { P2_16_CONFIG.width },
        { P2_16_CONFIG.sbox_degree },
        { P2_16_CONFIG.sbox_registers },
        { P2_16_CONFIG.half_full_rounds },
        { P2_16_CONFIG.partial_rounds },
    >(inputs.to_vec(), constants, extra_capacity_bits)
}
