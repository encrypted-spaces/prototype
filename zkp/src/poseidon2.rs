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
    inputs: Vec<[KoalaBear; P2_16_CONFIG.width]>,
    constants: &KoalaBearPoseidon2_16RoundConstants,
    extra_capacity_bits: usize,
) -> RowMajorMatrix<KoalaBear> {
    assert!(
        !inputs.is_empty(),
        "at least one Poseidon2 input is required"
    );

    if inputs.len().is_power_of_two() {
        return generate_poseidon2_16_trace_power_of_two(inputs, constants, extra_capacity_bits);
    }

    // Generate maximal power-of-two chunks so no duplicate Poseidon rows are
    // computed, while retaining Plonky3's requested aggregate allocation
    // headroom for callers that append trace columns in place.
    let first_chunk_len = 1usize << inputs.len().ilog2();
    let first_trace = generate_poseidon2_16_trace_power_of_two(
        inputs[..first_chunk_len].to_vec(),
        constants,
        extra_capacity_bits,
    );
    let width = first_trace.width;
    let target_capacity = (inputs.len() * width) << extra_capacity_bits;
    let mut values = first_trace.values;
    // The target covers every input row, while the current length contains
    // only the first (and therefore no larger) power-of-two chunk.
    values.reserve(target_capacity - values.len());

    let mut offset = first_chunk_len;
    while offset < inputs.len() {
        let remaining = inputs.len() - offset;
        let chunk_len = 1usize << remaining.ilog2();
        let trace = generate_poseidon2_16_trace_power_of_two(
            inputs[offset..offset + chunk_len].to_vec(),
            constants,
            0,
        );
        debug_assert_eq!(trace.width, width);
        values.extend(trace.values);
        offset += chunk_len;
    }

    RowMajorMatrix::new(values, width)
}

fn generate_poseidon2_16_trace_power_of_two(
    inputs: Vec<[KoalaBear; P2_16_CONFIG.width]>,
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
    >(inputs, constants, extra_capacity_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn non_power_of_two_trace_preserves_extra_capacity() {
        let inputs = vec![[KoalaBear::ZERO; P2_16_CONFIG.width]; 3];
        let trace = generate_poseidon2_16_trace(inputs, &poseidon_round_constants(), 2);

        assert_eq!(trace.values.len(), 3 * trace.width);
        assert!(trace.values.capacity() >= trace.values.len() << 2);
    }
}
