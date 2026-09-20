use alloc::vec::Vec;
use core::borrow::Borrow;

use encrypted_spaces_crypto::P2_16_CONFIG;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::DenseMatrix;
use p3_poseidon2_air::Poseidon2Air;
use p3_uni_stark::SubAirBuilder;

use crate::poseidon2::{
    generate_poseidon2_16_trace, poseidon_round_constants, KoalaBearPoseidon2_16Air,
    KoalaBearPoseidon2_16Cols,
};

/// Proves knowledge of some hash preimages, where some cells match some expected blocks.
pub struct KoalaBearPoseidon2_16PreimageAir {
    pub(crate) air: KoalaBearPoseidon2_16Air,
    pub(crate) expected: Vec<KoalaBear>,
    pub(crate) selector: Vec<KoalaBear>,
}

impl KoalaBearPoseidon2_16PreimageAir {
    pub fn new(expected_blocks: &[[Option<KoalaBear>; P2_16_CONFIG.width]]) -> Self {
        assert!(
            !expected_blocks.is_empty(),
            "at least one block is required"
        );
        let input_count = expected_blocks.len();

        let air = Poseidon2Air::new(poseidon_round_constants());
        let mut selector = Vec::with_capacity(input_count * P2_16_CONFIG.width);
        let mut expected = Vec::with_capacity(input_count * P2_16_CONFIG.width);
        for block in expected_blocks.iter().copied() {
            for value in block {
                selector.push(if value.is_some() {
                    KoalaBear::ONE
                } else {
                    KoalaBear::ZERO
                });
                expected.push(value.unwrap_or(KoalaBear::ZERO));
            }
        }

        Self {
            air,
            expected,
            selector,
        }
    }

    pub(crate) fn input_count(&self) -> usize {
        self.expected.len() / P2_16_CONFIG.width
    }
}

impl BaseAir<KoalaBear> for KoalaBearPoseidon2_16PreimageAir {
    fn width(&self) -> usize {
        self.air.width()
    }

    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<KoalaBear>> {
        let mut flat_preprocessed = Vec::new();

        let selector_chunks = self.selector.chunks(P2_16_CONFIG.width);
        let expected_chunks = self.expected.chunks(P2_16_CONFIG.width);
        for (selector_chunk, expected_chunk) in selector_chunks.zip(expected_chunks) {
            flat_preprocessed.extend_from_slice(selector_chunk);
            flat_preprocessed.extend_from_slice(expected_chunk);
        }
        Some(DenseMatrix::new(flat_preprocessed, P2_16_CONFIG.width * 2))
    }

    fn preprocessed_width(&self) -> usize {
        P2_16_CONFIG.width * 2
    }
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for KoalaBearPoseidon2_16PreimageAir {
    fn eval(&self, builder: &mut AB) {
        // Prove the sub-relation using p3-poseidon-air
        {
            let poseidon_width = self.air.width();
            let mut sub_builder = SubAirBuilder::<AB, KoalaBearPoseidon2_16Air, AB::Var>::new(
                builder,
                0..poseidon_width,
            );
            self.air.eval(&mut sub_builder);
        }

        // recover the selector and output from the pre-processed columns
        let main = builder.main();
        let poseidon_slice = &main.current_slice()[..self.air.width()];
        let local_columns: &KoalaBearPoseidon2_16Cols<_> = poseidon_slice.borrow();
        let expected_columns = builder.preprocessed().current_slice().to_vec();
        let selector = &expected_columns[0..P2_16_CONFIG.width];
        let expected_output = &expected_columns[P2_16_CONFIG.width..];

        let got = local_columns.ending_full_rounds[P2_16_CONFIG.half_full_rounds - 1].post;
        for i in 0..P2_16_CONFIG.width {
            // check that the output state is equal to the computed hash output
            builder.assert_eq(got[i] * selector[i], expected_output[i]);
        }
    }
}

impl KoalaBearPoseidon2_16PreimageAir {
    pub fn generate_trace_rows(
        &self,
        inputs: Vec<[KoalaBear; P2_16_CONFIG.width]>,
        extra_capacity_bits: usize,
    ) -> DenseMatrix<KoalaBear> {
        let constants = poseidon_round_constants();

        generate_poseidon2_16_trace(inputs, &constants, extra_capacity_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;
    use spongefish_stark::{
        air::AirTracePadding, ff::KoalaBearConfig, security_profile::Conservative,
    };

    #[test]
    fn keeps_logical_rows_separate_from_hiding_safe_trace_preparation() {
        for (input_count, expected_height) in
            [(1, 256), (2, 256), (31, 256), (128, 256), (257, 512)]
        {
            let expected_blocks = vec![[None; P2_16_CONFIG.width]; input_count];
            let inputs = vec![[KoalaBear::ZERO; P2_16_CONFIG.width]; input_count];
            let air = KoalaBearPoseidon2_16PreimageAir::new(&expected_blocks);
            let prepared = KoalaBearConfig::<Conservative>::prepare_air(
                &air,
                input_count,
                AirTracePadding::RepeatLast,
            );

            assert_eq!(air.input_count(), input_count);
            assert_eq!(air.preprocessed_trace().unwrap().height(), input_count);
            assert_eq!(prepared.trace_height(), expected_height);
            assert_eq!(
                prepared
                    .generate_trace(&inputs, |inputs| air.generate_trace_rows(inputs, 0))
                    .height(),
                expected_height
            );
        }
    }
}
