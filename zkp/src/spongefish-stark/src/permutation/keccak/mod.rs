use alloc::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeField64};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use spongefish::{Permutation, Unit};
use spongefish_circuit::permutation::PermutationWitness;

#[cfg(feature = "p3-baby-bear")]
mod baby_bear;
#[cfg(feature = "p3-koala-bear")]
mod koala_bear;

#[cfg(feature = "p3-baby-bear")]
pub use baby_bear::*;
#[cfg(feature = "p3-koala-bear")]
pub use koala_bear::*;

use crate::{QueryAnswerPair, RelationArithmetization};

pub const KECCAK_WORDS: usize = 25;
pub const KECCAK_LIMBS_PER_WORD: usize = 4;
pub const KECCAK_WIDTH: usize = KECCAK_WORDS * KECCAK_LIMBS_PER_WORD;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeccakF1600Permutation<F>(PhantomData<F>);

#[derive(Clone, Debug, Default)]
pub struct KeccakF1600HashAir<F>(PhantomData<F>);

fn pack_keccak_input<F>(input: &[F; KECCAK_WIDTH]) -> [u64; KECCAK_WORDS]
where
    F: PrimeField64,
{
    core::array::from_fn(|word| {
        (0..KECCAK_LIMBS_PER_WORD).fold(0u64, |acc, limb| {
            let value = input[word * KECCAK_LIMBS_PER_WORD + limb].as_canonical_u64();
            assert!(value < (1 << 16), "Keccak limbs must fit in 16 bits");
            acc | (value << (16 * limb))
        })
    })
}

fn unpack_keccak_state<F>(state: &[u64; KECCAK_WORDS]) -> [F; KECCAK_WIDTH]
where
    F: PrimeField64,
{
    core::array::from_fn(|idx| {
        let word = state[idx / KECCAK_LIMBS_PER_WORD];
        let limb = (word >> (16 * (idx % KECCAK_LIMBS_PER_WORD))) & 0xffff;
        F::from_u16(limb as u16)
    })
}

impl<F> Permutation<KECCAK_WIDTH> for KeccakF1600Permutation<F>
where
    F: PrimeField64 + Unit,
{
    type U = F;

    fn permute(&self, state: &[F; KECCAK_WIDTH]) -> [F; KECCAK_WIDTH] {
        let mut words = pack_keccak_input(state);
        keccak::f1600(&mut words);
        unpack_keccak_state(&words)
    }
}

impl<F> RelationArithmetization<F, KECCAK_WIDTH> for KeccakF1600HashAir<F>
where
    F: PrimeField64 + Field,
{
    type Frame<'a, Var>
        = &'a [Var]
    where
        Self: 'a,
        Var: 'a;

    fn main_width(&self) -> usize {
        BaseAir::<F>::width(&KeccakAir {})
    }

    fn trace_rows_per_invocation(&self) -> usize {
        NUM_ROUNDS
    }

    fn eval<AB>(&self, builder: &mut AB)
    where
        AB: AirBuilder<F = F>,
    {
        Air::<AB>::eval(&KeccakAir {}, builder);
    }

    fn row_frame<'a, Var>(&self, row: &'a [Var]) -> Self::Frame<'a, Var> {
        row
    }

    fn build_trace(&self, witness: &PermutationWitness<F, KECCAK_WIDTH>) -> RowMajorMatrix<F> {
        let inputs = witness
            .trace()
            .as_ref()
            .iter()
            .map(|pair| pack_keccak_input(&pair.input))
            .collect::<Vec<_>>();
        let real_invocations = inputs.len();
        // extra capacity bits is `1 + is_zk()` in plonky3.
        // Hardcoded to 2 here.
        let mut trace = p3_keccak_air::generate_trace_rows::<F>(inputs, 2);
        let (_, rows, _) = unsafe { trace.values.align_to_mut::<KeccakCols<F>>() };
        for invocation_rows in rows.chunks_mut(NUM_ROUNDS).take(real_invocations) {
            invocation_rows[NUM_ROUNDS - 1].export = F::ONE;
        }
        trace
    }

    fn invocation<AB>(
        &self,
        frame: &Self::Frame<'_, AB::Var>,
    ) -> QueryAnswerPair<AB::Expr, KECCAK_WIDTH>
    where
        AB: AirBuilder<F = F>,
    {
        let cols: &KeccakCols<_> = (*frame).borrow();
        let input = core::array::from_fn(|idx| {
            let word = idx / KECCAK_LIMBS_PER_WORD;
            let limb = idx % KECCAK_LIMBS_PER_WORD;
            let y = word / 5;
            let x = word % 5;
            cols.preimage[y][x][limb].into()
        });
        let output = core::array::from_fn(|idx| {
            let word = idx / KECCAK_LIMBS_PER_WORD;
            let limb = idx % KECCAK_LIMBS_PER_WORD;
            let y = word / 5;
            let x = word % 5;
            cols.a_prime_prime_prime(y, x, limb).into()
        });
        QueryAnswerPair::new(input, output)
    }

    fn lookup_selector<AB>(&self, frame: &Self::Frame<'_, AB::Var>) -> AB::Expr
    where
        AB: AirBuilder<F = F>,
    {
        let cols: &KeccakCols<_> = (*frame).borrow();
        cols.export.into()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "p3-baby-bear")]
    #[test]
    fn babybear_keccak_permutation_matches_reference() {
        use super::{pack_keccak_input, unpack_keccak_state, KeccakF1600Permutation};
        use p3_baby_bear::BabyBear;
        use p3_field::PrimeCharacteristicRing;
        use spongefish::Permutation;

        let input = core::array::from_fn(|i| BabyBear::from_u16(i as u16));
        let permutation = KeccakF1600Permutation::<BabyBear>::default();
        let actual = permutation.permute(&input);

        let mut expected_words = pack_keccak_input(&input);
        keccak::f1600(&mut expected_words);
        let expected = unpack_keccak_state::<BabyBear>(&expected_words);

        assert_eq!(actual, expected);
    }

    #[cfg(feature = "p3-baby-bear")]
    #[test]
    fn babybear_keccak_round_trip_limb_encoding() {
        use super::{pack_keccak_input, unpack_keccak_state, KECCAK_WIDTH};
        use p3_baby_bear::BabyBear;
        use p3_field::PrimeCharacteristicRing;

        let input = core::array::from_fn(|i| BabyBear::from_u16((i * 17) as u16));
        let packed = pack_keccak_input(&input);
        let unpacked = unpack_keccak_state::<BabyBear>(&packed);
        assert_eq!(unpacked.len(), KECCAK_WIDTH);
        assert_eq!(unpacked, input);
    }

    #[cfg(feature = "p3-koala-bear")]
    #[test]
    fn koalabear_keccak_permutation_matches_reference() {
        use super::{pack_keccak_input, unpack_keccak_state, KeccakF1600Permutation};
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        use spongefish::Permutation;

        let input = core::array::from_fn(|i| KoalaBear::from_u16(i as u16));
        let permutation = KeccakF1600Permutation::<KoalaBear>::default();
        let actual = permutation.permute(&input);

        let mut expected_words = pack_keccak_input(&input);
        keccak::f1600(&mut expected_words);
        let expected = unpack_keccak_state::<KoalaBear>(&expected_words);

        assert_eq!(actual, expected);
    }

    #[cfg(feature = "p3-koala-bear")]
    #[test]
    fn koalabear_keccak_round_trip_limb_encoding() {
        use super::{pack_keccak_input, unpack_keccak_state, KECCAK_WIDTH};
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;

        let input = core::array::from_fn(|i| KoalaBear::from_u16((i * 17) as u16));
        let packed = pack_keccak_input(&input);
        let unpacked = unpack_keccak_state::<KoalaBear>(&packed);
        assert_eq!(unpacked.len(), KECCAK_WIDTH);
        assert_eq!(unpacked, input);
    }
}
