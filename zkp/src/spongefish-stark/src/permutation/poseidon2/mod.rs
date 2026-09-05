use alloc::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_uni_stark::{StarkGenericConfig, Val};
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

pub const POSEIDON2_16_WIDTH: usize = 16;
pub const POSEIDON2_16_HALF_FULL_ROUNDS: usize = 4;

pub(super) type Poseidon2_16Air<
    F,
    LinearLayers,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const PARTIAL_ROUNDS: usize,
> = Poseidon2Air<
    F,
    LinearLayers,
    POSEIDON2_16_WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    POSEIDON2_16_HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

type Poseidon2_16Cols<
    T,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const PARTIAL_ROUNDS: usize,
> = Poseidon2Cols<
    T,
    POSEIDON2_16_WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    POSEIDON2_16_HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

pub(super) type Poseidon2_16RoundConstants<F, const PARTIAL_ROUNDS: usize> =
    RoundConstants<F, POSEIDON2_16_WIDTH, POSEIDON2_16_HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

#[doc(hidden)]
pub trait Poseidon2_16Spec<
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const PARTIAL_ROUNDS: usize,
>: Sync + 'static
{
    type StarkConfig: StarkGenericConfig;
    type LinearLayers: GenericPoseidon2LinearLayers<POSEIDON2_16_WIDTH> + Sync;

    fn round_constants() -> Poseidon2_16RoundConstants<Val<Self::StarkConfig>, PARTIAL_ROUNDS>;
}

pub struct Poseidon2_16HashAir<
    C,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const PARTIAL_ROUNDS: usize,
> where
    C: Poseidon2_16Spec<SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>,
    Val<C::StarkConfig>: Field + PrimeField,
{
    air: Poseidon2_16Air<
        Val<C::StarkConfig>,
        C::LinearLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        PARTIAL_ROUNDS,
    >,
    _marker: PhantomData<C>,
}

impl<C, const SBOX_DEGREE: u64, const SBOX_REGISTERS: usize, const PARTIAL_ROUNDS: usize> Clone
    for Poseidon2_16HashAir<C, SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>
where
    C: Poseidon2_16Spec<SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>,
    Val<C::StarkConfig>: Field + PrimeField,
{
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            _marker: PhantomData,
        }
    }
}

impl<C, const SBOX_DEGREE: u64, const SBOX_REGISTERS: usize, const PARTIAL_ROUNDS: usize> Default
    for Poseidon2_16HashAir<C, SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>
where
    C: Poseidon2_16Spec<SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>,
    Val<C::StarkConfig>: Field + PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C, const SBOX_DEGREE: u64, const SBOX_REGISTERS: usize, const PARTIAL_ROUNDS: usize>
    Poseidon2_16HashAir<C, SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>
where
    C: Poseidon2_16Spec<SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>,
    Val<C::StarkConfig>: Field + PrimeField,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            air: Poseidon2_16Air::new(C::round_constants()),
            _marker: PhantomData,
        }
    }

    #[must_use]
    pub fn air(
        &self,
    ) -> &Poseidon2_16Air<
        Val<C::StarkConfig>,
        C::LinearLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        PARTIAL_ROUNDS,
    > {
        &self.air
    }
}

impl<C, const SBOX_DEGREE: u64, const SBOX_REGISTERS: usize, const PARTIAL_ROUNDS: usize>
    RelationArithmetization<Val<C::StarkConfig>, POSEIDON2_16_WIDTH>
    for Poseidon2_16HashAir<C, SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>
where
    C: Poseidon2_16Spec<SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS>,
    Val<C::StarkConfig>: Field + PrimeField,
{
    type Frame<'a, Var>
        = &'a [Var]
    where
        Self: 'a,
        Var: 'a;

    fn main_width(&self) -> usize {
        BaseAir::<Val<C::StarkConfig>>::width(&self.air)
    }

    fn eval<AB>(&self, builder: &mut AB)
    where
        AB: AirBuilder<F = Val<C::StarkConfig>>,
    {
        Air::<AB>::eval(&self.air, builder);
    }

    fn row_frame<'a, Var>(&self, row: &'a [Var]) -> Self::Frame<'a, Var> {
        row
    }

    fn build_trace(
        &self,
        witness: &PermutationWitness<Val<C::StarkConfig>, POSEIDON2_16_WIDTH>,
    ) -> RowMajorMatrix<Val<C::StarkConfig>> {
        let inputs = witness
            .trace()
            .as_ref()
            .iter()
            .map(|pair| pair.input)
            .collect::<Vec<_>>();

        // extra capacity bits is `1 + is_zk()` in plonky3.
        // Hardcoded to 2 here.
        p3_poseidon2_air::generate_trace_rows::<
            Val<C::StarkConfig>,
            C::LinearLayers,
            POSEIDON2_16_WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            POSEIDON2_16_HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(inputs, &C::round_constants(), 2)
    }

    fn invocation<AB>(
        &self,
        frame: &Self::Frame<'_, AB::Var>,
    ) -> QueryAnswerPair<AB::Expr, POSEIDON2_16_WIDTH>
    where
        AB: AirBuilder<F = Val<C::StarkConfig>>,
    {
        let cols: &Poseidon2_16Cols<_, SBOX_DEGREE, SBOX_REGISTERS, PARTIAL_ROUNDS> =
            (*frame).borrow();

        QueryAnswerPair::new(
            cols.inputs.map(Into::into),
            cols.ending_full_rounds[POSEIDON2_16_HALF_FULL_ROUNDS - 1]
                .post
                .map(Into::into),
        )
    }
}
