use std::marker::PhantomData;

use p3_koala_bear::{KoalaBear, KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE};

pub struct PoseidonConfiguration<F> {
    pub width: usize,
    pub rate: usize,
    pub sbox_degree: u64,
    pub sbox_registers: usize,
    pub half_full_rounds: usize,
    pub partial_rounds: usize,
    _field: PhantomData<F>,
}

pub const P2_16_CONFIG: PoseidonConfiguration<KoalaBear> = PoseidonConfiguration {
    width: 16,
    rate: 8,
    sbox_degree: KOALABEAR_S_BOX_DEGREE,
    sbox_registers: 0,
    half_full_rounds: 4,
    partial_rounds: KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    _field: PhantomData,
};
