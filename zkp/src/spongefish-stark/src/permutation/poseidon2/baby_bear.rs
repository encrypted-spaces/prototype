use core::marker::PhantomData;

use p3_baby_bear::{
    default_babybear_poseidon2_16, BabyBear, GenericPoseidon2LinearLayersBabyBear,
    Poseidon2BabyBear, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::RoundConstants;

use crate::ff::{BabyBearConfig, BabyBearStarkConfig};
use crate::security_profile::{Aggressive, Conservative, SecurityProfile};
use crate::HashRelationBackend;

use super::{
    Poseidon2_16Air, Poseidon2_16HashAir, Poseidon2_16RoundConstants, Poseidon2_16Spec,
    POSEIDON2_16_WIDTH,
};

pub const BABYBEAR_POSEIDON2_SBOX_REGISTERS: usize = 1;

#[derive(Clone)]
pub struct BabyBearPoseidon2_16Backend<P> {
    permutation: Poseidon2BabyBear<POSEIDON2_16_WIDTH>,
    _profile: PhantomData<P>,
}

impl<P: SecurityProfile> BabyBearPoseidon2_16Backend<P> {
    #[must_use]
    pub fn new() -> Self {
        Self::with_permutation(default_babybear_poseidon2_16())
    }

    #[must_use]
    pub fn with_permutation(permutation: Poseidon2BabyBear<POSEIDON2_16_WIDTH>) -> Self {
        Self {
            permutation,
            _profile: PhantomData,
        }
    }
}

impl<P: SecurityProfile> Default for BabyBearPoseidon2_16Backend<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> spongefish::Permutation<POSEIDON2_16_WIDTH> for BabyBearPoseidon2_16Backend<P>
where
    P: SecurityProfile,
    Poseidon2BabyBear<POSEIDON2_16_WIDTH>:
        p3_symmetric::Permutation<[BabyBear; POSEIDON2_16_WIDTH]>,
{
    type U = BabyBear;

    fn permute(&self, state: &[Self::U; POSEIDON2_16_WIDTH]) -> [Self::U; POSEIDON2_16_WIDTH] {
        p3_symmetric::Permutation::permute(&self.permutation, *state)
    }

    fn permute_mut(&self, state: &mut [Self::U; POSEIDON2_16_WIDTH]) {
        p3_symmetric::Permutation::permute_mut(&self.permutation, state);
    }
}

impl<P>
    Poseidon2_16Spec<
        BABYBEAR_S_BOX_DEGREE,
        BABYBEAR_POSEIDON2_SBOX_REGISTERS,
        BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    > for BabyBearPoseidon2_16Backend<P>
where
    P: SecurityProfile,
{
    type StarkConfig = BabyBearStarkConfig;
    type LinearLayers = GenericPoseidon2LinearLayersBabyBear;

    fn round_constants() -> BabyBearPoseidon2_16RoundConstants {
        RoundConstants::new(
            p3_baby_bear::BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            p3_baby_bear::BABYBEAR_POSEIDON2_RC_16_INTERNAL,
            p3_baby_bear::BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
        )
    }
}

impl<P> HashRelationBackend<POSEIDON2_16_WIDTH> for BabyBearPoseidon2_16Backend<P>
where
    P: SecurityProfile,
{
    type Config = BabyBearStarkConfig;
    type Air = BabyBearPoseidon2_16HashAirFor<P>;
    type Permutation = Self;

    fn prover_config(&self) -> Self::Config {
        BabyBearConfig::<P>::prover_config()
    }

    fn verifier_config(&self) -> Self::Config {
        BabyBearConfig::<P>::verifier_config()
    }

    fn security_parameters(&self) -> crate::security_profile::SecurityParameters {
        P::security_parameters()
    }

    fn air(&self) -> Self::Air {
        BabyBearPoseidon2_16HashAirFor::<P>::default()
    }

    fn permutation(&self) -> Self::Permutation {
        self.clone()
    }
}

#[allow(non_camel_case_types)]
pub type BabyBearPoseidon2_16_Conservative = BabyBearPoseidon2_16Backend<Conservative>;
#[allow(non_camel_case_types)]
pub type BabyBearPoseidon2_16_Aggressive = BabyBearPoseidon2_16Backend<Aggressive>;

pub type BabyBearPoseidon2_16 = BabyBearPoseidon2_16_Conservative;

pub type BabyBearPoseidon2_16Air = Poseidon2_16Air<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    BABYBEAR_S_BOX_DEGREE,
    BABYBEAR_POSEIDON2_SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
>;

pub type BabyBearPoseidon2_16RoundConstants =
    Poseidon2_16RoundConstants<BabyBear, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16>;

pub type BabyBearPoseidon2_16HashAirFor<P> = Poseidon2_16HashAir<
    BabyBearPoseidon2_16Backend<P>,
    BABYBEAR_S_BOX_DEGREE,
    BABYBEAR_POSEIDON2_SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
>;
pub type BabyBearPoseidon2_16HashAirConservative = BabyBearPoseidon2_16HashAirFor<Conservative>;
pub type BabyBearPoseidon2_16HashAirAggressive = BabyBearPoseidon2_16HashAirFor<Aggressive>;
pub type BabyBearPoseidon2_16HashAir = BabyBearPoseidon2_16HashAirConservative;
