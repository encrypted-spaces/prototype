use core::marker::PhantomData;

use p3_koala_bear::{
    default_koalabear_poseidon2_16, GenericPoseidon2LinearLayersKoalaBear, KoalaBear,
    Poseidon2KoalaBear, KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::RoundConstants;

use crate::ff::{KoalaBearConfig, KoalaBearStarkConfig};
use crate::security_profile::{Aggressive, Conservative, SecurityProfile};
use crate::HashRelationBackend;

use super::{
    Poseidon2_16Air, Poseidon2_16HashAir, Poseidon2_16RoundConstants, Poseidon2_16Spec,
    POSEIDON2_16_WIDTH,
};

/// `SBOX_REGISTERS` counts only auxiliary trace registers used to decompose the S-box, not the S-box applications themselves.
/// KoalaBear uses a cubic Poseidon2 S-box, which the AIR constrains directly as `x^3`, so no intermediate registers are needed.
pub const KOALABEAR_POSEIDON2_SBOX_REGISTERS: usize = 0;

#[derive(Clone)]
pub struct KoalaBearPoseidon2_16Backend<P> {
    permutation: Poseidon2KoalaBear<POSEIDON2_16_WIDTH>,
    _profile: PhantomData<P>,
}

impl<P: SecurityProfile> KoalaBearPoseidon2_16Backend<P> {
    #[must_use]
    pub fn new() -> Self {
        Self::with_permutation(default_koalabear_poseidon2_16())
    }

    #[must_use]
    pub fn with_permutation(permutation: Poseidon2KoalaBear<POSEIDON2_16_WIDTH>) -> Self {
        Self {
            permutation,
            _profile: PhantomData,
        }
    }
}

impl<P: SecurityProfile> Default for KoalaBearPoseidon2_16Backend<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> spongefish::Permutation<POSEIDON2_16_WIDTH> for KoalaBearPoseidon2_16Backend<P>
where
    P: SecurityProfile,
    Poseidon2KoalaBear<POSEIDON2_16_WIDTH>:
        p3_symmetric::Permutation<[KoalaBear; POSEIDON2_16_WIDTH]>,
{
    type U = KoalaBear;

    fn permute(&self, state: &[Self::U; POSEIDON2_16_WIDTH]) -> [Self::U; POSEIDON2_16_WIDTH] {
        p3_symmetric::Permutation::permute(&self.permutation, *state)
    }

    fn permute_mut(&self, state: &mut [Self::U; POSEIDON2_16_WIDTH]) {
        p3_symmetric::Permutation::permute_mut(&self.permutation, state);
    }
}

impl<P: SecurityProfile>
    Poseidon2_16Spec<
        KOALABEAR_S_BOX_DEGREE,
        KOALABEAR_POSEIDON2_SBOX_REGISTERS,
        KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    > for KoalaBearPoseidon2_16Backend<P>
{
    type StarkConfig = KoalaBearStarkConfig;
    type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;

    fn round_constants() -> KoalaBearPoseidon2_16RoundConstants {
        RoundConstants::new(
            p3_koala_bear::KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            p3_koala_bear::KOALABEAR_POSEIDON2_RC_16_INTERNAL,
            p3_koala_bear::KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
        )
    }
}

impl<P> HashRelationBackend<POSEIDON2_16_WIDTH> for KoalaBearPoseidon2_16Backend<P>
where
    P: SecurityProfile,
{
    type Config = KoalaBearStarkConfig;
    type Air = KoalaBearPoseidon2_16HashAirFor<P>;
    type Permutation = Self;

    fn prover_config(&self) -> Self::Config {
        KoalaBearConfig::<P>::prover_config()
    }

    fn verifier_config(&self) -> Self::Config {
        KoalaBearConfig::<P>::verifier_config()
    }

    fn security_parameters(&self) -> crate::security_profile::SecurityParameters {
        P::security_parameters()
    }

    fn air(&self) -> Self::Air {
        KoalaBearPoseidon2_16HashAirFor::<P>::default()
    }

    fn permutation(&self) -> Self::Permutation {
        self.clone()
    }
}

#[allow(non_camel_case_types)]
pub type KoalaBearPoseidon2_16_Conservative = KoalaBearPoseidon2_16Backend<Conservative>;
#[allow(non_camel_case_types)]
pub type KoalaBearPoseidon2_16_Aggressive = KoalaBearPoseidon2_16Backend<Aggressive>;

pub type KoalaBearPoseidon2_16 = KoalaBearPoseidon2_16_Conservative;

pub type KoalaBearPoseidon2_16Air = Poseidon2_16Air<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    KOALABEAR_S_BOX_DEGREE,
    KOALABEAR_POSEIDON2_SBOX_REGISTERS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16,
>;

pub type KoalaBearPoseidon2_16RoundConstants =
    Poseidon2_16RoundConstants<KoalaBear, KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16>;

pub type KoalaBearPoseidon2_16HashAirFor<P> = Poseidon2_16HashAir<
    KoalaBearPoseidon2_16Backend<P>,
    KOALABEAR_S_BOX_DEGREE,
    KOALABEAR_POSEIDON2_SBOX_REGISTERS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16,
>;
pub type KoalaBearPoseidon2_16HashAirConservative = KoalaBearPoseidon2_16HashAirFor<Conservative>;
pub type KoalaBearPoseidon2_16HashAirAggressive = KoalaBearPoseidon2_16HashAirFor<Aggressive>;
pub type KoalaBearPoseidon2_16HashAir = KoalaBearPoseidon2_16HashAirConservative;
