use core::marker::PhantomData;

use p3_baby_bear::BabyBear;

use crate::ff::{BabyBearConfig, BabyBearStarkConfig};
use crate::security_profile::{Aggressive, Conservative, SecurityProfile};
use crate::HashRelationBackend;

use super::{KeccakF1600HashAir, KeccakF1600Permutation, KECCAK_WIDTH};

/// The proving backend for keccak permutations.
///
/// This struct bundles together the permutation function, the associated AIR,
/// and the security profile
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BabyBearKeccakF1600Backend<P>(PhantomData<P>);

impl<P> HashRelationBackend<KECCAK_WIDTH> for BabyBearKeccakF1600Backend<P>
where
    P: SecurityProfile,
{
    type Config = BabyBearStarkConfig;
    type Air = KeccakF1600HashAir<BabyBear>;
    type Permutation = KeccakF1600Permutation<BabyBear>;

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
        KeccakF1600HashAir::default()
    }

    fn permutation(&self) -> Self::Permutation {
        KeccakF1600Permutation::default()
    }
}

#[allow(non_camel_case_types)]
pub type BabyBearKeccakF1600_Conservative = BabyBearKeccakF1600Backend<Conservative>;
#[allow(non_camel_case_types)]
pub type BabyBearKeccakF1600_Aggressive = BabyBearKeccakF1600Backend<Aggressive>;

/// The default configuration for proving keccak relations
pub type BabyBearKeccakF1600 = BabyBearKeccakF1600Backend<Conservative>;
