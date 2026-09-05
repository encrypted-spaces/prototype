use core::marker::PhantomData;

use p3_koala_bear::KoalaBear;

use crate::ff::{KoalaBearConfig, KoalaBearStarkConfig};
use crate::security_profile::{Aggressive, Conservative, SecurityProfile};
use crate::HashRelationBackend;

use super::{KeccakF1600HashAir, KeccakF1600Permutation, KECCAK_WIDTH};

/// The proving backend for keccak permutations.
///
/// This struct bundles together the permutation function, the associated AIR,
/// and the security profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KoalaBearKeccakF1600Backend<P>(PhantomData<P>);

impl<P> HashRelationBackend<KECCAK_WIDTH> for KoalaBearKeccakF1600Backend<P>
where
    P: SecurityProfile,
{
    type Config = KoalaBearStarkConfig;
    type Air = KeccakF1600HashAir<KoalaBear>;
    type Permutation = KeccakF1600Permutation<KoalaBear>;

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
        KeccakF1600HashAir::default()
    }

    fn permutation(&self) -> Self::Permutation {
        KeccakF1600Permutation::default()
    }
}

#[allow(non_camel_case_types)]
pub type KoalaBearKeccakF1600_Conservative = KoalaBearKeccakF1600Backend<Conservative>;
#[allow(non_camel_case_types)]
pub type KoalaBearKeccakF1600_Aggressive = KoalaBearKeccakF1600Backend<Aggressive>;

/// The default configuration for proving keccak relations
pub type KoalaBearKeccakF1600 = KoalaBearKeccakF1600Backend<Conservative>;
