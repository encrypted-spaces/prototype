//! Internal policy for trace hiding and exact proof-degree binding.

use p3_field::BasedVectorSpace;
use p3_uni_stark::{StarkGenericConfig, Val};

use crate::security_profile::SecurityParameters;

/// Number of base-field constraints revealed by the configured FRI queries and
/// two extension-field out-of-domain openings.
pub(crate) fn revealed_base_field_constraints<SC>(security_parameters: SecurityParameters) -> usize
where
    SC: StarkGenericConfig,
    SC::Challenge: BasedVectorSpace<Val<SC>>,
{
    let extension_dimension = <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION;
    security_parameters.num_queries + 2 * extension_dimension
}

/// Minimum power-of-two trace height required by interleaved PCS masking.
///
/// Repeated FRI query indices only reduce the number of independent constraints,
/// so counting every configured query is deliberately conservative.
pub(crate) fn min_trace_height<SC>(security_parameters: SecurityParameters) -> usize
where
    SC: StarkGenericConfig,
    SC::Challenge: BasedVectorSpace<Val<SC>>,
{
    revealed_base_field_constraints::<SC>(security_parameters).next_power_of_two()
}

pub(crate) fn normalized_trace_height<SC>(
    security_parameters: SecurityParameters,
    trace_height: usize,
) -> usize
where
    SC: StarkGenericConfig,
    SC::Challenge: BasedVectorSpace<Val<SC>>,
{
    trace_height
        .next_power_of_two()
        .max(min_trace_height::<SC>(security_parameters))
}

pub(crate) fn assert_safe_trace_height<SC>(
    config: &SC,
    security_parameters: SecurityParameters,
    trace_height: usize,
) where
    SC: StarkGenericConfig,
    SC::Challenge: BasedVectorSpace<Val<SC>>,
{
    assert!(
        trace_height.is_power_of_two(),
        "trace height must be a non-zero power of two"
    );
    if config.is_zk() == 0 {
        return;
    }

    let min_height = min_trace_height::<SC>(security_parameters);
    assert!(
        trace_height >= min_height,
        "trace height {trace_height} is below the {min_height} rows required for hiding"
    );
}

pub(crate) fn validated_statement_degree_bits<SC>(
    config: &SC,
    security_parameters: SecurityParameters,
    proof_degree_bits: usize,
    expected_trace_height: usize,
) -> Option<usize>
where
    SC: StarkGenericConfig,
    SC::Challenge: BasedVectorSpace<Val<SC>>,
{
    if !expected_trace_height.is_power_of_two() {
        return None;
    }

    let degree_bits = proof_degree_bits.checked_sub(config.is_zk())?;
    if config.is_zk() != 0
        && degree_bits < min_trace_height::<SC>(security_parameters).trailing_zeros() as usize
    {
        return None;
    }

    (degree_bits == expected_trace_height.trailing_zeros() as usize).then_some(degree_bits)
}

#[cfg(all(test, any(feature = "p3-baby-bear", feature = "p3-koala-bear")))]
mod tests {
    use super::*;
    #[cfg(feature = "p3-baby-bear")]
    use crate::ff::{BabyBearConfig, BabyBearStarkConfig};
    #[cfg(feature = "p3-koala-bear")]
    use crate::ff::{KoalaBearConfig, KoalaBearStarkConfig};
    #[cfg(feature = "p3-koala-bear")]
    use crate::security_profile::Aggressive;
    use crate::security_profile::{Conservative, SecurityProfile};

    #[cfg(feature = "p3-koala-bear")]
    #[test]
    fn koala_bear_hiding_heights_are_derived_from_profile() {
        assert_eq!(
            min_trace_height::<KoalaBearStarkConfig>(Conservative::security_parameters()),
            128
        );
        assert_eq!(
            min_trace_height::<KoalaBearStarkConfig>(Aggressive::security_parameters()),
            64
        );
    }

    #[cfg(feature = "p3-baby-bear")]
    #[test]
    fn baby_bear_hiding_height_is_derived_from_profile() {
        let security_parameters = Conservative::security_parameters();
        assert_eq!(
            min_trace_height::<BabyBearStarkConfig>(security_parameters),
            128
        );
        assert_eq!(
            BabyBearConfig::<Conservative>::hiding_trace_height(),
            min_trace_height::<BabyBearStarkConfig>(security_parameters)
        );
    }

    #[cfg(feature = "p3-koala-bear")]
    #[test]
    fn validates_minimum_and_exact_statement_degree() {
        let security_parameters = Conservative::security_parameters();
        let config = KoalaBearConfig::<Conservative>::verifier_config();
        let expected_height = min_trace_height::<KoalaBearStarkConfig>(security_parameters);
        let expected_degree_bits = expected_height.trailing_zeros() as usize;
        let hiding_degree_bit = config.is_zk();

        assert_eq!(
            validated_statement_degree_bits(
                &config,
                security_parameters,
                expected_degree_bits + hiding_degree_bit,
                expected_height,
            ),
            Some(expected_degree_bits)
        );
        assert_eq!(
            validated_statement_degree_bits(
                &config,
                security_parameters,
                expected_degree_bits - 1 + hiding_degree_bit,
                expected_height,
            ),
            None
        );
        assert_eq!(
            validated_statement_degree_bits(
                &config,
                security_parameters,
                expected_degree_bits + 1 + hiding_degree_bit,
                expected_height,
            ),
            None
        );
        assert_eq!(
            validated_statement_degree_bits(
                &config,
                security_parameters,
                hiding_degree_bit.saturating_sub(1),
                expected_height,
            ),
            None
        );
        assert_eq!(
            validated_statement_degree_bits(
                &config,
                security_parameters,
                expected_degree_bits + hiding_degree_bit,
                expected_height - 1,
            ),
            None
        );
    }
}
