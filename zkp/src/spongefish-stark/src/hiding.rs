//! Internal policy for trace hiding and exact proof-degree binding.

use p3_field::BasedVectorSpace;
use p3_uni_stark::{StarkGenericConfig, Val};

use crate::security_profile::SecurityParameters;

/// Maximum constraint row window covered by the hiding-budget analysis.
pub(crate) const MAX_ROW_WINDOW: usize = 2;

#[cfg(debug_assertions)]
fn effective_row_window<F>(air: &impl p3_air::BaseAir<F>, has_interactions: bool) -> usize {
    if has_interactions
        || !air.main_next_row_columns().is_empty()
        || !air.preprocessed_next_row_columns().is_empty()
    {
        2
    } else {
        1
    }
}

#[cfg(debug_assertions)]
pub(crate) fn debug_assert_air_row_window<F>(
    air: &impl p3_air::BaseAir<F>,
    has_interactions: bool,
    builder_window: usize,
) {
    let row_window = effective_row_window(air, has_interactions);
    debug_assert!(
        row_window <= MAX_ROW_WINDOW,
        "AIR row window {row_window} exceeds MAX_ROW_WINDOW={MAX_ROW_WINDOW}; \
         re-evaluate the hiding padding budget"
    );
    debug_assert!(
        builder_window <= MAX_ROW_WINDOW,
        "AIR builder row window {builder_window} exceeds MAX_ROW_WINDOW={MAX_ROW_WINDOW}; \
         next-row metadata only describes current/next access; \
         re-evaluate the hiding padding budget"
    );
}

/// Conservative opening budget `wt + 2d` in base-field constraints.
///
/// Each of the `t` FRI queries can expose up to `w` trace evaluations, including
/// shifted evaluations through the quotient. The current local/next protocol
/// also opens the trace at up to two out-of-domain points over the degree-`d`
/// extension field.
pub(crate) fn revealed_base_field_constraints<SC>(security_parameters: SecurityParameters) -> usize
where
    SC: StarkGenericConfig,
    SC::Challenge: BasedVectorSpace<Val<SC>>,
{
    let extension_dimension = <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION;
    MAX_ROW_WINDOW * security_parameters.num_queries + 2 * extension_dimension
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
    #[cfg(any(feature = "p3-baby-bear", feature = "p3-koala-bear"))]
    use crate::security_profile::{Aggressive, Conservative, SecurityProfile};

    #[cfg(debug_assertions)]
    struct RowWindowAir {
        main_next: bool,
        preprocessed_next: bool,
    }

    #[cfg(debug_assertions)]
    impl p3_air::BaseAir<u32> for RowWindowAir {
        fn width(&self) -> usize {
            1
        }

        fn preprocessed_width(&self) -> usize {
            1
        }

        fn main_next_row_columns(&self) -> alloc::vec::Vec<usize> {
            if self.main_next {
                vec![0]
            } else {
                vec![]
            }
        }

        fn preprocessed_next_row_columns(&self) -> alloc::vec::Vec<usize> {
            if self.preprocessed_next {
                vec![0]
            } else {
                vec![]
            }
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn effective_row_window_accounts_for_next_rows_and_interactions() {
        for (main_next, preprocessed_next, has_interactions, expected_window) in [
            (false, false, false, 1),
            (true, false, false, 2),
            (false, true, false, 2),
            (false, false, true, 2),
            (true, true, true, 2),
        ] {
            let air = RowWindowAir {
                main_next,
                preprocessed_next,
            };
            assert_eq!(
                effective_row_window(&air, has_interactions),
                expected_window
            );
            debug_assert_air_row_window(&air, has_interactions, 2);
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "AIR builder row window 3 exceeds MAX_ROW_WINDOW=2")]
    fn wider_builder_is_rejected_even_with_current_row_only_metadata() {
        let air = RowWindowAir {
            main_next: false,
            preprocessed_next: false,
        };
        debug_assert_air_row_window(&air, false, 3);
    }

    #[cfg(feature = "p3-koala-bear")]
    #[test]
    fn koala_bear_hiding_heights_are_derived_from_profile() {
        assert_eq!(
            revealed_base_field_constraints::<KoalaBearStarkConfig>(
                Conservative::security_parameters()
            ),
            172
        );
        assert_eq!(
            revealed_base_field_constraints::<KoalaBearStarkConfig>(
                Aggressive::security_parameters()
            ),
            86
        );
        assert_eq!(
            min_trace_height::<KoalaBearStarkConfig>(Conservative::security_parameters()),
            256
        );
        assert_eq!(
            min_trace_height::<KoalaBearStarkConfig>(Aggressive::security_parameters()),
            128
        );
    }

    #[cfg(feature = "p3-baby-bear")]
    #[test]
    fn baby_bear_hiding_heights_are_derived_from_profile() {
        assert_eq!(
            revealed_base_field_constraints::<BabyBearStarkConfig>(
                Conservative::security_parameters()
            ),
            174
        );
        assert_eq!(
            revealed_base_field_constraints::<BabyBearStarkConfig>(
                Aggressive::security_parameters()
            ),
            88
        );
        assert_eq!(
            min_trace_height::<BabyBearStarkConfig>(Conservative::security_parameters()),
            256
        );
        assert_eq!(
            min_trace_height::<BabyBearStarkConfig>(Aggressive::security_parameters()),
            128
        );
        assert_eq!(
            BabyBearConfig::<Conservative>::hiding_trace_height(),
            min_trace_height::<BabyBearStarkConfig>(Conservative::security_parameters())
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

        let aggressive_parameters = Aggressive::security_parameters();
        let aggressive_config = KoalaBearConfig::<Aggressive>::verifier_config();
        assert_eq!(
            validated_statement_degree_bits(
                &aggressive_config,
                aggressive_parameters,
                64usize.trailing_zeros() as usize + aggressive_config.is_zk(),
                64,
            ),
            None
        );
    }
}
