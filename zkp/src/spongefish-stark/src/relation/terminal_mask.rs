use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirLayout, SymbolicExpressionExt, WindowAccess};
use p3_batch_stark::{BatchProof, BatchTranscript, CommonData};
use p3_field::{Algebra, BasedVectorSpace, Field, PrimeField};
use p3_lookup::{Count, InteractionBuilder, InteractionSymbolicBuilder, LogUpGadget};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_uni_stark::{StarkGenericConfig, Val};
use rand::{
    distr::{Distribution, Uniform},
    Rng,
};

use super::ProvingError;
use crate::rng::ChaChaCsrng;

pub(super) const BUS: &str = "zk-terminal-mask";
pub(super) const WIDTH: usize = 4;
pub(super) const ROWS: usize = 2;
const MAX_ATTEMPTS: usize = 3;
const KOALA_BEAR_MODULUS: u32 = 2_130_706_433;

pub(super) fn supported<
    Base: PrimeField,
    Challenge: BasedVectorSpace<Base>,
    const PERMUTATION_WIDTH: usize,
>() -> bool {
    PERMUTATION_WIDTH == 16
        && Base::order() == KOALA_BEAR_MODULUS.into()
        && Challenge::DIMENSION == WIDTH
}

pub(super) fn has_full_degree<Challenge: Field>(beta: Challenge) -> bool {
    beta.exp_u64(u64::from(KOALA_BEAR_MODULUS).pow(2)) != beta
}

pub(super) fn retry_completed_proofs<Proof>(
    mut attempt: impl FnMut() -> (Proof, bool),
) -> Result<Proof, ProvingError> {
    for _ in 0..MAX_ATTEMPTS {
        let (proof, accepted) = attempt();
        if accepted {
            return Ok(proof);
        }
    }
    Err(ProvingError)
}

pub(super) fn replay_lookup_challenges<Config, RelationAir>(
    config: &Config,
    airs: &[RelationAir],
    degree_bits: &[usize],
    publics: &[Vec<Val<Config>>],
    common: &CommonData<Config>,
    proof: &BatchProof<Config>,
) -> Option<Vec<Vec<Config::Challenge>>>
where
    Config: StarkGenericConfig,
    Val<Config>: PrimeField,
    RelationAir: Air<InteractionSymbolicBuilder<Val<Config>, Config::Challenge>>,
    SymbolicExpressionExt<Val<Config>, Config::Challenge>: Algebra<Config::Challenge>,
{
    let count = airs.len();
    if degree_bits.len() != count
        || proof.degree_bits.len() != count
        || publics.len() != count
        || common.lookups.len() != count
        || common
            .preprocessed
            .as_ref()
            .is_some_and(|preprocessed| preprocessed.instances.len() != count)
    {
        return None;
    }
    let mut transcript = BatchTranscript::<Config>::new(config.initialise_challenger());
    transcript.observe_instance_count(count);
    let mut preprocessed_widths = Vec::with_capacity(count);
    let gadget = LogUpGadget::new();
    for (index, air) in airs.iter().enumerate() {
        let extended_degree = degree_bits[index].checked_add(config.is_zk())?;
        if proof.degree_bits[index] != extended_degree {
            return None;
        }
        let preprocessed_width = common
            .preprocessed
            .as_ref()
            .and_then(|preprocessed| preprocessed.instances[index].as_ref())
            .map_or(0, |instance| instance.width);
        if preprocessed_width != air.preprocessed_width()
            || publics[index].len() != air.num_public_values()
        {
            return None;
        }
        preprocessed_widths.push(preprocessed_width);
        let log_chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
            Val<Config>,
            Config::Challenge,
            RelationAir,
            LogUpGadget,
        >(
            air,
            AirLayout::from_air(air),
            &common.lookups[index],
            config.is_zk(),
            &gadget,
        );
        transcript.observe_instance_binding(
            extended_degree,
            degree_bits[index],
            air.width(),
            1usize.checked_shl((log_chunks + config.is_zk()).try_into().ok()?)?,
        );
    }
    transcript.observe_main(&proof.commitments.main, publics);
    transcript.observe_preprocessed(&preprocessed_widths, common.preprocessed.as_ref());
    Some(transcript.sample_perm_challenges(&common.lookups, &gadget))
}

pub(super) fn sample_tuples<F: PrimeField>() -> [[F; WIDTH]; ROWS] {
    sample_tuples_with_rng(&mut ChaChaCsrng::from_entropy())
}

fn sample_tuples_with_rng<Base: PrimeField>(rng: &mut impl Rng) -> [[Base; WIDTH]; ROWS] {
    let distribution = Uniform::new(0, KOALA_BEAR_MODULUS).expect("nonempty field range");
    let tuples = core::array::from_fn(|_| core::array::from_fn(|_| distribution.sample(rng)));
    #[cfg(test)]
    SAMPLED_TUPLES.with(|history| {
        if let Some(history) = history.borrow_mut().as_mut() {
            history.push(tuples);
        }
    });
    tuples.map(|tuple| tuple.map(Base::from_u32))
}

#[cfg(test)]
std::thread_local! {
    static SAMPLED_TUPLES: std::cell::RefCell<Option<Vec<[[u32; WIDTH]; ROWS]>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn with_sample_observer<Output>(
    operation: impl FnOnce() -> Output,
) -> (Output, Vec<[[u32; WIDTH]; ROWS]>) {
    struct ResetObserver;

    impl Drop for ResetObserver {
        fn drop(&mut self) {
            SAMPLED_TUPLES.with(|history| history.replace(None));
        }
    }

    SAMPLED_TUPLES.with(|history| assert!(history.replace(Some(Vec::new())).is_none()));
    let _reset = ResetObserver;
    let output = operation();
    let samples = SAMPLED_TUPLES.with(|history| history.replace(None).unwrap());
    (output, samples)
}

pub(super) fn append_two_row_columns<F: Field, const EXTRA: usize>(
    trace: RowMajorMatrix<F>,
    active: &[[F; EXTRA]; ROWS],
) -> RowMajorMatrix<F> {
    assert!(trace.height() >= ROWS);
    let width = trace.width + EXTRA;
    let mut values = Vec::with_capacity(trace.height() * width);
    for (row_index, row) in trace.values.chunks_exact(trace.width).enumerate() {
        values.extend_from_slice(row);
        values.extend_from_slice(active.get(row_index).unwrap_or(&[F::ZERO; EXTRA]));
    }
    RowMajorMatrix::new(values, width)
}

pub(super) fn eval<AB: InteractionBuilder>(
    builder: &mut AB,
    main_offset: usize,
    selector_offset: usize,
    negative: bool,
) {
    let main = builder.main();
    let payload: [AB::Expr; WIDTH] =
        core::array::from_fn(|index| main.current_slice()[main_offset + index].into());
    let selector: AB::Expr = builder.preprocessed().current_slice()[selector_offset].into();
    let count = Count::bounded(selector, 1);
    builder.push_interaction(BUS, payload, if negative { -count } else { count });
}

#[derive(Clone)]
pub(super) struct PrefixWindow<Window> {
    inner: Window,
    width: usize,
}

impl<Var, Window: WindowAccess<Var>> WindowAccess<Var> for PrefixWindow<Window> {
    fn current_slice(&self) -> &[Var] {
        &self.inner.current_slice()[..self.width]
    }

    fn next_slice(&self) -> &[Var] {
        &self.inner.next_slice()[..self.width]
    }
}

pub(super) struct MainTracePrefix<'a, Builder> {
    pub(super) inner: &'a mut Builder,
    pub(super) width: usize,
}

impl<Builder: AirBuilder> AirBuilder for MainTracePrefix<'_, Builder> {
    type F = Builder::F;
    type Expr = Builder::Expr;
    type Var = Builder::Var;
    type PreprocessedWindow = Builder::PreprocessedWindow;
    type MainWindow = PrefixWindow<Builder::MainWindow>;
    type PublicVar = Builder::PublicVar;
    type PeriodicVar = Builder::PeriodicVar;

    const WINDOW: usize = Builder::WINDOW;

    fn main(&self) -> Self::MainWindow {
        PrefixWindow {
            inner: self.inner.main(),
            width: self.width,
        }
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<Expr: Into<Self::Expr>>(&mut self, value: Expr) {
        self.inner.assert_zero(value);
    }

    fn assert_zeros<const COUNT: usize, Expr: Into<Self::Expr>>(&mut self, values: [Expr; COUNT]) {
        self.inner.assert_zeros(values);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}

#[cfg(all(test, feature = "p3-koala-bear"))]
mod tests {
    use super::*;
    use crate::ff::KoalaBearChallenge;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    #[test]
    fn mask_mode_is_limited_to_quartic_koala_bear_16_lane_relations() {
        assert!(supported::<KoalaBear, KoalaBearChallenge, 16>());
        assert!(!supported::<KoalaBear, KoalaBearChallenge, 100>());
        assert!(!supported::<KoalaBear, KoalaBear, 16>());
        #[cfg(feature = "p3-baby-bear")]
        assert!(!supported::<
            p3_baby_bear::BabyBear,
            crate::ff::BabyBearChallenge,
            16,
        >());
    }

    #[test]
    fn tuple_sampling_rejects_biased_words_and_covers_field_endpoints() {
        struct ScriptedRng {
            words: std::collections::VecDeque<u32>,
        }

        impl rand::TryRng for ScriptedRng {
            type Error = core::convert::Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(self.words.pop_front().expect("unexpected RNG draw"))
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                panic!("unexpected u64 RNG draw");
            }

            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
                panic!("unexpected byte RNG draw");
            }
        }

        let mut words = std::collections::VecDeque::from([0, 1, 0, u32::MAX]);
        words.extend([1; WIDTH * ROWS - 2]);
        let mut rng = ScriptedRng { words };
        let tuples = sample_tuples_with_rng::<KoalaBear>(&mut rng);
        let mut expected = [[KoalaBear::ZERO; WIDTH]; ROWS];
        expected[0][1] = KoalaBear::NEG_ONE;
        assert_eq!(tuples, expected);
        assert!(rng.words.is_empty());
    }

    #[test]
    fn full_degree_excludes_base_and_quadratic_subfields() {
        let generator = KoalaBearChallenge::from_basis_coefficients_fn(|index| {
            KoalaBear::from_bool(index == 1)
        });
        assert!(!has_full_degree(KoalaBearChallenge::ZERO));
        assert!(!has_full_degree(KoalaBearChallenge::ONE));
        assert!(!has_full_degree(generator.square()));
        assert!(has_full_degree(generator));
        assert!(has_full_degree(generator + KoalaBearChallenge::ONE));
    }

    #[test]
    fn only_accepted_completed_proof_is_returned() {
        let mut completed = 0;
        let proof = retry_completed_proofs(|| {
            completed += 1;
            (completed, completed == MAX_ATTEMPTS)
        })
        .expect("last attempt should be accepted");
        assert_eq!(proof, MAX_ATTEMPTS);
        assert_eq!(completed, MAX_ATTEMPTS);
    }

    #[test]
    fn exceptional_challenge_retry_is_bounded() {
        let mut attempts = 0;
        let result = retry_completed_proofs(|| {
            attempts += 1;
            ((), false)
        });
        assert_eq!(result, Err(ProvingError));
        assert_eq!(attempts, MAX_ATTEMPTS);
    }

    #[test]
    fn unexpected_prover_panic_is_not_retried() {
        let mut attempts = 0;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retry_completed_proofs::<()>(|| {
                attempts += 1;
                panic!("injected proving failure");
            })
        }));
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }
}
