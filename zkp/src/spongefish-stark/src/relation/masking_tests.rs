use super::*;
use crate::ff::{
    KoalaBearChallenge, KoalaBearChallenger, KoalaBearConfig, KoalaBearPcs, KoalaBearStarkConfig,
};
use crate::permutation::poseidon2::KoalaBearPoseidon2_16;
use crate::security_profile::Conservative;
use p3_air::AirLayout;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_koala_bear::KoalaBear;
use p3_lookup::{Kind, LogUpGadget, LookupProtocol};
use spongefish_circuit::permutation::LinearEquation;
use std::sync::{Arc, Mutex};

type TestAir = PreparedRelationAir<KoalaBearPoseidon2_16, 16>;
type TestTrace = RowMajorMatrix<KoalaBear>;
type RecordedDraws = Arc<Mutex<Vec<KoalaBearChallenge>>>;

#[derive(Clone)]
struct ObservedConfig {
    inner: KoalaBearStarkConfig,
    draws: RecordedDraws,
    forced_beta: Option<KoalaBearChallenge>,
}

impl StarkGenericConfig for ObservedConfig {
    type Pcs = KoalaBearPcs;
    type Challenge = KoalaBearChallenge;
    type Challenger = ObservedChallenger;

    fn pcs(&self) -> &Self::Pcs {
        self.inner.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        ObservedChallenger {
            inner: self.inner.initialise_challenger(),
            draws: self.draws.clone(),
            forced_beta: self.forced_beta,
            algebra_draws: 0,
        }
    }
}

fn fixture_builders() -> (
    PermutationInstanceBuilder<KoalaBear, 16>,
    PermutationWitnessBuilder<KoalaBearPoseidon2_16, 16>,
) {
    let backend = KoalaBearPoseidon2_16::new();
    let instance = PermutationInstanceBuilder::<KoalaBear, 16>::new();
    let witness = PermutationWitnessBuilder::new(backend.permutation());
    let input = core::array::from_fn(|index| KoalaBear::from_usize(index + 1));
    let input_vars = core::array::from_fn(|_| instance.allocator().new_field_var());
    let output_vars = instance.allocate_permutation(&input_vars);
    let output = witness.allocate_permutation(&input);
    instance.add_equation(LinearEquation::new(
        [
            (<KoalaBear as PrimeCharacteristicRing>::ONE, output_vars[0]),
            (<KoalaBear as PrimeCharacteristicRing>::ONE, output_vars[1]),
        ],
        output[0] + output[1],
    ));
    witness.add_equation(LinearEquation::new(
        [
            (<KoalaBear as PrimeCharacteristicRing>::ONE, output[0]),
            (<KoalaBear as PrimeCharacteristicRing>::ONE, output[1]),
        ],
        output[0] + output[1],
    ));
    (instance, witness)
}

fn fixture() -> (
    PreparedRelation<KoalaBearPoseidon2_16, 16>,
    PreparedWitness<KoalaBearPoseidon2_16, 16>,
) {
    let (instance, witness) = fixture_builders();
    let relation = PreparedRelation::new(&KoalaBearPoseidon2_16::new(), &instance);
    let witness = relation.prepare_witness(&witness);
    (relation, witness)
}

fn proof_from_traces(
    airs: &[TestAir],
    traces: &[TestTrace],
) -> (
    BatchProof<KoalaBearStarkConfig>,
    ProverData<KoalaBearStarkConfig>,
) {
    let config = KoalaBearConfig::<Conservative>::prover_config();
    let degrees = log_ext_degrees(&trace_degree_bits(traces), &config);
    let data = ProverData::from_airs_and_degrees(
        &KoalaBearConfig::<Conservative>::verifier_config(),
        airs,
        &degrees,
    );
    let publics = vec![vec![]; airs.len()];
    let refs = traces.iter().collect::<Vec<_>>();
    let instances = StarkInstance::new_multiple(airs, &refs, &publics);
    (
        p3_batch_stark::prove_batch(&config, &instances, &data),
        data,
    )
}

fn verifies(airs: &[TestAir], traces: &[TestTrace]) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (proof, data) = proof_from_traces(airs, traces);
        p3_batch_stark::verify_batch(
            &KoalaBearConfig::<Conservative>::verifier_config(),
            airs,
            &proof,
            &vec![vec![]; airs.len()],
            &data.common,
        )
        .is_ok()
    }))
    .unwrap_or(false)
}

#[test]
fn mask_multiset_must_match_but_pair_order_is_irrelevant() {
    let (relation, witness) = fixture();
    let (airs, mut traces) = relation.generate_trace_rows(&witness);
    for coordinate in 0..terminal_mask::WIDTH {
        let first = MAX_LINEAR_WIDTH + coordinate;
        let second = traces[2].width + first;
        traces[2].values.swap(first, second);
    }
    assert!(verifies(&airs, &traces));
    traces[2].values[MAX_LINEAR_WIDTH] += <KoalaBear as PrimeCharacteristicRing>::ONE;
    assert!(!verifies(&airs, &traces));
}

#[test]
fn mask_bus_cannot_compensate_an_invalid_real_lookup() {
    let (relation, witness) = fixture();
    let (airs, mut traces) = relation.generate_trace_rows(&witness);
    for air_index in [0, 2] {
        let width = traces[air_index].width;
        for row in 0..2 {
            let offset = row * width + width - terminal_mask::WIDTH;
            traces[air_index].values[offset..offset + terminal_mask::WIDTH]
                .fill(KoalaBear::from_usize(row + 7));
        }
    }
    assert!(verifies(&airs, &traces));
    traces[2].values[0] += <KoalaBear as PrimeCharacteristicRing>::ONE;
    traces[2].values[1] -= <KoalaBear as PrimeCharacteristicRing>::ONE;
    assert!(!verifies(&airs, &traces));
}

fn without_masks(mut airs: Vec<TestAir>, traces: Vec<TestTrace>) -> (Vec<TestAir>, Vec<TestTrace>) {
    for air in &mut airs {
        match air {
            HashRelationAir::Hash(air) => air.terminal_masking = false,
            HashRelationAir::Linear(air) => air.terminal_masking = false,
            HashRelationAir::Public(_) => (),
        }
    }
    let traces = traces
        .into_iter()
        .zip(&airs)
        .map(|(trace, air)| {
            RowMajorMatrix::new(
                trace
                    .values
                    .chunks_exact(trace.width)
                    .flat_map(|row| row[..air.width()].iter().copied())
                    .collect(),
                air.width(),
            )
        })
        .collect();
    (airs, traces)
}

#[test]
fn mask_cost_is_two_fraction_columns_without_extra_quotient_chunks() {
    let (relation, witness) = fixture();
    let (airs, traces) = relation.generate_trace_rows(&witness);
    let (original, _) = without_masks(airs.clone(), traces);
    let config = KoalaBearConfig::<Conservative>::verifier_config();
    let degrees = log_ext_degrees(&relation.trace_degree_bits(), &config);
    let data = ProverData::from_airs_and_degrees(&config, &airs, &degrees);
    let original_data = ProverData::from_airs_and_degrees(&config, &original, &degrees);
    for index in 0..airs.len() {
        let added = usize::from(index != 1);
        assert_eq!(airs[index].width(), original[index].width() + 4 * added);
        assert_eq!(
            airs[index].preprocessed_width(),
            original[index].preprocessed_width() + added
        );
        assert_eq!(
            data.common.lookups[index].len(),
            original_data.common.lookups[index].len() + added
        );
        assert_eq!(
            data.common.lookups[index].total_count_weight(),
            original_data.common.lookups[index].total_count_weight() + added as u64,
        );
        let chunks = |air: &TestAir, lookups: &Lookups<KoalaBear>| {
            p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
                KoalaBear,
                KoalaBearChallenge,
                _,
                LogUpGadget,
            >(
                air,
                AirLayout::from_air(air),
                lookups,
                config.is_zk(),
                &LogUpGadget,
            )
        };
        assert_eq!(
            chunks(&airs[index], &data.common.lookups[index]),
            chunks(&original[index], &original_data.common.lookups[index])
        );
    }
}

#[derive(Clone)]
struct ObservedChallenger {
    inner: KoalaBearChallenger,
    draws: RecordedDraws,
    forced_beta: Option<KoalaBearChallenge>,
    algebra_draws: usize,
}

impl<Value> CanObserve<Value> for ObservedChallenger
where
    KoalaBearChallenger: CanObserve<Value>,
{
    fn observe(&mut self, value: Value) {
        self.inner.observe(value);
    }
}

impl CanSample<KoalaBear> for ObservedChallenger {
    fn sample(&mut self) -> KoalaBear {
        self.inner.sample()
    }
}

impl CanSample<KoalaBearChallenge> for ObservedChallenger {
    fn sample(&mut self) -> KoalaBearChallenge {
        self.sample_algebra_element()
    }
}

impl CanSampleBits<usize> for ObservedChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl FieldChallenger<KoalaBear> for ObservedChallenger {
    fn sample_algebra_element<Value: BasedVectorSpace<KoalaBear>>(&mut self) -> Value {
        let mut value: Value = self.inner.sample_algebra_element();
        if Value::DIMENSION == 4 {
            if self.algebra_draws == 1 {
                if let Some(beta) = self.forced_beta {
                    value =
                        Value::from_basis_coefficients_slice(beta.as_basis_coefficients_slice())
                            .unwrap();
                }
            }
            self.draws.lock().unwrap().push(
                KoalaBearChallenge::from_basis_coefficients_slice(
                    value.as_basis_coefficients_slice(),
                )
                .unwrap(),
            );
        }
        self.algebra_draws += 1;
        value
    }
}

impl GrindingChallenger for ObservedChallenger {
    type Witness = KoalaBear;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        self.inner.grind(bits)
    }
}

fn observed_config(
    config: KoalaBearStarkConfig,
    forced_beta: Option<KoalaBearChallenge>,
) -> (ObservedConfig, RecordedDraws) {
    let draws = Arc::new(Mutex::new(Vec::new()));
    let config = ObservedConfig {
        inner: config,
        draws: draws.clone(),
        forced_beta,
    };
    (config, draws)
}

#[test]
fn transcript_replay_matches_actual_draw_and_verifier_does_not_filter_beta() {
    let generator =
        KoalaBearChallenge::from_basis_coefficients_fn(|index| KoalaBear::from_bool(index == 1));
    for forced_beta in [
        None,
        Some(KoalaBearChallenge::ONE),
        Some(generator.square()),
    ] {
        let (instance, witness) = fixture_builders();
        let relation = PreparedRelation::new(&KoalaBearPoseidon2_16::new(), &instance);
        let witness = relation.prepare_witness(&witness);
        let (airs, traces) = relation.generate_trace_rows(&witness);
        let (config, draws) = observed_config(
            KoalaBearConfig::<Conservative>::prover_config(),
            forced_beta,
        );
        let (verifier, _) = observed_config(
            KoalaBearConfig::<Conservative>::verifier_config(),
            forced_beta,
        );
        let degrees = relation.trace_degree_bits();
        let data = ProverData::from_airs_and_degrees(
            &verifier,
            &airs,
            &log_ext_degrees(&degrees, &config),
        );
        let publics = vec![vec![]; airs.len()];
        let refs = traces.iter().collect::<Vec<_>>();
        let instances = StarkInstance::new_multiple(&airs, &refs, &publics);
        let proof = p3_batch_stark::prove_batch(&config, &instances, &data);
        let actual_beta = draws.lock().unwrap()[1];
        let replay = terminal_mask::replay_lookup_challenges(
            &config,
            &airs,
            &degrees,
            &publics,
            &data.common,
            &proof,
        )
        .unwrap();
        assert!(replay.iter().all(|challenges| challenges
            .chunks_exact(2)
            .all(|pair| pair[1] == actual_beta)));
        assert_eq!(forced_beta, forced_beta.map(|_| actual_beta));
        assert_eq!(
            terminal_mask::has_full_degree(actual_beta),
            forced_beta.is_none()
        );
        assert!(
            p3_batch_stark::verify_batch(&verifier, &airs, &proof, &publics, &data.common).is_ok()
        );
        let verifier_backend = RetryingBackend {
            verification_beta: forced_beta,
            ..Default::default()
        };
        let verifier_relation = PreparedRelation::new(&verifier_backend, &instance);
        let bytes = postcard::to_allocvec(&proof).unwrap();
        assert!(verifier_relation.verify(&verifier_backend, &bytes).is_ok());
        let mut malformed_degrees = degrees;
        malformed_degrees.pop();
        assert!(terminal_mask::replay_lookup_challenges(
            &config,
            &airs,
            &malformed_degrees,
            &publics,
            &data.common,
            &proof
        )
        .is_none());
    }
}

#[derive(Clone, Default)]
struct RetryingBackend {
    attempts: Arc<Mutex<Vec<RecordedDraws>>>,
    verification_beta: Option<KoalaBearChallenge>,
}

impl HashRelationBackend<16> for RetryingBackend {
    type Config = ObservedConfig;
    type Air = <KoalaBearPoseidon2_16 as HashRelationBackend<16>>::Air;
    type Permutation = KoalaBearPoseidon2_16;

    fn prover_config(&self) -> Self::Config {
        let generator = KoalaBearChallenge::from_basis_coefficients_fn(|index| {
            KoalaBear::from_bool(index == 1)
        });
        let mut attempts = self.attempts.lock().unwrap();
        let forced_beta = match attempts.len() {
            0 => Some(KoalaBearChallenge::ONE),
            1 => Some(generator.square()),
            _ => None,
        };
        let (config, draws) = observed_config(
            KoalaBearConfig::<Conservative>::prover_config(),
            forced_beta,
        );
        attempts.push(draws);
        config
    }

    fn verifier_config(&self) -> Self::Config {
        observed_config(
            KoalaBearConfig::<Conservative>::verifier_config(),
            self.verification_beta,
        )
        .0
    }

    fn security_parameters(&self) -> SecurityParameters {
        KoalaBearPoseidon2_16::new().security_parameters()
    }

    fn air(&self) -> Self::Air {
        KoalaBearPoseidon2_16::new().air()
    }

    fn permutation(&self) -> Self::Permutation {
        KoalaBearPoseidon2_16::new()
    }
}

#[test]
fn wrapper_discards_completed_exceptional_proofs_and_restarts_with_fresh_coins() {
    let (instance, witness) = fixture_builders();
    let backend = RetryingBackend::default();
    let relation = PreparedRelation::new(&backend, &instance);
    let witness = relation.prepare_witness(&witness);
    let (bytes, samples) =
        terminal_mask::with_sample_observer(|| relation.prove(&backend, &witness));
    assert_eq!(samples.len(), 3);
    assert!(samples.windows(2).all(|pair| pair[0] != pair[1]));
    assert!(relation.verify(&backend, &bytes).is_ok());
    let attempts = backend.attempts.lock().unwrap();
    assert_eq!(attempts.len(), 3);
    let draws = attempts
        .iter()
        .map(|attempt| attempt.lock().unwrap().clone())
        .collect::<Vec<_>>();
    assert!(draws.iter().all(|attempt| attempt.len() > 4));
    assert!(!terminal_mask::has_full_degree(draws[0][1]));
    assert!(!terminal_mask::has_full_degree(draws[1][1]));
    assert!(terminal_mask::has_full_degree(draws[2][1]));
    assert_ne!(draws[0][0], draws[1][0]);
    assert_ne!(draws[1][0], draws[2][0]);
    let ordinary_backend = KoalaBearPoseidon2_16::new();
    let ordinary_relation = PreparedRelation::new(&ordinary_backend, &instance);
    assert!(ordinary_relation.verify(&ordinary_backend, &bytes).is_ok());
}

#[test]
fn public_terminal_is_recomputable_and_balanced_terminal_tampering_is_rejected() {
    let (relation, witness) = fixture();
    let (airs, traces) = relation.generate_trace_rows(&witness);
    let (mut proof, data) = proof_from_traces(&airs, &traces);
    let config = KoalaBearConfig::<Conservative>::verifier_config();
    let publics = vec![vec![]; airs.len()];
    let challenges = terminal_mask::replay_lookup_challenges(
        &config,
        &airs,
        &relation.trace_degree_bits(),
        &publics,
        &data.common,
        &proof,
    )
    .unwrap();
    assert_eq!(data.common.lookups[1].len(), 1);
    let prefix = challenges[1][0];
    let beta = challenges[1][1];
    let table = airs[1].preprocessed_trace().unwrap();
    let expected =
        table
            .values
            .chunks_exact(table.width)
            .fold(KoalaBearChallenge::ZERO, |sum, row| {
                if row[2] == <KoalaBear as PrimeCharacteristicRing>::ZERO {
                    sum
                } else {
                    sum - KoalaBearChallenge::from(row[2]) / (prefix - beta * row[0] - row[1])
                }
            });
    assert_eq!(proof.lookup_terminals[1].unwrap().0, expected);
    assert_eq!(
        proof.lookup_terminals[0].unwrap().0 + proof.lookup_terminals[2].unwrap().0 + expected,
        KoalaBearChallenge::ZERO
    );
    proof.lookup_terminals[0].as_mut().unwrap().0 += KoalaBearChallenge::ONE;
    proof.lookup_terminals[2].as_mut().unwrap().0 -= KoalaBearChallenge::ONE;
    assert!(p3_batch_stark::verify_batch(&config, &airs, &proof, &publics, &data.common).is_err());
}

#[test]
fn active_zero_denominator_panics_but_zero_count_rows_do_not() {
    let (relation, witness) = fixture();
    let (airs, mut traces) = relation.generate_trace_rows(&witness);
    let config = KoalaBearConfig::<Conservative>::verifier_config();
    let data = ProverData::from_airs_and_degrees(
        &config,
        &airs,
        &log_ext_degrees(&relation.trace_degree_bits(), &config),
    );
    let mut lookup = data.common.lookups[0]
        .iter()
        .find(|lookup| lookup.kind == Kind::Global(terminal_mask::BUS.into()))
        .unwrap()
        .clone();
    lookup.column = 0;
    let width = traces[0].width;
    for row in 0..2 {
        let offset = row * width + width - 4;
        traces[0].values[offset..offset + 4].copy_from_slice(&[
            KoalaBear::from_usize(row + 1),
            <KoalaBear as PrimeCharacteristicRing>::ZERO,
            <KoalaBear as PrimeCharacteristicRing>::ZERO,
            <KoalaBear as PrimeCharacteristicRing>::ONE,
        ]);
    }
    let beta =
        KoalaBearChallenge::from_basis_coefficients_fn(|index| KoalaBear::from_bool(index == 1));
    let preprocessed = airs[0].preprocessed_trace();
    let (_, terminal) = LogUpGadget.generate_permutation::<KoalaBearStarkConfig>(
        &traces[0],
        &preprocessed,
        &[],
        &[lookup.clone()],
        &[KoalaBearChallenge::ZERO, beta],
    );
    assert!(terminal.is_some());
    let first_payload = beta.exp_u64(3) + KoalaBearChallenge::ONE;
    let result = std::panic::catch_unwind(|| {
        LogUpGadget.generate_permutation::<KoalaBearStarkConfig>(
            &traces[0],
            &preprocessed,
            &[],
            &[lookup],
            &[first_payload, beta],
        )
    });
    assert!(result.is_err());
}

#[test]
fn production_shapes_preserve_independent_heights_and_terminal_presence() {
    let backend = KoalaBearPoseidon2_16::new();
    for (operation, repetitions) in [("extend", 1), ("rekey", 1), ("delete", 1), ("rekey", 64)] {
        let (relation, witness) = super::production_fixtures::fixture(operation, repetitions);
        assert_eq!(relation.terminal_masking, operation != "extend");
        let heights = relation.trace_degree_bits();
        assert!(heights.iter().all(|&degree| degree >= 8));
        if repetitions > 1 {
            assert!(heights.windows(2).any(|pair| pair[0] != pair[1]));
        }
        let proof_bytes = relation.prove(&backend, &witness);
        let proof: BatchProof<KoalaBearStarkConfig> = postcard::from_bytes(&proof_bytes).unwrap();
        assert!(proof.lookup_terminals[0].is_some());
        assert!(proof.lookup_terminals[1].is_some());
        assert_eq!(proof.lookup_terminals[2].is_some(), operation != "extend");
        assert!(relation.verify(&backend, &proof_bytes).is_ok());
    }
}

#[test]
#[ignore = "manual release benchmark; run single-threaded with --ignored --nocapture"]
fn bench_terminal_masking() {
    use std::hint::black_box;
    use std::time::Instant;

    const WARMUPS: usize = 2;
    const SAMPLES: usize = 13;
    let backend = KoalaBearPoseidon2_16::new();
    std::println!("operation,repetitions,masked,heights,main_widths,preprocessed_widths,fraction_widths,quotient_chunks,record_slots,weighted_height,prove_median_ms,verify_median_ms,median_bytes");
    for (operation, repetitions) in [("extend", 1), ("rekey", 1), ("delete", 1), ("rekey", 64)] {
        let (mut relation, witness) = super::production_fixtures::fixture(operation, repetitions);
        let enabled = relation.terminal_masking;
        let mut timings = [Vec::new(), Vec::new()];
        for iteration in 0..WARMUPS + SAMPLES {
            for slot in 0..=usize::from(enabled) {
                let policy = if enabled { (iteration + slot) % 2 } else { 0 };
                relation.terminal_masking = enabled && policy == 1;
                let start = Instant::now();
                let proof = black_box(relation.prove(&backend, &witness));
                let proving = start.elapsed().as_secs_f64() * 1_000.0;
                let start = Instant::now();
                assert!(relation.verify(&backend, black_box(&proof)).is_ok());
                let verifying = start.elapsed().as_secs_f64() * 1_000.0;
                if iteration >= WARMUPS {
                    timings[policy].push((proving, verifying, proof.len()));
                }
            }
        }
        for (policy, samples) in timings
            .iter()
            .enumerate()
            .filter(|(_, samples)| !samples.is_empty())
        {
            relation.terminal_masking = enabled && policy == 1;
            let airs = relation.build_airs();
            let config = backend.verifier_config();
            let degrees = relation.trace_degree_bits();
            let data = ProverData::from_airs_and_degrees(
                &config,
                &airs,
                &log_ext_degrees(&degrees, &config),
            );
            let mut prove = samples.iter().map(|sample| sample.0).collect::<Vec<_>>();
            let mut verify = samples.iter().map(|sample| sample.1).collect::<Vec<_>>();
            let mut bytes = samples.iter().map(|sample| sample.2).collect::<Vec<_>>();
            prove.sort_by(f64::total_cmp);
            verify.sort_by(f64::total_cmp);
            bytes.sort_unstable();
            let chunks = airs
                .iter()
                .zip(&data.common.lookups)
                .map(|(air, lookups)| {
                    1usize
                        << (p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
                            KoalaBear,
                            KoalaBearChallenge,
                            _,
                            LogUpGadget,
                        >(
                            air,
                            AirLayout::from_air(air),
                            lookups,
                            config.is_zk(),
                            &LogUpGadget,
                        ) + config.is_zk())
                })
                .collect::<Vec<_>>();
            let records = data
                .common
                .lookups
                .iter()
                .zip(&degrees)
                .map(|(lookups, degree)| {
                    lookups
                        .iter()
                        .map(|lookup| lookup.elements.len())
                        .sum::<usize>()
                        * (1usize << degree)
                })
                .collect::<Vec<_>>();
            std::println!(
                "{operation},{repetitions},{},{:?},{:?},{:?},{:?},{:?},{:?},{},{:.3},{:.3},{}",
                relation.terminal_masking,
                degrees
                    .iter()
                    .map(|degree| 1usize << degree)
                    .collect::<Vec<_>>(),
                airs.iter().map(BaseAir::width).collect::<Vec<_>>(),
                airs.iter()
                    .map(BaseAir::preprocessed_width)
                    .collect::<Vec<_>>(),
                data.common
                    .lookups
                    .iter()
                    .map(|lookups| lookups.len())
                    .collect::<Vec<_>>(),
                chunks,
                records,
                relation.logup_weighted_height_sum(),
                prove[SAMPLES / 2],
                verify[SAMPLES / 2],
                bytes[SAMPLES / 2]
            );
        }
    }
}
