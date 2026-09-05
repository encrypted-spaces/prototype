use std::{
    fs::File,
    hint::black_box,
    io::{self, BufWriter, Write},
    ops::RangeInclusive,
    time::Instant,
};

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use spongefish::Permutation;
use spongefish_circuit::permutation::{
    LinearEquation, PermutationInstanceBuilder, PermutationWitnessBuilder,
};
use spongefish_stark::{
    ff::{KoalaBearConfig, KoalaBearStarkConfig},
    permutation::poseidon2::{
        KoalaBearPoseidon2_16, KoalaBearPoseidon2_16HashAir, POSEIDON2_16_WIDTH,
    },
    relation::PreparedRelation,
    security_profile::{Aggressive, Conservative, SecurityParameters, SecurityProfile},
    HashRelationBackend,
};

const TARGET_BITS: f64 = 128.0;
const MIN_SOUNDNESS_BITS: f64 = 126.0;
const MAX_SOUNDNESS_BITS: f64 = 130.0;
const ITERATIONS: usize = 5;
const SWEEP_BOUNDS: [Bound; 2] = [Bound::Capacity, Bound::Johnson];
const DEFAULT_ETA_DENOMINATOR: usize = 20;

// ---------------------
// Parameters to sweep
// ---------------------

const LOG_BLOWUP_RANGE: RangeInclusive<usize> = 3..=6;
const LOG_FINAL_POLY_LEN_RANGE: RangeInclusive<usize> = 0..=5;
const MAX_LOG_ARITIES: RangeInclusive<usize> = 1..=6;
// Johnson: eta = sqrt(rho) / denominator. Capacity: eta = rho / denominator.
const ETA_DENOMINATOR_RANGE: RangeInclusive<usize> = 10..=100;
const QUERY_POW_BITS: RangeInclusive<usize> = 10..=20;
const COMMIT_POW_BITS: RangeInclusive<usize> = 0..=10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bound {
    Johnson,
    Capacity,
}

impl Bound {
    const fn name(self) -> &'static str {
        match self {
            Self::Johnson => "johnson",
            Self::Capacity => "capacity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum Case {
    Simple,
    Batch30,
    Chain1000,
}

impl Case {
    const fn name(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Batch30 => "batch30",
            Self::Chain1000 => "chain1000",
        }
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    label: String,
    bound: Bound,
    eta_denominator: usize,
    params: SecurityParameters,
    // FRI query/query-PoW contribution only. Commit PoW is configured and
    // measured, but not credited as direct soundness bits.
    soundness_bits: f64,
    is_named_default: bool,
}

#[derive(Clone, Debug)]
struct Measurement {
    case: Case,
    candidate: Candidate,
    mean_ms: f64,
    stddev_ms: f64,
    proof_size_bytes: usize,
    // Same convention as `Candidate::soundness_bits`.
    soundness_bits: f64,
    pareto: bool,
}

#[derive(Clone)]
struct SweepKoalaBearPoseidon2_16 {
    permutation: KoalaBearPoseidon2_16,
    params: SecurityParameters,
}

impl SweepKoalaBearPoseidon2_16 {
    fn new(params: SecurityParameters) -> Self {
        Self {
            permutation: KoalaBearPoseidon2_16::new(),
            params,
        }
    }
}

impl HashRelationBackend<POSEIDON2_16_WIDTH> for SweepKoalaBearPoseidon2_16 {
    type Config = KoalaBearStarkConfig;
    type Air = KoalaBearPoseidon2_16HashAir;
    type Permutation = KoalaBearPoseidon2_16;

    fn prover_config(&self) -> Self::Config {
        KoalaBearConfig::<Conservative>::prover_config_with_security_parameters(self.params)
    }

    fn verifier_config(&self) -> Self::Config {
        KoalaBearConfig::<Conservative>::verifier_config_with_security_parameters(self.params)
    }

    fn security_parameters(&self) -> SecurityParameters {
        self.params
    }

    fn air(&self) -> Self::Air {
        KoalaBearPoseidon2_16HashAir::default()
    }

    fn permutation(&self) -> Self::Permutation {
        self.permutation.clone()
    }
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let csv_path = "target/soundness.csv";
    let csv_file = File::create(csv_path).expect("failed to create target/soundness.csv");
    let mut csv = BufWriter::new(csv_file);
    let cases = [Case::Simple, Case::Batch30]; // Case::Chain1000
    let candidates = sweep_candidates();
    let frontier_seed = candidates
        .iter()
        .filter(|candidate| candidate_in_soundness_window(candidate))
        .count();
    writeln!(
        out,
        "# sweep candidates total={} in_band={} soundness_window=[{MIN_SOUNDNESS_BITS:.0},{MAX_SOUNDNESS_BITS:.0}]",
        candidates.len(),
        frontier_seed
    )
    .expect("failed to write progress");
    writeln!(out, "# writing_csv path={csv_path}").expect("failed to write progress");
    write_csv_header(&mut csv).expect("failed to write CSV header");

    for case in &cases {
        let mut frontier = ParetoFrontier::default();
        let mut measured_for_case = Vec::<Candidate>::new();
        for candidate in candidates.iter().cloned() {
            if !candidate.is_named_default && !candidate_in_soundness_window(&candidate) {
                writeln!(
                    out,
                    "# skipped case={} label={} reason=out_of_band soundness_bits={:.3}",
                    case.name(),
                    candidate.label,
                    candidate.soundness_bits
                )
                .expect("failed to write progress");
                continue;
            }

            if should_skip_candidate(&candidate, &measured_for_case) {
                writeln!(
                    out,
                    "# skipped case={} label={} reason=same_structure_higher_queries soundness_bits={:.3}",
                    case.name(),
                    candidate.label,
                    candidate.soundness_bits
                )
                .expect("failed to write progress");
                continue;
            }

            writeln!(
                out,
                "# running case={} label={} bound={} soundness_bits={:.3} params={:?}",
                case.name(),
                candidate.label,
                candidate.bound.name(),
                candidate.soundness_bits,
                candidate.params
            )
            .expect("failed to write progress");
            match measure(*case, candidate.clone(), ITERATIONS) {
                Ok(mut measurement) => {
                    let evicted = if candidate_in_soundness_window(&measurement.candidate) {
                        frontier.insert(measurement.clone())
                    } else {
                        measurement.pareto = false;
                        FrontierInsertResult::Rejected
                    };
                    measurement.pareto = matches!(evicted, FrontierInsertResult::Accepted { .. });
                    if measurement.pareto {
                        writeln!(
                            out,
                            "# frontier case={} accepted label={} mean_ms={:.3} proof_size_bytes={} soundness_bits={:.3}",
                            case.name(),
                            measurement.candidate.label,
                            measurement.mean_ms,
                            measurement.proof_size_bytes,
                            measurement.soundness_bits
                        )
                        .expect("failed to write progress");
                    }
                    if let FrontierInsertResult::Accepted { evicted } = &evicted {
                        for evicted_label in evicted {
                            writeln!(
                                out,
                                "# frontier case={} evicted label={} by={}",
                                case.name(),
                                evicted_label,
                                measurement.candidate.label
                            )
                            .expect("failed to write progress");
                        }
                    }
                    measured_for_case.push(measurement.candidate.clone());
                    write_csv_row(&mut csv, &measurement).expect("failed to write CSV row");
                }
                Err(err) => {
                    writeln!(
                        out,
                        "# skipped case={} label={} reason=measurement_failed error={}",
                        case.name(),
                        candidate.label,
                        err
                    )
                    .expect("failed to write progress");
                }
            }
        }
    }
}

fn sweep_candidates() -> Vec<Candidate> {
    let mut candidates = vec![
        Candidate {
            label: "aggressive_default".to_string(),
            bound: Bound::Capacity,
            eta_denominator: DEFAULT_ETA_DENOMINATOR,
            params: Aggressive::security_parameters(),
            soundness_bits: soundness_bits(
                Bound::Capacity,
                DEFAULT_ETA_DENOMINATOR,
                Aggressive::security_parameters(),
            ),
            is_named_default: true,
        },
        Candidate {
            label: "conservative_default".to_string(),
            bound: Bound::Johnson,
            eta_denominator: DEFAULT_ETA_DENOMINATOR,
            params: Conservative::security_parameters(),
            soundness_bits: soundness_bits(
                Bound::Johnson,
                DEFAULT_ETA_DENOMINATOR,
                Conservative::security_parameters(),
            ),
            is_named_default: true,
        },
    ];

    for bound in SWEEP_BOUNDS {
        for log_blowup in LOG_BLOWUP_RANGE {
            for log_final_poly_len in LOG_FINAL_POLY_LEN_RANGE {
                for max_log_arity in MAX_LOG_ARITIES {
                    for eta_denominator in ETA_DENOMINATOR_RANGE {
                        for query_pow_bits in QUERY_POW_BITS {
                            for commit_pow_bits in COMMIT_POW_BITS {
                                candidates.extend(make_candidates_for_window(
                                    bound,
                                    log_blowup,
                                    log_final_poly_len,
                                    max_log_arity,
                                    eta_denominator,
                                    commit_pow_bits,
                                    query_pow_bits,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    let mut deduped = dedup_candidates(candidates);
    deduped.sort_by_key(candidate_priority_key);
    deduped
}

fn dedup_candidates(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut deduped = Vec::new();
    for candidate in candidates {
        if deduped.iter().any(|existing: &Candidate| {
            existing.bound == candidate.bound
                && existing.eta_denominator == candidate.eta_denominator
                && existing.params == candidate.params
        }) {
            continue;
        }
        deduped.push(candidate);
    }
    deduped
}

fn query_range_for_soundness_window(
    bound: Bound,
    log_blowup: usize,
    eta_denominator: usize,
    query_pow_bits: usize,
) -> Option<RangeInclusive<usize>> {
    let per_query = per_query_bits(bound, log_blowup, eta_denominator);
    let min_queries =
        ((MIN_SOUNDNESS_BITS - query_pow_bits as f64).max(0.0) / per_query).ceil() as usize;
    let max_queries = ((MAX_SOUNDNESS_BITS - query_pow_bits as f64) / per_query).floor() as isize;
    (max_queries >= min_queries as isize).then_some(min_queries..=max_queries as usize)
}

fn make_candidates_for_window(
    bound: Bound,
    log_blowup: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
    eta_denominator: usize,
    commit_pow_bits: usize,
    query_pow_bits: usize,
) -> Vec<Candidate> {
    query_range_for_soundness_window(bound, log_blowup, eta_denominator, query_pow_bits)
        .into_iter()
        .flatten()
        .map(|num_queries| {
            let params = SecurityParameters {
                log_blowup,
                log_final_poly_len,
                max_log_arity,
                num_queries,
                commit_proof_of_work_bits: commit_pow_bits,
                query_proof_of_work_bits: query_pow_bits,
            };
            Candidate {
                label: format!(
                    "{}_lb{}_lf{}_a{}_eta{}_cpow{}_qpow{}_q{}",
                    bound.name(),
                    log_blowup,
                    log_final_poly_len,
                    max_log_arity,
                    eta_denominator,
                    commit_pow_bits,
                    query_pow_bits,
                    num_queries
                ),
                bound,
                eta_denominator,
                params,
                soundness_bits: soundness_bits(bound, eta_denominator, params),
                is_named_default: false,
            }
        })
        .collect()
}

fn soundness_bits(bound: Bound, eta_denominator: usize, params: SecurityParameters) -> f64 {
    per_query_bits(bound, params.log_blowup, eta_denominator) * params.num_queries as f64
        + params.query_proof_of_work_bits as f64
}

fn per_query_bits(bound: Bound, log_blowup: usize, eta_denominator: usize) -> f64 {
    -one_minus_delta(bound, log_blowup, eta_denominator).log2()
}

fn one_minus_delta(bound: Bound, log_blowup: usize, eta_denominator: usize) -> f64 {
    base_proximity_term(bound, log_blowup) + eta(bound, log_blowup, eta_denominator)
}

fn eta(bound: Bound, log_blowup: usize, eta_denominator: usize) -> f64 {
    assert!(eta_denominator > 0, "eta denominator must be non-zero");
    base_proximity_term(bound, log_blowup) / eta_denominator as f64
}

fn base_proximity_term(bound: Bound, log_blowup: usize) -> f64 {
    let rho = 2.0f64.powi(-(log_blowup as i32));
    match bound {
        Bound::Johnson => rho.sqrt(),
        Bound::Capacity => rho,
    }
}

fn measure(case: Case, candidate: Candidate, iterations: usize) -> Result<Measurement, String> {
    let backend = SweepKoalaBearPoseidon2_16::new(candidate.params);
    let (instance, witness) = build_case(case, &backend);

    let relation = PreparedRelation::new(&backend, &instance);
    let witness = relation.prepare_witness(&witness);

    let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        relation.prove(&backend, &witness)
    }))
    .map_err(|_| "prover rejected this parameter set".to_string())?;
    relation
        .verify(&backend, &proof)
        .map_err(|_| "verification failed before timing".to_string())?;
    let proof_size_bytes = proof.len();

    let mut elapsed_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let proof = black_box(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                relation.prove(&backend, &witness)
            }))
            .map_err(|_| "prover rejected this parameter set during timing".to_string())?,
        );
        elapsed_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        black_box(proof.len());
    }

    let mean_ms = mean(&elapsed_ms);
    let stddev_ms = stddev(&elapsed_ms, mean_ms);

    Ok(Measurement {
        case,
        soundness_bits: candidate.soundness_bits,
        candidate,
        mean_ms,
        stddev_ms,
        proof_size_bytes,
        pareto: false,
    })
}

fn build_case(
    case: Case,
    backend: &SweepKoalaBearPoseidon2_16,
) -> (
    PermutationInstanceBuilder<KoalaBear, POSEIDON2_16_WIDTH>,
    PermutationWitnessBuilder<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>,
) {
    match case {
        Case::Simple => build_simple(backend),
        Case::Batch30 => build_batch30(backend),
        Case::Chain1000 => build_chain(backend, 1000),
    }
}

fn build_simple(
    backend: &SweepKoalaBearPoseidon2_16,
) -> (
    PermutationInstanceBuilder<KoalaBear, POSEIDON2_16_WIDTH>,
    PermutationWitnessBuilder<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>,
) {
    let permutation = backend.permutation();
    let input = input_from_seed(1);
    let output = permutation.permute(&input);
    let instance = PermutationInstanceBuilder::<KoalaBear, POSEIDON2_16_WIDTH>::new();
    let witness = PermutationWitnessBuilder::new(permutation);
    let input_vars = instance.allocator().allocate_vars::<POSEIDON2_16_WIDTH>();
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);

    instance
        .allocator()
        .set_public_vars([output_vars[0]], [output[0]]);
    instance.add_equation(LinearEquation::new(
        [
            (KoalaBear::ONE, output_vars[0]),
            (KoalaBear::ONE, input_vars[0]),
        ],
        output_vals[0] + input[0],
    ));
    witness.add_equation(LinearEquation::new(
        [(KoalaBear::ONE, output_vals[0]), (KoalaBear::ONE, input[0])],
        output_vals[0] + input[0],
    ));

    (instance, witness)
}

fn build_batch30(
    backend: &SweepKoalaBearPoseidon2_16,
) -> (
    PermutationInstanceBuilder<KoalaBear, POSEIDON2_16_WIDTH>,
    PermutationWitnessBuilder<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>,
) {
    let permutation = backend.permutation();
    let instance = PermutationInstanceBuilder::<KoalaBear, POSEIDON2_16_WIDTH>::new();
    let witness = PermutationWitnessBuilder::new(permutation);

    for hash_idx in 0..30 {
        let input = input_from_seed(hash_idx + 17);
        let input_vars = instance.allocator().allocate_vars::<POSEIDON2_16_WIDTH>();
        let output_vars = instance.allocate_permutation(&input_vars);
        let output_vals = witness.allocate_permutation(&input);

        instance.allocator().set_public_vars(
            output_vars[..8].iter().copied(),
            output_vals[..8].iter().copied(),
        );

        for limb in 0..8 {
            let image = output_vals[limb] + input[limb];
            instance.add_equation(LinearEquation::new(
                [
                    (KoalaBear::ONE, output_vars[limb]),
                    (KoalaBear::ONE, input_vars[limb]),
                ],
                image,
            ));
            witness.add_equation(LinearEquation::new(
                [
                    (KoalaBear::ONE, output_vals[limb]),
                    (KoalaBear::ONE, input[limb]),
                ],
                image,
            ));
        }
    }

    (instance, witness)
}

fn build_chain(
    backend: &SweepKoalaBearPoseidon2_16,
    len: usize,
) -> (
    PermutationInstanceBuilder<KoalaBear, POSEIDON2_16_WIDTH>,
    PermutationWitnessBuilder<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>,
) {
    let permutation = backend.permutation();
    let instance = PermutationInstanceBuilder::<KoalaBear, POSEIDON2_16_WIDTH>::new();
    let witness = PermutationWitnessBuilder::new(permutation);
    let mut input_vars = instance.allocator().allocate_vars::<POSEIDON2_16_WIDTH>();
    let mut input = input_from_seed(1009);

    for step in 0..len {
        for (limb, value) in input.iter_mut().enumerate().skip(8) {
            *value = KoalaBear::from_usize(step * 8 + limb);
        }
        let output_vars = instance.allocate_permutation(&input_vars);
        let output_vals = witness.allocate_permutation(&input);

        if step + 1 != len {
            let counter_vars = instance.allocator().allocate_vars::<8>();
            input_vars = core::array::from_fn(|i| {
                if i < 8 {
                    output_vars[i]
                } else {
                    counter_vars[i - 8]
                }
            });
            input = core::array::from_fn(|i| {
                if i < 8 {
                    output_vals[i]
                } else {
                    KoalaBear::from_usize((step + 1) * 8 + i)
                }
            });
        }
    }

    (instance, witness)
}

fn input_from_seed(seed: usize) -> [KoalaBear; POSEIDON2_16_WIDTH] {
    core::array::from_fn(|i| KoalaBear::from_usize(seed * 131 + i * 17 + 1))
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64], mean: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }

    (values
        .iter()
        .map(|value| {
            let diff = value - mean;
            diff * diff
        })
        .sum::<f64>()
        / (values.len() - 1) as f64)
        .sqrt()
}

#[derive(Default)]
struct ParetoFrontier {
    points: Vec<Measurement>,
}

enum FrontierInsertResult {
    Accepted { evicted: Vec<String> },
    Rejected,
}

impl ParetoFrontier {
    fn insert(&mut self, measurement: Measurement) -> FrontierInsertResult {
        if self
            .points
            .iter()
            .any(|other| dominates(other, &measurement))
        {
            return FrontierInsertResult::Rejected;
        }
        let mut evicted = Vec::new();
        self.points.retain(|other| {
            let keep = !dominates(&measurement, other);
            if !keep {
                evicted.push(other.candidate.label.clone());
            }
            keep
        });
        self.points.push(measurement);
        FrontierInsertResult::Accepted { evicted }
    }
}

fn candidate_in_soundness_window(candidate: &Candidate) -> bool {
    (MIN_SOUNDNESS_BITS..=MAX_SOUNDNESS_BITS).contains(&candidate.soundness_bits)
}

fn candidate_priority_key(
    candidate: &Candidate,
) -> (bool, u64, usize, usize, usize, usize, usize, usize, usize) {
    (
        !candidate_in_soundness_window(candidate),
        ((candidate.soundness_bits - TARGET_BITS).abs() * 1_000.0) as u64,
        candidate.params.num_queries,
        candidate.params.query_proof_of_work_bits,
        candidate.eta_denominator,
        candidate.params.commit_proof_of_work_bits,
        candidate.params.log_blowup,
        candidate.params.max_log_arity,
        candidate.params.log_final_poly_len,
    )
}

fn same_structure_except_queries(a: &Candidate, b: &Candidate) -> bool {
    a.bound == b.bound
        && a.eta_denominator == b.eta_denominator
        && a.params.log_blowup == b.params.log_blowup
        && a.params.log_final_poly_len == b.params.log_final_poly_len
        && a.params.max_log_arity == b.params.max_log_arity
        && a.params.commit_proof_of_work_bits == b.params.commit_proof_of_work_bits
        && a.params.query_proof_of_work_bits == b.params.query_proof_of_work_bits
}

fn should_skip_candidate(candidate: &Candidate, measured: &[Candidate]) -> bool {
    measured.iter().any(|other| {
        same_structure_except_queries(other, candidate)
            && other.params.num_queries <= candidate.params.num_queries
            && candidate_in_soundness_window(other)
            && candidate_in_soundness_window(candidate)
    })
}

fn dominates(a: &Measurement, b: &Measurement) -> bool {
    a.case == b.case
        && candidate_in_soundness_window(&a.candidate)
        && candidate_in_soundness_window(&b.candidate)
        && a.mean_ms <= b.mean_ms
        && a.proof_size_bytes <= b.proof_size_bytes
        && (a.mean_ms < b.mean_ms || a.proof_size_bytes < b.proof_size_bytes)
}

fn write_csv_header(writer: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        writer,
        "case,label,bound,log_blowup,log_final_poly_len,max_log_arity,eta_denominator,eta,num_queries,commit_pow_bits,query_pow_bits,soundness_bits,mean_ms,stddev_ms,proof_size_bytes,proof_size_kib,pareto"
    )
}

fn write_csv_row(writer: &mut impl Write, measurement: &Measurement) -> std::io::Result<()> {
    let params = measurement.candidate.params;
    writeln!(
        writer,
        "{},{},{},{},{},{},{},{:.8},{},{},{},{:.3},{:.3},{:.3},{},{:.3},{}",
        measurement.case.name(),
        measurement.candidate.label,
        measurement.candidate.bound.name(),
        params.log_blowup,
        params.log_final_poly_len,
        params.max_log_arity,
        measurement.candidate.eta_denominator,
        eta(
            measurement.candidate.bound,
            params.log_blowup,
            measurement.candidate.eta_denominator
        ),
        params.num_queries,
        params.commit_proof_of_work_bits,
        params.query_proof_of_work_bits,
        measurement.soundness_bits,
        measurement.mean_ms,
        measurement.stddev_ms,
        measurement.proof_size_bytes,
        measurement.proof_size_bytes as f64 / 1024.0,
        measurement.pareto
    )?;
    writer.flush()
}
