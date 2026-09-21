//! ML-KEM preparation benchmarks. `encaps` isolates parallel encapsulation; `mve`
//! measures end-to-end proving and verification at the production parameters.
//!
//! # Running
//!
//! ```text
//! RAYON_NUM_THREADS=4 cargo bench -p encrypted-spaces-zkp --bench mkem_precompute -- encaps
//! ```
//!
//! ```text
//! RAYON_NUM_THREADS=4 taskset -c 4-7 cargo bench -p encrypted-spaces-zkp \
//!     --features bench-baseline --bench mkem_precompute -- --noplot mve
//! ```
//!
//! `bench-baseline` adds the unprepared end-to-end variant. Cases run sequentially, so
//! same-process comparison does not eliminate thermal or background-load drift.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use encrypted_spaces_crypto::{
    key_derivation::DerivationKoalaBearPoseidon2_16, pke::DefaultMkem, KeyDerivation, KeyMaterial,
    Mkem,
};
use encrypted_spaces_zkp::mve::{PoseidonMve, MVE_DEFAULT_K, MVE_DEFAULT_U};
use p3_maybe_rayon::prelude::*;
use rand::{Rng, SeedableRng};
use std::time::Duration;

const K: usize = MVE_DEFAULT_K;
const U: usize = MVE_DEFAULT_U;
const IMPLEMENTATION: &str = "MKEM-XWR-PRE";

const RECIPIENT_COUNTS: [usize; 3] = [10, 50, 256];

fn config() -> String {
    format!(
        "suite={} ml-kem={} threads={} k={K} u={U}",
        IMPLEMENTATION,
        encrypted_spaces_crypto::pke::mlkem_backend(),
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
    )
}

/// Measures the `k` parallel encapsulations performed by `PoseidonMve::prove`.
fn bench_encaps(c: &mut Criterion) {
    let mkem = DefaultMkem::default();
    let mut rng = rand::rng();

    let mut group = c.benchmark_group("encaps");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(15));

    for n in RECIPIENT_COUNTS {
        let pks: Vec<_> = (0..n).map(|_| mkem.keygen(&mut rng).0).collect();
        let seeds: Vec<[u8; 32]> = (0..K).map(|_| rand::rng().random()).collect();
        let prepared = mkem.prepare(&pks);

        // Each repetition encapsulates to all n recipients.
        group.throughput(Throughput::Elements((K * n) as u64));

        group.bench_with_input(BenchmarkId::new("baseline", n), &n, |b, _| {
            b.iter(|| {
                seeds
                    .par_iter()
                    .map(|s| {
                        let mut r = rand_chacha::ChaCha12Rng::from_seed(*s);
                        mkem.encaps(&mut r, &pks)
                    })
                    .collect::<Vec<_>>()
            })
        });

        // What `prove` actually pays: one `prepare` plus k prepared encapsulations.
        group.bench_with_input(BenchmarkId::new("prepared_amortized", n), &n, |b, _| {
            b.iter(|| {
                let prepared = mkem.prepare(&pks);
                seeds
                    .par_iter()
                    .map(|s| {
                        let mut r = rand_chacha::ChaCha12Rng::from_seed(*s);
                        mkem.encaps_prepared(&mut r, &prepared)
                    })
                    .collect::<Vec<_>>()
            })
        });

        // Excludes `prepare`, to separate the steady-state gain from the setup cost.
        group.bench_with_input(BenchmarkId::new("prepared_only", n), &n, |b, _| {
            b.iter(|| {
                seeds
                    .par_iter()
                    .map(|s| {
                        let mut r = rand_chacha::ChaCha12Rng::from_seed(*s);
                        mkem.encaps_prepared(&mut r, &prepared)
                    })
                    .collect::<Vec<_>>()
            })
        });
    }

    group.finish();
}

/// The one-off precomputation, on its own.
fn bench_prepare(c: &mut Criterion) {
    let mkem = DefaultMkem::default();
    let mut rng = rand::rng();

    let mut group = c.benchmark_group("prepare");
    group.sample_size(30);

    for n in RECIPIENT_COUNTS {
        let pks: Vec<_> = (0..n).map(|_| mkem.keygen(&mut rng).0).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| mkem.prepare(&pks))
        });
    }

    group.finish();
}

/// Select the end-to-end benchmark path; production builds only the prepared path.
#[inline]
fn set_variant(prepared: bool) {
    #[cfg(feature = "bench-baseline")]
    encrypted_spaces_zkp::mve::set_prepared_encaps(prepared);
    #[cfg(not(feature = "bench-baseline"))]
    let _ = prepared;
}

fn bench_mve(c: &mut Criterion) {
    let mkem = DefaultMkem::default();
    let mut rng = rand::rng();
    let derivation = DerivationKoalaBearPoseidon2_16::default();

    println!("\nmVE end-to-end: {}\n", config());

    let mut group = c.benchmark_group(format!(
        "mve_k{K}_u{U}_{}_threads{}",
        IMPLEMENTATION,
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
    ));
    group.sample_size(10);

    for n in RECIPIENT_COUNTS {
        let pks: Vec<_> = (0..n).map(|_| mkem.keygen(&mut rng).0).collect();
        let key = KeyMaterial::random();
        let kc = derivation.commit(&key);
        set_variant(true);
        let proof = PoseidonMve::<DefaultMkem, K, U>::prove(&pks, &kc, &key, "bench");
        println!(
            "mVE sizes: suite={IMPLEMENTATION} n={n} proof={} ciphertexts={} stark={}",
            postcard::to_allocvec(&proof).unwrap().len(),
            postcard::to_allocvec(&proof.ciphertexts).unwrap().len(),
            proof.proof.len(),
        );

        #[cfg(not(feature = "bench-baseline"))]
        let variants: &[(&str, bool)] = &[("prepared", true)];
        #[cfg(feature = "bench-baseline")]
        let variants: &[(&str, bool)] = &[("baseline", false), ("prepared", true)];

        for &(label, prepared) in variants {
            group.bench_with_input(BenchmarkId::new(format!("prove_{label}"), n), &n, |b, _| {
                b.iter(|| {
                    set_variant(prepared);
                    PoseidonMve::<DefaultMkem, K, U>::prove(&pks, &kc, &key, "bench")
                })
            });
            group.bench_with_input(
                BenchmarkId::new(format!("verify_{label}"), n),
                &n,
                |b, _| {
                    b.iter(|| {
                        set_variant(prepared);
                        PoseidonMve::<DefaultMkem, K, U>::verify(&proof, &pks, &kc, "bench")
                            .expect("verification should succeed")
                    })
                },
            );
        }
    }

    set_variant(true);
    group.finish();
}

criterion_group! {
    name = mkem_precompute;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(20));
    targets = bench_encaps, bench_prepare, bench_mve
}
criterion_main!(mkem_precompute);
