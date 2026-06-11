//! Benchmarks for PKE encapsulation operations across all KEM schemes.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use encrypted_spaces_crypto::pke::{
    Kem, Mkem, MlKem768, Ristretto255Dh, XWing, XWingMkem, XWingRistretto, XWingRistrettoMkem,
};

/// Generic benchmark for KEM encapsulation (single recipient)
fn bench_kem_encaps<K: Kem>(c: &mut Criterion) {
    let kem = K::default();
    let mut rng = rand::rng();

    // Generate a keypair for encapsulation
    let (pk, _sk) = kem.keygen(&mut rng);

    c.bench_with_input(BenchmarkId::new("encaps", K::NAME), &pk, |b, pk| {
        b.iter(|| kem.encaps(&mut rng, pk))
    });
}

/// Generic benchmark for mKEM encapsulation
fn bench_mkem_encaps<M: Mkem>(c: &mut Criterion) {
    const NUM_RECIPIENTS: usize = 10;

    let mkem = M::default();
    let mut rng = rand::rng();

    // Generate keypairs for recipients
    let pks: Vec<_> = (0..NUM_RECIPIENTS)
        .map(|_| mkem.keygen(&mut rng).0)
        .collect();

    c.bench_with_input(
        BenchmarkId::new(format!("encaps_{NUM_RECIPIENTS}"), M::NAME),
        &pks,
        |b, pks| b.iter(|| mkem.encaps(&mut rng, pks)),
    );
}

/// Benchmark raw X25519 operations with libcrux
fn bench_x25519_libcrux(c: &mut Criterion) {
    use rand::RngCore;
    let mut rng = rand::rng();

    // Setup for libcrux X25519
    let mut libcrux_sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut libcrux_sk_bytes);
    let libcrux_sk = libcrux_ecdh::X25519PrivateKey::from(&libcrux_sk_bytes);
    let libcrux_pk_bytes =
        libcrux_ecdh::secret_to_public(libcrux_ecdh::Algorithm::X25519, &libcrux_sk).unwrap();
    let libcrux_pk_array: [u8; 32] = libcrux_pk_bytes.as_slice().try_into().unwrap();
    let libcrux_pk = libcrux_ecdh::X25519PublicKey::from(&libcrux_pk_array);

    // Benchmark libcrux X25519 DH
    c.bench_function("x25519_dh/libcrux", |b| {
        b.iter(|| {
            libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &libcrux_pk, &libcrux_sk).unwrap()
        })
    });

    // Benchmark libcrux keygen (secret_to_public)
    // Note: libcrux-ecdh uses variable-base scalar multiplication here,
    // which is slower than x25519-dalek's fixed-base implementation.
    c.bench_function("x25519_keygen/libcrux", |b| {
        b.iter(|| {
            libcrux_ecdh::secret_to_public(libcrux_ecdh::Algorithm::X25519, &libcrux_sk).unwrap()
        })
    });
}

// x25519-dalek bench removed (dependency commented out).

fn bench_ristretto_dh(c: &mut Criterion) {
    let dh = Ristretto255Dh;
    let mut rng = rand::rng();

    // Benchmark keygen
    c.bench_function("ristretto_dh/keygen", |b| b.iter(|| dh.keygen(&mut rng)));

    // Benchmark single-recipient encaps (includes DH operation)
    let (pk, _sk) = dh.keygen(&mut rng);
    let pks = vec![pk];
    c.bench_function("ristretto_dh/encaps_1", |b| {
        b.iter(|| dh.encaps(&mut rng, &pks))
    });
}

fn benchmark_all_kems(c: &mut Criterion) {
    // Bench KEMs
    bench_kem_encaps::<MlKem768>(c);
    bench_kem_encaps::<XWing>(c);
    bench_kem_encaps::<XWingRistretto>(c);
    //bench_kem_encaps::<RistrettoDh>(c, "RistrettoDH");

    // Bench mKEMs
    bench_mkem_encaps::<MlKem768>(c);
    bench_mkem_encaps::<XWingMkem>(c);
    bench_mkem_encaps::<XWingRistrettoMkem>(c);
}

criterion_group!(
    benches,
    benchmark_all_kems,
    bench_x25519_libcrux,
    bench_ristretto_dh
);
criterion_main!(benches);
