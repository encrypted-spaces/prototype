use criterion::{criterion_group, criterion_main, Criterion};

use encrypted_spaces_crypto::{
    default_rng, key_derivation::DerivationKoalaBearPoseidon2_16, pke::DefaultMkem, KeyDerivation,
    KeyMaterial, Mkem,
};
use encrypted_spaces_zkp::mve::{PoseidonMve, MVE_PARAMS};
use std::time::Duration;

fn benchmark_poseidon_mve(c: &mut Criterion) {
    benchmark_poseidon_mve_helper::<DefaultMkem>(c)
}

fn benchmark_poseidon_mve_helper<M: Mkem>(c: &mut Criterion) {
    let recipient_counts = [10, 50, 256];
    let mut rng = default_rng();

    for num_recipients in recipient_counts {
        for (k, u) in MVE_PARAMS {
            match (k, u) {
                (247, 30) => {
                    benchmark_poseidon_for_params::<M, 247, 30>(c, &mut rng, num_recipients)
                }
                (100, 50) => {
                    benchmark_poseidon_for_params::<M, 100, 50>(c, &mut rng, num_recipients)
                }
                (126, 30) => {
                    benchmark_poseidon_for_params::<M, 126, 30>(c, &mut rng, num_recipients)
                }
                (443, 16) => {
                    benchmark_poseidon_for_params::<M, 443, 16>(c, &mut rng, num_recipients)
                }

                _ => panic!("unsupported mVE parameter set ({k}, {u})"),
            }
        }
    }
}

fn benchmark_poseidon_for_params<M: Mkem, const K: usize, const U: usize>(
    c: &mut Criterion,
    rng: &mut impl rand_core::CryptoRng,
    num_recipients: usize,
) {
    let mkem = M::default();

    let mut pks = Vec::with_capacity(num_recipients);
    let mut sks = Vec::with_capacity(num_recipients);
    for _ in 0..num_recipients {
        let (pk, sk) = mkem.keygen(rng);
        pks.push(pk);
        sks.push(sk);
    }

    let key = KeyMaterial::random_with(rng);
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let key_commitment = derivation.commit(&key);

    c.bench_function(
        &format!("Poseidon mVE Prove() recipients = {num_recipients}, k = {K}, u = {U}"),
        |b| b.iter(|| PoseidonMve::<M, K, U>::prove(&pks, &key_commitment, &key, "bench")),
    );

    let proof = PoseidonMve::<M, K, U>::prove(&pks, &key_commitment, &key, "bench");

    c.bench_function(
        &format!("Poseidon mVE Verify() recipients = {num_recipients}, k = {K}, u = {U}"),
        |b| {
            b.iter(|| {
                PoseidonMve::<M, K, U>::verify(&proof, &pks, &key_commitment, "bench")
                    .expect("verification should succeed")
            })
        },
    );

    let ciphertexts = PoseidonMve::<M, K, U>::verify(&proof, &pks, &key_commitment, "bench")
        .expect("verification should succeed");

    let recipient_idx = 0;
    c.bench_function(
        &format!(
            "Poseidon mVE Decrypt() recipients = {num_recipients}, k = {K}, u = {U} (single recipient)"
        ),
        |b| {
            b.iter(|| {
                let recipient_ct = ciphertexts
                    .get(recipient_idx)
                    .expect("recipient index should be in bounds");
                PoseidonMve::<M, K, U>::decrypt(&sks[recipient_idx], &recipient_ct, key_commitment)
                    .expect("decryption should succeed")
            })
        },
    );
}

criterion_group! {
    name = poseidon_mve_benches;
    config = Criterion::default().sample_size(10).warm_up_time(Duration::from_secs(5));
    targets = benchmark_poseidon_mve
}
criterion_main!(poseidon_mve_benches);
