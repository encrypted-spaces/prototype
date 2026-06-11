use super::human;
use crate::mve::{Mve, PoseidonMve, MVE_DEFAULT_K, MVE_DEFAULT_U};
use encrypted_spaces_crypto::{
    key_derivation::DerivationKoalaBearPoseidon2_16, pke::KemKeyPair, KeyDerivation, KeyMaterial,
    Mkem,
};
use postcard::to_allocvec;

// allowing type complexity until we figure out if we need this level of generality
#[allow(clippy::type_complexity)]
fn run_mve_demo<S, F>(
    num_recipients: usize,
    relation_sampler: F,
) -> (
    S::Proof,
    S::Ciphertext,
    S::RecipientCiphertext,
    S::Witness,
    S::Witness,
)
where
    S: Mve,
    S::Mkem: Mkem,
    S::Witness: Clone,
    F: FnOnce(&mut rand::rngs::ThreadRng) -> (S::Instance, S::Witness),
    S::Error: core::fmt::Debug,
{
    assert!(
        num_recipients > 0,
        "num_recipients must be greater than zero"
    );

    let mut rng = rand::rng();
    let mut pks = Vec::with_capacity(num_recipients);
    let mut keypairs = Vec::<KemKeyPair<S::Mkem>>::with_capacity(num_recipients);
    for _ in 0..num_recipients {
        let keypair = S::keygen(&mut rng);
        pks.push(keypair.public().clone());
        keypairs.push(keypair);
    }

    let (instance, witness) = relation_sampler(&mut rng);
    let witness_copy = witness.clone();

    let proof = S::prove(&pks, &instance, &witness, "demo");
    let ciphertexts =
        S::verify(&pks, &instance, &proof, "demo").expect("verification should succeed in demo");
    let recipient_idx = 0;
    let recipient_ct = S::compress(&ciphertexts, recipient_idx)
        .expect("recipient index should be in bounds in demo");
    let recovered = S::decrypt(keypairs[recipient_idx].secret(), &recipient_ct, &instance)
        .expect("decryption should succeed in demo");

    (proof, ciphertexts, recipient_ct, witness_copy, recovered)
}

pub fn poseidon_mve_demo<M: Mkem>(num_recipients: usize) -> Vec<u8> {
    let (proof, ciphertexts, recipient_ct, expected_key, recovered_key) =
        run_mve_demo::<PoseidonMve<M>, _>(num_recipients, |rng| {
            let key = KeyMaterial::random_with(rng);
            let derivation = DerivationKoalaBearPoseidon2_16::default();
            let key_commitment = derivation.commit(&key);
            (key_commitment, key)
        });

    let k = MVE_DEFAULT_K;
    let u = MVE_DEFAULT_U;
    let proof_size = serialized_size(&proof);
    let ciphertext_size = serialized_size(&ciphertexts);
    let single_recipient_size = serialized_size(&recipient_ct);

    println!("=== mVE demo with {} (Poseidon) ===", M::NAME);
    println!("Recipients: {num_recipients}");
    println!("Parameters: k = {k}, u = {u}");
    println!("Proof size: {}", human(proof_size));
    println!("Total ciphertext size: {}", human(ciphertext_size));
    println!(
        "Single-recipient ciphertext size: {}",
        human(single_recipient_size)
    );
    println!(
        "Recovered key matches: {}",
        recovered_key.as_bytes() == expected_key.as_bytes()
    );

    vec![0; proof_size]
}

fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    to_allocvec(value).map(|v| v.len()).unwrap_or_default()
}
