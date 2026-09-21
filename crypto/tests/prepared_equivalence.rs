//! Equivalence tests for `encaps_prepared`, including RNG consumption required by mVE.

use encrypted_spaces_crypto::{
    pke::{Ristretto255Dh, XWing, XWingMkem, XWingRistretto, XWingRistrettoMkem},
    KeyMaterial, Mkem,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use rand_core::RngCore;

fn check<M: Mkem>(label: &str, n: usize) {
    let mkem = M::default();
    let mut rng = ChaCha12Rng::from_seed([9u8; 32]);
    let pks: Vec<_> = (0..n).map(|_| mkem.keygen(&mut rng).0).collect();
    let prepared = mkem.prepare(&pks);

    for trial in 0..8u8 {
        let seed = [trial; 32];

        let mut r1 = ChaCha12Rng::from_seed(seed);
        let (ct_a, key_a) = mkem.encaps(&mut r1, &pks);

        let mut r2 = ChaCha12Rng::from_seed(seed);
        let (ct_b, key_b) = mkem.encaps_prepared(&mut r2, &prepared);

        assert_eq!(
            key_a.as_bytes(),
            key_b.as_bytes(),
            "{label}: key differs (n={n}, trial={trial})"
        );
        assert_eq!(
            postcard::to_allocvec(&ct_a).unwrap(),
            postcard::to_allocvec(&ct_b).unwrap(),
            "{label}: ciphertext differs (n={n}, trial={trial})"
        );

        // The RNG must be consumed identically, or any subsequent draw diverges.
        let mut tail_a = [0u8; 32];
        let mut tail_b = [0u8; 32];
        r1.fill_bytes(&mut tail_a);
        r2.fill_bytes(&mut tail_b);
        assert_eq!(
            tail_a, tail_b,
            "{label}: RNG consumption differs (n={n}, trial={trial})"
        );
    }
}

#[test]
fn prepared_matches_encaps() {
    for n in [1usize, 2, 10, 50] {
        // Specialized mKEMs: these carry real precomputation.
        check::<XWingMkem>("XWingMkem", n);
        check::<XWingRistrettoMkem>("XWingRistrettoMkem", n);
        // Blanket impls: `encaps_prepared` falls back to `encaps`.
        check::<XWing>("XWing", n);
        check::<XWingRistretto>("XWingRistretto", n);
        check::<Ristretto255Dh>("Ristretto255Dh", n);
    }
}

#[test]
fn prepared_ciphertexts_decapsulate() {
    let mkem = XWingRistrettoMkem::default();
    let mut rng = ChaCha12Rng::from_seed([4u8; 32]);
    let n = 8;
    let mut pks = Vec::new();
    let mut sks = Vec::new();
    for _ in 0..n {
        let (pk, sk) = mkem.keygen(&mut rng);
        pks.push(pk);
        sks.push(sk);
    }
    let prepared = mkem.prepare(&pks);
    let (ct, key) = mkem.encaps_prepared(&mut rng, &prepared);

    for (i, sk) in sks.iter().enumerate() {
        let indiv = mkem.get(&ct, i).expect("index in bounds");
        let got: KeyMaterial = mkem.decaps(sk, &indiv).expect("decaps succeeds");
        assert_eq!(got.as_bytes(), key.as_bytes(), "recipient {i} mismatch");
    }
}

#[test]
fn prepared_is_order_sensitive() {
    let mkem = XWingRistrettoMkem::default();
    let mut rng = ChaCha12Rng::from_seed([11u8; 32]);
    let pks: Vec<_> = (0..4).map(|_| mkem.keygen(&mut rng).0).collect();
    let mut swapped = pks.clone();
    swapped.swap(0, 1);

    let mut r1 = ChaCha12Rng::from_seed([1u8; 32]);
    let (ct_a, _) = mkem.encaps_prepared(&mut r1, &mkem.prepare(&pks));
    let mut r2 = ChaCha12Rng::from_seed([1u8; 32]);
    let (ct_b, _) = mkem.encaps_prepared(&mut r2, &mkem.prepare(&swapped));

    assert_ne!(
        postcard::to_allocvec(&ct_a).unwrap(),
        postcard::to_allocvec(&ct_b).unwrap(),
        "prepared state ignored recipient order"
    );
}
