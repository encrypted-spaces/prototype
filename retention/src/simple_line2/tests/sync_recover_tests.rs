//! Tests for the delivery-slot sync/recovery helpers.

use encrypted_spaces_crypto::key_derivation::{DerivationKoalaBearPoseidon2_16, KeyDerivation};
use encrypted_spaces_crypto::pke::KemKeyPair;
use encrypted_spaces_crypto::signature::{Ed25519Signature, SignatureKeyPair};
use encrypted_spaces_crypto::KeyMaterial;
use encrypted_spaces_key_manager::traits::GroupKeySync;
use encrypted_spaces_key_manager::{
    verify_rekey, DefaultMkem, GkDeliveryEnvelope, KeyManager, MemoryOperationBuilder, SimpleKeyId,
    SpaceKey,
};

use super::super::space_key::SimpleLine2SpaceKey;
use super::super::NoProver;

type D = DerivationKoalaBearPoseidon2_16;
type TestSpaceKey = SimpleLine2SpaceKey<NoProver>;

fn derivation() -> D {
    D::default()
}

// =====================================================================
// SimpleLine2SpaceKey::sync_group_key
// =====================================================================

#[tokio::test]
async fn sync_returns_already_current_when_local_matches_canonical() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Fresh state: local hgk is the only FGK commitment.
    let result = sk.sync_group_key(&builder).await.unwrap();
    assert!(matches!(result, GroupKeySync::AlreadyCurrent));
}

#[tokio::test]
async fn sync_returns_derived_forward_after_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Create some room to reduce: extend past seq 0, then reduce before seq 1.
    // After reduce, the canonical HGK commitment is the DGK's, but self.hgk
    // is still the pre-derivation HGK.
    sk.extend(&mut builder).await.unwrap();

    let hgk_before_reduce = sk.hgk.clone();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    // reduce() in this codebase doesn't advance self.hgk (see the recent
    // 342543fe "Drop eager self.hgk mutation from SimpleLine2SpaceKey::reduce"
    // commit), so the local HGK is now stale relative to canonical.
    assert_eq!(sk.hgk, hgk_before_reduce);
    let target = super::super::space_key::current_hgk_commitment(&builder)
        .await
        .unwrap();
    assert_ne!(derivation().commit(&sk.hgk), target);

    // sync should walk the DGK forward and install the derived HGK.
    let result = sk.sync_group_key(&builder).await.unwrap();
    assert!(matches!(result, GroupKeySync::DerivedForward));
    assert_eq!(derivation().commit(&sk.hgk), target);
}

#[tokio::test]
async fn sync_returns_needs_delivery_after_fresh_rekey() {
    // Two clients sharing the same canonical builder. Client A rekeys; client
    // B's local HGK is no longer on the derivation chain.
    let mut builder = MemoryOperationBuilder::new();
    let mut sk_a = TestSpaceKey::new(&mut builder).await.unwrap();
    let mut sk_b = sk_a.clone();

    // Client A generates and applies a fresh group key.
    let (commitment, new_key) = sk_a.generate_group_key(&mut builder).await.unwrap();
    sk_a.apply_new_group_key(new_key, commitment, &builder)
        .await
        .unwrap();

    // Canonical state has advanced; B's local HGK cannot derive forward.
    let result = sk_b.sync_group_key(&builder).await.unwrap();
    assert!(matches!(result, GroupKeySync::NeedsDelivery));
}

#[tokio::test]
async fn sync_needs_delivery_leaves_local_hgk_unchanged() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk_a = TestSpaceKey::new(&mut builder).await.unwrap();
    let mut sk_b = sk_a.clone();
    let b_hgk_before = sk_b.hgk.clone();

    let (commitment, new_key) = sk_a.generate_group_key(&mut builder).await.unwrap();
    sk_a.apply_new_group_key(new_key, commitment, &builder)
        .await
        .unwrap();

    let result = sk_b.sync_group_key(&builder).await.unwrap();
    assert!(matches!(result, GroupKeySync::NeedsDelivery));
    assert_eq!(sk_b.hgk, b_hgk_before, "self.hgk must not be mutated");
}

// =====================================================================
// SimpleLine2SpaceKey::recover_group_key_from_candidate
// =====================================================================

#[tokio::test]
async fn recover_from_candidate_installs_matching_hgk() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk_a = TestSpaceKey::new(&mut builder).await.unwrap();
    let mut sk_b = sk_a.clone();

    let (commitment, new_key) = sk_a.generate_group_key(&mut builder).await.unwrap();
    sk_a.apply_new_group_key(new_key.clone(), commitment, &builder)
        .await
        .unwrap();

    // B gets the recovered GK out-of-band (in production, via delivery slot).
    sk_b.recover_group_key_from_candidate(new_key.clone(), &builder)
        .await
        .unwrap();

    let target = super::super::space_key::current_hgk_commitment(&builder)
        .await
        .unwrap();
    assert_eq!(derivation().commit(&sk_b.hgk), target);
    assert_eq!(sk_b.hgk, new_key);
}

#[tokio::test]
async fn recover_from_candidate_rejects_wrong_key() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let original_hgk = sk.hgk.clone();

    // A completely unrelated key can't derive to the canonical commitment.
    let bogus = KeyMaterial::random();
    let err = sk
        .recover_group_key_from_candidate(bogus, &builder)
        .await
        .unwrap_err();
    let _ = err;

    assert_eq!(
        sk.hgk, original_hgk,
        "self.hgk must not be mutated on error"
    );
}

// =====================================================================
// KeyManager::sync_group_key (wrapper)
// =====================================================================

#[tokio::test]
async fn km_sync_group_key_delegates_to_space_key() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let mut rng = rand::rng();
    let km_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
    let auth_kp = SignatureKeyPair::<Ed25519Signature>::new();
    let mut km = KeyManager::new(km_kp, auth_kp, sk);

    // Fresh state → AlreadyCurrent.
    let result = km.sync_group_key(&builder).await.unwrap();
    assert!(matches!(result, GroupKeySync::AlreadyCurrent));
}

// =====================================================================
// KeyManager::recover_group_key_from_delivery (end-to-end MVE)
// =====================================================================

#[tokio::test]
async fn km_recover_group_key_from_delivery_round_trips() {
    // Client A runs a rekey, produces a per-recipient ciphertext for B, wraps
    // it in a GkDeliveryEnvelope, and B recovers through the KeyManager helper.
    let mut rng = rand::rng();

    // Shared canonical retention state.
    let mut builder = MemoryOperationBuilder::new();
    let sk_a = TestSpaceKey::new(&mut builder).await.unwrap();

    let a_km_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
    let b_km_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
    let a_auth = SignatureKeyPair::<Ed25519Signature>::new();
    let b_auth = SignatureKeyPair::<Ed25519Signature>::new();

    let mut km_a = KeyManager::new(a_km_kp.clone(), a_auth, sk_a.clone());
    let mut km_b = KeyManager::new(b_km_kp.clone(), b_auth, sk_a.clone());

    // A issues a rekey addressed to [A, B].
    let recipients = [a_km_kp.public().clone(), b_km_kp.public().clone()];
    let rekey = km_a.rekey(&recipients, &mut builder).await.unwrap();
    let ciphertexts = verify_rekey(&recipients, &rekey).unwrap();

    // A applies their own ciphertext to advance their local state; this also
    // writes the new FGK etc. to the shared builder as part of rekey.
    let a_ct = ciphertexts.get(0).unwrap();
    km_a.apply_delivered_group_key(&a_ct, rekey.new_root_commitment, &builder)
        .await
        .unwrap();

    // B would have gotten their per-recipient ciphertext from the delivery
    // slot bundled as a GkDeliveryEnvelope.
    let b_ct = ciphertexts.get(1).unwrap();
    let envelope = GkDeliveryEnvelope {
        binding_commitment: rekey.new_root_commitment,
        ciphertext: b_ct,
    };

    // Before recovery B is stale.
    assert!(matches!(
        km_b.sync_group_key(&builder).await.unwrap(),
        GroupKeySync::NeedsDelivery,
    ));

    // After recovery B's HGK commitment matches canonical.
    km_b.recover_group_key_from_delivery(&envelope, &builder)
        .await
        .unwrap();
    let target = super::super::space_key::current_hgk_commitment(&builder)
        .await
        .unwrap();
    assert_eq!(
        derivation().commit(&km_b.space_key().hgk),
        target,
        "B's HGK should now match canonical",
    );
    // And repeated sync is a no-op.
    assert!(matches!(
        km_b.sync_group_key(&builder).await.unwrap(),
        GroupKeySync::AlreadyCurrent,
    ));
}

#[tokio::test]
async fn km_recover_rejects_envelope_with_wrong_binding_commitment() {
    let mut rng = rand::rng();

    let mut builder = MemoryOperationBuilder::new();
    let sk_a = TestSpaceKey::new(&mut builder).await.unwrap();

    let a_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
    let b_kp = KemKeyPair::<DefaultMkem>::new(&mut rng);
    let km_a = KeyManager::new(
        a_kp.clone(),
        SignatureKeyPair::<Ed25519Signature>::new(),
        sk_a.clone(),
    );
    let mut km_b = KeyManager::new(
        b_kp.clone(),
        SignatureKeyPair::<Ed25519Signature>::new(),
        sk_a.clone(),
    );
    let b_hgk_before = km_b.space_key().hgk.clone();

    let recipients = [a_kp.public().clone(), b_kp.public().clone()];
    let rekey = km_a.rekey(&recipients, &mut builder).await.unwrap();
    let ciphertexts = verify_rekey(&recipients, &rekey).unwrap();
    let b_ct = ciphertexts.get(1).unwrap();

    // Tamper with the binding commitment — decryption/commitment check fails.
    let tampered_commitment = derivation().commit(&KeyMaterial::random());
    let envelope = GkDeliveryEnvelope {
        binding_commitment: tampered_commitment,
        ciphertext: b_ct,
    };

    assert!(km_b
        .recover_group_key_from_delivery(&envelope, &builder)
        .await
        .is_err());
    assert_eq!(
        km_b.space_key().hgk,
        b_hgk_before,
        "local HGK must not be mutated when recovery fails",
    );
}
