use std::collections::HashMap;

use encrypted_spaces_crypto::key_derivation::DerivationTag;
use encrypted_spaces_crypto::EncryptedKeyMaterial;
use encrypted_spaces_crypto::{
    DerivationKoalaBearPoseidon2_16, KeyCommitment, KeyDerivation, KeyMaterial,
};
use encrypted_spaces_zkp::transitions::{
    prove_transition, verify_transition, CanonicalPath, KeyTreeTransition,
};

fn derive_commit_fixture() -> (
    DerivationKoalaBearPoseidon2_16,
    KeyTreeTransition,
    HashMap<CanonicalPath, KeyMaterial>,
    KeyMaterial,
    KeyMaterial,
) {
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let root_id = CanonicalPath::new("/root");
    let child_id = root_id.child("child");

    let root_key = KeyMaterial::random();
    let tag = DerivationTag::from(&child_id);
    let child_key = derivation.derive(&root_key, tag);

    let root_commitment: KeyCommitment = derivation.commit(&root_key);
    let child_commitment: KeyCommitment = derivation.commit(&child_key);

    let mut transition = KeyTreeTransition::new();
    transition
        .commit(root_id.clone(), root_commitment)
        .derive(root_id.clone(), child_id.clone(), tag)
        .commit(child_id.clone(), child_commitment);

    let keys = HashMap::from([(root_id, root_key.clone()), (child_id, child_key.clone())]);
    (derivation, transition, keys, root_key, child_key)
}

fn encrypt_fixture() -> (
    DerivationKoalaBearPoseidon2_16,
    KeyTreeTransition,
    HashMap<CanonicalPath, KeyMaterial>,
    KeyMaterial,
    DerivationTag,
    KeyCommitment,
) {
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let key_node = CanonicalPath::new("/key");
    let under_node = CanonicalPath::new("/under");

    let key = KeyMaterial::random();
    let under_tag = DerivationTag::from(&under_node);
    let under = derivation.derive(&key, under_tag);
    let ciphertext = EncryptedKeyMaterial::encrypt(key.clone(), &under);
    let key_commitment = derivation.commit(&key);

    let mut transition = KeyTreeTransition::new();
    transition.commit(key_node.clone(), key_commitment).encrypt(
        key_node.clone(),
        key_node.clone(),
        under_tag,
        ciphertext.clone(),
    );

    let keys = HashMap::from([(key_node, key.clone())]);
    (derivation, transition, keys, key, under_tag, key_commitment)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn test_transition_derive_commit() {
    let (derivation, transition, keys, ..) = derive_commit_fixture();
    let proof = prove_transition(&derivation, &transition, &keys);
    assert!(verify_transition(&transition, &proof).is_ok());
}

#[test]
fn test_transition_encrypt() {
    let (derivation, transition, keys, ..) = encrypt_fixture();
    let proof = prove_transition(&derivation, &transition, &keys);
    assert!(verify_transition(&transition, &proof).is_ok());
}

#[test]
fn test_large_transition() {
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let root = CanonicalPath::new("/root");
    let root_key = KeyMaterial::random();
    let root_commitment: KeyCommitment = derivation.commit(&root_key);

    let mut transition = KeyTreeTransition::new();
    transition.commit(root.clone(), root_commitment);

    let mut keys = HashMap::from([(root.clone(), root_key.clone())]);

    let mut last_child = root.clone();
    let mut last_child_key = root_key.clone();
    const N: usize = 30;
    // build a chain of derivations root/0/1/2/.../N
    for i in 0..N {
        let child = last_child.child(format!("{i}"));
        let tag = DerivationTag::from(&child);
        let child_key = derivation.derive(&last_child_key, tag);

        transition.derive(last_child.clone(), child.clone(), tag);

        keys.insert(child.clone(), child_key.clone());
        last_child = child;
        last_child_key = child_key;
    }

    // create another branch from the root
    let rotation = root.child("anotherbranch");
    let rotation_tag = DerivationTag::from(&rotation);
    let rotation_key = derivation.derive(&root_key, rotation_tag);
    transition.derive(root.clone(), rotation.clone(), rotation_tag);
    keys.insert(rotation.clone(), rotation_key.clone());

    let ciphertext = EncryptedKeyMaterial::encrypt(rotation_key.clone(), &last_child_key);
    transition.encrypt(last_child, root.clone(), rotation_tag, ciphertext.clone());

    // check the instance:
    // N derivations + 1 commit + 1 encrypt + 1 derive "another-branch"
    assert_eq!(transition.len(), N + 3);

    let proof = prove_transition(&derivation, &transition, &keys);
    assert!(verify_transition(&transition, &proof).is_ok());

    // flip a byte in the proof to invalidate it
    let mut bad_proof = proof.clone();
    bad_proof[10] ^= 0xff;
    assert!(verify_transition(&transition, &bad_proof).is_err());

    // add a new (wrong) condition to the transition:
    transition.commit(root.clone(), derivation.commit(&last_child_key));
    assert!(verify_transition(&transition, &proof).is_err());
}

#[test]
fn test_transition_proof_does_not_embed_raw_key_material() {
    let (derivation, transition, keys, root_key, child_key, ..) = derive_commit_fixture();
    let proof = prove_transition(&derivation, &transition, &keys);

    assert!(
        !contains_subslice(&proof, root_key.as_bytes()),
        "proof contains raw root key bytes"
    );
    assert!(
        !contains_subslice(&proof, child_key.as_bytes()),
        "proof contains raw child key bytes"
    );
}

#[test]
fn test_transition_rejects_tampered_proof() {
    let (derivation, transition, keys, ..) = derive_commit_fixture();
    let proof = prove_transition(&derivation, &transition, &keys);
    let mut bad_proof = proof.clone();
    let bad_index = bad_proof.len() / 2;
    bad_proof[bad_index] ^= 0x01;

    assert!(verify_transition(&transition, &bad_proof).is_err());
    assert!(verify_transition(&transition, &[]).is_err());
}

#[test]
fn test_transition_rejects_invalid_commitment_statement() {
    let (derivation, transition, keys, root_key, child_key, ..) = derive_commit_fixture();
    let proof = prove_transition(&derivation, &transition, &keys);

    let root_id = CanonicalPath::new("/root");
    let child_id = root_id.child("child");
    let tag = DerivationTag::from(&child_id);
    let mut invalid_transition = KeyTreeTransition::new();
    invalid_transition
        .commit(root_id.clone(), derivation.commit(&root_key))
        .derive(root_id, child_id.clone(), tag)
        .commit(child_id, derivation.commit(&root_key));

    assert_ne!(derivation.commit(&root_key), derivation.commit(&child_key));
    assert!(verify_transition(&invalid_transition, &proof).is_err());
}

#[test]
fn test_transition_rejects_invalid_encrypt_statement() {
    let (derivation, transition, keys, key, under_tag, key_commitment) = encrypt_fixture();
    let proof = prove_transition(&derivation, &transition, &keys);
    let key_node = CanonicalPath::new("/key");

    let wrong_ciphertext = EncryptedKeyMaterial::encrypt(KeyMaterial::random(), &key);
    let mut invalid_transition = KeyTreeTransition::new();
    invalid_transition
        .commit(key_node.clone(), key_commitment)
        .encrypt(key_node.clone(), key_node, under_tag, wrong_ciphertext);

    assert!(verify_transition(&invalid_transition, &proof).is_err());
}
