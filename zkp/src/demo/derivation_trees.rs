use std::collections::HashMap;
use std::time::Instant;

use encrypted_spaces_crypto::key_derivation::DerivationTag;
use encrypted_spaces_crypto::EncryptedKeyMaterial;
use encrypted_spaces_crypto::{
    DerivationKoalaBearPoseidon2_16, KeyCommitment, KeyDerivation, KeyMaterial,
};
use tracing::{info, info_span};

use crate::demo::human;
use crate::transitions::{prove_transition, verify_transition, CanonicalPath, KeyTreeTransition};

pub fn derivation_trees(input_size: usize) -> Vec<u8> {
    let _span = info_span!("derivation_trees_demo", input_size).entered();
    let num_children = if input_size == 0 {
        info!("input_size was 0; using 1 child to keep encryption meaningful");
        1
    } else {
        input_size
    };

    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let root = CanonicalPath::new("root");
    let root_key = KeyMaterial::random();
    let root_commitment: KeyCommitment = derivation.commit(&root_key);

    let mut transition = KeyTreeTransition::new();
    transition.commit(root.clone(), root_commitment);

    let mut keys = HashMap::from([(root.clone(), root_key.clone())]);

    let mut last_child = None;
    let mut last_child_key = None;
    for i in 0..num_children {
        let child = root.child(format!("child{i}"));
        let tag = DerivationTag::from(&child);
        let child_key = derivation.derive(&root_key, tag);

        transition.derive(root.clone(), child.clone(), tag);
        keys.insert(child.clone(), child_key.clone());

        last_child = Some(child);
        last_child_key = Some(child_key);
    }

    let rotation = root.child("rotation");
    let rotation_tag = DerivationTag::from(&rotation);
    let rotation_key = derivation.derive(&root_key, rotation_tag);
    transition.derive(root.clone(), rotation.clone(), rotation_tag);
    keys.insert(rotation.clone(), rotation_key.clone());

    let last_child = last_child.expect("expected at least one child");
    let last_child_key = last_child_key.expect("expected last child key");
    let ciphertext = EncryptedKeyMaterial::encrypt(rotation_key.clone(), &last_child_key);
    transition.encrypt(last_child, root, rotation_tag, ciphertext);

    info!(
        commit_ops = 1,
        derive_ops = num_children + 1,
        encrypt_ops = 1,
        key_materials = keys.len(),
        "built derivation tree transition"
    );

    let prove_start = Instant::now();
    let proof = prove_transition(&derivation, &transition, &keys);
    info!(
        elapsed_ms = prove_start.elapsed().as_millis(),
        proof_size = human(proof.len()),
        "proved derivation tree transition"
    );

    let verify_start = Instant::now();
    let verify_result = verify_transition(&transition, &proof);
    info!(
        elapsed_ms = verify_start.elapsed().as_millis(),
        verified = verify_result.is_ok(),
        "verified derivation tree transition"
    );

    proof
}
