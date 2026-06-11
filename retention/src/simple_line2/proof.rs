//! Proof trait and adapters for SimpleLine2 operation verification.
//!
//! Defines proof input/output types and the [`SimpleLine2Proofs`] trait, plus
//! the [`NoProver`] placeholder adapter for testing without proof overhead.
//!
//! Proof inputs carry the public and witness data directly rather than going
//! through a separate protocol-state abstraction: mutation sites in
//! [`super::space_key`] already compute the staged rows and resolved key
//! material needed, and prover/verifier callers must agree on the same public
//! inputs anyway.

use core::convert::Infallible;

use encrypted_spaces_crypto::key_derivation::{DerivationKoalaBearPoseidon2_16, KeyDerivation};
use encrypted_spaces_crypto::{KeyCommitment, KeyMaterial};
use encrypted_spaces_key_manager::error::KeyManagerError;

use super::store::{DTableRow, FGKRow, GBCiphertextPair};

/// Alias for the default derivation backend used by SimpleLine2.
pub type DefaultDerivation = DerivationKoalaBearPoseidon2_16;

// =========================================================================
// Extend
// =========================================================================

#[derive(Clone, Debug)]
pub struct ExtendProofInput<'a, D: KeyDerivation> {
    pub current_d_commitment: KeyCommitment,
    pub next_row: &'a DTableRow,
    pub derivation: &'a D,
    pub current_d_key: &'a KeyMaterial,
    pub next_d_key: &'a KeyMaterial,
}

#[derive(Clone, Debug)]
pub struct ExtendVerifyInput<'a> {
    pub current_d_commitment: KeyCommitment,
    pub next_row: &'a DTableRow,
}

// =========================================================================
// Rekey
// =========================================================================

#[derive(Clone, Debug)]
pub struct RekeyProofInput<'a, D: KeyDerivation> {
    pub old_hgk_commitment: KeyCommitment,
    pub next_fgk_row: &'a FGKRow,
    pub next_row: &'a DTableRow,
    pub next_head_links: &'a GBCiphertextPair,
    pub derivation: &'a D,
    pub old_hgk: &'a KeyMaterial,
    pub new_hgk: &'a KeyMaterial,
    pub new_d_head: &'a KeyMaterial,
}

#[derive(Clone, Debug)]
pub struct RekeyVerifyInput<'a> {
    pub old_hgk_commitment: KeyCommitment,
    pub next_fgk_row: &'a FGKRow,
    pub next_row: &'a DTableRow,
    pub next_head_links: &'a GBCiphertextPair,
}

// =========================================================================
// DeleteKeys
// =========================================================================

/// One surviving chain node's D-head witness: its effective start sequence and
/// the D-row commitment at that sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteKeysSurvivor {
    pub d_head_seq: u64,
    pub d_head_commitment: KeyCommitment,
}

#[derive(Clone, Debug)]
pub struct DeleteKeysProofInput<'a, D: KeyDerivation> {
    pub old_hgk_commitment: KeyCommitment,
    pub dgk_commitment: KeyCommitment,
    pub survivors: &'a [DeleteKeysSurvivor],
    pub next_links: &'a [GBCiphertextPair],
    pub derivation: &'a D,
    pub old_hgk: &'a KeyMaterial,
    pub new_hgk: &'a KeyMaterial,
    pub b_keys: &'a [KeyMaterial],
    pub d_head_keys: &'a [KeyMaterial],
}

#[derive(Clone, Debug)]
pub struct DeleteKeysVerifyInput<'a> {
    pub old_hgk_commitment: KeyCommitment,
    pub dgk_commitment: KeyCommitment,
    pub survivors: &'a [DeleteKeysSurvivor],
    pub next_links: &'a [GBCiphertextPair],
}

// =========================================================================
// Trait
// =========================================================================

/// Trait for proof generation and verification of SimpleLine2 operations.
///
/// Abstracts over the proof backend so the protocol logic is independent of
/// the concrete proof system. Implementors provide prove/verify pairs for
/// Extend, Rekey, and DeleteKeys.
pub trait SimpleLine2Proofs<D: KeyDerivation> {
    type ExtendProof;
    type RekeyProof;
    type DeleteKeysProof;
    type Error;

    fn prove_extend(
        &self,
        input: ExtendProofInput<'_, D>,
    ) -> Result<Self::ExtendProof, Self::Error>;

    fn verify_extend(&self, input: ExtendVerifyInput<'_>, proof: &[u8]) -> Result<(), Self::Error>;

    fn prove_rekey(&self, input: RekeyProofInput<'_, D>) -> Result<Self::RekeyProof, Self::Error>;

    fn verify_rekey(&self, input: RekeyVerifyInput<'_>, proof: &[u8]) -> Result<(), Self::Error>;

    fn prove_delete_keys(
        &self,
        input: DeleteKeysProofInput<'_, D>,
    ) -> Result<Self::DeleteKeysProof, Self::Error>;

    fn verify_delete_keys(
        &self,
        input: DeleteKeysVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Convenience bound: proof adapter for SimpleLine2 mutations whose three
/// proof types are all `Vec<u8>`. This matches the byte-oriented carriage
/// `OperationBuilder::record_proof` expects.
pub trait VecProofs:
    SimpleLine2Proofs<
    DefaultDerivation,
    ExtendProof = Vec<u8>,
    RekeyProof = Vec<u8>,
    DeleteKeysProof = Vec<u8>,
>
{
}

impl<P> VecProofs for P where
    P: SimpleLine2Proofs<
        DefaultDerivation,
        ExtendProof = Vec<u8>,
        RekeyProof = Vec<u8>,
        DeleteKeysProof = Vec<u8>,
    >
{
}

/// Object-safe runtime prover interface for SimpleLine2 mutations.
///
/// This is the prover slot used by the generic [`SpaceKey`] trait. It carries
/// only the prove operations needed by client-side mutation paths and maps
/// all errors into [`KeyManagerError`], so both [`NoProver`] and
/// [`super::StarkProver`](crate::simple_line2::StarkProver) can be passed
/// through the same backend-specific prover parameter.
pub trait SimpleLine2RuntimeProver: Default + Clone {
    fn prove_extend_runtime(
        &self,
        input: ExtendProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError>;

    fn prove_rekey_runtime(
        &self,
        input: RekeyProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError>;

    fn prove_delete_keys_runtime(
        &self,
        input: DeleteKeysProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError>;

    fn verify_extend_runtime(
        &self,
        input: ExtendVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError>;

    fn verify_rekey_runtime(
        &self,
        input: RekeyVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError>;

    fn verify_delete_keys_runtime(
        &self,
        input: DeleteKeysVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError>;
}

// =========================================================================
// NoProver
// =========================================================================

/// Placeholder proof adapter: all `prove_*` calls succeed and emit an empty
/// byte payload; all `verify_*` calls succeed. Used as the default adapter
/// for the fast test lane, where STARK round-trip is gated out.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProver;

impl<D: KeyDerivation> SimpleLine2Proofs<D> for NoProver {
    type ExtendProof = Vec<u8>;
    type RekeyProof = Vec<u8>;
    type DeleteKeysProof = Vec<u8>;
    type Error = Infallible;

    fn prove_extend(
        &self,
        _input: ExtendProofInput<'_, D>,
    ) -> Result<Self::ExtendProof, Self::Error> {
        Ok(Vec::new())
    }

    fn verify_extend(
        &self,
        _input: ExtendVerifyInput<'_>,
        _proof: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn prove_rekey(&self, _input: RekeyProofInput<'_, D>) -> Result<Self::RekeyProof, Self::Error> {
        Ok(Vec::new())
    }

    fn verify_rekey(&self, _input: RekeyVerifyInput<'_>, _proof: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn prove_delete_keys(
        &self,
        _input: DeleteKeysProofInput<'_, D>,
    ) -> Result<Self::DeleteKeysProof, Self::Error> {
        Ok(Vec::new())
    }

    fn verify_delete_keys(
        &self,
        _input: DeleteKeysVerifyInput<'_>,
        _proof: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl SimpleLine2RuntimeProver for NoProver {
    fn prove_extend_runtime(
        &self,
        input: ExtendProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::prove_extend(self, input)
            .map_err(|never| match never {})
    }

    fn prove_rekey_runtime(
        &self,
        input: RekeyProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::prove_rekey(self, input)
            .map_err(|never| match never {})
    }

    fn prove_delete_keys_runtime(
        &self,
        input: DeleteKeysProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::prove_delete_keys(self, input)
            .map_err(|never| match never {})
    }

    fn verify_extend_runtime(
        &self,
        input: ExtendVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::verify_extend(self, input, proof)
            .map_err(|never| match never {})
    }

    fn verify_rekey_runtime(
        &self,
        input: RekeyVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::verify_rekey(self, input, proof)
            .map_err(|never| match never {})
    }

    fn verify_delete_keys_runtime(
        &self,
        input: DeleteKeysVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::verify_delete_keys(self, input, proof)
            .map_err(|never| match never {})
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_crypto::EncryptedKeyMaterial;
    use encrypted_spaces_crypto::KeyDerivation;

    fn derivation() -> DefaultDerivation {
        DefaultDerivation::default()
    }

    fn dummy_ct() -> EncryptedKeyMaterial {
        EncryptedKeyMaterial::encrypt(KeyMaterial::random(), &KeyMaterial::random())
    }

    // `NoProver` is generic over any `D: KeyDerivation`, so direct method calls
    // on a `NoProver` value can be ambiguous when the method signature does
    // not mention `D` (e.g. `verify_*`). The fully-qualified trait-method
    // syntax used below pins the impl to `DefaultDerivation`.
    type Prover = NoProver;

    #[test]
    fn no_prover_extend_round_trip() {
        let d = derivation();
        let current_d = KeyMaterial::random();
        let next_d = KeyMaterial::random();
        let next_row = DTableRow {
            seq: 1,
            commitment: d.commit(&next_d),
        };

        let prover = NoProver;
        let proof = <Prover as SimpleLine2Proofs<DefaultDerivation>>::prove_extend(
            &prover,
            ExtendProofInput {
                current_d_commitment: d.commit(&current_d),
                next_row: &next_row,
                derivation: &d,
                current_d_key: &current_d,
                next_d_key: &next_d,
            },
        )
        .expect("prove");
        assert!(proof.is_empty());

        <Prover as SimpleLine2Proofs<DefaultDerivation>>::verify_extend(
            &prover,
            ExtendVerifyInput {
                current_d_commitment: d.commit(&current_d),
                next_row: &next_row,
            },
            &proof,
        )
        .expect("verify");
    }

    #[test]
    fn no_prover_rekey_round_trip() {
        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let new_hgk = KeyMaterial::random();
        let new_d_head = KeyMaterial::random();
        let next_fgk_row = FGKRow {
            d_start: 1,
            commitment: d.commit(&new_hgk),
        };
        let next_row = DTableRow {
            seq: 1,
            commitment: d.commit(&new_d_head),
        };
        let links = GBCiphertextPair {
            older_gb_key_ciphertext: Some(dummy_ct()),
            d_head_ciphertext: dummy_ct(),
        };

        let prover = NoProver;
        let proof = <Prover as SimpleLine2Proofs<DefaultDerivation>>::prove_rekey(
            &prover,
            RekeyProofInput {
                old_hgk_commitment: d.commit(&old_hgk),
                next_fgk_row: &next_fgk_row,
                next_row: &next_row,
                next_head_links: &links,
                derivation: &d,
                old_hgk: &old_hgk,
                new_hgk: &new_hgk,
                new_d_head: &new_d_head,
            },
        )
        .expect("prove");
        assert!(proof.is_empty());

        <Prover as SimpleLine2Proofs<DefaultDerivation>>::verify_rekey(
            &prover,
            RekeyVerifyInput {
                old_hgk_commitment: d.commit(&old_hgk),
                next_fgk_row: &next_fgk_row,
                next_row: &next_row,
                next_head_links: &links,
            },
            &proof,
        )
        .expect("verify");
    }

    #[test]
    fn no_prover_delete_keys_round_trip() {
        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let new_hgk = KeyMaterial::random();
        let d_head_0 = KeyMaterial::random();
        let survivors = [DeleteKeysSurvivor {
            d_head_seq: 3,
            d_head_commitment: d.commit(&d_head_0),
        }];
        let next_links = [GBCiphertextPair {
            older_gb_key_ciphertext: None,
            d_head_ciphertext: dummy_ct(),
        }];

        let prover = NoProver;
        let proof = <Prover as SimpleLine2Proofs<DefaultDerivation>>::prove_delete_keys(
            &prover,
            DeleteKeysProofInput {
                old_hgk_commitment: d.commit(&old_hgk),
                dgk_commitment: d.commit(&new_hgk),
                survivors: &survivors,
                next_links: &next_links,
                derivation: &d,
                old_hgk: &old_hgk,
                new_hgk: &new_hgk,
                b_keys: &[],
                d_head_keys: &[d_head_0],
            },
        )
        .expect("prove");
        assert!(proof.is_empty());

        <Prover as SimpleLine2Proofs<DefaultDerivation>>::verify_delete_keys(
            &prover,
            DeleteKeysVerifyInput {
                old_hgk_commitment: d.commit(&old_hgk),
                dgk_commitment: d.commit(&new_hgk),
                survivors: &survivors,
                next_links: &next_links,
            },
            &proof,
        )
        .expect("verify");
    }
}
