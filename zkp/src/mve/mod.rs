#![allow(non_snake_case)]

mod errors;
mod poseidon2;

use encrypted_spaces_crypto::{
    pke::{DefaultMkem, KemKeyPair},
    KeyMaterial, Mkem,
};
pub use poseidon2::{PoseidonMve, PoseidonMveProof};
use rand_core::{CryptoRng, RngCore};
use spongefish::DuplexSpongeInterface;

pub use errors::MveError;
use serde::{Deserialize, Serialize};

// TODO: document features: portable doesn't use AVX2 for Kyber (off by default), and parallel uses rayon for parallelization (on by default)
// TODO: in the context of a rekey the server can optimistically send only one of the (m0, r0, ctext) tuples, since usually the proofs will be generated honestly and
//  any of the tuples will decrypt.  If it fails the server can then send the whole list
// TODO: (perf) use batch check for sigma-proof verification equation in verifier.
// TODO: (perf) parallelize recomputation of ciphertexts in verifier.
// TODO don't panic/assert in this lib.
// TODO: for debug builds we should check to make sure that *all* components of mVE ciphertexts decrypt correctly.
// TODO: (perf) in our XWingIshPke we could use the optimization for multi-recipient ECDH (requires a change to the MRPKE trait which would no longer be generic over PKE)

/// Parameters controlling the soundness of the proof.
/// Params (k,u) must satisfy log(binomial(k,u))/log(2) > security level in bits.
/// The larger u is, the larger the transcript.  The larger k is, the higher the computational cost.
/// We give options at 128 and 96 bit security, and default to a 96-bit option.
/// These were chosen for the Poseidon+Xwing construction, if a different mKEM is used, other parameters
/// probably give a better speed/size balance.
pub const MVE_PARAMS: [(usize, usize); 4] = [
    (247, 30), // 128-bit security
    (100, 50), // 96-bit security: lowest time, higher size
    (126, 30), // 96-bit security: balanced time/size
    (443, 16), // 96-bit security: lowest size, higher time
];
pub const MVE_DEFAULT_K: usize = 126;
pub const MVE_DEFAULT_U: usize = 30;

pub trait Mve {
    /// The underlying multi-recipient key-encapsulation mechanism.
    type Mkem: Mkem;
    /// The instance being proven.
    type Instance;
    /// The witness for the instance.
    type Witness;
    type Proof;
    type Ciphertext;
    type RecipientCiphertext;
    type Error;

    fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> KemKeyPair<Self::Mkem> {
        KemKeyPair::new(rng)
    }

    fn prove(
        pks: &[<Self::Mkem as Mkem>::PublicKey],
        instance: &Self::Instance,
        witness: &Self::Witness,
        session_identifier: &str,
    ) -> Self::Proof;

    fn verify(
        pks: &[<Self::Mkem as Mkem>::PublicKey],
        instance: &Self::Instance,
        proof: &Self::Proof,
        session_identifier: &str,
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn compress(ct: &Self::Ciphertext, recipient_index: usize)
        -> Option<Self::RecipientCiphertext>;

    fn decrypt(
        sk: &<Self::Mkem as Mkem>::SecretKey,
        ct_i: &Self::RecipientCiphertext,
        instance: &Self::Instance,
    ) -> Result<Self::Witness, Self::Error>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MkemCiphertextGroup<Ct> {
    pub payload: Vec<u8>,
    pub ciphertext: Ct,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MkemRecipientCiphertext<Ct> {
    pub payload: Vec<u8>,
    pub ciphertext: Ct,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MveCiphertext<M: Mkem, R = KeyMaterial>(
    pub Vec<(R, MkemCiphertextGroup<M::Ciphertext>)>,
);

#[derive(Clone, Serialize, Deserialize)]
pub struct MveRecipientCiphertext<M = DefaultMkem, R = KeyMaterial>(
    pub Vec<(R, MkemRecipientCiphertext<M::IndividualCiphertext>)>,
)
where
    M: Mkem;

pub type RecipientCiphertext<M = DefaultMkem, R = KeyMaterial> = MveRecipientCiphertext<M, R>;

impl<M: Mkem, R> MveCiphertext<M, R>
where
    M::Ciphertext: Clone,
    R: Clone,
{
    #[tracing::instrument(name = "mVE ciphertext get", skip_all)]
    pub fn get(&self, recipient_index: usize) -> Option<MveRecipientCiphertext<M, R>> {
        // The input full_ctext contains ciphertexts for all N recipients
        // This function returns the data necessary for one of the recipients to decrypt
        // full_ctext: is a vector of (F, F, group ciphertext)
        // For recipient index i we use mkem.get to extract the recipient ciphertext.

        let mkem = M::default();
        let mut result = Vec::with_capacity(self.0.len());
        for (element, ct_group) in self.0.iter() {
            let ciphertext = mkem.get(&ct_group.ciphertext, recipient_index)?;
            result.push((
                element.clone(),
                MkemRecipientCiphertext {
                    payload: ct_group.payload.clone(),
                    ciphertext,
                },
            ));
        }
        Some(MveRecipientCiphertext(result))
    }
}

pub(crate) fn expand_challenge(k: usize, u: usize, challenge: &[u8]) -> Vec<usize> {
    let length_required = k - u;
    let mut output = Vec::<usize>::new();
    let mut hasher = spongefish::StdHash::default();
    hasher
        .absorb(&k.to_be_bytes())
        .absorb(&u.to_be_bytes())
        .absorb(challenge);

    while output.len() < length_required {
        let random_u64 = u64::from_be_bytes(hasher.squeeze_array());
        // XXX. this is not exactly uniform, but should be OK for special soundness
        let index = (random_u64 as usize) % k;
        if !output.contains(&index) {
            output.push(index);
        }
    }
    output.sort();
    output
}
