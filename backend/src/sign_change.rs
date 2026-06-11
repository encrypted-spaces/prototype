use encrypted_spaces_changelog_core::changelog::ChangelogEntry;
use encrypted_spaces_crypto::{
    signature::SignatureKeyPair, signature::SignatureVerificationError, Signature,
};

/// Shared changelog signing helpers for SDK and server code.
///
/// This lives in `encrypted-spaces-backend` as a pragmatic shared layer until the
/// repo has a cleaner home for code that is used by both client and server.
/// Keeping this crypto-dependent logic out of `encrypted-spaces-changelog-core`
/// matters because `changelog_core` sits on zkVM-facing dependency paths and
/// should stay lean.
pub fn sign_change<S: Signature<Message = [u8]>>(
    change: &mut ChangelogEntry,
    key_pair: &SignatureKeyPair<S>,
) {
    change.signature.clear();
    let bytes = change.as_bytes();
    change.signature = key_pair.sign(&bytes).as_ref().to_vec();
}

pub fn verify_change_signature<S: Signature<Message = [u8]>>(
    change: &ChangelogEntry,
    vk: &S::VerificationKey,
) -> Result<(), SignatureVerificationError> {
    let mut unsigned_change = change.clone();
    unsigned_change.signature.clear();
    let bytes = unsigned_change.as_bytes();
    S::verify(vk, &bytes, &change.signature)
}
