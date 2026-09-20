use super::*;
use encrypted_spaces_crypto::KeyDerivation;
use encrypted_spaces_zkp::transitions::ProvingError;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Kind, LogUpGadget, Lookup, LookupProtocol};
use p3_matrix::dense::RowMajorMatrix;
use spongefish_stark::{
    ff::{KoalaBearChallenge, KoalaBearStarkConfig},
    permutation::poseidon2::KoalaBearPoseidon2_16,
    RelationField,
};
use std::cell::Cell;

type Base = RelationField<KoalaBearPoseidon2_16, 16>;

#[derive(Clone, Copy)]
enum Fault {
    ActiveZeroDenominator,
    RetryExhaustion,
    UnexpectedPanic,
}

thread_local! {
    static FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
    static ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn prove_transition(
    derivation: &DefaultDerivation,
    transition: &KeyTreeTransition,
    keys: &HashMap<CanonicalPath, KeyMaterial>,
) -> Result<Vec<u8>, ProvingError> {
    ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    match FAULT.with(Cell::get) {
        Some(Fault::ActiveZeroDenominator) => {
            let lookup = Lookup::<Base> {
                kind: Kind::Global("zk-terminal-mask".into()),
                elements: vec![vec![Base::ZERO.into(); 4]],
                multiplicities: vec![Base::ONE.into()],
                count_weight: 1,
                column: 0,
            };
            let trace = RowMajorMatrix::new(vec![Base::ZERO; 2], 1);
            LogUpGadget.generate_permutation::<KoalaBearStarkConfig>(
                &trace,
                &None,
                &[],
                &[lookup],
                &[KoalaBearChallenge::ZERO, KoalaBearChallenge::ONE],
            );
            Ok(Vec::new())
        }
        Some(Fault::RetryExhaustion) => Err(ProvingError),
        Some(Fault::UnexpectedPanic) => panic!("injected unexpected proving failure"),
        None => {
            encrypted_spaces_zkp::transitions::try_prove_transition(derivation, transition, keys)
        }
    }
}

fn assert_native_failure(fault: Fault, expected_attempts: usize) {
    use crate::simple_line2::store::DTableRow;

    struct ResetFault;

    impl Drop for ResetFault {
        fn drop(&mut self) {
            FAULT.with(|fault| fault.set(None));
        }
    }

    let derivation = DefaultDerivation::default();
    let current_key = KeyMaterial::random();
    let next_key = derivation.derive(&current_key, tag(D_DERIVE_TAG));
    let next_row = DTableRow {
        seq: 1,
        commitment: derivation.commit(&next_key),
    };
    let _reset = ResetFault;
    FAULT.with(|current| current.set(Some(fault)));
    ATTEMPTS.with(|attempts| attempts.set(0));
    let result = StarkProver.prove_extend(ExtendProofInput {
        current_d_commitment: derivation.commit(&current_key),
        next_row: &next_row,
        derivation: &derivation,
        current_d_key: &current_key,
        next_d_key: &next_key,
    });
    assert!(result.is_err());
    assert_eq!(ATTEMPTS.with(Cell::get), expected_attempts);
}

#[cfg(panic = "unwind")]
#[test]
fn active_zero_denominator_returns_native_error_without_retry() {
    assert_native_failure(Fault::ActiveZeroDenominator, 1);
}

#[cfg(panic = "unwind")]
#[test]
fn retry_exhaustion_returns_native_error_without_panicking() {
    assert_native_failure(Fault::RetryExhaustion, 1);
}

#[cfg(panic = "unwind")]
#[test]
fn unexpected_panic_returns_native_error_without_retry() {
    assert_native_failure(Fault::UnexpectedPanic, 1);
}

#[cfg(panic = "abort")]
#[test]
fn abort_build_declines_native_attempts() {
    assert_native_failure(Fault::ActiveZeroDenominator, 0);
    assert_native_failure(Fault::RetryExhaustion, 0);
    assert_native_failure(Fault::UnexpectedPanic, 0);
}
