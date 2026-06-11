use crate::{Kem, Mkem};
use postcard::{take_from_bytes, to_allocvec};

fn from_bytes_strict<'a, T>(bytes: &'a [u8]) -> postcard::Result<T>
where
    T: serde::Deserialize<'a>,
{
    let (value, remainder) = take_from_bytes(bytes)?;
    if remainder.is_empty() {
        Ok(value)
    } else {
        Err(postcard::Error::DeserializeBadEncoding)
    }
}

fn test_pk_serialization<K: Kem>() {
    let pke = K::default();
    let mut rng = rand::rng();
    let (pk, _sk) = pke.keygen(&mut rng);
    let serialized = to_allocvec(&pk).expect("serialize public key");

    let deserialized: K::PublicKey =
        from_bytes_strict(&serialized).expect("Error deserializing a public key");
    // serialize composed deserialized is the identity
    assert_eq!(
        to_allocvec(&deserialized).expect("Error re-serializing a public key"),
        serialized
    );

    // adding bytes before or after should lead to an error
    let pk_with_prepended_bytes = [b"testtesttest".as_slice(), &serialized].concat();
    assert!(from_bytes_strict::<K::PublicKey>(&pk_with_prepended_bytes).is_err());
    let pk_with_appended_bytes = [&serialized, b"testtesttest".as_slice()].concat();
    assert!(from_bytes_strict::<K::PublicKey>(&pk_with_appended_bytes).is_err());
}

fn test_pk_serialization_mkem<M: Mkem>() {
    let pke = M::default();
    let mut rng = rand::rng();
    let (pk, _sk) = pke.keygen(&mut rng);
    let serialized = to_allocvec(&pk).expect("serialize public key");

    let deserialized: M::PublicKey =
        from_bytes_strict(&serialized).expect("Error deserializing a public key");
    // serialize composed deserialized is the identity
    assert_eq!(
        to_allocvec(&deserialized).expect("Error re-serializing a public key"),
        serialized
    );

    // adding bytes before or after should lead to an error
    let pk_with_prepended_bytes = [b"testtesttest".as_slice(), &serialized].concat();
    assert!(from_bytes_strict::<M::PublicKey>(&pk_with_prepended_bytes).is_err());
    let pk_with_appended_bytes = [&serialized, b"testtesttest".as_slice()].concat();
    assert!(from_bytes_strict::<M::PublicKey>(&pk_with_appended_bytes).is_err());
}

fn test_kem<K: Kem>() {
    let pke = K::default();
    let mut rng = rand::rng();
    let (pk, sk) = pke.keygen(&mut rng);
    let (ct, expected) = pke.encaps(&mut rng, &pk);
    let actual = pke.decaps(&sk, &ct).expect("kem decaps failed");
    assert_eq!(expected, actual);
}

fn test_mkem<M: Mkem>() {
    let pke = M::default();
    let mut rng = rand::rng();
    let mut pks = Vec::new();
    let mut sks = Vec::new();
    for _ in 0..10 {
        let (pk, sk) = pke.keygen(&mut rng);
        pks.push(pk);
        sks.push(sk);
    }
    let (ct, expected) = pke.encaps(&mut rng, &pks);
    let serialized_ct = to_allocvec(&ct).expect("serialize mkem ciphertext");
    let deserialized_ct: M::Ciphertext =
        from_bytes_strict(&serialized_ct).expect("deserialize mkem ciphertext");
    for (index, sk) in sks.iter().enumerate() {
        let individual = pke.get(&deserialized_ct, index).expect("mkem get failed");
        let serialized_individual =
            to_allocvec(&individual).expect("serialize individual mkem ciphertext");
        let individual: M::IndividualCiphertext = from_bytes_strict(&serialized_individual)
            .expect("deserialize individual mkem ciphertext");
        let actual = pke.decaps(sk, &individual).expect("mkem decaps failed");
        assert_eq!(expected, actual);
    }
}

#[test]
fn test_pk_serialization_mlkem768() {
    test_pk_serialization::<crate::pke::mlkem::MlKem768>();
}

#[test]
fn test_pk_serialization_ristretto() {
    test_pk_serialization_mkem::<crate::pke::ristretto255::Ristretto255Dh>();
}

#[test]
fn test_pk_serialization_xwing() {
    test_pk_serialization::<crate::pke::xwing::XWing>();
}

#[test]
fn test_pk_serialization_xwing_ristretto() {
    test_pk_serialization::<crate::pke::xwing_ristretto255::XWingRistretto>();
}

#[test]
fn test_kem_mlkem768() {
    test_kem::<crate::pke::mlkem::MlKem768>();
}

#[test]
fn test_kem_xwing() {
    test_kem::<crate::pke::xwing::XWing>();
}

#[test]
fn test_kem_xwing_ristretto() {
    test_kem::<crate::pke::xwing_ristretto255::XWingRistretto>();
}

#[test]
fn test_mkem_mlkem768() {
    test_mkem::<crate::pke::mlkem::MlKem768>();
}

#[test]
fn test_mkem_ristretto() {
    test_mkem::<crate::pke::ristretto255::Ristretto255Dh>();
}

#[test]
fn test_mkem_xwing() {
    test_mkem::<crate::pke::xwing::XWing>();
}

#[test]
fn test_mkem_xwing_ristretto() {
    test_mkem::<crate::pke::xwing_ristretto255::XWingRistrettoMkem>();
}
