use encrypted_spaces_crypto::key_derivation::DerivationKoalaBearPoseidon2_16;
use encrypted_spaces_crypto::key_derivation::KeyDerivation;
use encrypted_spaces_crypto::KeyMaterial;
use encrypted_spaces_key_manager::{MemoryOperationBuilder, OperationBuilder};

use super::super::space_key::encrypt_d_head;
use super::super::store::*;

fn derivation() -> DerivationKoalaBearPoseidon2_16 {
    DerivationKoalaBearPoseidon2_16::default()
}

// ===================================================================
// Scalar metadata round-trip tests
// ===================================================================

#[tokio::test]
async fn u64_round_trip() {
    let mut builder = MemoryOperationBuilder::new();
    save_u64(&mut builder, "test/scalar", 42).await;
    let loaded = load_u64_required(&builder, "test/scalar")
        .await
        .expect("load u64");
    assert_eq!(loaded, 42);
}

#[tokio::test]
async fn missing_u64_returns_none() {
    let builder = MemoryOperationBuilder::new();
    let result: Option<u64> = load_u64(&builder, "nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn missing_required_u64_returns_err() {
    let builder = MemoryOperationBuilder::new();
    assert!(load_u64_required(&builder, "nonexistent").await.is_err());
}

// ===================================================================
// Row round-trip tests
// ===================================================================

#[tokio::test]
async fn fgk_row_round_trip() {
    let mut builder = MemoryOperationBuilder::new();
    let d = derivation();
    let row = FGKRow {
        d_start: 42,
        commitment: d.commit(&KeyMaterial::random()),
    };
    save_fgk_row(&mut builder, 7, &row).await;
    let loaded = load_fgk_row(&builder, 7).await.expect("load fgk row");
    assert_eq!(loaded, row);
}

#[tokio::test]
async fn dgk_row_round_trip() {
    let mut builder = MemoryOperationBuilder::new();
    let d = derivation();
    let row = DGKRow {
        commitment: d.commit(&KeyMaterial::random()),
    };
    save_dgk_row(&mut builder, 0, &row).await;
    let loaded = load_dgk_row(&builder, 0).await.expect("load dgk row");
    assert_eq!(loaded, row);
}

#[tokio::test]
async fn d_row_round_trip() {
    let mut builder = MemoryOperationBuilder::new();
    let d = derivation();
    let row = DTableRow {
        seq: 7,
        commitment: d.commit(&KeyMaterial::random()),
    };
    save_d_row(&mut builder, &row).await;
    let loaded = load_d_row(&builder, 7).await.expect("load d row");
    assert_eq!(loaded, row);
}

#[tokio::test]
async fn gbct_row_round_trip() {
    let mut builder = MemoryOperationBuilder::new();
    let d = derivation();
    let hgk = KeyMaterial::random();
    let d0 = KeyMaterial::random();
    let pair = GBCiphertextPair {
        older_gb_key_ciphertext: None,
        d_head_ciphertext: encrypt_d_head(&d, &hgk, &d0),
    };
    save_gbct_row(&mut builder, 0, &pair).await;
    let loaded = load_gbct_row(&builder, 0, true)
        .await
        .expect("load gbct row");
    assert_eq!(loaded, pair);
}

#[tokio::test]
async fn gbct_row_malformed_ciphertext_returns_err() {
    let mut builder = MemoryOperationBuilder::new();
    builder.put("sl2/gbct/row/0/d_head_ct", vec![0u8; 10]).await;
    assert!(load_gbct_row(&builder, 0, true).await.is_err());

    let d = derivation();
    let hgk = KeyMaterial::random();
    let d0 = KeyMaterial::random();
    let pair = GBCiphertextPair {
        older_gb_key_ciphertext: None,
        d_head_ciphertext: encrypt_d_head(&d, &hgk, &d0),
    };
    save_gbct_row(&mut builder, 1, &pair).await;
    builder.put("sl2/gbct/row/1/gb_ct", vec![0u8; 10]).await;
    assert!(load_gbct_row(&builder, 1, false).await.is_err());
}

#[tokio::test]
async fn missing_row_returns_err() {
    let builder = MemoryOperationBuilder::new();
    assert!(load_fgk_row(&builder, 99).await.is_err());
    assert!(load_dgk_row(&builder, 99).await.is_err());
    assert!(load_d_row(&builder, 99).await.is_err());
    assert!(load_gbct_row(&builder, 99, false).await.is_err());
}
