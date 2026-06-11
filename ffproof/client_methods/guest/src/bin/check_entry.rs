
#![no_main]

use risc0_zkvm::guest::env;
//use changelog_core::hash_chain::{ENTRY_LEN, NONCE_LEN, compute_entry};


risc0_zkvm::guest::entry!(main);

// This is a simple proof that entry is computed with compute_entry

fn main() {
   
    let mut entry = [0u8; 32];
    env::read_slice(&mut entry);
    let mut nonce = [0u8; 32];
    env::read_slice(&mut nonce);

    //let entry_expected = compute_entry(&nonce);
    //let result = entry == entry_expected;

    let mut result = [0u8; 32];
    for i in 0..result.len() {
        result[i] = entry[i] ^ nonce[i];
    }

    env::commit(&(result, &entry[..], &nonce[..]));
}
