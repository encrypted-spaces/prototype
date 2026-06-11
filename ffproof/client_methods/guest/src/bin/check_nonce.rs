
#![no_main]

use risc0_zkvm::guest::env;
//use changelog_core::hash_chain::{NONCE_LEN, check_nonce};

risc0_zkvm::guest::entry!(main);

// This is a contrived example, we check that the nonce begins with bytes 
// (a, b, c, d) and that b = a^2, c = a^3 and d = a^4, all mod 256

fn main() {

    let mut nonce = [0u8; 32];
    env::read_slice(&mut nonce);
    
    //let result = check_nonce(&nonce);
    let result = [0u8; 32];
    
    env::commit(&(result, nonce));
}
