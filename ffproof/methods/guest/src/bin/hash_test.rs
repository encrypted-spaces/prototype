#![no_main]

risc0_zkvm::guest::entry!(main);

fn main() {
    encrypted_spaces_changelog_core::zkvm_hash_tests();
}
