use std::collections::HashMap;

const GUEST_PACKAGE: &str = "encrypted-spaces-ffproof-bench";

fn main() {
    risc0_build::embed_methods_with_options(guest_options());
}

// Forward the host-side `avl` feature into the RISC-V guest build so host and
// guest agree on the merk backend (MRT is the default on both sides).
fn guest_options() -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut options = HashMap::new();
    if std::env::var_os("CARGO_FEATURE_AVL").is_some() {
        let mut guest_options = risc0_build::GuestOptions::default();
        guest_options.features.push("avl".to_string());
        options.insert(GUEST_PACKAGE, guest_options);
    }
    options
}
