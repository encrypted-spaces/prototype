// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;

const GUEST_PACKAGE: &str = "encrypted-spaces-ffproof";

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
