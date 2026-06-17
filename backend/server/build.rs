//! Build script for the inspector SPA bundling.
//!
//! `src/inspector/http.rs` embeds the SPA via `include_dir!`, which is a
//! compile-time proc macro: it reads `../inspector-ui/dist/` and panics if
//! the directory is missing. On a fresh clone — before anybody has run
//! `npm run build` in `backend/inspector-ui` — that panic blocks
//! `cargo build` entirely. This script papers over the first build by
//! writing a placeholder `dist/index.html` when the real one is absent,
//! and emits a clear `cargo:warning` telling the developer how to build
//! the real SPA.
//!
//! Secondarily, it walks `dist/` to emit `rerun-if-changed` lines and
//! hashes the contents into a `rustc-env` (`INSPECTOR_SPA_MARKER`) that
//! `http.rs` reads at compile time. Without that, cargo wouldn't know to
//! re-compile the inspector module after `npm run build` writes new
//! SPA bundles, so the embedded payload could lag the on-disk one.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

const PLACEHOLDER_HTML: &str = include_str!("inspector_placeholder.html");

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let dist = manifest_dir.join("..").join("inspector-ui").join("dist");
    let index = dist.join("index.html");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=inspector_placeholder.html");

    if !index.exists() {
        std::fs::create_dir_all(&dist)
            .unwrap_or_else(|e| panic!("create_dir_all({}): {e}", dist.display()));
        std::fs::write(&index, PLACEHOLDER_HTML)
            .unwrap_or_else(|e| panic!("write placeholder index.html: {e}"));
        println!(
            "cargo:warning=inspector SPA not built; embedding a placeholder. \
             Run `cd backend/inspector-ui && npm install && npm run build` \
             then rebuild to embed the real app."
        );
    }

    // Walk dist for change tracking *after* the placeholder write so the
    // newly-created index.html is included in the rerun-if-changed set.
    watch(&dist);

    // Hash the dist contents and surface as a rustc-env so cargo invalidates
    // the http.rs object file (and thus re-expands include_dir!) when any
    // SPA file changes.
    let marker = dist_marker(&dist);
    println!("cargo:rustc-env=INSPECTOR_SPA_MARKER={marker}");
}

fn watch(dir: &Path) {
    // `rerun-if-changed` on a missing path tells cargo to re-run build.rs
    // when that path *appears*, so emitting it once on the directory is
    // enough even when dist is empty.
    println!("cargo:rerun-if-changed={}", dir.display());
    if !dir.exists() {
        return;
    }
    if dir.is_file() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            watch(&entry.path());
        }
    }
}

fn dist_marker(dir: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    feed_metadata(dir, &mut hasher);
    format!("{:x}", hasher.finish())
}

fn feed_metadata(path: &Path, hasher: &mut DefaultHasher) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    path.to_string_lossy().hash(hasher);
    meta.len().hash(hasher);
    if let Ok(mtime) = meta.modified() {
        if let Ok(d) = mtime.duration_since(UNIX_EPOCH) {
            d.as_secs().hash(hasher);
            d.subsec_nanos().hash(hasher);
        }
    }
    if meta.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            paths.sort();
            for p in paths {
                feed_metadata(&p, hasher);
            }
        }
    }
}
