//! Integration tests for tracer functionality.

#[cfg(test)]
use crate::json_loader::load_from_file;
#[cfg(test)]
use crate::trace_prove::{create_trace, verify_trace};
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::Path;

/// Run all fixtures matching prefix through create_trace/verify_trace.
/// Automatically excludes `{prefix}unique_` variants when testing base prefix.
/// Additional exclude prefixes can be passed via `extra_excludes`.
#[cfg(test)]
fn run_prefix_tests(prefix: &str) {
    run_prefix_tests_with_excludes(prefix, &[]);
}

#[cfg(test)]
fn run_prefix_tests_with_excludes(prefix: &str, extra_excludes: &[&str]) {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_fixtures");
    let exclude = format!("{prefix}unique_");

    let mut files: Vec<String> = fs::read_dir(&fixtures_dir)
        .expect("Failed to read test_fixtures directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with(prefix)
                && file_name.ends_with(".json")
                && !file_name.starts_with(&exclude)
                && !extra_excludes.iter().any(|ex| file_name.starts_with(ex))
            {
                Some(entry.path().to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect();
    files.sort();

    assert!(!files.is_empty(), "No {prefix}* fixtures found");

    for path in files {
        println!("Testing fixture: {path}");
        let (full_tree, steps) = load_from_file(&path);
        let traced_fixture = create_trace(&full_tree, &steps);
        verify_trace(&traced_fixture).expect("traced_fixture should verify");
        println!("  ✓ Passed: {} steps verified", steps.len());
    }
}

#[test]
fn test_trace_delete() {
    run_prefix_tests("delete_");
}

#[test]
fn test_trace_delete_unique() {
    run_prefix_tests("delete_unique_");
}

#[test]
fn test_trace_insert() {
    run_prefix_tests("insert_");
}

#[test]
fn test_trace_insert_unique() {
    run_prefix_tests("insert_unique_");
}

#[test]
fn test_trace_serial() {
    run_prefix_tests("serial_");
}

#[test]
fn test_trace_single_update() {
    run_prefix_tests("single_update_");
}

#[test]
fn test_trace_update() {
    run_prefix_tests("update_");
}

#[test]
fn test_trace_update_unique() {
    run_prefix_tests("update_unique_");
}

#[test]
fn test_trace_read() {
    run_prefix_tests_with_excludes("read_", &["read_range_", "read_prefix_"]);
}

#[test]
fn test_trace_read_range() {
    run_prefix_tests("read_range_");
}

#[test]
fn test_trace_read_prefix() {
    run_prefix_tests("read_prefix_");
}

#[test]
fn test_trace_mixed() {
    run_prefix_tests("mixed_");
}
