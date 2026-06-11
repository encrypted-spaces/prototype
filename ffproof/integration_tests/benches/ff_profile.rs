//! Profile the realistic 100-change FF workloads with RISC0's pprof support.
//!
//! This is a `harness = false` "bench" used as a small CLI. By default it
//! runs ALL workloads (currently `table` and `list`), one prove per child
//! process so each gets its own pprof file. At the end it prints the
//! `go tool pprof` commands to inspect the resulting profiles.
//!
//!   cargo bench -p encrypted-spaces-ff-test --bench ff_profile
//!
//! Override the workload list with `BENCH_PPROF_WORKLOADS=table,list`
//! (comma-separated). Override the pprof output dir with
//! `BENCH_PPROF_DIR=/some/dir` (default `/tmp`).
//!
//! Internal: when `BENCH_PPROF_WORKLOAD` is set the binary runs in
//! single-workload mode (one prove, one pprof file). The parent process
//! re-execs itself per workload to keep each profile isolated — running
//! both proves in one process would have the second prove overwrite the
//! first's pprof output.
//!
//! Notes on the RISC0 memory model:
//!   * `user_cycles`    — guest instructions executed; this is what the
//!     pprof profile attributes to source locations.
//!   * `paging_cycles`  — overhead for paging memory in/out of the zkVM's
//!     working set. NOT attributed by pprof to specific guest functions,
//!     but it's a real proving cost (more pages touched ⇒ more paging).
//!   * `total_cycles`   — user + paging + reserved (segment housekeeping).

#[path = "ff_common/mod.rs"]
mod ff_common;

use ff_common::{lookup_workload, WORKLOADS};

/// Narrow RUST_LOG default: only the session module logs at INFO, so
/// we get the per-prove cycle/ecall summary but not the executor's
/// unconditional `execution time:` line.
const DEFAULT_RUST_LOG: &str = "error,risc0_zkvm::host::server::session=info";

fn main() {
    // Default to dev mode unless caller overrode — pprof works in either
    // mode but real proofs are very slow.
    if std::env::var_os("RISC0_DEV_MODE").is_none() {
        std::env::set_var("RISC0_DEV_MODE", "1");
    }
    // Surface RISC0's own session INFO log (segments, ecall counts +
    // cycles per kind including Sha2).  Scope INFO to the `session`
    // module so the executor's per-run `execution time:` line (which
    // fires unconditionally at INFO) doesn't show up for the workload's
    // own throwaway seed proves.  NOTE: this in-process `set_var` is
    // too late for risc0's tracing subscriber, which reads `RUST_LOG`
    // before `main` runs.  The setting only takes effect when passed to
    // children via `Command::env` below; for users running this binary
    // directly, set `RUST_LOG` in the shell.
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", DEFAULT_RUST_LOG);
    }
    // RISC0_INFO is gated per-prove inside `run_one_workload` so that
    // throwaway seed proves (action workloads that pre-populate fixture
    // rows) don't double up the session log.  Make sure it's not
    // already set globally.
    std::env::remove_var("RISC0_INFO");
    std::env::set_var("RISC0_GUEST_LOGFILE", "/dev/null");

    let pprof_dir = std::env::var("BENCH_PPROF_DIR").unwrap_or_else(|_| "/tmp".to_string());

    match std::env::var("BENCH_PPROF_WORKLOAD") {
        // Child mode: prove exactly one workload, write its pprof file.
        Ok(workload) => run_one_workload(&workload, &pprof_dir),
        // Parent mode: re-exec self per workload, then print pprof commands.
        Err(_) => run_all_workloads(&pprof_dir),
    }
}

fn default_workload_list() -> String {
    WORKLOADS
        .iter()
        .map(|w| w.name)
        .collect::<Vec<_>>()
        .join(",")
}

fn run_all_workloads(pprof_dir: &str) {
    let workloads: Vec<String> = std::env::var("BENCH_PPROF_WORKLOADS")
        .unwrap_or_else(|_| default_workload_list())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let exe = std::env::current_exe().expect("could not locate current_exe");
    eprintln!(
        "ff_profile: running {} workload(s): {:?}",
        workloads.len(),
        workloads
    );
    eprintln!("ff_profile: pprof output dir = {pprof_dir}");

    let mut produced: Vec<(String, String)> = Vec::new();
    for workload in &workloads {
        if lookup_workload(workload).is_none() {
            let known: Vec<&str> = WORKLOADS.iter().map(|w| w.name).collect();
            eprintln!("ff_profile: unknown workload {workload:?} (known: {known:?})");
            std::process::exit(2);
        }
        let out = format!("{pprof_dir}/ff_pprof_{workload}.pb");
        eprintln!();
        eprintln!("================================================================");
        eprintln!("  ff_profile: spawning child for workload `{workload}`");
        eprintln!("  pprof out : {out}");
        eprintln!("================================================================");
        let status = std::process::Command::new(&exe)
            .env("BENCH_PPROF_WORKLOAD", workload)
            .env("RISC0_PPROF_OUT", &out)
            // Set in the child's startup env so risc0's tracing
            // subscriber picks it up before `main` runs.
            .env("RUST_LOG", DEFAULT_RUST_LOG)
            .status()
            .expect("failed to spawn child");
        if !status.success() {
            eprintln!("ff_profile: child for workload `{workload}` failed: {status}");
            std::process::exit(status.code().unwrap_or(1));
        }
        produced.push((workload.clone(), out));
    }

    eprintln!();
    eprintln!("================================================================");
    eprintln!("  ff_profile: done — inspect the profiles with `go tool pprof`");
    eprintln!("================================================================");
    for (workload, path) in &produced {
        eprintln!();
        eprintln!("  # {workload}");
        eprintln!("  go tool pprof -top -nodecount=40 {path}");
        eprintln!("  go tool pprof -http=:8000          {path}");
    }
    eprintln!();
    eprintln!("  # peek into a specific symbol (cum cycles + callers/callees):");
    eprintln!("  go tool pprof -peek '<regex>' <pprof_file>");
    eprintln!();
}

fn run_one_workload(workload: &str, pprof_dir: &str) {
    let entry = lookup_workload(workload).unwrap_or_else(|| {
        let known: Vec<&str> = WORKLOADS.iter().map(|w| w.name).collect();
        panic!("unknown workload {workload:?} (known: {known:?})")
    });

    if std::env::var_os("RISC0_PPROF_OUT").is_none() {
        let default = format!("{pprof_dir}/ff_pprof_{workload}.pb");
        std::env::set_var("RISC0_PPROF_OUT", &default);
    }
    let pprof_out = std::env::var("RISC0_PPROF_OUT").unwrap();
    eprintln!("ff_profile: workload={workload}, pprof_out={pprof_out}");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (state, n_changes) = rt.block_on((entry.run)(entry.pre_pop));
    eprintln!(
        "ff_profile: applied {n_changes} changes (pre_pop={}), proving once...",
        entry.pre_pop
    );
    eprintln!("--- RISC0 session stats (raw, look for the `Sha2 calls` line) ---");

    // Only enable RISC0's session INFO log for the measured prove so
    // workload-internal proves (e.g. pre-seeding) stay quiet.
    std::env::set_var("RISC0_INFO", "1");
    let r = rt.block_on(ff_common::prove_pending_changes(&state));
    std::env::remove_var("RISC0_INFO");

    eprintln!("--- end RISC0 session stats ---");

    eprintln!();
    eprintln!("=== ff_profile {workload} (single proof, {n_changes} changes) ===");
    eprintln!("  wall_clock     : {:.2?}", r.elapsed);
    eprintln!(
        "  per-change user: {:>12} cycles",
        fmt(r.cycles / n_changes.max(1) as u64)
    );
    eprintln!();
    eprintln!("pprof file: {pprof_out}");
}

fn fmt(v: u64) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}
