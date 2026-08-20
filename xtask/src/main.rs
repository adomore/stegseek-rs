//! Developer tasks.
//!
//! Subcommands:
//!   bench       [STEGO_FILE] [ITERS]              in-process crack hot-path micro-benchmark
//!   crack-bench [STEGO_FILE] [NWORDS] [THREADS]   end-to-end threaded wordlist-crack throughput
//!
//! The differential ("diff") and golden-vector checks live in the integration
//! tests (`crates/stegseek-*/tests/`); run them with
//!   STEGSEEK_REF=/path/to/stegseek cargo test --release --workspace
//!
//! `bench` measures the per-candidate work in isolation (no I/O / thread noise).
//! `crack-bench` measures full worst-case wordlist throughput (a non-matching
//! list scanned to the end) at several thread counts — the number `BENCHMARK.md`
//! compares against the C++ original, reproducible from the repo with no external
//! files.

use std::io::Write;
use std::sync::Arc;
use std::time::Instant;
use stegseek_core::crack::{crack_wordlist_file, Cracker};
use stegseek_core::format::read_file;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("bench") => bench(&args[1..]),
        Some("crack-bench") => crack_bench(&args[1..]),
        _ => {
            eprintln!("xtask subcommands:");
            eprintln!("  bench [stego_file] [iters]   crack hot-path throughput");
            eprintln!("        defaults: ../tests/data/stego/none.jpg, 2000000 iterations");
            eprintln!("  crack-bench [stego_file] [nwords] [threads_csv]");
            eprintln!("        end-to-end worst-case wordlist throughput at each thread count");
            eprintln!("        defaults: ../tests/data/stego/none.jpg, 2000000, 1,2,<max>");
            eprintln!();
            eprintln!("Build optimized first:  cargo run -p xtask --release -- crack-bench");
        }
    }
}

/// End-to-end wordlist-crack throughput: generate `nwords` non-matching entries
/// (so every candidate is checked — worst case, no early exit) and time
/// `crack_wordlist_file` at each requested thread count, best-of-3.
fn crack_bench(args: &[String]) {
    let default_stego = format!(
        "{}/../tests/data/stego/none.jpg",
        env!("CARGO_MANIFEST_DIR")
    );
    let path = args.first().cloned().unwrap_or(default_stego);
    let nwords: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);
    let max = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let threads: Vec<usize> = match args.get(2) {
        Some(csv) => csv.split(',').filter_map(|s| s.parse().ok()).collect(),
        None => {
            let mut v = vec![1usize, 2];
            if max > 2 {
                v.push(max);
            }
            v
        }
    };

    let file = match read_file(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        }
    };
    let cracker = Arc::new(Cracker::new(&*file));

    // Write a non-matching wordlist to a temp file once.
    let wl = std::env::temp_dir().join(format!("ssrs_crackbench_{}.txt", std::process::id()));
    {
        let mut w = std::io::BufWriter::new(std::fs::File::create(&wl).unwrap());
        for i in 0..nwords {
            writeln!(w, "x{i}").unwrap();
        }
    }
    let wl = wl.to_string_lossy().into_owned();

    eprintln!("wordlist-crack throughput (worst-case full scan)");
    eprintln!("  file:    {path}");
    eprintln!("  nwords:  {nwords}");
    if cfg!(debug_assertions) {
        eprintln!("  WARNING: debug build — run with `--release` for meaningful numbers");
    }
    eprintln!();
    eprintln!("{:>8}{:>12}{:>14}", "threads", "best time", "throughput");
    eprintln!("{}", "-".repeat(34));
    for &t in &threads {
        let mut best = f64::INFINITY;
        for _ in 0..3 {
            let start = Instant::now();
            let found =
                crack_wordlist_file(cracker.clone(), &wl, t, true, &path, false, None).unwrap();
            let secs = start.elapsed().as_secs_f64();
            assert!(found.is_empty(), "benchmark wordlist must not match");
            best = best.min(secs);
        }
        let mps = nwords as f64 / best / 1e6;
        eprintln!("{t:>8}{:>9.0} ms{:>9.2} M/s", best * 1e3, mps);
    }
    let _ = std::fs::remove_file(&wl);
}

fn bench(args: &[String]) {
    let default_stego = format!(
        "{}/../tests/data/stego/none.jpg",
        env!("CARGO_MANIFEST_DIR")
    );
    let path = args.first().cloned().unwrap_or(default_stego);
    let iters: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);

    let file = match read_file(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        }
    };
    let cracker = Cracker::new(&*file);

    eprintln!("crack micro-benchmark");
    eprintln!("  file:       {path}");
    eprintln!("  samples:    {}", file.num_samples());
    eprintln!("  iterations: {iters}");
    if cfg!(debug_assertions) {
        eprintln!("  WARNING: debug build — run with `--release` for meaningful numbers");
    }
    eprintln!();
    eprintln!(
        "{:40}{:>10}{:>11}{:>13}",
        "stage", "time", "throughput", "magic hits"
    );
    eprintln!("{}", "-".repeat(74));

    // 1) verify_magic_seed — the inlined-LCG magic check (no MD5). This is the
    //    common-case fast reject the seed cracker runs, and the bulk of a
    //    wordlist candidate's cost once the MD5 is done.
    let t = Instant::now();
    let mut hits = 0u64;
    for i in 0..iters {
        if cracker.verify_magic_seed(i as u32) {
            hits += 1;
        }
    }
    report(
        "verify_magic_seed (LCG magic)",
        iters,
        t.elapsed().as_secs_f64(),
        hits,
    );

    // 2) verify_magic_passphrase — MD5(passphrase) -> seed -> magic check: one
    //    wordlist candidate end to end. The passphrase is built into a reused
    //    buffer so the measurement reflects crypto+magic, not string allocation.
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    let t = Instant::now();
    let mut hits2 = 0u64;
    for i in 0..iters {
        buf.clear();
        let _ = write!(buf, "candidate{i}");
        if cracker.verify_magic_passphrase(&buf) {
            hits2 += 1;
        }
    }
    report(
        "verify_magic_passphrase (MD5+magic)",
        iters,
        t.elapsed().as_secs_f64(),
        hits2,
    );
}

fn report(label: &str, iters: u64, secs: f64, hits: u64) {
    let rate = iters as f64 / secs / 1e6;
    eprintln!(
        "{label:40}{:>7.1} ms{:>8.2} M/s{:>13}",
        secs * 1e3,
        rate,
        hits
    );
}
