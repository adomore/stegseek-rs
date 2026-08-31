# Building stegseek-rs

> *This document is English-only; there is no Chinese mirror. 本文档仅有英文版。*

## Requirements
- Rust 1.75+ (stable). Install via https://rustup.rs.
- A C compiler/linker (`cc`) on PATH.
- No system libraries. The port has **no C-library dependencies** — libmcrypt,
  libmhash, libjpeg and zlib are all replaced by pure-Rust code.

## Standard build
```bash
cargo build --release        # binary: target/release/stegseek-rs
cargo test --workspace       # unit + integration tests
```

`Cargo.lock` is committed, so `cargo build --locked` (used by the `Dockerfile`)
reproduces the exact dependency set from a clean checkout.

## Notes for restricted/sandboxed environments
This project was bootstrapped in a sandbox with no root and a proxy-restricted
network. Two gotchas, recorded here so they aren't rediscovered:

1. **Put `target/` on a native filesystem.** On some mounted/virtual filesystems
   rustc cannot `unlink` intermediate object files (`Operation not permitted`),
   which silently corrupts builds. Set:
   ```bash
   export CARGO_TARGET_DIR="$HOME/<somewhere-native>"
   ```
2. **Crate fetch via proxy.** If `crates.io` is only reachable over a SOCKS proxy,
   configure cargo:
   ```toml
   # ~/.cargo/config.toml
   [http]
   proxy = "socks5h://localhost:1080"
   ```

## Differential testing against the C++ oracle
The differential and embed-interoperability suites are ordinary integration tests
gated on the `STEGSEEK_REF` environment variable: point it at a built `stegseek`
0.6 binary and they run; leave it unset and they return early.

```bash
STEGSEEK_REF=/path/to/stegseek cargo test --workspace
```

Build instructions for the reference `stegseek` 0.6 oracle (no root required) are
in [`BENCHMARK.md`](BENCHMARK.md) § Reproduce.

## Benchmarks
```bash
cargo run -p xtask --release -- crack-bench   # end-to-end wordlist throughput
cargo run -p xtask --release -- bench         # per-candidate hot-path micro-bench
```

## Documentation gate
The EN/ZH README pair is held in structural lockstep by a CI check:

```bash
python3 scripts/lockstep.py README.en.md README.md
```
