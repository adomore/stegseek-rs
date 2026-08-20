# Building stegseek-rs

## Requirements
- Rust 1.75+ (stable). Install via https://rustup.rs.
- A C compiler/linker (`cc`) on PATH.
- For the optional `libjpeg` feature (differential baseline / fallback): system
  libjpeg **v8** headers (`libjpeg8-dev`) — see the original `Dockerfile`.

## Standard build
```bash
cargo build --release        # binary: target/release/stegseek
cargo test                   # unit + integration tests
```

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

## Differential testing (M9)
Build the reference `stegseek` 0.6 with **libjpeg8** (per the original Dockerfile)
to use as the oracle, then run `cargo run -p xtask -- diff` over the corpus.
