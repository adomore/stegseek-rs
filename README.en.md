<div align="center">

# stegseek-rs

**A lightning-fast steghide cracker in pure Rust** — a reimplementation of [StegSeek](https://github.com/RickdeJager/stegseek) 0.6 (a fork of steghide 0.5.1)

[![CI](https://github.com/adomore/stegseek-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/adomore/stegseek-rs/actions/workflows/ci.yml)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](COPYING)
![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)
![C deps](https://img.shields.io/badge/C%20deps-none-brightgreen.svg)
![Size](https://img.shields.io/badge/binary-873%20KB-informational.svg)

**English** | [简体中文](README.md)

</div>

---

For its core purpose — **cracking and extraction** — this port is **functionally
compatible**, **bidirectionally interoperable**, and **1.2–1.5× faster** than the
C++ original (verified by end-to-end differential testing; see
[`BENCHMARK.md`](BENCHMARK.md) and [`AUDIT.md`](AUDIT.md)). Embedding is
interoperable too, but produces slightly higher distortion on palette/RGB images
(imperceptibility only, **never correctness**).

Unlike the original (which needs libmcrypt, libmhash, libjpeg and zlib), this port
has **no C-library dependencies** — everything is pure Rust, a single **873 KB**
binary, ready to run.

## ✨ Highlights

| | |
|---|---|
| ⚡ **Faster** | **1.2–1.5×** faster than the C++ original at every thread count; **66 M pw/s** on 16 cores, rockyou.txt scanned in ~**0.2 s** |
| 🔗 **Interoperable** | cracking/extraction is **byte-identical** to steghide 0.6, verified in both directions |
| 📦 **Zero deps** | no libmcrypt/libmhash/libjpeg/zlib — pure Rust, a single 873 KB file |
| 🔐 **Full crypto** | **18 ciphers × 8 mcrypt modes** + KEYGEN_MCRYPT, checked against 108 golden vectors |
| 🖼️ **Multi-format** | BMP (palette/RGB), WAV (PCM8/16), AU (PCM/µ-law), JPEG (baseline + progressive) |
| 🕵️ **Passwordless** | `--seed` brute-forces the RNG seed to detect/recover data (CVE-2021-27211) |
| 🛡️ **Robust** | corrupt/truncated JPEGs return clean errors (fuzz-hardened), never panic |
| 🧩 **steghide-compatible** | `--embed` / `--extract` / `--info` / `--encinfo` commands and output aligned |

## ⚡ Performance

Worst-case full scan of `none.jpg` against a **rockyou-sized wordlist (14,344,391
non-matching passphrases)** on a 16-core machine, best-of-5:

| Threads | stegseek-rs | C++ `-O2` (release default) | Speedup |
|:---:|:---:|:---:|:---:|
| 1 | **5.14 M/s** | 4.15 M/s | **1.24×** |
| 2 | **10.43 M/s** | 8.27 M/s | **1.26×** |
| 16 | **66.0 M/s** | 45.4 M/s | **1.46×** |

> Rebuilding the C++ with `-O3 -flto` makes it **no faster** (level with `-O2`), so
> the fair baseline is the `-O2` binary distributions actually ship. Full method
> and data in [`BENCHMARK.md`](BENCHMARK.md).

## 📦 Install / build

**Prebuilt binaries.** Every tagged release ships x86-64 Linux (gnu + musl), macOS
(Intel + Apple Silicon) and Windows builds, each with a `.sha256`:

```bash
# from https://github.com/adomore/stegseek-rs/releases/latest
tar -xzf stegseek-rs-v1.1.0-x86_64-unknown-linux-gnu.tar.gz
./stegseek-rs --version
```

**From source.** MSRV is **Rust 1.75**; details in [`BUILD-rs.md`](BUILD-rs.md).

```bash
cargo build --release        # -> target/release/stegseek-rs
cargo test --workspace
docker build -t stegseek-rs .
```

## 🚀 Usage

```bash
# crack (the default command)
stegseek-rs [stego.jpg] [wordlist.txt] [output]
stegseek-rs --crack -sf stego.jpg -wl rockyou.txt -xf out.bin

# passwordless detection / recovery (CVE-2021-27211)
stegseek-rs --seed stego.jpg

# extract / embed (steghide-compatible)
stegseek-rs --extract -sf stego.jpg -p passphrase -xf out
stegseek-rs --embed -cf cover.jpg -ef secret.txt -sf stego.jpg -p passphrase

# info
stegseek-rs --info file.jpg     # add -p <passphrase> to show embedded-file info
stegseek-rs --encinfo           # list the supported encryption algorithms
```

Common flags: `-t` thread count · `-c/--continue` keep searching after a hit to
recover several embedded files · `-q` hide progress · `-s` skip the default
guesses · `-f` overwrite existing files.

## 🧱 Layout

| Crate | Responsibility |
|---|---|
| `crates/stegseek-core` | BitString, PRNG, selector, EmbData, formats, crackers, embed |
| `crates/stegseek-crypto` | libmcrypt/libmhash-compatible crypto (18 ciphers, KEYGEN_MCRYPT) |
| `crates/stegseek-jpeg` | pure-Rust JPEG DCT decode (baseline+progressive) + baseline encode |
| `crates/stegseek-cli` | the `stegseek-rs` executable |
| `xtask` | hot-path and end-to-end throughput benchmarks |

## ✅ Tests & audit

- **86 in-tree tests** plus a **bidirectional differential** harness against a
  freshly-built C++ stegseek 0.6 oracle, covering all 18 ciphers × 4 formats ×
  plain/encrypted/compressed.
- The JPEG decoder has **deterministic fuzz** coverage (exhaustive byte
  substitution + random corruption), which turned several out-of-bounds panics
  into clean errors.
- [`AUDIT.md`](AUDIT.md) re-verified compatibility against a live C++ oracle and
  drove the current fixes (clean JPEG errors, `--info -p`, passphrase prompt,
  `--continue`, live progress, `-r/-g`).

```bash
cargo test --workspace                          # the quick suite
cargo test -p stegseek-core -- --ignored        # plus the slow full-seed scan
STEGSEEK_REF=/path/to/stegseek cargo test       # enable the differential (needs a self-built C++ oracle)
cargo run -p xtask --release -- crack-bench     # reproduce the throughput benchmark
```

## 📚 Documentation

| Document | Contents | Language |
|---|---|:---:|
| [`README.md`](README.md) · [`README.en.md`](README.en.md) | this page | ZH · EN |
| [`AUDIT.md`](AUDIT.md) | the 2026-08-18 audit against a live C++ oracle | ZH |
| [`BENCHMARK.md`](BENCHMARK.md) | throughput method, data, and how to reproduce it | EN |
| [`COMPATIBILITY.md`](COMPATIBILITY.md) | what matches steghide, and every known difference | EN |
| [`BUILD-rs.md`](BUILD-rs.md) | building, differential testing, benchmarks | EN |
| [`CHANGELOG.md`](CHANGELOG.md) | release history | ZH |
| [`EMBED_NOTES.md`](crates/stegseek-core/src/EMBED_NOTES.md) | embedding and distortion-optimizer design | EN |
| [`COVERAGE.md`](crates/stegseek-crypto/COVERAGE.md) | cipher × mode coverage against libmcrypt | EN |

Only the two READMEs exist in both languages, and CI holds them in structural
lockstep via `scripts/lockstep.py`. Every other document is single-language and
says so in a note at the top.

## 📄 License & credits

**GPL-2.0-or-later**, based on steghide 0.5.1 (Stefan Hetzl) and stegseek 0.6
(Rick de Jager). Full text in [`COPYING`](COPYING); compatibility notes in
[`COMPATIBILITY.md`](COMPATIBILITY.md).

> ⚠️ For authorized security research, CTFs and education only. Do not use it for
> unauthorized purposes.
