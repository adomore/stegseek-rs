**English** | [简体中文](README.md)

# stegseek-rs

[![CI](https://github.com/adomore/stegseek-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/adomore/stegseek-rs/actions/workflows/ci.yml)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](COPYING)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)
![C deps](https://img.shields.io/badge/C%20deps-none-brightgreen.svg)

A **pure-Rust** reimplementation of [StegSeek](https://github.com/RickdeJager/stegseek) 0.6
(a fork of steghide 0.5.1) — a lightning-fast steghide cracker. For its core
purpose — **cracking and extraction** — this port is **functionally compatible**,
**bidirectionally interoperable**, and **1.2–1.5× faster** than the C++ original
(verified by end-to-end differential testing; see [`BENCHMARK.md`](BENCHMARK.md)
and [`AUDIT.md`](AUDIT.md)). Embedding is interoperable too, but produces
higher-distortion (less imperceptible) stego on palette/RGB images — quality only,
never a correctness issue.

Unlike the original (which needs libmcrypt, libmhash, libjpeg and zlib), this
port has **no C-library dependencies** — everything is pure Rust (823 KB binary,
zero external libs).

## Features

- **Cracking & extraction**: bit-exact, bidirectionally interoperable with steghide 0.6.
- **18 ciphers × 8 mcrypt modes** + KEYGEN_MCRYPT, validated against 108 golden vectors.
- **4 formats**: BMP (palette/RGB), WAV (PCM8/16), AU (PCM/µ-law), JPEG (baseline + progressive).
- **`--seed`** passwordless detection/recovery (CVE-2021-27211).
- **steghide-compatible** `--embed` / `--extract` / `--info` / `--encinfo`.
- Robust: corrupt/truncated JPEGs return clean errors (fuzz-hardened), never panic.

## Usage

```bash
# crack (default command)
stegseek [stegofile.jpg] [wordlist.txt] [output]
stegseek --crack -sf stego.jpg -wl rockyou.txt -xf out.bin

# passwordless detection / recovery (CVE-2021-27211)
stegseek --seed stego.jpg

# extract / embed (steghide-compatible)
stegseek --extract -sf stego.jpg -p passphrase -xf out
stegseek --embed -cf cover.jpg -ef secret.txt -sf stego.jpg -p passphrase

# info
stegseek --info file.jpg
stegseek --encinfo
```

## Build

```bash
cargo build --release       # -> target/release/stegseek
cargo test --workspace
```
MSRV: Rust 1.75. See [`BUILD-rs.md`](BUILD-rs.md). Docker: `docker build -t stegseek-rs .`.

## Performance

**1.2–1.5× faster than the C++ original** at every thread count (66 M pw/s on 16
cores; rockyou.txt in ~0.2 s). `-O3 -flto` gives the C++ build no advantage over
its stock `-O2`. Full head-to-head measured on one machine in [`BENCHMARK.md`](BENCHMARK.md).

## Layout

- `crates/stegseek-core` — bitstring, PRNG, selector, embdata, formats, crackers, embed
- `crates/stegseek-crypto` — libmcrypt/libmhash-compatible crypto (18 ciphers, KEYGEN_MCRYPT)
- `crates/stegseek-jpeg` — pure-Rust JPEG DCT decode (baseline+progressive) + baseline encode
- `crates/stegseek-cli` — the `stegseek` binary

## Validation & audit

86 in-tree tests + a bidirectional differential harness against a freshly-built
stegseek 0.6 oracle, covering all 18 ciphers × all 4 formats ×
plain/encrypted/compressed. A 2026-08-18 audit ([`AUDIT.md`](AUDIT.md)) re-verified
this against a live C++ oracle and drove the current fixes (clean JPEG errors,
`--info -p`, passphrase prompt, `--continue`, progress metrics, `-r/-g`).

## Compatibility & license

See [`COMPATIBILITY.md`](COMPATIBILITY.md). GPL-2.0-or-later, based on steghide 0.5.1
(Stefan Hetzl) and stegseek 0.6 (Rick de Jager).
