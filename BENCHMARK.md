# Performance / 性能测试

> *Body text is English-only; there is no Chinese mirror. 本文档正文仅有英文版。*

Head-to-head throughput of **stegseek-rs (pure Rust)** vs the **C++ `stegseek` 0.6
original**, both built and measured on the same machine. Unlike the previous
edition of this file (numbers taken from a 2-core build sandbox), every figure
below is a fresh best-of-N measurement of two binaries running side by side.

## Test environment

| | |
|---|---|
| CPU | 16 logical cores (x86-64, Kali/Debian rolling) |
| Rust | `stegseek-rs` release profile — `opt-level=3, lto=true, codegen-units=1, panic=abort` |
| C++ (stock) | `stegseek` 0.6 from `src/`, CMake `Release` = **`-O2 -s`** (the default a user gets) |
| C++ (matched) | same, rebuilt with **`-O3 -flto -DNDEBUG -s`** to match the Rust profile |
| C++ libs | statically links `libmcrypt 2.5.8`, `libmhash 0.9.9.9`, `libjpeg-turbo 3.x`, `zlib` |
| Timing | wall-clock via `perf_counter`, **best-of-N** (min = least noise), system idle |
| Workload | `--crack none.jpg <wordlist> -q -s -t <N>` (quiet, skip-default, no early exit) |

**Why a non-matching wordlist?** Every candidate is wrong, so the cracker performs
a **full worst-case scan** of the entire list — no lucky early exit — which
isolates pure per-candidate throughput.

## Result 1 — rockyou-sized full scan (14,344,391 candidates, best-of-5)

This is the headline number: a wordlist the size of `rockyou.txt`, scanned to the
end. Fixed startup (JPEG load, thread spawn) is fully amortized here, so these are
the most representative throughput figures.

| Threads | Rust | C++ `-O2` (stock) | C++ `-O3 -flto` | **Rust speedup** |
|:---:|:---:|:---:|:---:|:---:|
| 1  | **2790 ms · 5.14 M/s** | 3456 ms · 4.15 M/s | 3518 ms · 4.08 M/s | **1.24×** |
| 2  | **1375 ms · 10.43 M/s** | 1734 ms · 8.27 M/s | 1736 ms · 8.26 M/s | **1.26×** |
| 16 | **217 ms · 66.0 M/s** | 316 ms · 45.4 M/s | 315 ms · 45.5 M/s | **1.46×** |

## Result 2 — 2,000,001-candidate full scan (best-of-7)

| Threads | Rust | C++ `-O2` (stock) | C++ `-O3 -flto` | **Rust speedup** |
|:---:|:---:|:---:|:---:|:---:|
| 1  | **371 ms · 5.40 M/s** | 444 ms · 4.50 M/s | 469 ms · 4.26 M/s | **1.20×** |
| 2  | **195 ms · 10.25 M/s** | 262 ms · 7.62 M/s | 279 ms · 7.18 M/s | **1.34×** |
| 4  | **122 ms · 16.45 M/s** | 153 ms · 13.10 M/s | 198 ms · 10.10 M/s | **1.26×** |
| 8  | **82 ms · 24.31 M/s** | 99 ms · 20.28 M/s | 94 ms · 21.25 M/s | **1.20×** |
| 16 | **40 ms · 50.41 M/s** | 53 ms · 37.43 M/s | 51 ms · 39.32 M/s | **1.35×** |

*(At 2 M candidates and ≥8 threads the run is so short that fixed startup begins to
dominate; treat Result 1 as the canonical throughput comparison.)*

## Result 3 — realistic `rockyou.txt`

Cracking `tests/data/stego/none.jpg` against the **real** `rockyou.txt`. Its
passphrase `"Sesame"` sits at line **10,607,496 / 14,344,366 (~74 %)**, so this is
a realistic near-worst-case hit (best-of-3):

| | 2 threads | 16 threads |
|---|:---:|:---:|
| **Rust** | **0.70 s** | **0.19 s** |
| C++ `-O2` | 0.94 s | 0.31 s |

The famous *"rockyou.txt in under 2 seconds"* claim is met with a wide margin by
both tools on this hardware; the Rust port does it in ~0.2 s on 16 cores.

## Findings

1. **The pure-Rust port is 1.2–1.5× faster than the C++ original at every thread
   count**, and scales cleanly to 16 threads (66 M pw/s).
2. **`-O3 -flto` gives the C++ build no advantage over stock `-O2`** — the two are
   within noise, and `-O3` is sometimes *slightly slower* (code bloat / i-cache).
   So the fair (and if anything C++-favourable) baseline is the `-O2` binary users
   actually ship.
3. The Rust binary is also smaller and dependency-free: **873 KB as
   `cargo build --release` produces it — 744 KB stripped — with zero external
   libraries**, vs 1029 KB for the C++ binary (built `-s`, i.e. already stripped,
   and statically linking libmcrypt/libmhash/libjpeg). Sizes are for v1.0.0;
   `KB` means 1024 bytes throughout this file. (The exact byte count varies by a
   few bytes with the build path, which rustc embeds.)

## Why the Rust port is faster — the two hot-path fixes

Both live in the per-candidate hot path (`crates/stegseek-core/src/crack.rs`) and
were the difference between the port trailing and leading the C++ original:

1. **Per-passphrase heap allocation.** `verify_magic_seed` allocated its RNG
   collision buffer with `vec![0u32; 25 * spv]` — a `malloc`/`free` on *every*
   candidate. steghide keeps this on the stack (`UWORD32 rngBuf[25*samplesPerVertex]`).
   Replaced with a fixed stack array (`[0u32; 128]`, sliced to `25*spv`; spv ≤ 3 for
   every supported format). A counting-allocator regression test
   (`crates/stegseek-core/tests/hotpath_no_alloc.rs`) asserts **0 heap allocations**
   across 100 k calls.
2. **Per-line `lseek` syscall.** `consume_wordlist` called
   `BufReader::stream_position()` once per line (an `lseek` syscall — millions of
   them over a large wordlist). C++ uses `ftell`, a cheap userspace read. Replaced
   with a running byte counter (`pos += bytes_read`), bit-identical and syscall-free.

Both are behaviour-preserving; the differential harness and all crack/extract tests
pass unchanged.

## Where the time goes now

In-process micro-benchmark (`cargo run -p xtask --release -- bench`, single thread):

| Stage | Throughput |
|-------|-----------|
| `verify_magic_seed` (LCG magic check) | ~24.6 M/s |
| `verify_magic_passphrase` (MD5 + magic) | ~7.1 M/s |

The magic check is now extremely cheap; **MD5 of the passphrase is ~73 % of
per-candidate cost.** That MD5 is steghide's seed derivation and cannot be changed
without breaking file compatibility, so it is the practical floor. Further gains
would require a SIMD / multi-buffer MD5 (diminishing returns, significant
complexity) — not pursued, as the port already outruns the original.

## Embedding distortion (not a speed metric)

For completeness, embedding *quality* was also measured (fewer changed samples =
more imperceptible). This is the one axis where the port is **weaker** than
steghide, because it replaces steghide's graph-matching optimizer with a greedy
matcher (see `AUDIT.md` §7 and `EMBED_NOTES.md`):

| Cover | stegseek-rs changed samples | steghide changed samples | Ratio |
|-------|:---:|:---:|:---:|
| 24-bit RGB BMP | ~2118 | ~1584 | **1.34×** |
| 16-bit PCM WAV | ~2150 | ~2161 | **~1.0× (neutral)** |

Both tools make only ±1 changes; the gap is confined to palette/RGB images. It
affects steganographic undetectability only — output stays a valid, extractable
steghide 0.6 file. **No effect on cracking or extraction throughput/correctness.**

## Reproduce

**Build the C++ oracle without root** (Kali/Debian):
```bash
# grab dev headers + static archives without installing
apt-get download libmcrypt-dev libmhash-dev libjpeg62-turbo-dev
for d in *.deb; do dpkg-deb -x "$d" prefix/; done
cp prefix/usr/include/x86_64-linux-gnu/jconfig.h prefix/usr/include/   # libjpeg-turbo split header
PFX="$PWD/prefix/usr"
( cd stegseek-master && mkdir -p build && cd build
  cmake -DCMAKE_INCLUDE_PATH="$PFX/include" -DCMAKE_LIBRARY_PATH="$PFX/lib/x86_64-linux-gnu" \
        -DCMAKE_PREFIX_PATH="$PFX" .. && make -j stegseek )   # -> build/src/stegseek (self-contained)
```

**Build the Rust binary and a worst-case wordlist:**
```bash
export CARGO_TARGET_DIR="$HOME/.cache/stegseek-rs-target"   # keep target/ on a native fs
cargo build --release                                        # -> target/release/stegseek-rs
python3 -c "open('wl.txt','w').write(''.join(f'x{i}\n' for i in range(14344391)))"
```

**Time both** (full worst-case scan, quiet, skip-default):
```bash
time ./target/release/stegseek-rs --crack tests/data/stego/none.jpg wl.txt -q -s -t 16
time stegseek-master/build/src/stegseek --crack tests/data/stego/none.jpg wl.txt -q -s -t 16
```

**Repo-native benchmarks** (no external files, no C++ build needed):
```bash
# end-to-end worst-case wordlist throughput at 1 / 2 / <max> threads, best-of-3
cargo run -p xtask --release -- crack-bench [stego_file] [nwords] [threads_csv]

# per-candidate hot-path micro-benchmark (isolates crypto+magic, no I/O)
cargo run -p xtask --release -- bench [stego_file] [iterations]
```
`crack-bench` generates a non-matching wordlist internally and reports M pw/s per
thread count — the same worst-case full scan tabulated above, reproducible from a
checkout alone.
