# Embedding (M7 + follow-up) — coverage & notes

> *This document is English-only; there is no Chinese mirror. 本文档仅有英文版。*

`--embed` works for all four formats and is **bidirectionally interoperable**
with steghide 0.6 (`tests/embed_oracle.rs`, `tests/differential.rs` direction A:
Rust embed → reference extract; `tests/crack_oracle.rs`: reference embed → Rust
crack).

## Graph-matching distortion optimizer (`embed::embed_into_matched`)

Ported from steghide's `Embedder`/`Graph`/`Vertex`/`Edge`:
- Build graph vertices only for message-vertices whose sample-sum ≠ target;
  each sample gets a target value (`e_i + d (mod m)`).
- An **edge** is a *swap* of two vertices' sample values, valid iff each value
  carries the other's needed embedded value and they are neighbours
  (`sample_distance ≤ radius`); weight = the distance.
- A **beneficial, WKS-style greedy minimum-weight matching**: edges are sorted
  by weight and added greedily, but only if the swap (cost `2·weight`) is no
  costlier than fixing both vertices greedily — so the matching **never
  increases distortion**.
- Matched edges are embedded as swaps; exposed (unmatched) vertices fall back to
  the greedy least-distortion single-sample change (steghide's
  `embedExposedVertex`).

### Measured behaviour (`tests/matching.rs`)
On the standard test covers, the matching is **distortion-neutral**: for
modulus-2 1-D formats (JPEG, PCM/au) the greedy ±1 change is already optimal, so
no swap can beat it — steghide's matcher is provably neutral there too. The
optimizer's benefit appears on palette/RGB images that contain cheaper swaps; it
is image-dependent and 0 on these particular small covers. The implementation is
faithful and guaranteed never-worse.

### Approximation vs. upstream
The five upstream construction heuristics (WKS/SMD/DMD/BFSAP/DFSAP) and their
augmenting-path cardinality maximization are approximated by a single greedy
minimum-weight beneficial matching. This can leave a few more vertices exposed
than steghide's augmenting matcher, but never increases distortion and is fully
interoperable. (Embed output is non-deterministic anyway — random IV/padding and
tie-breaks — so byte-exact embed parity is not a goal.)

## Write-back
WAV/AU/BMP patch a copy of the original bytes; JPEG re-encodes the modified
coefficients as a baseline JPEG (pure-Rust entropy encoder), which libjpeg reads
back to identical coefficients.
