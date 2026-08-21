# Compatibility with steghide 0.5.1 / stegseek 0.6

stegseek-rs is validated **bidirectionally against a built-from-source stegseek 0.6
oracle** (linked against the system `libmcrypt 2.5.8` / `libmhash 0.9.9.9` /
`libjpeg-turbo 3.x`). The following were confirmed **bit-for-bit / byte-for-byte
compatible by end-to-end differential testing** (not just golden fixtures — see
`AUDIT.md` §2):

- **Cracking**: passwords and seeds found match the oracle; extracted files are
  byte-identical. 13 block ciphers (× CBC) and all 3 stream ciphers (× stream)
  embedded by the C++ tool were cracked and extracted byte-identically by
  stegseek-rs.
- **`--encinfo`**: the set of 18 encryption algorithms listed is **identical** to
  the oracle's (only the enumeration order differs).
- **Extraction**: the EmbData frame, decryption (KEYGEN_MCRYPT + ciphers × 8
  modes), zlib decompression (levels 1–9, both directions), CRC-32 (BZIP2 variant),
  filename handling, and computed `--info` capacity all match — verified on all
  four formats.
- **Embedding (interoperability)**: files embedded by stegseek-rs are extracted
  correctly by the original steghide across all formats and ciphers, and
  vice-versa. Verified on 9 cover variants (palette/RGB BMP, PCM8/16 WAV,
  PCM8/mu-law AU, baseline + progressive JPEG).
- **`--seed` (CVE-2021-27211)**: finds the identical seed and produces a
  byte-identical extraction.
- **CLI basics**: default cipher (rijndael-128/cbc), `[i]`/`[w]`/`[e]` message
  prefixes, color gated on TTY, and exit codes (0 found / non-zero
  not-found+error) match.

> **Deliberate divergence — the identity banner.** Since v1.0.0 the binary is
> named `stegseek-rs` and its `--version` / start-up banner reads
> `stegseek-rs <version> - https://github.com/adomore/stegseek-rs` (verbose adds
> `based on steghide 0.5.1, compatible with stegseek 0.6`), instead of mirroring
> the upstream `StegSeek 0.6 - …` line. Only this one identity line differs; the
> per-result output (`[i] Found passphrase`, `Original filename`, `Extracting
> to`, the `[i]`/`[w]`/`[e]` prefixes) and exit codes are unchanged, so tools that
> parse the *result* lines are unaffected.

## Fixed since the audit (2026-08-18)

The JPEG-panic robustness bug and every confirmed CLI/functional gap were fixed
and re-verified against the C++ oracle (`AUDIT.md` §0): JPEG decoder now returns a
clean error instead of panicking on truncated/corrupt input; arithmetic/lossless
JPEG is explicitly rejected; `--info -p` reports embedded-data properties
(byte-identical to the oracle); a missing `-p` now prompts (echo-off) instead of
silently using an empty key; `--extract` defaults to the embedded filename;
`-c/--continue` recovers multiple embedded files (`.out`/`.out.1`/…); live
`Progress:` metrics are emitted and hidden by `-q`; `-r/--radius` and `-g/--goal`
are accepted (radius applied to embedding); `-z` is range-checked; and the seed
cracker now tests `0xFFFFFFFF`. Full bidirectional interoperability and 61/61
tests are preserved.

## Known differences

Ranked by user impact. Full evidence and the complete list are in `AUDIT.md`.

### Correctness / robustness

1. **Embedding distortion (quality, not correctness).** The graph-matching
   optimizer is replaced by a single greedy beneficial minimum-weight matching,
   with an 8192-vertex cap above which it degrades to pure greedy. Output is always
   a valid, interoperable steghide 0.6 file, but on **palette/RGB images** it
   changes ~**1.34×** as many samples as steghide (measured). On JPEG and audio
   (1-D, modulus-2 formats) it is **distortion-neutral** (measured: WAV 2150 vs
   2161). Affects steganographic undetectability only — never extraction or
   cracking. Embed is non-deterministic (random IV/padding), so byte-exact embed
   parity is not a goal. See `EMBED_NOTES.md`.

2. **24-bit RGB BMP embedding never modifies the red channel.** All ±1 changes are
   concentrated in the B and G channels (measured: B/G changed, R=0), whereas
   steghide spreads them across all three. Both tools use only ±1 changes; this
   contributes to difference (1) above. Imperceptibility only.

3. **Passphrase with a NUL byte.** steghide truncates the passphrase at the first
   NUL for key derivation; stegseek-rs uses the full byte slice. Rare, but would
   make such a passphrase non-interoperable.

### Cipher set — build-specific caveat

4. **Four ciphers absent: safer-sk64, safer-sk128, threeway, panama.** These are
   not implemented in stegseek-rs. In **the libmcrypt build used to validate**
   (Debian/Kali `libmcrypt 2.5.8-8+b2`) those algorithm modules are **also absent
   from the library** — its only "safer" cipher is `saferplus` (Safer+) — so the
   reference steghide linked against it likewise refuses them on every mode, and
   stegseek-rs *matches the oracle*. This was verified empirically (`AUDIT.md` §6).

   > **Portability caveat:** this is a property of *this* libmcrypt build, not a
   > universal guarantee. A steghide linked against a fully-built upstream libmcrypt
   > that *does* expose these four modules could produce files stegseek-rs cannot
   > extract. Files encrypted with these ciphers are rare (default is rijndael-128).

### JPEG format coverage

5. **JPEG output is always baseline.** A progressive cover is re-emitted as a
   baseline JPEG on embed. The embedded data lives in the (preserved) coefficients,
   so this is transparent to extraction (verified: progressive round-trips).
6. **Arithmetic-coded / lossless JPEG is not *decoded*** — it is now explicitly
   rejected with a clear message (previously a generic error). Implementing an
   arithmetic-coded JPEG decoder is out of scope; standard 8-bit Huffman
   baseline/progressive is fully supported, and 12-bit precision is now rejected
   rather than silently mis-decoded.

### CLI / pipeline surface (remaining, lower-value)

Most CLI gaps were fixed (see "Fixed since the audit" above). Still open:

7. **Misc. steghide conventions**: stdin/stdout `-` value not honored; looser
   per-command flag / duplicate-flag / `-e` algo·mode validation; passphrase not
   scrubbed from `argv` (visible in `ps`); `--help -v` steghide-help block absent;
   cover-security warnings and BMP padding-byte normalization omitted; top-down
   (negative-height) BMPs are accepted by stegseek-rs but crash/reject in steghide.
   (`-g/--goal` is accepted but only coarsely honored — `goal=0` disables the
   optimizer — since the greedy matcher has no cardinality-target knob.)

## Bottom line

For **cracking and extraction** — stegseek's headline purpose — stegseek-rs is a
faithful, fully-interoperable, and *faster* reimplementation (see `BENCHMARK.md`).
The differences above are concentrated in **embedding quality** and the
**CLI/pipeline periphery**; none of them affect the correctness of cracking or
extracting mainstream steghide files.

GPL-2.0-or-later, based on steghide 0.5.1 (Stefan Hetzl) and stegseek 0.6
(Rick de Jager).
