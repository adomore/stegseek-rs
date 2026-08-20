# M3 crypto coverage vs libmcrypt 2.5.8 (the reference oracle)

All ciphers validated **bit-exact** against golden encrypt/decrypt vectors from
the system libmcrypt 2.5.8, for every supported mode (`ecb`, `cbc`, `cfb`=CFB-8,
`ncfb`=CFB-128, `ofb`=OFB-8, `nofb`=OFB-128, `ctr`, `stream`). See
`tests/golden_mcrypt.rs` + `tests/fixtures/golden_mcrypt.txt` (**108 algo×mode
vectors green**).

## Validated (18/18 — every cipher this libmcrypt provides)
none, rijndael-128 (default), rijndael-192, rijndael-256, twofish, serpent,
blowfish, des, tripledes, cast-128, cast-256, rc2, xtea, gost, **saferplus**,
**loki97**, arcfour, enigma, wake.

RustCrypto-backed: des/twofish/blowfish/cast5/cast6/serpent/rc2 (wrapped, with a
little-endian word-swap for cast-256). Hand-ported from the mcrypt source:
rijndael (128/192/256), xtea, gost (Schneier S-boxes), wake, enigma, rc4,
**saferplus** (PHT + Armenian permutation), **loki97** (GF-generated S-boxes +
64-bit Feistel).

libmcrypt quirks reproduced & tested: `cfb`/`ofb`=8-bit, `ncfb`/`nofb`=full-block,
`ctr`=big-endian counter; several ciphers load block/key words little-endian.

## Not in this libmcrypt build (4) — correctly unsupported
safer-sk64, safer-sk128, threeway, panama: `mcrypt_module_open` fails for these
in libmcrypt 2.5.8, so the reference steghide also errors on them. Refusing them
*matches* the oracle. (Upstream sources are saved under `reference/mcrypt-2.5.8/`.)
