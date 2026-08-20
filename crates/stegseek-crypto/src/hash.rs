//! Hash primitives matching steghide's libmhash usage.
//!
//! - `md5`: standard MD5 (libmhash `MHASH_MD5`).
//! - `crc32_steghide`: the checksum embedded by steghide. steghide uses
//!   libmhash `MHASH_CRC32`, which (unlike `MHASH_CRC32B`, the usual
//!   zlib/IEEE CRC-32) is **CRC-32/BZIP2** (poly 0x04C11DB7, init/xorout
//!   0xFFFFFFFF, non-reflected). steghide stores the 4 result bytes
//!   little-endian and reads them back with `getValue(0,32)`, so the integer
//!   value it compares equals the CRC-32/BZIP2 checksum directly.
//! - `md5_fold_seed`: the passphrase→seed derivation (XOR of the four
//!   little-endian u32 words of the MD5 digest).

use md5::{Digest, Md5};

/// Standard MD5 digest (16 bytes).
pub fn md5(data: &[u8]) -> [u8; 16] {
    let d = Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d);
    out
}

/// CRC-32/BZIP2 (poly 0x04C11DB7, init 0xFFFFFFFF, non-reflected, xorout
/// 0xFFFFFFFF) — the value steghide embeds/verifies via libmhash MHASH_CRC32.
pub fn crc32_steghide(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Derive steghide's 32-bit seed from a passphrase: four little-endian u32
/// words of MD5(passphrase), XOR-folded together.
pub fn md5_fold_seed(passphrase: &[u8]) -> u32 {
    let d = md5(passphrase);
    let mut seed = 0u32;
    for i in 0..4 {
        seed ^= u32::from_le_bytes([d[4 * i], d[4 * i + 1], d[4 * i + 2], d[4 * i + 3]]);
    }
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors generated from the system libmhash 0.9.9.9.
    #[test]
    fn md5_matches_libmhash() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex(&md5(b"secret.txt")), "eedce3b4ab633e0eef10bc22084bd852");
    }

    #[test]
    fn crc32_is_bzip2_variant_like_libmhash_mhash_crc32() {
        assert_eq!(crc32_steghide(b""), 0x0000_0000);
        assert_eq!(crc32_steghide(b"abc"), 0x648c_bb73);
        assert_eq!(crc32_steghide(b"123456789"), 0xfc89_1918);
        assert_eq!(
            crc32_steghide(b"The quick brown fox jumps over the lazy dog"),
            0x459d_ee61
        );
        assert_eq!(crc32_steghide(b"secret.txt"), 0x8c07_48ab);
    }

    #[test]
    fn fold_seed_xors_le_words() {
        let d = md5(b"abc");
        let mut s = 0u32;
        for i in 0..4 {
            s ^= u32::from_le_bytes([d[4 * i], d[4 * i + 1], d[4 * i + 2], d[4 * i + 3]]);
        }
        assert_eq!(md5_fold_seed(b"abc"), s);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
