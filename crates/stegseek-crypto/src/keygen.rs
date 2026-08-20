//! KEYGEN_MCRYPT key derivation (libmhash), as used by steghide via
//! `MHashKeyGen(KEYGEN_MCRYPT, MHASH_MD5, keysize)` with no salt and count 0.
//!
//! Algorithm (verified bit-exact against libmhash 0.9.9.9):
//! ```text
//! key = []
//! i = 0
//! while i < keysize:
//!     digest = MD5(password ‖ key[0..i])   // key[0..i] is empty when i == 0
//!     append first min(16, keysize - i) bytes of digest to key
//!     i += 16
//! ```
//! i.e. each block hashes the password **followed by** the key bytes produced
//! so far. (libmhash hashes salt/password then the running key; steghide uses
//! no salt.)

use md5::{Digest, Md5};

const MD5_SIZE: usize = 16;

/// Derive a `keysize`-byte key from `password` exactly as libmhash's
/// KEYGEN_MCRYPT does with MD5.
pub fn keygen_mcrypt_md5(password: &[u8], keysize: usize) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(keysize + MD5_SIZE);
    let mut i = 0usize;
    while i < keysize {
        let mut h = Md5::new();
        h.update(password);
        h.update(&key[0..i]); // exactly i bytes generated so far (empty at i==0)
        let digest = h.finalize();
        let take = std::cmp::min(MD5_SIZE, keysize - i);
        key.extend_from_slice(&digest[0..take]);
        i += MD5_SIZE;
    }
    key.truncate(keysize);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Golden vectors from the system libmhash 0.9.9.9 KEYGEN_MCRYPT(MHASH_MD5).
    #[test]
    fn keygen_matches_libmhash_golden() {
        assert_eq!(hex(&keygen_mcrypt_md5(b"", 8)), "d41d8cd98f00b204");
        assert_eq!(
            hex(&keygen_mcrypt_md5(b"", 16)),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hex(&keygen_mcrypt_md5(b"", 24)),
            "d41d8cd98f00b204e9800998ecf8427e59adb24ef3cdbe02"
        );
        assert_eq!(
            hex(&keygen_mcrypt_md5(b"", 32)),
            "d41d8cd98f00b204e9800998ecf8427e59adb24ef3cdbe0297f05b395827453f"
        );

        assert_eq!(hex(&keygen_mcrypt_md5(b"abc", 8)), "900150983cd24fb0");
        assert_eq!(
            hex(&keygen_mcrypt_md5(b"abc", 24)),
            "900150983cd24fb0d6963f7d28e17f725567b5b1fead6d02"
        );
        assert_eq!(
            hex(&keygen_mcrypt_md5(b"abc", 32)),
            "900150983cd24fb0d6963f7d28e17f725567b5b1fead6d0204c32317844fdc96"
        );

        assert_eq!(
            hex(&keygen_mcrypt_md5(b"password", 32)),
            "5f4dcc3b5aa765d61d8327deb882cf997ca8c41324cfd758a707ea70233cb90a"
        );
        assert_eq!(
            hex(&keygen_mcrypt_md5(b"hunter2", 16)),
            "2ab96390c7dbe3439de74d0c9b0b1767"
        );
        assert_eq!(
            hex(&keygen_mcrypt_md5(b"Schwierig", 32)),
            "8453b4cb13bab0acdfa0a528270d827148401b1883e0f20571c8ef547413f36c"
        );
    }

    #[test]
    fn keygen_prefix_property() {
        // A shorter key is a prefix of a longer one (same password).
        let k32 = keygen_mcrypt_md5(b"hunter2", 32);
        for ks in [8usize, 16, 24] {
            assert_eq!(keygen_mcrypt_md5(b"hunter2", ks), k32[..ks]);
        }
    }
}
