//! High-level, byte-oriented crypto facade mirroring `MCryptPP`.
//! Dispatches an (algorithm, mode) pair to the right cipher + mode and applies
//! it in place. The BitString-level wrapper (random IV/padding) lives in
//! stegseek-core, which owns BitString and the RandomSource.

use crate::algorithm::EncryptionAlgorithm;
use crate::cipher::block_cipher_by_name;
use crate::cipher::stream::apply_stream;
use crate::keygen::keygen_mcrypt_md5;
use crate::mode::EncryptionMode;
use crate::modes::*;

/// Whether this build can encrypt/decrypt the given algorithm.
pub fn is_supported(algo: EncryptionAlgorithm) -> bool {
    let p = algo.params();
    if algo == EncryptionAlgorithm::NONE {
        return true;
    }
    if p.is_block {
        block_cipher_by_name(p.name, &vec![0u8; p.key_size]).is_some()
    } else {
        // probe the stream dispatcher with a dummy buffer
        let mut b = [0u8; 1];
        apply_stream(p.name, &vec![0u8; p.key_size], &mut b, true)
    }
}

/// Derive the cipher key for `algo` from a passphrase (KEYGEN_MCRYPT/MD5).
pub fn key_for(algo: EncryptionAlgorithm, passphrase: &[u8]) -> Vec<u8> {
    keygen_mcrypt_md5(passphrase, algo.params().key_size)
}

/// Apply (algorithm, mode) to `buf` in place. Returns false if unsupported.
/// `key`/`iv` are the raw cipher key and IV (IV ignored for ECB/stream).
pub fn crypt(
    algo: EncryptionAlgorithm,
    mode: EncryptionMode,
    key: &[u8],
    iv: &[u8],
    buf: &mut [u8],
    encrypt: bool,
) -> bool {
    let p = algo.params();
    if algo == EncryptionAlgorithm::NONE {
        return true; // no-op
    }
    if let Some(c) = block_cipher_by_name(p.name, key) {
        match (mode, encrypt) {
            (EncryptionMode::Ecb, true) => ecb_encrypt(&*c, buf),
            (EncryptionMode::Ecb, false) => ecb_decrypt(&*c, buf),
            (EncryptionMode::Cbc, true) => cbc_encrypt(&*c, iv, buf),
            (EncryptionMode::Cbc, false) => cbc_decrypt(&*c, iv, buf),
            (EncryptionMode::Cfb, true) => cfb8_encrypt(&*c, iv, buf),
            (EncryptionMode::Cfb, false) => cfb8_decrypt(&*c, iv, buf),
            (EncryptionMode::Ncfb, true) => ncfb_encrypt(&*c, iv, buf),
            (EncryptionMode::Ncfb, false) => ncfb_decrypt(&*c, iv, buf),
            (EncryptionMode::Ofb, _) => ofb8_crypt(&*c, iv, buf),
            (EncryptionMode::Nofb, _) => nofb_crypt(&*c, iv, buf),
            (EncryptionMode::Ctr, _) => ctr_crypt(&*c, iv, buf),
            (EncryptionMode::Stream, _) => return false, // block algo with stream mode: invalid
        }
        true
    } else {
        // stream cipher (mode must be Stream)
        apply_stream(p.name, key, buf, encrypt)
    }
}

/// Size (in bits) of the ciphertext for a plaintext of `plnsize_bits`,
/// including the IV. Mirrors `MCryptPP::getEncryptedSize`.
pub fn encrypted_size_bits(
    algo: EncryptionAlgorithm,
    mode: EncryptionMode,
    plnsize_bits: u64,
) -> u64 {
    if algo == EncryptionAlgorithm::NONE {
        return plnsize_bits;
    }
    let p = algo.params();
    let mut retval = 0u64;
    if mode.has_iv() {
        retval += 8 * p.iv_size as u64;
    }
    // block size in bits (1 byte for stream ciphers)
    let blocksize = 8 * (p.block_size.max(1)) as u64;
    let blocks = if plnsize_bits % blocksize == 0 {
        plnsize_bits / blocksize
    } else {
        plnsize_bits / blocksize + 1
    };
    retval + blocks * blocksize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_default_path() {
        // rijndael-128 / cbc, key+iv via the real schemes
        let algo = EncryptionAlgorithm::from_name("rijndael-128").unwrap();
        let key = key_for(algo, b"hunter2");
        let iv = vec![0x11u8; algo.params().iv_size];
        let plain = b"0123456789abcdef0123456789abcdef".to_vec(); // 2 blocks
        let mut buf = plain.clone();
        assert!(crypt(algo, EncryptionMode::Cbc, &key, &iv, &mut buf, true));
        assert_ne!(buf, plain);
        assert!(crypt(algo, EncryptionMode::Cbc, &key, &iv, &mut buf, false));
        assert_eq!(buf, plain);
    }

    #[test]
    fn encrypted_size_matches_mcrypt_formula() {
        let aes = EncryptionAlgorithm::from_name("rijndael-128").unwrap();
        // 1 plaintext bit -> IV (128b) + one 128-bit block = 256 bits (cbc)
        assert_eq!(encrypted_size_bits(aes, EncryptionMode::Cbc, 1), 256);
        // exactly one block, no IV (ecb): 128 bits
        assert_eq!(encrypted_size_bits(aes, EncryptionMode::Ecb, 128), 128);
        // none: identity
        assert_eq!(
            encrypted_size_bits(EncryptionAlgorithm::NONE, EncryptionMode::Ecb, 12345),
            12345
        );
    }

    #[test]
    fn supported_set() {
        for n in [
            "rijndael-128",
            "twofish",
            "serpent",
            "des",
            "tripledes",
            "blowfish",
            "cast-128",
            "rc2",
            "xtea",
            "gost",
            "arcfour",
            "enigma",
            "wake",
        ] {
            assert!(
                is_supported(EncryptionAlgorithm::from_name(n).unwrap()),
                "{n}"
            );
        }
    }
}
