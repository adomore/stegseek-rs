//! BitString-level encryption wrapper mirroring `MCryptPP::encrypt`/`decrypt`:
//! random padding + prepended IV on encrypt, IV extraction on decrypt. Keys are
//! derived with KEYGEN_MCRYPT(MD5). Delegates the cipher+mode to stegseek-crypto.

use crate::bitstring::BitString;
use crate::error::{StegError, StegResult};
use crate::rng::RandomSource;
use stegseek_crypto::{crypt, key_for, EncryptionAlgorithm, EncryptionMode};

/// Decrypt `c` (IV ‖ ciphertext) with the passphrase; returns the plaintext.
pub fn decrypt(
    algo: EncryptionAlgorithm,
    mode: EncryptionMode,
    c: &BitString,
    passphrase: &[u8],
) -> StegResult<BitString> {
    let key = key_for(algo, passphrase);
    let ct = c.get_bytes().to_vec();
    let ivsize = if mode.has_iv() {
        algo.params().iv_size
    } else {
        0
    };
    if ct.len() < ivsize {
        return Err(StegError::Steghide("could not decrypt data.".into()));
    }
    let iv = ct[..ivsize].to_vec();
    let mut buf = ct[ivsize..].to_vec();
    if !crypt(algo, mode, &key, &iv, &mut buf, false) {
        return Err(StegError::Steghide("could not decrypt data.".into()));
    }
    Ok(BitString::from_bytes(&buf))
}

/// Encrypt `p`: random-pad to a block boundary, generate a random IV, and
/// return IV ‖ ciphertext.
pub fn encrypt(
    algo: EncryptionAlgorithm,
    mode: EncryptionMode,
    p: &BitString,
    passphrase: &[u8],
    rng: &mut dyn RandomSource,
) -> StegResult<BitString> {
    let mut p = p.clone();
    let blocksize = algo.params().block_size.max(1);
    p.pad_random(8 * blocksize as u32, rng);
    let key = key_for(algo, passphrase);
    let ivsize = if mode.has_iv() {
        algo.params().iv_size
    } else {
        0
    };
    let iv = rng.get_bytes(ivsize);
    let mut buf = p.get_bytes().to_vec();
    if !crypt(algo, mode, &key, &iv, &mut buf, true) {
        return Err(StegError::Steghide("could not encrypt data.".into()));
    }
    let mut out = iv;
    out.extend_from_slice(&buf);
    Ok(BitString::from_bytes(&out))
}
