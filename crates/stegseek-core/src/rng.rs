//! Port of `PseudoRandomSource` (the steghide LCG) and `RandomSource`,
//! plus the MD5-fold passphrase→seed derivation shared by the Selector,
//! the Extractor and the crackers.

use md5::{Digest, Md5};

/// Derive the 32-bit seed from a passphrase exactly as steghide does:
/// take the 16-byte MD5 digest as four little-endian `u32` words and XOR them.
///
/// Mirrors the inlined code in `Selector`, `Cracker::verifyMagic` and friends:
/// ```c
/// MHASH td = mhash_init(MHASH_MD5); mhash(td, pp.data(), pp.size());
/// UWORD32 hash[4]; mhash_deinit(td, hash);
/// UWORD32 seed = 0; for (i=0;i<4;i++) seed ^= hash[i];
/// ```
pub fn passphrase_seed(passphrase: &[u8]) -> u32 {
    let digest = Md5::digest(passphrase); // 16 bytes
    let mut seed = 0u32;
    for i in 0..4 {
        let word = u32::from_le_bytes([
            digest[4 * i],
            digest[4 * i + 1],
            digest[4 * i + 2],
            digest[4 * i + 3],
        ]);
        seed ^= word;
    }
    seed
}

/// Reproducible pseudo-random source using the linear congruential method with
/// modulus 2^32. The overflow in `A * Value + C` is intentional and controlled
/// (wrapping), exactly as in the original (which relied on `UWORD32` wraparound).
#[derive(Clone, Debug)]
pub struct PseudoRandomSource {
    value: u32,
}

impl PseudoRandomSource {
    /// LCG multiplier (public in the original so crackers can inline the step).
    pub const A: u32 = 1_367_208_549;
    /// LCG increment.
    pub const C: u32 = 1;

    pub fn new(seed: u32) -> Self {
        PseudoRandomSource { value: seed }
    }

    /// Get a pseudo-random value in `{0, ..., n-1}`.
    ///
    /// Faithful to:
    /// ```c
    /// Value = A * Value + C;
    /// return (UWORD32)(((double)n) * ((double)Value / (double)4294967296.0));
    /// ```
    /// The `f64` arithmetic and truncation are reproduced precisely; `as u32`
    /// truncates toward zero just like the C cast (the product is `< n <= 2^32`).
    pub fn get_value(&mut self, n: u32) -> u32 {
        self.value = Self::A.wrapping_mul(self.value).wrapping_add(Self::C);
        ((n as f64) * (self.value as f64 / 4_294_967_296.0_f64)) as u32
    }

    /// Expose the raw internal state (used by the seed cracker's inlined loop).
    pub fn state(&self) -> u32 {
        self.value
    }
}

/// Source of (cryptographically irrelevant) randomness used only on the embed
/// path (random padding, IV generation, tie-breaking in nearest-target search).
///
/// Modelled as a trait so deterministic sources can be injected for tests and
/// differential checks. Extraction/cracking never need real randomness.
pub trait RandomSource {
    fn get_byte(&mut self) -> u8;

    /// One random bit, consuming a byte 8 bits at a time (mirrors
    /// `RandomSource::getBool`, LSB first).
    fn get_bool(&mut self) -> bool;

    fn get_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.get_byte()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcg_is_deterministic_and_in_range() {
        let mut a = PseudoRandomSource::new(0xDEAD_BEEF);
        let mut b = PseudoRandomSource::new(0xDEAD_BEEF);
        for n in [1u32, 2, 100, 65536, 1_000_000, u32::MAX] {
            let va = a.get_value(n);
            let vb = b.get_value(n);
            assert_eq!(va, vb, "LCG must be deterministic");
            if n > 0 {
                assert!(va < n, "value {va} must be < n {n}");
            }
        }
    }

    #[test]
    fn lcg_step_matches_manual_computation() {
        // First step from seed 0: value = A*0 + C = 1; (n=10)*(1/2^32) -> 0
        let mut r = PseudoRandomSource::new(0);
        assert_eq!(r.get_value(10), 0);
        // Internal state is now 1.
        assert_eq!(r.state(), 1);
    }
}
