//! XTEA block cipher (block 8, key 16), matching libmcrypt's `xtea` module.
//! libmcrypt reads block and key words as big-endian.

use super::BlockCipher;

const DELTA: u32 = 0x9E37_79B9;
const ROUNDS: u32 = 32;

pub struct Xtea {
    k: [u32; 4],
}

impl Xtea {
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        let mut k = [0u32; 4];
        for i in 0..4 {
            k[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        Xtea { k }
    }
}

impl BlockCipher for Xtea {
    fn block_size(&self) -> usize {
        8
    }
    fn encrypt_block(&self, b: &mut [u8]) {
        let mut v0 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let mut v1 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let mut sum = 0u32;
        for _ in 0..ROUNDS {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
        }
        b[0..4].copy_from_slice(&v0.to_be_bytes());
        b[4..8].copy_from_slice(&v1.to_be_bytes());
    }
    fn decrypt_block(&self, b: &mut [u8]) {
        let mut v0 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let mut v1 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let mut sum = DELTA.wrapping_mul(ROUNDS);
        for _ in 0..ROUNDS {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
        }
        b[0..4].copy_from_slice(&v0.to_be_bytes());
        b[4..8].copy_from_slice(&v1.to_be_bytes());
    }
}
