//! GOST 28147-89 as implemented by libmcrypt's `gost` module (block 8, key 32).
//! Uses the Schneier "Central Bank of Russia" S-boxes shipped with libmcrypt.
//! Block words are read/written big-endian; key words little-endian.

use super::BlockCipher;

const K1: [u8; 16] = [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 2];
const K2: [u8; 16] = [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12];
const K3: [u8; 16] = [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14];
const K4: [u8; 16] = [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2];
const K5: [u8; 16] = [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3];
const K6: [u8; 16] = [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11];
const K7: [u8; 16] = [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9];
const K8: [u8; 16] = [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3];

struct Tables {
    k87: [u8; 256],
    k65: [u8; 256],
    k43: [u8; 256],
    k21: [u8; 256],
}

const fn tables() -> Tables {
    let mut t = Tables {
        k87: [0; 256],
        k65: [0; 256],
        k43: [0; 256],
        k21: [0; 256],
    };
    let mut i = 0;
    while i < 256 {
        t.k87[i] = (K8[i >> 4] << 4) | K7[i & 15];
        t.k65[i] = (K6[i >> 4] << 4) | K5[i & 15];
        t.k43[i] = (K4[i >> 4] << 4) | K3[i & 15];
        t.k21[i] = (K2[i >> 4] << 4) | K1[i & 15];
        i += 1;
    }
    t
}
const T: Tables = tables();

#[inline]
fn f(x: u32) -> u32 {
    let y = (T.k87[((x >> 24) & 255) as usize] as u32) << 24
        | (T.k65[((x >> 16) & 255) as usize] as u32) << 16
        | (T.k43[((x >> 8) & 255) as usize] as u32) << 8
        | (T.k21[(x & 255) as usize] as u32);
    y.rotate_left(11)
}

pub struct Gost {
    key: [u32; 8],
}

impl Gost {
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut k = [0u32; 8];
        for i in 0..8 {
            k[i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        Gost { key: k }
    }
}

impl BlockCipher for Gost {
    fn block_size(&self) -> usize {
        8
    }
    fn encrypt_block(&self, b: &mut [u8]) {
        let k = &self.key;
        let mut n1 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let mut n2 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        for _ in 0..3 {
            n2 ^= f(n1.wrapping_add(k[0]));
            n1 ^= f(n2.wrapping_add(k[1]));
            n2 ^= f(n1.wrapping_add(k[2]));
            n1 ^= f(n2.wrapping_add(k[3]));
            n2 ^= f(n1.wrapping_add(k[4]));
            n1 ^= f(n2.wrapping_add(k[5]));
            n2 ^= f(n1.wrapping_add(k[6]));
            n1 ^= f(n2.wrapping_add(k[7]));
        }
        n2 ^= f(n1.wrapping_add(k[7]));
        n1 ^= f(n2.wrapping_add(k[6]));
        n2 ^= f(n1.wrapping_add(k[5]));
        n1 ^= f(n2.wrapping_add(k[4]));
        n2 ^= f(n1.wrapping_add(k[3]));
        n1 ^= f(n2.wrapping_add(k[2]));
        n2 ^= f(n1.wrapping_add(k[1]));
        n1 ^= f(n2.wrapping_add(k[0]));
        b[0..4].copy_from_slice(&n2.to_be_bytes());
        b[4..8].copy_from_slice(&n1.to_be_bytes());
    }
    fn decrypt_block(&self, b: &mut [u8]) {
        let k = &self.key;
        let mut n1 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let mut n2 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        n2 ^= f(n1.wrapping_add(k[0]));
        n1 ^= f(n2.wrapping_add(k[1]));
        n2 ^= f(n1.wrapping_add(k[2]));
        n1 ^= f(n2.wrapping_add(k[3]));
        n2 ^= f(n1.wrapping_add(k[4]));
        n1 ^= f(n2.wrapping_add(k[5]));
        n2 ^= f(n1.wrapping_add(k[6]));
        n1 ^= f(n2.wrapping_add(k[7]));
        for _ in 0..3 {
            n2 ^= f(n1.wrapping_add(k[7]));
            n1 ^= f(n2.wrapping_add(k[6]));
            n2 ^= f(n1.wrapping_add(k[5]));
            n1 ^= f(n2.wrapping_add(k[4]));
            n2 ^= f(n1.wrapping_add(k[3]));
            n1 ^= f(n2.wrapping_add(k[2]));
            n2 ^= f(n1.wrapping_add(k[1]));
            n1 ^= f(n2.wrapping_add(k[0]));
        }
        b[0..4].copy_from_slice(&n2.to_be_bytes());
        b[4..8].copy_from_slice(&n1.to_be_bytes());
    }
}
