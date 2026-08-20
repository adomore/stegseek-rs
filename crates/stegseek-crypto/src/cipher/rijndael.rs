//! Generic Rijndael (FIPS-197 / Daemen-Rijmen), parameterised by block size.
//! Covers steghide's `rijndael-128` (Nb=4), `rijndael-192` (Nb=6) and
//! `rijndael-256` (Nb=8), all with up to a 256-bit key (Nk=8), matching the
//! libmcrypt modules of the same names.

use super::BlockCipher;

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const fn make_inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}
const INV_SBOX: [u8; 256] = make_inv_sbox();

#[inline]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

pub struct Rijndael {
    nb: usize,
    nr: usize,
    /// Round keys, one word ([u8;4]) per entry, length nb*(nr+1).
    w: Vec<[u8; 4]>,
}

impl Rijndael {
    pub fn new(key: &[u8], block_size: usize) -> Self {
        assert!(block_size == 16 || block_size == 24 || block_size == 32);
        let nb = block_size / 4;
        let nk = key.len() / 4;
        assert!(key.len() % 4 == 0 && nk >= 4);
        let nr = core::cmp::max(nb, nk) + 6;

        // Round constants
        let mut rcon = [0u8; 32];
        rcon[1] = 1;
        let mut i = 2;
        while i < rcon.len() {
            rcon[i] = {
                let x = rcon[i - 1];
                (x << 1) ^ (if x & 0x80 != 0 { 0x1b } else { 0 })
            };
            i += 1;
        }

        let total = nb * (nr + 1);
        let mut w: Vec<[u8; 4]> = Vec::with_capacity(total);
        for i in 0..nk {
            w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        for i in nk..total {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                // RotWord + SubWord + Rcon
                temp = [
                    SBOX[temp[1] as usize] ^ rcon[i / nk],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                    SBOX[temp[0] as usize],
                ];
            } else if nk > 6 && i % nk == 4 {
                temp = [
                    SBOX[temp[0] as usize],
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                ];
            }
            let p = w[i - nk];
            w.push([
                temp[0] ^ p[0],
                temp[1] ^ p[1],
                temp[2] ^ p[2],
                temp[3] ^ p[3],
            ]);
        }

        Rijndael { nb, nr, w }
    }

    fn shifts(&self) -> [usize; 4] {
        if self.nb == 8 {
            [0, 1, 3, 4]
        } else {
            [0, 1, 2, 3]
        }
    }

    fn add_round_key(&self, state: &mut [u8], round: usize) {
        for c in 0..self.nb {
            let wk = self.w[round * self.nb + c];
            for r in 0..4 {
                state[r + 4 * c] ^= wk[r];
            }
        }
    }

    fn sub_bytes(state: &mut [u8]) {
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
    }
    fn inv_sub_bytes(state: &mut [u8]) {
        for b in state.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }
    }

    fn shift_rows(&self, state: &mut [u8]) {
        let sh = self.shifts();
        let nb = self.nb;
        for r in 1..4 {
            let mut row = [0u8; 8];
            for c in 0..nb {
                row[c] = state[r + 4 * c];
            }
            let s = sh[r];
            for c in 0..nb {
                state[r + 4 * c] = row[(c + s) % nb];
            }
        }
    }
    fn inv_shift_rows(&self, state: &mut [u8]) {
        let sh = self.shifts();
        let nb = self.nb;
        for r in 1..4 {
            let mut row = [0u8; 8];
            for c in 0..nb {
                row[c] = state[r + 4 * c];
            }
            let s = sh[r];
            for c in 0..nb {
                state[r + 4 * c] = row[(c + nb - s) % nb];
            }
        }
    }

    fn mix_columns(&self, state: &mut [u8]) {
        for c in 0..self.nb {
            let i = 4 * c;
            let a = [state[i], state[i + 1], state[i + 2], state[i + 3]];
            state[i] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
            state[i + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
            state[i + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
            state[i + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
        }
    }
    fn inv_mix_columns(&self, state: &mut [u8]) {
        for c in 0..self.nb {
            let i = 4 * c;
            let a = [state[i], state[i + 1], state[i + 2], state[i + 3]];
            state[i] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
            state[i + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
            state[i + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
            state[i + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
        }
    }
}

impl BlockCipher for Rijndael {
    fn block_size(&self) -> usize {
        self.nb * 4
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        self.add_round_key(block, 0);
        for round in 1..self.nr {
            Self::sub_bytes(block);
            self.shift_rows(block);
            self.mix_columns(block);
            self.add_round_key(block, round);
        }
        Self::sub_bytes(block);
        self.shift_rows(block);
        self.add_round_key(block, self.nr);
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        self.add_round_key(block, self.nr);
        for round in (1..self.nr).rev() {
            self.inv_shift_rows(block);
            Self::inv_sub_bytes(block);
            self.add_round_key(block, round);
            self.inv_mix_columns(block);
        }
        self.inv_shift_rows(block);
        Self::inv_sub_bytes(block);
        self.add_round_key(block, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn fips197_aes256_ecb() {
        // FIPS-197 Appendix C.3 (AES-256, 128-bit block)
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = unhex("00112233445566778899aabbccddeeff");
        let ct = unhex("8ea2b7ca516745bfeafc49904b496089");
        let c = Rijndael::new(&key, 16);
        let mut b = pt.clone();
        c.encrypt_block(&mut b);
        assert_eq!(b, ct);
        c.decrypt_block(&mut b);
        assert_eq!(b, pt);
    }
}
