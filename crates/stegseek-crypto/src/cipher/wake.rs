//! WAKE stream cipher as implemented by libmcrypt's `wake` module (key 32,
//! no IV in the mcrypt build). Words read little-endian. The feedback register
//! is fed the ciphertext in both directions.

const TT: [u32; 8] = [
    0x726a8f3b, 0xe69a3b5c, 0xd3c71fe5, 0xab3c73d2, 0x4d3a8eb3, 0x0396d6e8, 0x3d4c2f7a, 0x9ee27cf3,
];

pub struct Wake {
    t: [u32; 257],
    r: [u32; 4],
}

#[inline]
fn m(x: u32, y: u32, t: &[u32; 257]) -> u32 {
    let s = x.wrapping_add(y);
    ((s >> 8) & 0x00ff_ffff) ^ t[(s & 0xff) as usize]
}

impl Wake {
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut k = [0u32; 4];
        for i in 0..4 {
            k[i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        let mut t = [0u32; 257];
        t[..4].copy_from_slice(&k);
        for p in 4..256 {
            let x = t[p - 4].wrapping_add(t[p - 1]);
            t[p] = (x >> 3) ^ TT[(x & 7) as usize];
        }
        for p in 0..23 {
            t[p] = t[p].wrapping_add(t[p + 89]);
        }
        let mut x = t[33];
        let mut z = t[59] | 0x0100_0001;
        z &= 0xff7f_ffff;
        for p in 0..256 {
            x = (x & 0xff7f_ffff).wrapping_add(z);
            t[p] = (t[p] & 0x00ff_ffff) ^ x;
        }
        t[256] = t[0];
        let mut xi = (x & 0xff) as usize;
        for p in 0..256 {
            xi = ((t[p ^ xi] ^ (xi as u32)) & 0xff) as usize;
            t[p] = t[xi];
            t[xi] = t[p + 1];
        }
        Wake { t, r: k }
    }

    /// Apply WAKE in place. `encrypt` selects which value feeds back, but in
    /// both directions the *ciphertext* byte is what enters the register.
    pub fn apply(&self, buf: &mut [u8], encrypt: bool) {
        let (mut r3, mut r4, mut r5, mut r6) = (self.r[0], self.r[1], self.r[2], self.r[3]);
        let mut tmp = 0u32;
        let mut counter = 0usize;
        for byte in buf.iter_mut() {
            let ks = ((r6 >> (8 * counter)) & 0xff) as u8;
            let cipher = if encrypt {
                let c = *byte ^ ks;
                *byte = c;
                c
            } else {
                let c = *byte;
                *byte ^= ks;
                c
            };
            tmp = (tmp & !(0xffu32 << (8 * counter))) | ((cipher as u32) << (8 * counter));
            counter += 1;
            if counter == 4 {
                counter = 0;
                r3 = m(r3, tmp, &self.t);
                r4 = m(r4, r3, &self.t);
                r5 = m(r5, r4, &self.t);
                r6 = m(r6, r5, &self.t);
            }
        }
    }
}
