//! LOKI97 block cipher — port of libmcrypt's `loki97` module (block 16,
//! key 32). S-boxes and permutation generated as in the C; 64-bit halves are
//! kept as `[u32; 2]` (low, high) to reproduce the carry arithmetic exactly.
//! Validated against libmcrypt golden vectors.

use super::BlockCipher;
use std::sync::OnceLock;

const S1_MASK: u32 = 0x1fff;
const S2_MASK: u32 = 0x07ff;
const S1_HMASK: u32 = S1_MASK & !0xff; // 0x1f00
const S2_HMASK: u32 = S2_MASK & !0xff; // 0x0700
const DELTA: [u32; 2] = [0x7f4a_7c15, 0x9e37_79b9];

struct Tables {
    sb1: Vec<u8>,       // 8192
    sb2: Vec<u8>,       // 2048
    prm: Vec<[u32; 2]>, // 256
}

fn ff_mult(mut a: u32, mut b: u32, tpow: u32, mpol: u32) -> u32 {
    let mut s = 0u32;
    let m = 1u32 << tpow;
    while b != 0 {
        if b & 1 != 0 {
            s ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & m != 0 {
            a ^= mpol;
        }
    }
    s
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut sb1 = vec![0u8; 1 << 13];
        for i in 0..(1u32 << 13) {
            let j = i ^ S1_MASK;
            let v = ff_mult(j, j, 13, 0x2911);
            sb1[i as usize] = ff_mult(v, j, 13, 0x2911) as u8;
        }
        let mut sb2 = vec![0u8; 1 << 11];
        for i in 0..(1u32 << 11) {
            let j = i ^ S2_MASK;
            let v = ff_mult(j, j, 11, 0x0aa7);
            sb2[i as usize] = ff_mult(v, j, 11, 0x0aa7) as u8;
        }
        let mut prm = vec![[0u32; 2]; 256];
        for i in 0..256u32 {
            prm[i as usize][0] =
                ((i & 1) << 7) | ((i & 2) << 14) | ((i & 4) << 21) | ((i & 8) << 28);
            prm[i as usize][1] =
                ((i & 16) << 3) | ((i & 32) << 10) | ((i & 64) << 17) | ((i & 128) << 24);
        }
        Tables { sb1, sb2, prm }
    })
}

#[inline]
fn add_eq(x: &mut [u32; 2], y: &[u32; 2]) {
    let (s0, c) = x[0].overflowing_add(y[0]);
    x[0] = s0;
    x[1] = x[1].wrapping_add(y[1]).wrapping_add(c as u32);
}
#[inline]
fn sub_eq(x: &mut [u32; 2], y: &[u32; 2]) {
    let (d0, b) = x[0].overflowing_sub(y[0]);
    x[0] = d0;
    x[1] = x[1].wrapping_sub(y[1]).wrapping_sub(b as u32);
}
#[inline]
fn byte(x: u32, n: u32) -> u32 {
    (x >> (8 * n)) & 0xff
}

fn f_fun(res: &mut [u32; 2], inv: &[u32; 2], key: &[u32; 2], t: &Tables) {
    let tt0 = (inv[0] & !key[0]) | (inv[1] & key[0]);
    let tt1 = (inv[1] & !key[0]) | (inv[0] & key[0]);
    let (sb1, sb2, prm) = (&t.sb1, &t.sb2, &t.prm);

    let mut pp0;
    let mut pp1;
    let mut i = sb1[(((tt1 >> 24) | (tt0 << 8)) & S1_MASK) as usize] as usize;
    pp0 = prm[i][0] >> 7;
    pp1 = prm[i][1] >> 7;
    i = sb2[((tt1 >> 16) & S2_MASK) as usize] as usize;
    pp0 |= prm[i][0] >> 6;
    pp1 |= prm[i][1] >> 6;
    i = sb1[((tt1 >> 8) & S1_MASK) as usize] as usize;
    pp0 |= prm[i][0] >> 5;
    pp1 |= prm[i][1] >> 5;
    i = sb2[(tt1 & S2_MASK) as usize] as usize;
    pp0 |= prm[i][0] >> 4;
    pp1 |= prm[i][1] >> 4;
    i = sb2[(((tt0 >> 24) | (tt1 << 8)) & S2_MASK) as usize] as usize;
    pp0 |= prm[i][0] >> 3;
    pp1 |= prm[i][1] >> 3;
    i = sb1[((tt0 >> 16) & S1_MASK) as usize] as usize;
    pp0 |= prm[i][0] >> 2;
    pp1 |= prm[i][1] >> 2;
    i = sb2[((tt0 >> 8) & S2_MASK) as usize] as usize;
    pp0 |= prm[i][0] >> 1;
    pp1 |= prm[i][1] >> 1;
    i = sb1[(tt0 & S1_MASK) as usize] as usize;
    pp0 |= prm[i][0];
    pp1 |= prm[i][1];

    res[0] ^= sb1[(byte(pp0, 0) | ((key[1] << 8) & S1_HMASK)) as usize] as u32
        | ((sb1[(byte(pp0, 1) | ((key[1] << 3) & S1_HMASK)) as usize] as u32) << 8)
        | ((sb2[(byte(pp0, 2) | ((key[1] >> 2) & S2_HMASK)) as usize] as u32) << 16)
        | ((sb2[(byte(pp0, 3) | ((key[1] >> 5) & S2_HMASK)) as usize] as u32) << 24);
    res[1] ^= sb1[(byte(pp1, 0) | ((key[1] >> 8) & S1_HMASK)) as usize] as u32
        | ((sb1[(byte(pp1, 1) | ((key[1] >> 13) & S1_HMASK)) as usize] as u32) << 8)
        | ((sb2[(byte(pp1, 2) | ((key[1] >> 18) & S2_HMASK)) as usize] as u32) << 16)
        | ((sb2[(byte(pp1, 3) | ((key[1] >> 21) & S2_HMASK)) as usize] as u32) << 24);
}

pub struct Loki97 {
    l_key: [u32; 96],
}

fn rd_words(b: &[u8]) -> [u32; 4] {
    let mut w = [0u32; 4];
    for j in 0..4 {
        w[j] = u32::from_le_bytes([b[4 * j], b[4 * j + 1], b[4 * j + 2], b[4 * j + 3]]);
    }
    w
}

impl Loki97 {
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let ik = {
            let mut v = [0u32; 8];
            for i in 0..8 {
                v[i] = u32::from_le_bytes([
                    key[4 * i],
                    key[4 * i + 1],
                    key[4 * i + 2],
                    key[4 * i + 3],
                ]);
            }
            v
        };
        let t = tables();
        let mut k4 = [ik[1], ik[0]];
        let mut k3 = [ik[3], ik[2]];
        let mut k2 = [ik[5], ik[4]];
        let mut k1 = [ik[7], ik[6]];
        let mut del = DELTA;
        let mut l_key = [0u32; 96];
        for i in 0..48 {
            let mut tt = k1;
            add_eq(&mut tt, &k3);
            add_eq(&mut tt, &del);
            add_eq(&mut del, &DELTA);
            let sk = k4;
            k4 = k3;
            k3 = k2;
            k2 = k1;
            k1 = sk;
            f_fun(&mut k1, &tt, &k3, t);
            l_key[i * 2] = k1[0];
            l_key[i * 2 + 1] = k1[1];
        }
        Loki97 { l_key }
    }
}

impl BlockCipher for Loki97 {
    fn block_size(&self) -> usize {
        16
    }
    fn encrypt_block(&self, b: &mut [u8]) {
        let w = rd_words(b);
        // blk[3]=w[0], blk[2]=w[1], blk[1]=w[2], blk[0]=w[3]
        let mut h = [[w[3], w[2]], [w[1], w[0]]]; // h[0]=blk[0..2], h[1]=blk[2..4]
        let t = tables();
        for round in 0..16 {
            let k = round * 6;
            let (li, ri) = if round % 2 == 0 { (0, 1) } else { (1, 0) };
            add_eq(&mut h[li], &[self.l_key[k], self.l_key[k + 1]]);
            let inv = h[li];
            f_fun(&mut h[ri], &inv, &[self.l_key[k + 2], self.l_key[k + 3]], t);
            add_eq(&mut h[li], &[self.l_key[k + 4], self.l_key[k + 5]]);
        }
        // blk[0..2]=h[0], blk[2..4]=h[1]; out: _blk[3]=blk[2],_blk[2]=blk[3],_blk[1]=blk[0],_blk[0]=blk[1]
        let out = [h[0][1], h[0][0], h[1][1], h[1][0]];
        for j in 0..4 {
            b[4 * j..4 * j + 4].copy_from_slice(&out[j].to_le_bytes());
        }
    }
    fn decrypt_block(&self, b: &mut [u8]) {
        let w = rd_words(b);
        let mut h = [[w[3], w[2]], [w[1], w[0]]];
        let t = tables();
        for round in 0..16 {
            let k = (15 - round) * 6;
            let (li, ri) = if round % 2 == 0 { (0, 1) } else { (1, 0) };
            sub_eq(&mut h[li], &[self.l_key[k + 4], self.l_key[k + 5]]);
            let inv = h[li];
            f_fun(&mut h[ri], &inv, &[self.l_key[k + 2], self.l_key[k + 3]], t);
            sub_eq(&mut h[li], &[self.l_key[k], self.l_key[k + 1]]);
        }
        let out = [h[0][1], h[0][0], h[1][1], h[1][0]];
        for j in 0..4 {
            b[4 * j..4 * j + 4].copy_from_slice(&out[j].to_le_bytes());
        }
    }
}
