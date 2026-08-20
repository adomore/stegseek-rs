//! SAFER+ (Cylink) block cipher — port of libmcrypt's `saferplus` module
//! (block 16, key 32). Ported from the upstream C; validated against libmcrypt
//! golden vectors. Words are loaded little-endian with 4-word reversal.

use super::BlockCipher;

static EXPF: [u8; 256] = [
    1, 45, 226, 147, 190, 69, 21, 174, 120, 3, 135, 164, 184, 56, 207, 63, 8, 103, 9, 148, 235, 38,
    168, 107, 189, 24, 52, 27, 187, 191, 114, 247, 64, 53, 72, 156, 81, 47, 59, 85, 227, 192, 159,
    216, 211, 243, 141, 177, 255, 167, 62, 220, 134, 119, 215, 166, 17, 251, 244, 186, 146, 145,
    100, 131, 241, 51, 239, 218, 44, 181, 178, 43, 136, 209, 153, 203, 140, 132, 29, 20, 129, 151,
    113, 202, 95, 163, 139, 87, 60, 130, 196, 82, 92, 28, 232, 160, 4, 180, 133, 74, 246, 19, 84,
    182, 223, 12, 26, 142, 222, 224, 57, 252, 32, 155, 36, 78, 169, 152, 158, 171, 242, 96, 208,
    108, 234, 250, 199, 217, 0, 212, 31, 110, 67, 188, 236, 83, 137, 254, 122, 93, 73, 201, 50,
    194, 249, 154, 248, 109, 22, 219, 89, 150, 68, 233, 205, 230, 70, 66, 143, 10, 193, 204, 185,
    101, 176, 210, 198, 172, 30, 65, 98, 41, 46, 14, 116, 80, 2, 90, 195, 37, 123, 138, 42, 91,
    240, 6, 13, 71, 111, 112, 157, 126, 16, 206, 18, 39, 213, 76, 79, 214, 121, 48, 104, 54, 117,
    125, 228, 237, 128, 106, 144, 55, 162, 94, 118, 170, 197, 127, 61, 175, 165, 229, 25, 97, 253,
    77, 124, 183, 11, 238, 173, 75, 34, 245, 231, 115, 35, 33, 200, 5, 225, 102, 221, 179, 88, 105,
    99, 86, 15, 161, 49, 149, 23, 7, 58, 40,
];
static LOGF: [u8; 512] = [
    128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105, 186, 173, 248, 192, 56, 194, 101, 79,
    6, 148, 252, 25, 222, 106, 27, 93, 78, 168, 130, 112, 237, 232, 236, 114, 179, 21, 195, 255,
    171, 182, 71, 68, 1, 172, 37, 201, 250, 142, 65, 26, 33, 203, 211, 13, 110, 254, 38, 88, 218,
    50, 15, 32, 169, 157, 132, 152, 5, 156, 187, 34, 140, 99, 231, 197, 225, 115, 198, 175, 36, 91,
    135, 102, 39, 247, 87, 244, 150, 177, 183, 92, 139, 213, 84, 121, 223, 170, 246, 62, 163, 241,
    17, 202, 245, 209, 23, 123, 147, 131, 188, 189, 82, 30, 235, 174, 204, 214, 53, 8, 200, 138,
    180, 226, 205, 191, 217, 208, 80, 89, 63, 77, 98, 52, 10, 72, 136, 181, 86, 76, 46, 107, 158,
    210, 61, 60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35, 190, 118, 42, 95, 249, 212, 85, 11,
    220, 55, 49, 22, 116, 215, 119, 167, 230, 7, 219, 164, 47, 70, 243, 97, 69, 103, 227, 12, 162,
    59, 28, 133, 24, 4, 29, 41, 160, 143, 178, 90, 216, 166, 126, 238, 141, 83, 75, 161, 154, 193,
    14, 122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67, 149, 51, 242, 108, 104, 109, 240, 2, 40,
    206, 221, 155, 234, 94, 153, 124, 20, 134, 207, 229, 66, 184, 64, 120, 45, 58, 233, 100, 31,
    146, 144, 125, 57, 111, 224, 137, 48, 128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105,
    186, 173, 248, 192, 56, 194, 101, 79, 6, 148, 252, 25, 222, 106, 27, 93, 78, 168, 130, 112,
    237, 232, 236, 114, 179, 21, 195, 255, 171, 182, 71, 68, 1, 172, 37, 201, 250, 142, 65, 26, 33,
    203, 211, 13, 110, 254, 38, 88, 218, 50, 15, 32, 169, 157, 132, 152, 5, 156, 187, 34, 140, 99,
    231, 197, 225, 115, 198, 175, 36, 91, 135, 102, 39, 247, 87, 244, 150, 177, 183, 92, 139, 213,
    84, 121, 223, 170, 246, 62, 163, 241, 17, 202, 245, 209, 23, 123, 147, 131, 188, 189, 82, 30,
    235, 174, 204, 214, 53, 8, 200, 138, 180, 226, 205, 191, 217, 208, 80, 89, 63, 77, 98, 52, 10,
    72, 136, 181, 86, 76, 46, 107, 158, 210, 61, 60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35,
    190, 118, 42, 95, 249, 212, 85, 11, 220, 55, 49, 22, 116, 215, 119, 167, 230, 7, 219, 164, 47,
    70, 243, 97, 69, 103, 227, 12, 162, 59, 28, 133, 24, 4, 29, 41, 160, 143, 178, 90, 216, 166,
    126, 238, 141, 83, 75, 161, 154, 193, 14, 122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67,
    149, 51, 242, 108, 104, 109, 240, 2, 40, 206, 221, 155, 234, 94, 153, 124, 20, 134, 207, 229,
    66, 184, 64, 120, 45, 58, 233, 100, 31, 146, 144, 125, 57, 111, 224, 137, 48,
];

#[inline]
fn rotl3(b: u8) -> u8 {
    (b << 3) | (b >> 5)
}

pub struct SaferPlus {
    l_key: Vec<u8>,
    k_bytes: usize,
}

fn word_reverse(input: &[u8]) -> [u8; 16] {
    let mut blk = [0u8; 16];
    for j in 0..4 {
        for k in 0..4 {
            blk[4 * j + k] = input[4 * (3 - j) + k];
        }
    }
    blk
}

impl SaferPlus {
    pub fn new(key: &[u8]) -> Self {
        let k_bytes = key.len();
        let nwords = k_bytes / 4;
        let mut lk = [0u8; 36];
        for i in 0..nwords {
            let src = nwords - 1 - i;
            let w = u32::from_le_bytes([
                key[4 * src],
                key[4 * src + 1],
                key[4 * src + 2],
                key[4 * src + 3],
            ]);
            lk[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        lk[k_bytes] = 0;
        let mut l_key = vec![0u8; 16 * k_bytes + 16];
        for i in 0..k_bytes {
            lk[k_bytes] ^= lk[i];
            l_key[i] = lk[i];
        }
        for i in 0..k_bytes {
            for j in 0..=k_bytes {
                lk[j] = rotl3(lk[j]);
            }
            let k = 17 * i + 35;
            let l = 16 * i + 16;
            let mut m = i + 1;
            if i < 16 {
                for j in 0..16 {
                    l_key[l + j] = lk[m].wrapping_add(EXPF[EXPF[(k + j) & 255] as usize]);
                    m = if m == k_bytes { 0 } else { m + 1 };
                }
            } else {
                for j in 0..16 {
                    l_key[l + j] = lk[m].wrapping_add(EXPF[(k + j) & 255]);
                    m = if m == k_bytes { 0 } else { m + 1 };
                }
            }
        }
        SaferPlus { l_key, k_bytes }
    }
}

#[inline]
fn pht(x: &mut [u8; 16], a: usize, b: usize) {
    x[b] = x[b].wrapping_add(x[a]);
    x[a] = x[a].wrapping_add(x[b]);
}

fn do_fr(x: &mut [u8; 16], kp: &[u8]) {
    for i in 0..16 {
        match i % 4 {
            0 | 3 => x[i] = EXPF[(x[i] ^ kp[i]) as usize].wrapping_add(kp[16 + i]),
            _ => x[i] = LOGF[x[i] as usize + kp[i] as usize] ^ kp[16 + i],
        }
    }
    // pseudo-Hadamard mixing (4 layers), matching the C exactly
    pht(x, 0, 1);
    pht(x, 2, 3);
    pht(x, 4, 5);
    pht(x, 6, 7);
    pht(x, 8, 9);
    pht(x, 10, 11);
    pht(x, 12, 13);
    pht(x, 14, 15);
    pht(x, 0, 7);
    pht(x, 2, 1);
    pht(x, 4, 3);
    pht(x, 6, 5);
    pht(x, 8, 11);
    pht(x, 10, 9);
    pht(x, 12, 15);
    pht(x, 14, 13);
    pht(x, 0, 3);
    pht(x, 2, 15);
    pht(x, 4, 7);
    pht(x, 6, 1);
    pht(x, 8, 5);
    pht(x, 10, 13);
    pht(x, 12, 11);
    pht(x, 14, 9);
    pht(x, 0, 13);
    pht(x, 2, 5);
    pht(x, 4, 9);
    pht(x, 6, 11);
    pht(x, 8, 15);
    pht(x, 10, 1);
    pht(x, 12, 3);
    pht(x, 14, 7);
    // Armenian permutation
    let t = x[0];
    x[0] = x[14];
    x[14] = x[12];
    x[12] = x[10];
    x[10] = x[2];
    x[2] = x[8];
    x[8] = x[4];
    x[4] = t;
    let t = x[1];
    x[1] = x[7];
    x[7] = x[11];
    x[11] = x[5];
    x[5] = x[13];
    x[13] = t;
    let t = x[15];
    x[15] = x[3];
    x[3] = t;
}

#[inline]
fn ipht(x: &mut [u8; 16], a: usize, b: usize) {
    x[b] = x[b].wrapping_sub(x[a]);
    x[a] = x[a].wrapping_sub(x[b]);
}

fn do_ir(x: &mut [u8; 16], kp: &[u8]) {
    let t = x[3];
    x[3] = x[15];
    x[15] = t;
    let t = x[13];
    x[13] = x[5];
    x[5] = x[11];
    x[11] = x[7];
    x[7] = x[1];
    x[1] = t;
    let t = x[4];
    x[4] = x[8];
    x[8] = x[2];
    x[2] = x[10];
    x[10] = x[12];
    x[12] = x[14];
    x[14] = x[0];
    x[0] = t;
    ipht(x, 7, 14);
    ipht(x, 3, 12);
    ipht(x, 1, 10);
    ipht(x, 15, 8);
    ipht(x, 11, 6);
    ipht(x, 9, 4);
    ipht(x, 5, 2);
    ipht(x, 13, 0);
    ipht(x, 9, 14);
    ipht(x, 11, 12);
    ipht(x, 13, 10);
    ipht(x, 5, 8);
    ipht(x, 1, 6);
    ipht(x, 7, 4);
    ipht(x, 15, 2);
    ipht(x, 3, 0);
    ipht(x, 13, 14);
    ipht(x, 15, 12);
    ipht(x, 9, 10);
    ipht(x, 11, 8);
    ipht(x, 5, 6);
    ipht(x, 3, 4);
    ipht(x, 1, 2);
    ipht(x, 7, 0);
    ipht(x, 15, 14);
    ipht(x, 13, 12);
    ipht(x, 11, 10);
    ipht(x, 9, 8);
    ipht(x, 7, 6);
    ipht(x, 5, 4);
    ipht(x, 3, 2);
    ipht(x, 1, 0);
    for i in 0..16 {
        match i % 4 {
            0 | 3 => x[i] = LOGF[(x[i] as i32 - kp[16 + i] as i32 + 256) as usize] ^ kp[i],
            _ => x[i] = EXPF[(x[i] ^ kp[16 + i]) as usize].wrapping_sub(kp[i]),
        }
    }
}

impl BlockCipher for SaferPlus {
    fn block_size(&self) -> usize {
        16
    }
    fn encrypt_block(&self, b: &mut [u8]) {
        let mut x = word_reverse(b);
        let mut off = 0usize;
        for _ in 0..8 {
            do_fr(&mut x, &self.l_key[off..]);
            off += 32;
        }
        if self.k_bytes > 16 {
            for _ in 0..4 {
                do_fr(&mut x, &self.l_key[off..]);
                off += 32;
            }
        }
        if self.k_bytes > 24 {
            for _ in 0..4 {
                do_fr(&mut x, &self.l_key[off..]);
                off += 32;
            }
        }
        let kp = &self.l_key[16 * self.k_bytes..];
        for i in 0..16 {
            match i % 4 {
                0 | 3 => x[i] ^= kp[i],
                _ => x[i] = x[i].wrapping_add(kp[i]),
            }
        }
        let out = word_reverse(&x);
        b[..16].copy_from_slice(&out);
    }
    fn decrypt_block(&self, b: &mut [u8]) {
        let mut x = word_reverse(b);
        let kp = &self.l_key[16 * self.k_bytes..];
        for i in 0..16 {
            match i % 4 {
                0 | 3 => x[i] ^= kp[i],
                _ => x[i] = x[i].wrapping_sub(kp[i]),
            }
        }
        // do_ir in reverse round order
        let total = if self.k_bytes > 24 {
            16
        } else if self.k_bytes > 16 {
            12
        } else {
            8
        };
        for r in (0..total).rev() {
            do_ir(&mut x, &self.l_key[r * 32..]);
        }
        let out = word_reverse(&x);
        b[..16].copy_from_slice(&out);
    }
}
