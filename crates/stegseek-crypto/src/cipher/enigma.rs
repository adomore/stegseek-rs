//! libmcrypt `enigma` — a one-rotor machine (public-domain replacement for the
//! UNIX `crypt` command). Stream cipher, key up to 13 bytes, encrypt == decrypt.
//! All rotor arithmetic is performed modulo 256, matching the C (whose signed
//! `char` tables are equivalent mod 256 once masked).

const ROTORSZ: usize = 256;

pub struct Enigma {
    t1: [u8; ROTORSZ],
    t2: [u8; ROTORSZ],
    t3: [u8; ROTORSZ],
}

impl Enigma {
    pub fn new(password: &[u8]) -> Self {
        let mut cbuf = [0i32; 13];
        let plen = password.len().min(13);
        for i in 0..plen {
            cbuf[i] = password[i] as i8 as i32; // signed char
        }
        let mut seed: i32 = 123;
        for i in 0..13 {
            seed = seed.wrapping_mul(cbuf[i]).wrapping_add(i as i32);
        }
        let mut t1 = [0u8; ROTORSZ];
        let mut t2 = [0u8; ROTORSZ];
        let mut t3 = [0u8; ROTORSZ];
        for i in 0..ROTORSZ {
            t1[i] = i as u8;
        }
        for i in 0..ROTORSZ {
            seed = seed.wrapping_mul(5).wrapping_add(cbuf[i % 13]);
            let mut random = (seed % 65521) as u32;
            let k = ROTORSZ - 1 - i;
            let ic = ((random & 0xff) as usize) % (k + 1);
            random >>= 8;
            t1.swap(k, ic);
            if t3[k] != 0 {
                continue;
            }
            if k == 0 {
                continue; // C relies on t3[0] already set; guard the %0
            }
            let mut ic2 = ((random & 0xff) as usize) % k;
            while t3[ic2] != 0 {
                ic2 = (ic2 + 1) % k;
            }
            t3[k] = ic2 as u8;
            t3[ic2] = k as u8;
        }
        for i in 0..ROTORSZ {
            t2[t1[i] as usize] = i as u8;
        }
        Enigma { t1, t2, t3 }
    }

    pub fn apply(&self, buf: &mut [u8]) {
        let (mut n1, mut n2): (usize, usize) = (0, 0);
        let mut nr2: usize = 0;
        for x in buf.iter_mut() {
            let nr1 = n1;
            let i = *x as usize;
            let a = self.t1[(i + nr1) & 0xff] as usize;
            let b = self.t3[(a + nr2) & 0xff] as usize;
            let c = self.t2[(b.wrapping_sub(nr2)) & 0xff] as usize;
            *x = (c.wrapping_sub(nr1) & 0xff) as u8;
            n1 += 1;
            if n1 == ROTORSZ {
                n1 = 0;
                n2 += 1;
                if n2 == ROTORSZ {
                    n2 = 0;
                }
                nr2 = n2;
            }
        }
    }
}
