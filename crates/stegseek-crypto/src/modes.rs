//! Block-cipher mode layer matching libmcrypt semantics.
//!
//! libmcrypt specifics reproduced here:
//! - `cfb`/`ofb` are **8-bit** (byte-wise) feedback.
//! - `ncfb`/`nofb` are **full-block** feedback.
//! - `ctr` increments the counter **big-endian** (last byte first), as
//!   libmcrypt's `ctr.c` `increase_counter` does.
//!
//! steghide always passes buffers that are a whole number of blocks.

use crate::cipher::BlockCipher;

pub fn ecb_encrypt(c: &dyn BlockCipher, buf: &mut [u8]) {
    let bs = c.block_size();
    for chunk in buf.chunks_mut(bs) {
        c.encrypt_block(chunk);
    }
}
pub fn ecb_decrypt(c: &dyn BlockCipher, buf: &mut [u8]) {
    let bs = c.block_size();
    for chunk in buf.chunks_mut(bs) {
        c.decrypt_block(chunk);
    }
}

pub fn cbc_encrypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut prev = iv.to_vec();
    for chunk in buf.chunks_mut(bs) {
        for i in 0..chunk.len() {
            chunk[i] ^= prev[i];
        }
        c.encrypt_block(chunk);
        prev[..chunk.len()].copy_from_slice(chunk);
    }
}
pub fn cbc_decrypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut prev = iv.to_vec();
    for chunk in buf.chunks_mut(bs) {
        let ct = chunk.to_vec();
        c.decrypt_block(chunk);
        for i in 0..chunk.len() {
            chunk[i] ^= prev[i];
        }
        prev[..ct.len()].copy_from_slice(&ct);
    }
}

/// Full-block CFB (mcrypt `ncfb`).
pub fn ncfb_encrypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut fb = iv.to_vec();
    for chunk in buf.chunks_mut(bs) {
        let mut ks = fb.clone();
        c.encrypt_block(&mut ks);
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
        fb[..chunk.len()].copy_from_slice(chunk);
    }
}
pub fn ncfb_decrypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut fb = iv.to_vec();
    for chunk in buf.chunks_mut(bs) {
        let mut ks = fb.clone();
        c.encrypt_block(&mut ks);
        let ct = chunk.to_vec();
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
        fb[..ct.len()].copy_from_slice(&ct);
    }
}

/// Full-block OFB (mcrypt `nofb`); identical for encrypt and decrypt.
pub fn nofb_crypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut o = iv.to_vec();
    for chunk in buf.chunks_mut(bs) {
        c.encrypt_block(&mut o);
        for i in 0..chunk.len() {
            chunk[i] ^= o[i];
        }
    }
}

/// 8-bit CFB (mcrypt `cfb`).
pub fn cfb8_encrypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut reg = iv.to_vec();
    for x in buf.iter_mut() {
        let mut t = reg.clone();
        c.encrypt_block(&mut t);
        let ct = *x ^ t[0];
        reg.copy_within(1..bs, 0);
        reg[bs - 1] = ct;
        *x = ct;
    }
}
pub fn cfb8_decrypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut reg = iv.to_vec();
    for x in buf.iter_mut() {
        let mut t = reg.clone();
        c.encrypt_block(&mut t);
        let ct = *x;
        let pt = ct ^ t[0];
        reg.copy_within(1..bs, 0);
        reg[bs - 1] = ct;
        *x = pt;
    }
}

/// 8-bit OFB (mcrypt `ofb`); identical for encrypt and decrypt.
pub fn ofb8_crypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut reg = iv.to_vec();
    for x in buf.iter_mut() {
        let mut t = reg.clone();
        c.encrypt_block(&mut t);
        let k = t[0];
        reg.copy_within(1..bs, 0);
        reg[bs - 1] = k;
        *x ^= k;
    }
}

/// Counter mode (mcrypt `ctr`); identical for encrypt and decrypt.
pub fn ctr_crypt(c: &dyn BlockCipher, iv: &[u8], buf: &mut [u8]) {
    let bs = c.block_size();
    let mut ctr = iv.to_vec();
    for chunk in buf.chunks_mut(bs) {
        let mut ks = ctr.clone();
        c.encrypt_block(&mut ks);
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
        // big-endian increment, last byte first (mcrypt ctr.c)
        for b in ctr.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
}
