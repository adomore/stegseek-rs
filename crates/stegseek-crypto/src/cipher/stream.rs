//! Stream ciphers used by steghide.

use super::{enigma::Enigma, wake::Wake};

/// Standard RC4 (libmcrypt `arcfour`); encrypt == decrypt.
pub fn rc4_apply(key: &[u8], buf: &mut [u8]) {
    let mut s: [u8; 256] = [0; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for byte in buf.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *byte ^= k;
    }
}

/// Apply a stream cipher by name in place; returns true if handled.
pub fn apply_stream(name: &str, key: &[u8], buf: &mut [u8], encrypt: bool) -> bool {
    match name {
        "arcfour" => {
            rc4_apply(key, buf);
            true
        }
        "enigma" => {
            Enigma::new(key).apply(buf);
            true
        }
        "wake" => {
            Wake::new(key).apply(buf, encrypt);
            true
        }
        _ => false,
    }
}
