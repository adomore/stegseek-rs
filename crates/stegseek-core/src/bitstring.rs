//! Port of `BitString` (`BitString.cc` / `.h`).
//!
//! A string of bits stored in a `Vec<u8>` with **little-endian bit order**:
//! the first bit is the least-significant bit of the first byte, and so on.
//! Compression uses zlib (via `flate2`, miniz_oxide backend) to match steghide's
//! `compress2`/`uncompress` semantics for round-tripping embedded data.

use crate::autils::div_roundup;
use crate::error::{StegError, StegResult};
use crate::rng::RandomSource;
use crate::types::EmbValue;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

#[inline]
fn bytepos(n: u32) -> usize {
    (n / 8) as usize
}
#[inline]
fn bitpos(n: u32) -> u32 {
    n % 8
}

#[derive(Clone, Debug)]
pub struct BitString {
    length: u32,
    arity: EmbValue,
    arity_nbits: u16,
    data: Vec<u8>,
}

impl Default for BitString {
    fn default() -> Self {
        BitString::new(2)
    }
}

impl BitString {
    /// Construct an empty BitString with the given arity (default 2).
    pub fn new(arity: EmbValue) -> Self {
        let mut bs = BitString {
            length: 0,
            arity: 2,
            arity_nbits: 0,
            data: Vec::new(),
        };
        bs.set_arity(arity);
        bs
    }

    /// Construct a BitString of `l` zero bits.
    pub fn with_len(l: u32) -> Self {
        let nbytes = if l % 8 == 0 { l / 8 } else { l / 8 + 1 } as usize;
        BitString {
            length: l,
            arity: 2,
            arity_nbits: 1,
            data: vec![0u8; nbytes],
        }
    }

    /// Construct from raw bytes (arity 2).
    pub fn from_bytes(d: &[u8]) -> Self {
        let mut bs = BitString::new(2);
        bs.append_bytes(d);
        bs
    }

    /// Construct from the bytes of a string (arity 2).
    pub fn from_str_bytes(d: &str) -> Self {
        let mut bs = BitString::new(2);
        bs.append_str(d);
        bs
    }

    pub fn set_arity(&mut self, arity: EmbValue) {
        self.arity = arity;
        let mut tmp = arity;
        self.arity_nbits = 0;
        while tmp > 1 {
            assert!(tmp % 2 == 0, "arity must be a power of two");
            tmp /= 2;
            self.arity_nbits += 1;
        }
    }

    pub fn arity(&self) -> EmbValue {
        self.arity
    }

    pub fn length(&self) -> u32 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Number of n-ary digits (ceil(length / arity_nbits)).
    pub fn nary_length(&self) -> u32 {
        div_roundup::<u32>(self.length, self.arity_nbits as u32)
    }

    pub fn clear(&mut self) -> &mut Self {
        self.data.clear();
        self.length = 0;
        self
    }

    #[inline]
    fn _append(&mut self, v: u8) {
        if self.length % 8 == 0 {
            self.data.push(0);
        }
        let bp = bytepos(self.length);
        self.data[bp] |= (v & 1) << bitpos(self.length);
        self.length += 1;
    }

    pub fn append_bit(&mut self, v: u8) -> &mut Self {
        self._append(v);
        self
    }

    /// Append the `n` lowest bits of a byte (LSB first).
    pub fn append_byte_n(&mut self, v: u8, n: u16) -> &mut Self {
        for i in 0..n {
            self._append((v >> i) & 1);
        }
        self
    }

    /// Append the `n` lowest bits of a u16 (LSB first).
    pub fn append_u16_n(&mut self, v: u16, n: u16) -> &mut Self {
        for i in 0..n {
            self._append(((v >> i) & 1) as u8);
        }
        self
    }

    /// Append the `n` lowest bits of a u32 (LSB first).
    pub fn append_u32_n(&mut self, v: u32, n: u16) -> &mut Self {
        for i in 0..n {
            self._append(((v >> i) & 1) as u8);
        }
        self
    }

    pub fn append_bytes(&mut self, v: &[u8]) -> &mut Self {
        for &b in v {
            self.append_byte_n(b, 8);
        }
        self
    }

    pub fn append_str(&mut self, v: &str) -> &mut Self {
        for &b in v.as_bytes() {
            self.append_byte_n(b, 8);
        }
        self
    }

    pub fn append_bitstring(&mut self, v: &BitString) -> &mut Self {
        for i in 0..v.length {
            self._append(v.get(i));
        }
        self
    }

    /// Value of the `i`-th bit (0 or 1). Mirrors `operator[]`.
    #[inline]
    pub fn get(&self, i: u32) -> u8 {
        assert!(i < self.length);
        (self.data[bytepos(i)] >> bitpos(i)) & 1
    }

    pub fn set_bit(&mut self, i: u32, v: u8) -> &mut Self {
        assert!(i < self.length);
        let mask = !(1u8 << bitpos(i));
        let bp = bytepos(i);
        self.data[bp] &= mask;
        self.data[bp] |= (v & 1) << bitpos(i);
        self
    }

    /// Copy bits `[s .. s+l)` into a fresh BitString.
    pub fn get_bits(&self, s: u32, l: u32) -> BitString {
        let mut retval = BitString::new(2);
        for i in s..s + l {
            retval.append_bit(self.get(i));
        }
        retval
    }

    /// Cut bits `[s .. s+l)` out of this BitString, returning them.
    /// Afterwards this BitString consists of bits `0..s, s+l..`.
    pub fn cut_bits(&mut self, s: u32, l: u32) -> BitString {
        assert!(s + l <= self.length);
        let mut retval = BitString::new(2);
        let mut i = s;
        let mut j = s + l;
        while i < s + l || j < self.length {
            if i < s + l {
                retval.append_bit(self.get(i));
            }
            if j < self.length {
                let b = self.get(j);
                self.set_bit(i, b);
            }
            i += 1;
            j += 1;
        }
        self.length -= l;
        self.data
            .resize(div_roundup::<u32>(self.length, 8) as usize, 0);
        self.clear_unused();
        retval
    }

    /// Compose a value (up to 32 bits) from bits `[s .. s+l)`, LSB first.
    pub fn get_value(&self, s: u32, l: u16) -> u32 {
        assert!(l <= 32);
        let mut retval = 0u32;
        for i in 0..l as u32 {
            retval |= (self.get(s + i) as u32) << i;
        }
        retval
    }

    /// Raw bytes (requires byte-aligned length).
    pub fn get_bytes(&self) -> &[u8] {
        assert!(self.length % 8 == 0);
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        assert!(self.length % 8 == 0);
        self.data
    }

    /// Keep only bits `[s .. e)`, shifting them to the front.
    pub fn truncate(&mut self, s: u32, e: u32) -> &mut Self {
        let newsize = e - s;
        for i in 0..newsize {
            let bit = self.get(s + i);
            let bp = bytepos(i);
            self.data[bp] &= !(1u8 << bitpos(i));
            self.data[bp] |= bit << bitpos(i);
        }
        self.length = newsize;
        self.clear_unused();
        self
    }

    /// Pad with bit value `v` until length is a multiple of `mult`.
    pub fn pad(&mut self, mult: u32, v: u8) -> &mut Self {
        while self.length % mult != 0 {
            self._append(v);
        }
        self
    }

    /// Pad with random bits until length is a multiple of `mult`.
    pub fn pad_random<R: RandomSource + ?Sized>(&mut self, mult: u32, rng: &mut R) -> &mut Self {
        while self.length % mult != 0 {
            self._append(rng.get_bool() as u8);
        }
        self
    }

    /// Get the `p`-th n-ary digit.
    pub fn get_nary(&self, p: u32) -> EmbValue {
        let pbinary = p * self.arity_nbits as u32;
        let mut retval = 0u8;
        let mut i = 0u32;
        while i < self.arity_nbits as u32 && pbinary + i < self.length {
            retval |= self.get(pbinary + i) << i;
            i += 1;
        }
        retval
    }

    /// Append an n-ary digit (LSB first, `arity_nbits` bits).
    pub fn append_nary(&mut self, v: EmbValue) {
        for i in 0..self.arity_nbits {
            self._append((v >> i) & 1);
        }
    }

    /// Compress using zlib at the given level (1..=9). Pads to a byte boundary
    /// first (as the original does). Matches `BitString::compress`.
    pub fn compress(&mut self, level: i32) -> StegResult<&mut Self> {
        assert!((1..=9).contains(&level));
        self.pad(8, 0);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(level as u32));
        enc.write_all(&self.data).map_err(|e| {
            StegError::Steghide(format!("error while calling zlib's compress2: {e}"))
        })?;
        let out = enc.finish().map_err(|e| {
            StegError::Steghide(format!("error while calling zlib's compress2: {e}"))
        })?;
        self.length = (out.len() as u32) * 8;
        self.data = out;
        Ok(self)
    }

    /// Uncompress, where `idestlen` is the exact uncompressed length in bits.
    /// Matches `BitString::uncompress` (which asserts the inflated size equals
    /// the rounded-up destination length).
    pub fn uncompress(&mut self, idestlen: u32) -> StegResult<&mut Self> {
        assert!(self.length % 8 == 0);
        let ydestlen = if idestlen % 8 == 0 {
            idestlen / 8
        } else {
            idestlen / 8 + 1
        } as usize;
        let srclen = (self.length / 8) as usize;
        let mut decoder = ZlibDecoder::new(&self.data[..srclen]);
        let mut out = Vec::with_capacity(ydestlen);
        decoder.read_to_end(&mut out).map_err(|_| {
            StegError::Steghide("can not uncompress data. compressed data is corrupted.".into())
        })?;
        if out.len() != ydestlen {
            return Err(StegError::Steghide(
                "can not uncompress data. compressed data is corrupted.".into(),
            ));
        }
        self.data = out;
        self.length = idestlen;
        self.clear_unused();
        Ok(self)
    }

    /// XOR another BitString into this one (in place, length-preserving).
    pub fn xor_assign(&mut self, v: &BitString) -> &mut Self {
        for i in 0..self.length {
            let b = self.get(i) ^ v.get(i);
            self.set_bit(i, b);
        }
        self
    }

    fn clear_unused(&mut self) {
        if self.length % 8 != 0 {
            let nbitsfilled = self.length % 8;
            let mut mask = 0u8;
            for _ in 0..nbitsfilled {
                mask <<= 1;
                mask |= 1;
            }
            let last = self.data.len() - 1;
            self.data[last] &= mask;
        }
    }
}

impl PartialEq for BitString {
    fn eq(&self, other: &Self) -> bool {
        if self.length != other.length {
            return false;
        }
        for i in 0..self.length {
            if self.get(i) != other.get(i) {
                return false;
            }
        }
        true
    }
}
impl Eq for BitString {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_index_little_endian() {
        let mut bs = BitString::new(2);
        // append byte 0b0000_0001 -> bit0=1, rest 0
        bs.append_byte_n(0x01, 8);
        assert_eq!(bs.length(), 8);
        assert_eq!(bs.get(0), 1);
        for i in 1..8 {
            assert_eq!(bs.get(i), 0);
        }
        assert_eq!(bs.get_value(0, 8), 0x01);
    }

    #[test]
    fn append_u32_and_get_value_roundtrip() {
        let mut bs = BitString::new(2);
        bs.append_u32_n(0xDEAD_BEEF, 32);
        assert_eq!(bs.get_value(0, 32), 0xDEAD_BEEF);
        // 24-bit magic style read
        bs.clear();
        bs.append_u32_n(0x0073_688D, 24);
        assert_eq!(bs.get_value(0, 24), 0x0073_688D);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let data = vec![0x00, 0xFF, 0x80, 0x01, 0x7E];
        let bs = BitString::from_bytes(&data);
        assert_eq!(bs.length(), 40);
        assert_eq!(bs.get_bytes(), &data[..]);
    }

    #[test]
    fn cut_bits_behaves() {
        // bits: 1 0 1 1  0 0 1 0  (two bytes worth = 8 bits)
        let mut bs = BitString::new(2);
        for b in [1u8, 0, 1, 1, 0, 0, 1, 0] {
            bs.append_bit(b);
        }
        let cut = bs.cut_bits(2, 3); // removes bits [2,3,4] = 1,1,0
        assert_eq!(cut.length(), 3);
        assert_eq!((cut.get(0), cut.get(1), cut.get(2)), (1, 1, 0));
        // remaining: 1 0 | 0 1 0  -> length 5
        assert_eq!(bs.length(), 5);
        let rem: Vec<u8> = (0..5).map(|i| bs.get(i)).collect();
        assert_eq!(rem, vec![1, 0, 0, 1, 0]);
    }

    #[test]
    fn truncate_keeps_window() {
        let mut bs = BitString::new(2);
        for b in [1u8, 1, 0, 1, 0, 0, 1, 1] {
            bs.append_bit(b);
        }
        bs.truncate(2, 6); // keep bits 2..6 = 0,1,0,0
        assert_eq!(bs.length(), 4);
        let v: Vec<u8> = (0..4).map(|i| bs.get(i)).collect();
        assert_eq!(v, vec![0, 1, 0, 0]);
    }

    #[test]
    fn nary_append_and_read() {
        let mut bs = BitString::new(4); // arity 4 -> 2 bits/digit
        bs.append_nary(3); // 11
        bs.append_nary(1); // 01
        bs.append_nary(2); // 10
        assert_eq!(bs.length(), 6);
        assert_eq!(bs.nary_length(), 3);
        assert_eq!(bs.get_nary(0), 3);
        assert_eq!(bs.get_nary(1), 1);
        assert_eq!(bs.get_nary(2), 2);
    }

    #[test]
    fn compress_uncompress_roundtrip() {
        let original: Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut bs = BitString::from_bytes(&original);
        let nbits = bs.length();
        bs.compress(9).unwrap();
        assert!(bs.length() % 8 == 0);
        bs.uncompress(nbits).unwrap();
        assert_eq!(bs.get_bytes(), &original[..]);
    }

    #[test]
    fn equality() {
        let a = BitString::from_bytes(&[1, 2, 3]);
        let b = BitString::from_bytes(&[1, 2, 3]);
        let c = BitString::from_bytes(&[1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
