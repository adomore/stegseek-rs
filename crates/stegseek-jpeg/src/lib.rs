//! JPEG entropy-layer codec: exposes quantized DCT coefficients in the exact
//! order libjpeg (and hence steghide) produces them, for steganographic
//! read/write. Pure Rust; supports baseline and progressive Huffman JPEGs.

// The decoder/encoder are a faithful port of libjpeg's entropy layer. The
// index-based loops (`for l in 1..=16`, `for k in 0..64`, natural-order coeff
// scans) mirror the JPEG spec / reference structure and are kept as-is for
// auditability against it, rather than rewritten into iterator form.
#![allow(clippy::needless_range_loop)]

pub mod decoder;

pub use decoder::{JpegError, JpegImage};
