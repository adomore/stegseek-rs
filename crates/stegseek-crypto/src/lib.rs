//! libmcrypt / libmhash compatible crypto layer.
#![allow(dead_code)]
// The ciphers are bit-exact ports of the libmcrypt C reference (golden-validated
// against 108 vectors). Index-based loops, manual rotations/copies, and the
// SAFER+ "Armenian permutation" — a cyclic element rotation clippy mis-reads as a
// pairwise `swap` — mirror the source and must stay structurally faithful, so
// clippy's rewrites here are inappropriate (and for the permutation, wrong).
#![allow(
    clippy::needless_range_loop,
    clippy::manual_swap,
    clippy::manual_memcpy,
    clippy::manual_rotate
)]

pub mod algorithm;
pub mod cipher;
pub mod facade;
pub mod hash;
pub mod keygen;
pub mod mode;
pub mod modes;

pub use algorithm::{EncryptionAlgorithm, ALGORITHMS};
pub use facade::{crypt, encrypted_size_bits, is_supported, key_for};
pub use hash::{crc32_steghide, md5, md5_fold_seed};
pub use keygen::keygen_mcrypt_md5;
pub use mode::EncryptionMode;
