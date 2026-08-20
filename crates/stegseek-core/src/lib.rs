//! StegSeek core — steghide-compatible steganography primitives.
//!
//! Fidelity is the hard requirement: every algorithm here is a bit-exact port
//! of steghide 0.5.1 / stegseek 0.6 behaviour.

// Many items are introduced milestone-by-milestone; silence dead-code noise
// until the full pipeline is wired up.
#![allow(dead_code)]

pub mod autils;
pub mod bitstring;
pub mod crack;
pub mod embdata;
pub mod embed;
pub mod error;
pub mod format;
pub mod mcrypt;
pub mod rng;
pub mod selector;
pub mod types;
pub mod utils;

pub use error::{StegError, StegResult};
