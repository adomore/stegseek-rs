//! Core type aliases mirroring steghide's `common.h` semantics.
//!
//! The original uses fixed-width typedefs (`UWORD32`, `BYTE`, ...). In Rust we
//! use the native fixed-width integers directly and keep only the *semantic*
//! aliases that make the ported code read like the original.

/// Value embedded in a single sample (always `< EmbValueModulus`).
pub type EmbValue = u8;
/// Position of a sample inside a cover/stego file.
pub type SamplePos = u32;
/// Label identifying a unique sample value.
pub type SampleValueLabel = u32;
/// Label identifying a vertex in the embedding graph.
pub type VertexLabel = u32;
/// Key uniquely identifying a sample value.
pub type SampleKey = u32;

pub const UWORD32_MAX: u32 = u32::MAX;
