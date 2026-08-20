//! Cover/stego file abstraction (`CvrStgFile`) and format detection.
//!
//! For the cracking/extraction path only `num_samples`, `get_embedded_value`,
//! and the per-format constants are needed; the full SampleValue graph model
//! (embedding) is added in the embed milestone.

pub mod audio;
pub mod bmp;
pub mod jpeg;

use crate::error::{StegError, StegResult};
use crate::types::{EmbValue, SamplePos};

// A cover-/stego-file: a sequence of samples each carrying an embedded value.
use crate::rng::RandomSource;

/// A cover file that can be embedded into and serialized back to stego bytes.
pub trait EmbedFile: CvrStgFile {
    /// Distortion (distance) of changing sample `pos` to the nearest value with
    /// embedded value `t` (0 if it already has that value).
    fn nearest_distance(&self, pos: u32, t: EmbValue) -> u32;
    /// Change sample `pos` to the nearest value with embedded value `t`
    /// (random tie-break among equidistant candidates).
    fn apply_target(&mut self, pos: u32, t: EmbValue, rng: &mut dyn RandomSource);
    /// Serialize the (possibly modified) cover to stego-file bytes.
    fn to_stego_bytes(&self) -> Vec<u8>;

    /// Distance (steghide `calcDistance`) between the sample values at two
    /// positions — used to weight graph-matching edges.
    fn sample_distance(&self, p1: u32, p2: u32) -> u32;
    /// Swap the sample values at two positions (the steghide "edge" operation).
    fn swap_samples(&mut self, p1: u32, p2: u32);
    /// A signed scalar identity of the sample value at `pos` (for distortion
    /// measurement / comparison across two copies of the same cover).
    fn sample_scalar(&self, pos: u32) -> i64;
}

pub trait CvrStgFile {
    fn num_samples(&self) -> u32;
    fn get_embedded_value(&self, pos: SamplePos) -> EmbValue;
    fn samples_per_vertex(&self) -> u16;
    fn radius(&self) -> u32;
    fn emb_value_modulus(&self) -> EmbValue;
    /// Short format string used by `--info` (e.g. "jpeg", "wave audio, PCM encoding").
    fn format_name(&self) -> String;

    /// Capacity in bytes — mirrors `CvrStgFile::getCapacity` (note the integer
    /// division of samples by samples-per-vertex before the float math).
    fn capacity_bytes(&self) -> u64 {
        let maxnvertices = (self.num_samples() / self.samples_per_vertex() as u32) as f64;
        let maxnbits = maxnvertices * (self.emb_value_modulus() as f64).log2();
        (maxnbits / 8.0) as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileFormat {
    Bmp,
    Wav,
    Au,
    Jpeg,
    Unknown,
}

/// Guess the file format from the leading bytes (mirrors `CvrStgFile::guessff`).
pub fn guess_format(data: &[u8]) -> FileFormat {
    if data.len() >= 2 && &data[0..2] == b"BM" {
        FileFormat::Bmp
    } else if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
        FileFormat::Jpeg
    } else if data.len() >= 4 && &data[0..4] == b".snd" {
        FileFormat::Au
    } else if data.len() >= 4 && &data[0..4] == b"RIFF" {
        FileFormat::Wav
    } else {
        FileFormat::Unknown
    }
}

/// Read a cover/stego file from raw bytes, dispatching on the detected format.
pub fn read_bytes(data: Vec<u8>, name: &str) -> StegResult<Box<dyn CvrStgFile>> {
    match guess_format(&data) {
        FileFormat::Wav => Ok(Box::new(audio::AudioFile::read_wav(&data, name)?)),
        FileFormat::Au => Ok(Box::new(audio::AudioFile::read_au(&data, name)?)),
        FileFormat::Jpeg => Ok(Box::new(jpeg::JpegFile::read(&data, name)?)),
        FileFormat::Bmp => Ok(Box::new(bmp::BmpFile::read(&data, name)?)),
        FileFormat::Unknown => Err(StegError::UnsupportedFileFormat(format!(
            "the file format of the file \"{name}\" is not supported."
        ))),
    }
}

/// Read a cover file for embedding (formats that support write-back).
pub fn read_for_embed(data: Vec<u8>, name: &str) -> StegResult<Box<dyn EmbedFile>> {
    match guess_format(&data) {
        FileFormat::Wav => Ok(Box::new(audio::AudioFile::read_wav(&data, name)?)),
        FileFormat::Au => Ok(Box::new(audio::AudioFile::read_au(&data, name)?)),
        FileFormat::Bmp => Ok(Box::new(bmp::BmpFile::read(&data, name)?)),
        FileFormat::Jpeg => Ok(Box::new(jpeg::JpegFile::read(&data, name)?)),
        FileFormat::Unknown => Err(StegError::UnsupportedFileFormat(format!(
            "the file format of the file \"{name}\" is not supported."
        ))),
    }
}

/// Read a cover/stego file from a path.
pub fn read_file(path: &str) -> StegResult<Box<dyn CvrStgFile>> {
    let data = std::fs::read(path)?;
    read_bytes(data, path)
}
