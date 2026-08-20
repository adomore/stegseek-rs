//! WAV (PCM) and Sun AU read + embed. EValue = sample & 1 for all audio
//! formats. Embedding flips a sample by ±1 (the nearest value with the desired
//! LSB) and patches it back into a copy of the original file bytes.

use super::{CvrStgFile, EmbedFile};
use crate::error::{StegError, StegResult};
use crate::rng::RandomSource;
use crate::types::{EmbValue, SamplePos};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    WavSmall, // <= 8 bit, unsigned
    WavLarge, // > 8 bit, signed two's complement, little-endian
    AuMuLaw,
    AuPcm8,
    AuPcm16, // big-endian
}

pub struct AudioFile {
    samples: Vec<i64>,
    samples_per_vertex: u16,
    radius: u32,
    name: String,
    format: String,
    // embed state
    raw: Vec<u8>,
    data_start: usize,
    bytespersample: usize,
    firstbitpos: u32,
    min_value: i64,
    max_value: i64,
    kind: Kind,
}

fn le_u16(b: &[u8], o: usize) -> u16 {
    (b[o] as u16) | ((b[o + 1] as u16) << 8)
}
fn le_u32(b: &[u8], o: usize) -> u32 {
    (b[o] as u32) | ((b[o + 1] as u32) << 8) | ((b[o + 2] as u32) << 16) | ((b[o + 3] as u32) << 24)
}
fn be_u32(b: &[u8], o: usize) -> u32 {
    ((b[o] as u32) << 24) | ((b[o + 1] as u32) << 16) | ((b[o + 2] as u32) << 8) | (b[o + 3] as u32)
}

impl AudioFile {
    pub fn read_wav(data: &[u8], name: &str) -> StegResult<Self> {
        let err = || StegError::Steghide(format!("the wav file \"{name}\" is corrupted."));
        if data.len() < 12 || &data[8..12] != b"WAVE" {
            return Err(StegError::UnsupportedFileFormat(format!(
                "the file \"{name}\" is not a WAVE file."
            )));
        }
        let mut pos = 12usize;
        let mut bits_per_sample: u16 = 0;
        let mut fmt_seen = false;
        let mut data_range: Option<(usize, usize)> = None;
        while pos + 8 <= data.len() {
            let id = &data[pos..pos + 4];
            let len = le_u32(data, pos + 4) as usize;
            let body = pos + 8;
            if !fmt_seen {
                if body + 16 > data.len() {
                    return Err(err());
                }
                if le_u16(data, body) != 0x0001 {
                    return Err(StegError::NotImplemented(format!(
                        "the wav file \"{name}\" has a format that is not supported."
                    )));
                }
                bits_per_sample = le_u16(data, body + 14);
                fmt_seen = true;
            } else if id == b"data" {
                let end = (body + len).min(data.len());
                data_range = Some((body, end));
                break;
            }
            pos = body + len;
        }
        let (ds, de) = data_range.ok_or_else(err)?;
        let bps = bits_per_sample;
        let bytespersample = if bps % 8 == 0 { bps / 8 } else { bps / 8 + 1 } as usize;
        let firstbitpos = if bps % 8 == 0 {
            0u32
        } else {
            (8 - (bps % 8)) as u32
        };
        let mask: u32 = if bps >= 32 {
            u32::MAX
        } else {
            (1u32 << bps) - 1
        };

        let mut samples = Vec::new();
        let mut readpos = ds;
        while readpos + bytespersample <= de {
            if bps <= 8 {
                samples.push((data[readpos] >> firstbitpos) as i64);
            } else {
                let mut value = 0u32;
                for i in 0..bytespersample {
                    value |= (data[readpos + i] as u32) << (8 * i);
                }
                value >>= firstbitpos;
                let signed = if ((value >> (bps - 1)) & 1) == 0 {
                    value as i64
                } else {
                    let mut v = !value;
                    v = v.wrapping_add(1);
                    v &= mask;
                    -(v as i64)
                };
                samples.push(signed);
            }
            readpos += bytespersample;
        }
        let (min_value, max_value, kind) = if bps <= 8 {
            (0i64, 1i64 << bps, Kind::WavSmall)
        } else {
            (
                -(1i64 << (bps - 1)),
                (1i64 << (bps - 1)) - 1,
                Kind::WavLarge,
            )
        };
        Ok(AudioFile {
            samples,
            samples_per_vertex: 2,
            radius: if bps <= 8 { 1 } else { 20 },
            name: name.to_string(),
            format: "wave audio, PCM encoding".to_string(),
            raw: data.to_vec(),
            data_start: ds,
            bytespersample,
            firstbitpos,
            min_value,
            max_value,
            kind,
        })
    }

    pub fn read_au(data: &[u8], name: &str) -> StegResult<Self> {
        if data.len() < 24 {
            return Err(StegError::Steghide(format!(
                "premature end of file \"{name}\" while reading au headers."
            )));
        }
        let offset = be_u32(data, 4) as usize;
        let size = be_u32(data, 8);
        let encoding = be_u32(data, 12);
        let (bytespersample, radius, fmt, kind, minv, maxv): (usize, u32, &str, Kind, i64, i64) =
            match encoding {
                1 => (1, 1, "au audio, mu-law encoding", Kind::AuMuLaw, 0, 255),
                2 => (1, 1, "au audio, PCM encoding", Kind::AuPcm8, -128, 127),
                3 => (
                    2,
                    20,
                    "au audio, PCM encoding",
                    Kind::AuPcm16,
                    -32768,
                    32767,
                ),
                _ => {
                    return Err(StegError::NotImplemented(format!(
                        "the au file \"{name}\" uses the unknown encoding {encoding}."
                    )))
                }
            };
        let data_start = offset.min(data.len());
        let avail = data.len() - data_start;
        let n = if size != 0xFFFF_FFFF {
            (size as usize) / bytespersample
        } else {
            avail / bytespersample
        };
        let mut samples = Vec::with_capacity(n);
        for i in 0..n {
            let o = data_start + i * bytespersample;
            if o + bytespersample > data.len() {
                break;
            }
            let v = match encoding {
                1 => data[o] as i64,
                2 => data[o] as i8 as i64,
                3 => (((data[o] as i16) << 8) | (data[o + 1] as i16)) as i64,
                _ => unreachable!(),
            };
            samples.push(v);
        }
        Ok(AudioFile {
            samples,
            samples_per_vertex: 2,
            radius,
            name: name.to_string(),
            format: fmt.to_string(),
            raw: data.to_vec(),
            data_start,
            bytespersample,
            firstbitpos: 0,
            min_value: minv,
            max_value: maxv,
            kind,
        })
    }

    #[inline]
    fn eval(&self, v: i64) -> EmbValue {
        (v & 1) as EmbValue
    }

    /// Nearest value to `samples[pos]` with embedded value `t`, and its distance.
    fn nearest(&self, pos: u32, t: EmbValue, rng: Option<&mut dyn RandomSource>) -> (i64, u32) {
        let v = self.samples[pos as usize];
        if self.eval(v) == t {
            return (v, 0);
        }
        let mut up = v;
        let mut down = v;
        loop {
            if up < self.max_value {
                up += 1;
            }
            if down > self.min_value {
                down -= 1;
            }
            let eu = self.eval(up) == t;
            let ed = self.eval(down) == t;
            let chosen = if eu && ed {
                let pick_up = rng.map(|r| r.get_bool()).unwrap_or(true);
                if pick_up {
                    up
                } else {
                    down
                }
            } else if eu {
                up
            } else if ed {
                down
            } else {
                continue;
            };
            return (chosen, (chosen - v).unsigned_abs() as u32);
        }
    }

    fn patch(&mut self, pos: u32, value: i64) {
        self.samples[pos as usize] = value;
        let off = self.data_start + (pos as usize) * self.bytespersample;
        match self.kind {
            Kind::WavSmall => {
                self.raw[off] = (value as u8) << self.firstbitpos;
            }
            Kind::WavLarge => {
                let mut uv = if value >= 0 {
                    value as u64
                } else {
                    (!(value.unsigned_abs())).wrapping_add(1)
                };
                uv <<= self.firstbitpos;
                for i in 0..self.bytespersample {
                    self.raw[off + i] = (uv >> (8 * i)) as u8;
                }
            }
            Kind::AuMuLaw | Kind::AuPcm8 => {
                self.raw[off] = value as u8;
            }
            Kind::AuPcm16 => {
                let uv = value as i16 as u16;
                self.raw[off] = (uv >> 8) as u8;
                self.raw[off + 1] = (uv & 0xff) as u8;
            }
        }
    }
}

impl CvrStgFile for AudioFile {
    fn num_samples(&self) -> u32 {
        self.samples.len() as u32
    }
    fn get_embedded_value(&self, pos: SamplePos) -> EmbValue {
        (self.samples[pos as usize] & 1) as EmbValue
    }
    fn samples_per_vertex(&self) -> u16 {
        self.samples_per_vertex
    }
    fn radius(&self) -> u32 {
        self.radius
    }
    fn emb_value_modulus(&self) -> EmbValue {
        2
    }
    fn format_name(&self) -> String {
        self.format.clone()
    }
}

impl EmbedFile for AudioFile {
    fn nearest_distance(&self, pos: u32, t: EmbValue) -> u32 {
        self.nearest(pos, t, None).1
    }
    fn apply_target(&mut self, pos: u32, t: EmbValue, rng: &mut dyn RandomSource) {
        let (v, _) = self.nearest(pos, t, Some(rng));
        self.patch(pos, v);
    }
    fn to_stego_bytes(&self) -> Vec<u8> {
        self.raw.clone()
    }
    fn sample_distance(&self, p1: u32, p2: u32) -> u32 {
        (self.samples[p1 as usize] - self.samples[p2 as usize]).unsigned_abs() as u32
    }
    fn swap_samples(&mut self, p1: u32, p2: u32) {
        let a = self.samples[p1 as usize];
        let b = self.samples[p2 as usize];
        self.patch(p1, b);
        self.patch(p2, a);
    }
    fn sample_scalar(&self, pos: u32) -> i64 {
        self.samples[pos as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn datafile(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap()
    }
    #[test]
    fn reads_pcm_wavs() {
        for f in ["pcm8_std.wav", "pcm16_std.wav"] {
            let af = AudioFile::read_wav(&datafile(f), f).unwrap();
            assert!(af.num_samples() > 0, "{f}");
            let ones: u32 = (0..af.num_samples())
                .map(|i| af.get_embedded_value(i) as u32)
                .sum();
            assert!(ones > 0 && ones < af.num_samples());
        }
    }
    #[test]
    fn reads_aus() {
        for f in ["pcm8_std.au", "pcm16_std.au", "mulaw_std.au"] {
            let af = AudioFile::read_au(&datafile(f), f).unwrap();
            assert!(af.num_samples() > 0, "{f}");
            for i in 0..af.num_samples() {
                let _ = af.get_embedded_value(i);
            }
        }
    }
}
