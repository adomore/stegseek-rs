//! JPEG read + embed. Samples are the non-zero DCT coefficients; EValue =
//! |coeff| % 2. Embedding shifts a coefficient to the nearest value with the
//! desired parity (same sign, magnitude >= 1) and re-encodes as baseline JPEG.

use super::{CvrStgFile, EmbedFile};
use crate::error::{StegError, StegResult};
use crate::rng::RandomSource;
use crate::types::{EmbValue, SamplePos};
use stegseek_jpeg::JpegImage;

pub struct JpegFile {
    img: JpegImage,
    locations: Vec<(usize, usize, usize)>,
    name: String,
}

impl JpegFile {
    pub fn read(data: &[u8], name: &str) -> StegResult<Self> {
        let img = JpegImage::parse(data)
            .map_err(|e| StegError::UnsupportedFileFormat(format!("jpeg \"{name}\": {e}")))?;
        let locations = img.stego_locations();
        Ok(JpegFile {
            img,
            locations,
            name: name.to_string(),
        })
    }

    #[inline]
    fn coeff(&self, pos: u32) -> i16 {
        let (c, b, k) = self.locations[pos as usize];
        self.img.coeff(c, b, k)
    }

    #[inline]
    fn ev(c: i16) -> EmbValue {
        (c.unsigned_abs() % 2) as EmbValue
    }

    /// JpegSampleValue::getNearestTargetSampleValue — nearest coeff with the
    /// target parity, keeping the sign and |coeff| >= 1.
    fn nearest(&self, pos: u32, t: EmbValue, rng: Option<&mut dyn RandomSource>) -> (i16, u32) {
        let c = self.coeff(pos);
        if Self::ev(c) == t {
            return (c, 0);
        }
        let (minv, maxv) = if c > 0 {
            (1i16, i16::MAX)
        } else {
            (i16::MIN, -1i16)
        };
        let mut up = c;
        let mut down = c;
        let mut rng = rng;
        loop {
            if up < maxv {
                up += 1;
            }
            if down > minv {
                down -= 1;
            }
            let eu = Self::ev(up) == t;
            let ed = Self::ev(down) == t;
            let chosen = if eu && ed {
                if rng.as_mut().map(|r| r.get_bool()).unwrap_or(true) {
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
            return (chosen, (chosen as i32 - c as i32).unsigned_abs());
        }
    }
}

impl CvrStgFile for JpegFile {
    fn num_samples(&self) -> u32 {
        self.locations.len() as u32
    }
    fn get_embedded_value(&self, pos: SamplePos) -> EmbValue {
        Self::ev(self.coeff(pos))
    }
    fn samples_per_vertex(&self) -> u16 {
        3
    }
    fn radius(&self) -> u32 {
        1
    }
    fn emb_value_modulus(&self) -> EmbValue {
        2
    }
    fn format_name(&self) -> String {
        "jpeg".to_string()
    }
}

impl EmbedFile for JpegFile {
    fn nearest_distance(&self, pos: u32, t: EmbValue) -> u32 {
        self.nearest(pos, t, None).1
    }
    fn apply_target(&mut self, pos: u32, t: EmbValue, rng: &mut dyn RandomSource) {
        let (v, _) = self.nearest(pos, t, Some(rng));
        let (c, b, k) = self.locations[pos as usize];
        self.img.set_coeff(c, b, k, v);
    }
    fn to_stego_bytes(&self) -> Vec<u8> {
        self.img.encode_baseline()
    }
    fn sample_distance(&self, p1: u32, p2: u32) -> u32 {
        (self.coeff(p1) as i32 - self.coeff(p2) as i32).unsigned_abs()
    }
    fn swap_samples(&mut self, p1: u32, p2: u32) {
        let a = self.coeff(p1);
        let b = self.coeff(p2);
        let (c1, b1, k1) = self.locations[p1 as usize];
        let (c2, b2, k2) = self.locations[p2 as usize];
        self.img.set_coeff(c1, b1, k1, b);
        self.img.set_coeff(c2, b2, k2, a);
    }
    fn sample_scalar(&self, pos: u32) -> i64 {
        self.coeff(pos) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn datafile(n: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/data/{}",
            env!("CARGO_MANIFEST_DIR"),
            n
        ))
        .unwrap()
    }
    #[test]
    fn reads_baseline_and_progressive() {
        assert_eq!(
            JpegFile::read(&datafile("std.jpg"), "std.jpg")
                .unwrap()
                .num_samples(),
            3548
        );
        assert_eq!(
            JpegFile::read(&datafile("prog.jpg"), "prog.jpg")
                .unwrap()
                .num_samples(),
            4887
        );
    }
}
