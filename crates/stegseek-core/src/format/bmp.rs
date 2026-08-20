//! Windows/OS-2 BMP read + embed (1/4/8/24-bit). Palette samples embed
//! `index % modulus`; 24-bit samples embed `((R&1)^(G&1))<<1 | ((R&1)^(B&1))`.
//! Embedding patches a copy of the original file bytes.

use super::{CvrStgFile, EmbedFile};
use crate::error::{StegError, StegResult};
use crate::rng::RandomSource;
use crate::types::{EmbValue, SamplePos};

#[derive(Clone, Copy, PartialEq)]
enum Sub {
    Win,
    Os2,
}

pub struct BmpFile {
    width: u32,
    height: u32,
    bitcount: u16,
    spv: u16,
    radius: u32,
    modulus: EmbValue,
    linelength: usize,
    data: Vec<u8>,
    sub: Sub,
    // embed state
    raw: Vec<u8>,
    header_end: usize,
    padding: usize,
    palette: Vec<(u8, u8, u8)>, // (r,g,b) per index
}

fn le16(b: &[u8], o: usize) -> u16 {
    (b[o] as u16) | ((b[o + 1] as u16) << 8)
}
fn le32(b: &[u8], o: usize) -> u32 {
    (b[o] as u32) | ((b[o + 1] as u32) << 8) | ((b[o + 2] as u32) << 16) | ((b[o + 3] as u32) << 24)
}

impl BmpFile {
    pub fn read(data: &[u8], name: &str) -> StegResult<Self> {
        let unsup = |m: String| StegError::UnsupportedFileFormat(m);
        if data.len() < 18 || &data[0..2] != b"BM" {
            return Err(unsup(format!("\"{name}\" is not a BMP file.")));
        }
        let bisize = le32(data, 14);
        let (sub, width, height, bitcount, header_end, palette_off, ncolors): (
            Sub,
            u32,
            u32,
            u16,
            usize,
            usize,
            usize,
        ) = if bisize == 40 {
            let w = le32(data, 18) as i32;
            let h = le32(data, 22) as i32;
            let bc = le16(data, 28);
            if le32(data, 30) != 0 {
                return Err(StegError::NotImplemented(format!(
                    "the bitmap data in \"{name}\" is compressed which is not supported."
                )));
            }
            let clrused = le32(data, 46);
            let nc = if bc < 24 {
                if clrused != 0 {
                    clrused as usize
                } else {
                    match bc {
                        1 => 2,
                        4 => 16,
                        8 => 256,
                        _ => 0,
                    }
                }
            } else {
                0
            };
            (
                Sub::Win,
                w.unsigned_abs(),
                h.unsigned_abs(),
                bc,
                54 + nc * 4,
                54,
                nc,
            )
        } else if bisize == 12 {
            let w = le16(data, 18) as u32;
            let h = le16(data, 20) as u32;
            let bc = le16(data, 24);
            let nc = if bc < 24 {
                match bc {
                    1 => 2,
                    4 => 16,
                    8 => 256,
                    _ => 0,
                }
            } else {
                0
            };
            (Sub::Os2, w, h, bc, 26 + nc * 3, 26, nc)
        } else {
            return Err(StegError::NotImplemented(format!(
                "the bmp file \"{name}\" has a format that is not supported (biSize: {bisize})."
            )));
        };

        let (spv, modulus, radius): (u16, EmbValue, u32) = match bitcount {
            1 | 4 => (2, 2, 400),
            8 => (3, 4, 400),
            24 => (2, 4, 100),
            _ => {
                return Err(StegError::NotImplemented(format!(
                    "the bmp file \"{name}\" has a format not supported (biBitCount: {bitcount})."
                )))
            }
        };

        // palette (entry size 4 for WIN, 3 for OS2; stored B,G,R[,resv])
        let entry = if sub == Sub::Win { 4 } else { 3 };
        let mut palette = Vec::with_capacity(ncolors);
        for i in 0..ncolors {
            let o = palette_off + i * entry;
            if o + 3 > data.len() {
                break;
            }
            palette.push((data[o + 2], data[o + 1], data[o])); // (r,g,b)
        }

        let linelength = {
            let bits = (bitcount as usize) * (width as usize);
            if bits % 8 == 0 {
                bits / 8
            } else {
                bits / 8 + 1
            }
        };
        let padding = if linelength % 4 == 0 {
            0
        } else {
            4 - (linelength % 4)
        };
        let stride = linelength + padding;

        let mut bitmap = vec![0u8; (height as usize) * linelength];
        for line in 0..height as usize {
            let src = header_end + line * stride;
            if src + linelength > data.len() {
                return Err(StegError::Steghide(format!(
                    "premature end of file \"{name}\" while reading bmp data."
                )));
            }
            bitmap[line * linelength..(line + 1) * linelength]
                .copy_from_slice(&data[src..src + linelength]);
        }

        Ok(BmpFile {
            width,
            height,
            bitcount,
            spv,
            radius,
            modulus,
            linelength,
            data: bitmap,
            sub,
            raw: data.to_vec(),
            header_end,
            padding,
            palette,
        })
    }

    fn calc_index(&self, pos: u32) -> (usize, u16) {
        let row = (pos / self.width) as usize;
        let p = pos % self.width;
        match self.bitcount {
            1 | 4 | 8 => {
                let spb = (8 / self.bitcount) as u32;
                let column = (p / spb) as usize;
                let firstbit = ((spb - (p % spb) - 1) * self.bitcount as u32) as u16;
                (self.linelength * row + column, firstbit)
            }
            24 => (self.linelength * row + (p as usize) * 3, 0),
            _ => unreachable!(),
        }
    }

    /// raw-file byte offset corresponding to a non-padded bitmap byte index.
    fn raw_off(&self, index: usize) -> usize {
        let row = index / self.linelength;
        self.header_end + index + row * self.padding
    }

    fn palette_index(&self, pos: u32) -> u8 {
        let (index, firstbit) = self.calc_index(pos);
        let mut idx: u16 = 0;
        for i in 0..self.bitcount {
            idx |= ((self.data[index] as u16) & (1u16 << (firstbit + i))) >> firstbit;
        }
        idx as u8
    }

    fn rgb(&self, pos: u32) -> (u8, u8, u8) {
        let (index, _) = self.calc_index(pos);
        (self.data[index + 2], self.data[index + 1], self.data[index]) // (r,g,b)
    }

    fn coldist(a: (u8, u8, u8), b: (u8, u8, u8)) -> u32 {
        let dr = a.0 as i32 - b.0 as i32;
        let dg = a.1 as i32 - b.1 as i32;
        let db = a.2 as i32 - b.2 as i32;
        (dr * dr + dg * dg + db * db) as u32
    }

    /// nearest palette index with idx%modulus==t (min colour distance, lowest index on ties).
    fn nearest_palette(&self, pos: u32, t: EmbValue) -> (u8, u32) {
        let cur = self.palette_index(pos);
        let curcol = self.palette[cur as usize];
        let mut best = (cur, u32::MAX);
        for (i, &col) in self.palette.iter().enumerate() {
            if (i as u8) % self.modulus == t {
                let d = Self::coldist(curcol, col);
                if d < best.1 {
                    best = (i as u8, d);
                }
            }
        }
        best
    }

    /// 24-bit: adjust G and/or B LSBs (keeping R) so EValue==t; returns (rgb, dist).
    fn nearest_rgb(
        &self,
        pos: u32,
        t: EmbValue,
        rng: Option<&mut dyn RandomSource>,
    ) -> ((u8, u8, u8), u32) {
        let (r, g, b) = self.rgb(pos);
        let t1 = (t >> 1) & 1;
        let t0 = t & 1;
        let want_g = (r & 1) ^ t1;
        let want_b = (r & 1) ^ t0;
        let mut rng = rng;
        let adj = |v: u8, want: u8, rng: &mut Option<&mut dyn RandomSource>| -> u8 {
            if v & 1 == want {
                return v;
            }
            let up = v < 255;
            let down = v > 0;
            let pick_up = if up && down {
                rng.as_mut().map(|r| r.get_bool()).unwrap_or(true)
            } else {
                up
            };
            if pick_up {
                v + 1
            } else {
                v - 1
            }
        };
        let ng = adj(g, want_g, &mut rng);
        let nb = adj(b, want_b, &mut rng);
        let d = Self::coldist((r, g, b), (r, ng, nb));
        ((r, ng, nb), d)
    }

    fn patch_palette(&mut self, pos: u32, new_idx: u8) {
        let (index, firstbit) = self.calc_index(pos);
        let bitcount = self.bitcount;
        for arr in [false, true] {
            let buf_index = if arr { self.raw_off(index) } else { index };
            let target = if arr { &mut self.raw } else { &mut self.data };
            for i in 0..bitcount {
                target[buf_index] &= !(1u8 << (firstbit + i));
                target[buf_index] |= (new_idx & (1u8 << i)) << firstbit;
            }
        }
    }

    fn patch_rgb(&mut self, pos: u32, rgb: (u8, u8, u8)) {
        let (index, _) = self.calc_index(pos);
        let ro = self.raw_off(index);
        // stored B,G,R
        self.data[index] = rgb.2;
        self.data[index + 1] = rgb.1;
        self.data[index + 2] = rgb.0;
        self.raw[ro] = rgb.2;
        self.raw[ro + 1] = rgb.1;
        self.raw[ro + 2] = rgb.0;
    }
}

impl CvrStgFile for BmpFile {
    fn num_samples(&self) -> u32 {
        self.width * self.height
    }
    fn get_embedded_value(&self, pos: SamplePos) -> EmbValue {
        match self.bitcount {
            1 | 4 | 8 => self.palette_index(pos) % self.modulus,
            24 => {
                let (r, g, b) = self.rgb(pos);
                ((r & 1) ^ (g & 1)) << 1 | ((r & 1) ^ (b & 1))
            }
            _ => unreachable!(),
        }
    }
    fn samples_per_vertex(&self) -> u16 {
        self.spv
    }
    fn radius(&self) -> u32 {
        self.radius
    }
    fn emb_value_modulus(&self) -> EmbValue {
        self.modulus
    }
    fn format_name(&self) -> String {
        match self.sub {
            Sub::Win => "Windows 3.x bitmap".to_string(),
            Sub::Os2 => "OS/2 1.x bitmap".to_string(),
        }
    }
}

impl EmbedFile for BmpFile {
    fn nearest_distance(&self, pos: u32, t: EmbValue) -> u32 {
        if self.bitcount == 24 {
            self.nearest_rgb(pos, t, None).1
        } else {
            self.nearest_palette(pos, t).1
        }
    }
    fn apply_target(&mut self, pos: u32, t: EmbValue, rng: &mut dyn RandomSource) {
        if self.bitcount == 24 {
            let (rgb, _) = self.nearest_rgb(pos, t, Some(rng));
            self.patch_rgb(pos, rgb);
        } else {
            let (idx, _) = self.nearest_palette(pos, t);
            self.patch_palette(pos, idx);
        }
    }
    fn to_stego_bytes(&self) -> Vec<u8> {
        self.raw.clone()
    }
    fn sample_distance(&self, p1: u32, p2: u32) -> u32 {
        if self.bitcount == 24 {
            Self::coldist(self.rgb(p1), self.rgb(p2))
        } else {
            let c1 = self.palette[self.palette_index(p1) as usize];
            let c2 = self.palette[self.palette_index(p2) as usize];
            Self::coldist(c1, c2)
        }
    }
    fn swap_samples(&mut self, p1: u32, p2: u32) {
        if self.bitcount == 24 {
            let a = self.rgb(p1);
            let b = self.rgb(p2);
            self.patch_rgb(p1, b);
            self.patch_rgb(p2, a);
        } else {
            let a = self.palette_index(p1);
            let b = self.palette_index(p2);
            self.patch_palette(p1, b);
            self.patch_palette(p2, a);
        }
    }
    fn sample_scalar(&self, pos: u32) -> i64 {
        if self.bitcount == 24 {
            let (r, g, b) = self.rgb(pos);
            ((r as i64) << 16) | ((g as i64) << 8) | (b as i64)
        } else {
            self.palette_index(pos) as i64
        }
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
    fn reads_all_bmp_variants() {
        for f in [
            "win3x1_std.bmp",
            "win3x4_std.bmp",
            "win3x8_std.bmp",
            "win3x24_std.bmp",
            "os21x1_std.bmp",
            "os21x4_std.bmp",
            "os21x8_std.bmp",
            "os21x24_std.bmp",
        ] {
            let b = BmpFile::read(&datafile(f), f).unwrap();
            assert_eq!(b.num_samples(), b.width * b.height, "{f}");
            for i in 0..b.num_samples() {
                assert!(b.get_embedded_value(i) < b.emb_value_modulus(), "{f}");
            }
        }
    }
}
