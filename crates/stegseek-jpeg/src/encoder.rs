// Baseline JPEG re-encoder + coefficient access (included into the JpegImage impl).
// Re-encodes the (possibly modified) quantized DCT coefficients as a baseline
// JPEG using the standard Annex-K Huffman tables. libjpeg reads it back to the
// exact same coefficients, so steghide extraction is unchanged.

impl JpegImage {
    /// Locations (component, block index in padded grid, coeff k) of each
    /// non-zero coefficient, in steghide linearization order.
    pub fn stego_locations(&self) -> Vec<(usize, usize, usize)> {
        let mut v = Vec::new();
        for (ci, c) in self.components.iter().enumerate() {
            for row in 0..c.hib_real {
                for col in 0..c.wib_real {
                    let bp = row * c.wib_pad + col;
                    let blk = &c.blocks[bp];
                    for k in 0..64 {
                        if blk[k] != 0 {
                            v.push((ci, bp, k));
                        }
                    }
                }
            }
        }
        v
    }

    pub fn coeff(&self, ci: usize, bp: usize, k: usize) -> i16 {
        self.components[ci].blocks[bp][k]
    }
    pub fn set_coeff(&mut self, ci: usize, bp: usize, k: usize, val: i16) {
        self.components[ci].blocks[bp][k] = val;
    }

    /// Re-encode as a baseline JPEG.
    pub fn encode_baseline(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xFF, 0xD8]); // SOI

        // DQT for every quant table referenced by a component
        let mut tqs: Vec<usize> = self.components.iter().map(|c| c.tq).collect();
        tqs.sort_unstable();
        tqs.dedup();
        for &tq in &tqs {
            out.extend_from_slice(&[0xFF, 0xDB]);
            out.extend_from_slice(&[0x00, 0x43]); // length 67
            out.push(tq as u8); // Pq=0, Tq
            for i in 0..64 {
                out.push(self.qtables[tq][NATURAL_ORDER[i]] as u8);
            }
        }

        // SOF0
        let nc = self.components.len();
        let lf = 8 + 3 * nc;
        out.extend_from_slice(&[0xFF, 0xC0]);
        out.extend_from_slice(&[(lf >> 8) as u8, lf as u8]);
        out.push(8); // precision
        out.extend_from_slice(&[(self.height >> 8) as u8, self.height as u8]);
        out.extend_from_slice(&[(self.width >> 8) as u8, self.width as u8]);
        out.push(nc as u8);
        for c in &self.components {
            out.push(c.id);
            out.push(((c.h as u8) << 4) | (c.v as u8));
            out.push(c.tq as u8);
        }

        // DHT (standard tables 0 and 1, DC and AC)
        write_dht(&mut out, 0x00, &STD_DC_LUMA_COUNTS, &STD_DC_LUMA_VALUES);
        write_dht(&mut out, 0x10, &STD_AC_LUMA_COUNTS, &STD_AC_LUMA_VALUES);
        if nc > 1 {
            write_dht(&mut out, 0x01, &STD_DC_CHROMA_COUNTS, &STD_DC_CHROMA_VALUES);
            write_dht(&mut out, 0x11, &STD_AC_CHROMA_COUNTS, &STD_AC_CHROMA_VALUES);
        }

        // SOS
        let ls = 6 + 2 * nc;
        out.extend_from_slice(&[0xFF, 0xDA]);
        out.extend_from_slice(&[(ls >> 8) as u8, ls as u8]);
        out.push(nc as u8);
        for (ci, c) in self.components.iter().enumerate() {
            let tbl = if ci == 0 { 0u8 } else { 1u8 };
            out.push(c.id);
            out.push((tbl << 4) | tbl);
        }
        out.extend_from_slice(&[0x00, 0x3F, 0x00]); // Ss, Se, Ah/Al

        // entropy-coded segment
        let dc_codes: Vec<&HuffCodes> = (0..nc)
            .map(|ci| if ci == 0 { dc_luma() } else { dc_chroma() })
            .collect();
        let ac_codes: Vec<&HuffCodes> = (0..nc)
            .map(|ci| if ci == 0 { ac_luma() } else { ac_chroma() })
            .collect();

        let mut bw = BitWriter::new(&mut out);
        let mut dc_pred = vec![0i32; nc];
        let max_h = self.components.iter().map(|c| c.h).max().unwrap();
        let max_v = self.components.iter().map(|c| c.v).max().unwrap();
        let mcus_w = divru(self.width, 8 * max_h);
        let mcus_h = divru(self.height, 8 * max_v);
        for my in 0..mcus_h {
            for mx in 0..mcus_w {
                for ci in 0..nc {
                    let (h, v, wib_pad) = {
                        let c = &self.components[ci];
                        (c.h, c.v, c.wib_pad)
                    };
                    for by in 0..v {
                        for bx in 0..h {
                            let bp = (my * v + by) * wib_pad + (mx * h + bx);
                            encode_block(
                                &mut bw,
                                &self.components[ci].blocks[bp],
                                dc_codes[ci],
                                ac_codes[ci],
                                &mut dc_pred[ci],
                            );
                        }
                    }
                }
            }
        }
        bw.flush();

        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }
}

struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    acc: u32,
    nbits: u32,
}
impl<'a> BitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        BitWriter { out, acc: 0, nbits: 0 }
    }
    fn put(&mut self, code: u32, len: u32) {
        self.acc |= code << (32 - self.nbits - len);
        self.nbits += len;
        while self.nbits >= 8 {
            let b = (self.acc >> 24) as u8;
            self.out.push(b);
            if b == 0xFF {
                self.out.push(0x00); // byte stuffing
            }
            self.acc <<= 8;
            self.nbits -= 8;
        }
    }
    fn flush(&mut self) {
        if self.nbits > 0 {
            // pad the final partial byte with 1-bits (JPEG convention)
            let pad = 8 - self.nbits;
            self.put((1u32 << pad) - 1, pad);
        }
    }
}

fn magnitude_category(v: i32) -> u32 {
    let mut a = v.unsigned_abs();
    let mut s = 0;
    while a != 0 {
        s += 1;
        a >>= 1;
    }
    s
}
fn mantissa(v: i32, s: u32) -> u32 {
    if v >= 0 {
        v as u32
    } else {
        (v - 1) as u32 & ((1u32 << s) - 1)
    }
}

fn encode_block(
    bw: &mut BitWriter,
    block: &[i16; 64],
    dc: &HuffCodes,
    ac: &HuffCodes,
    dc_pred: &mut i32,
) {
    // DC
    let diff = block[0] as i32 - *dc_pred;
    *dc_pred = block[0] as i32;
    let s = magnitude_category(diff);
    let (code, len) = dc[s as usize];
    bw.put(code, len);
    if s > 0 {
        bw.put(mantissa(diff, s), s);
    }
    // AC
    let mut run = 0;
    for k in 1..64 {
        let coeff = block[NATURAL_ORDER[k]] as i32;
        if coeff == 0 {
            run += 1;
        } else {
            while run > 15 {
                let (c, l) = ac[0xF0]; // ZRL
                bw.put(c, l);
                run -= 16;
            }
            let size = magnitude_category(coeff);
            let rs = ((run << 4) | size) as usize;
            let (c, l) = ac[rs];
            bw.put(c, l);
            bw.put(mantissa(coeff, size), size);
            run = 0;
        }
    }
    if run > 0 {
        let (c, l) = ac[0x00]; // EOB
        bw.put(c, l);
    }
}

fn write_dht(out: &mut Vec<u8>, tc_th: u8, counts: &[u8; 16], values: &[u8]) {
    out.extend_from_slice(&[0xFF, 0xC4]);
    let len = 2 + 1 + 16 + values.len();
    out.extend_from_slice(&[(len >> 8) as u8, len as u8]);
    out.push(tc_th);
    out.extend_from_slice(counts);
    out.extend_from_slice(values);
}

/// (code, length) per symbol value (index 0..=255).
type HuffCodes = [(u32, u32); 256];

fn build_codes(counts: &[u8; 16], values: &[u8]) -> HuffCodes {
    let mut codes = [(0u32, 0u32); 256];
    let mut code = 0u32;
    let mut k = 0usize;
    for len in 1..=16u32 {
        for _ in 0..counts[(len - 1) as usize] {
            codes[values[k] as usize] = (code, len);
            code += 1;
            k += 1;
        }
        code <<= 1;
    }
    codes
}

// Standard JPEG Annex K Huffman tables.
const STD_DC_LUMA_COUNTS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const STD_DC_LUMA_VALUES: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const STD_DC_CHROMA_COUNTS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
const STD_DC_CHROMA_VALUES: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const STD_AC_LUMA_COUNTS: [u8; 16] =
    [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d];
const STD_AC_LUMA_VALUES: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];
const STD_AC_CHROMA_COUNTS: [u8; 16] =
    [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77];
const STD_AC_CHROMA_VALUES: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
    0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

use std::sync::OnceLock;
fn dc_luma() -> &'static HuffCodes {
    static C: OnceLock<HuffCodes> = OnceLock::new();
    C.get_or_init(|| build_codes(&STD_DC_LUMA_COUNTS, &STD_DC_LUMA_VALUES))
}
fn dc_chroma() -> &'static HuffCodes {
    static C: OnceLock<HuffCodes> = OnceLock::new();
    C.get_or_init(|| build_codes(&STD_DC_CHROMA_COUNTS, &STD_DC_CHROMA_VALUES))
}
fn ac_luma() -> &'static HuffCodes {
    static C: OnceLock<HuffCodes> = OnceLock::new();
    C.get_or_init(|| build_codes(&STD_AC_LUMA_COUNTS, &STD_AC_LUMA_VALUES))
}
fn ac_chroma() -> &'static HuffCodes {
    static C: OnceLock<HuffCodes> = OnceLock::new();
    C.get_or_init(|| build_codes(&STD_AC_CHROMA_COUNTS, &STD_AC_CHROMA_VALUES))
}
