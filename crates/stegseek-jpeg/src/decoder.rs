//! Pure-Rust JPEG quantized-DCT-coefficient decoder (baseline + progressive
//! Huffman). Produces coefficients laid out exactly as libjpeg stores them, so
//! steghide's linearization (component-major, raster blocks, 64 natural-order
//! coefficients) matches bit-for-bit.

use std::fmt;

#[derive(Debug)]
pub enum JpegError {
    Truncated,
    Unsupported(String),
    Corrupt(String),
}
impl fmt::Display for JpegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JpegError::Truncated => write!(f, "truncated jpeg"),
            JpegError::Unsupported(s) => write!(f, "unsupported jpeg: {s}"),
            JpegError::Corrupt(s) => write!(f, "corrupt jpeg: {s}"),
        }
    }
}
impl std::error::Error for JpegError {}

type Result<T> = std::result::Result<T, JpegError>;

/// JPEG zig-zag → natural (row-major) position map.
const NATURAL_ORDER: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

#[derive(Default, Clone)]
struct HuffTable {
    mincode: [i32; 17],
    maxcode: [i32; 18],
    valptr: [i32; 17],
    values: Vec<u8>,
}
impl HuffTable {
    fn build(counts: &[u8; 17], values: Vec<u8>) -> HuffTable {
        // canonical code generation (per JPEG spec / libjpeg)
        let mut huffcode = [0i32; 257];
        let mut code = 0i32;
        let mut k = 0usize;
        for l in 1..=16 {
            for _ in 0..counts[l] {
                // A JPEG Huffman table holds at most 256 codes; guard the buffer
                // so a malformed DHT (caller should also reject it) can never
                // index out of bounds here.
                if k >= huffcode.len() {
                    break;
                }
                huffcode[k] = code;
                code += 1;
                k += 1;
            }
            code <<= 1;
        }
        let mut t = HuffTable {
            values,
            ..Default::default()
        };
        let mut p = 0i32;
        for l in 1..=16usize {
            if counts[l] > 0 {
                t.valptr[l] = p;
                t.mincode[l] = huffcode[p as usize];
                p += counts[l] as i32;
                t.maxcode[l] = huffcode[(p - 1) as usize];
            } else {
                t.maxcode[l] = -1;
            }
        }
        t.maxcode[17] = 0x0FFFFF;
        t
    }
}

struct Component {
    id: u8,
    h: usize,
    v: usize,
    tq: usize,
    wib_real: usize,
    hib_real: usize,
    wib_pad: usize,
    /// padded grid, row-major: (mcus_h·v) rows × wib_pad cols, each [i16;64] natural order
    blocks: Vec<[i16; 64]>,
    // per-scan huffman selectors
    td: usize,
    ta: usize,
    // progressive AC EOB run state is per-scan (single component), kept in decoder
}

/// A decoded JPEG with quantized DCT coefficients.
pub struct JpegImage {
    pub width: usize,
    pub height: usize,
    pub progressive: bool,
    components: Vec<Component>,
    qtables: [[u16; 64]; 4],
    restart_interval: usize,
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bits: u32,
    nbits: u32,
    marker: u8, // nonzero if a marker was hit
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        BitReader {
            data,
            pos,
            bits: 0,
            nbits: 0,
            marker: 0,
        }
    }
    fn reset(&mut self) {
        self.bits = 0;
        self.nbits = 0;
        self.marker = 0;
    }
    fn fill(&mut self) {
        while self.nbits <= 24 {
            if self.marker != 0 {
                self.nbits += 8; // feed zero bits past the marker
                continue;
            }
            if self.pos >= self.data.len() {
                self.marker = 0xD9;
                self.nbits += 8;
                continue;
            }
            let b = self.data[self.pos];
            if b == 0xFF {
                let n = self.data.get(self.pos + 1).copied().unwrap_or(0xD9);
                if n == 0x00 {
                    self.pos += 2;
                } else {
                    // marker reached; stop feeding real bits
                    self.marker = n;
                    self.nbits += 8;
                    continue;
                }
            } else {
                self.pos += 1;
            }
            self.bits |= (b as u32) << (24 - self.nbits);
            self.nbits += 8;
        }
    }
    #[inline]
    fn get_bit(&mut self) -> i32 {
        if self.nbits == 0 {
            self.fill();
        }
        let b = (self.bits >> 31) & 1;
        self.bits <<= 1;
        self.nbits -= 1;
        b as i32
    }
    fn get_bits(&mut self, n: u32) -> i32 {
        let mut v = 0i32;
        for _ in 0..n {
            v = (v << 1) | self.get_bit();
        }
        v
    }
    fn decode(&mut self, t: &HuffTable) -> Result<u8> {
        let mut code = 0i32;
        for l in 1..=16usize {
            code = (code << 1) | self.get_bit();
            if t.maxcode[l] >= 0 && code <= t.maxcode[l] {
                let idx = (t.valptr[l] + (code - t.mincode[l])) as usize;
                // A corrupt/degenerate DHT can point past the value list; error
                // instead of indexing out of bounds.
                return t
                    .values
                    .get(idx)
                    .copied()
                    .ok_or_else(|| JpegError::Corrupt("huffman value index".into()));
            }
        }
        Err(JpegError::Corrupt("bad huffman code".into()))
    }
    /// align to byte boundary and consume an expected RSTn marker
    fn restart(&mut self) {
        // drop any partial bits and the pending marker
        self.reset();
        // skip the FF Dx marker in the stream
        if self.pos + 1 < self.data.len() && self.data[self.pos] == 0xFF {
            let n = self.data[self.pos + 1];
            if (0xD0..=0xD7).contains(&n) {
                self.pos += 2;
            }
        }
    }
}

#[inline]
fn extend(v: i32, s: u32) -> i32 {
    if s == 0 {
        0
    } else if v < (1 << (s - 1)) {
        v - (1 << s) + 1
    } else {
        v
    }
}

fn divru(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

/// Bounds-checked big-endian u16 read. Returns `Truncated` instead of panicking
/// when the marker segment runs past the end of a truncated/corrupt file.
#[inline]
fn rd16(d: &[u8], p: usize) -> Result<usize> {
    match (d.get(p), d.get(p + 1)) {
        (Some(&hi), Some(&lo)) => Ok(((hi as usize) << 8) | lo as usize),
        _ => Err(JpegError::Truncated),
    }
}

/// Bounds-checked single-byte read.
#[inline]
fn rb(d: &[u8], p: usize) -> Result<u8> {
    d.get(p).copied().ok_or(JpegError::Truncated)
}

impl JpegImage {
    pub fn parse(data: &[u8]) -> Result<JpegImage> {
        if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
            return Err(JpegError::Corrupt("no SOI".into()));
        }
        let mut pos = 2usize;
        let mut qtables = [[0u16; 64]; 4];
        let mut dc_tables: [HuffTable; 4] = Default::default();
        let mut ac_tables: [HuffTable; 4] = Default::default();
        let mut restart_interval = 0usize;
        let mut img: Option<JpegImage> = None;

        while pos + 1 < data.len() {
            if data[pos] != 0xFF {
                pos += 1;
                continue;
            }
            let marker = data[pos + 1];
            pos += 2;
            match marker {
                0xD9 => break, // EOI
                0x01 | 0xD0..=0xD7 => continue,
                // Arithmetic-coded (C9/CA/CB/CD/CE/CF), lossless (C3/CB), and
                // differential (C5/C6/C7) frames are not supported: fail cleanly
                // with an explicit message rather than falling through to a
                // confusing "no frame" error.
                // SOF3 (lossless), SOF5-7 (differential), SOF9-11 + SOF13-15
                // (arithmetic). 0xC4=DHT, 0xC8=JPG, 0xCC=DAC are handled elsewhere.
                0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                    return Err(JpegError::Unsupported(
                        "arithmetic-coded, lossless, or differential JPEG".into(),
                    ));
                }
                0xC0..=0xC2 => {
                    // SOF0/1 baseline-ish, SOF2 progressive
                    let progressive = marker == 0xC2;
                    let _len = rd16(data, pos)?;
                    let prec = rb(data, pos + 2)?;
                    // Only 8-bit sample precision is supported; libjpeg (which
                    // steghide uses) rejects other precisions, so reject rather
                    // than silently mis-decoding as 8-bit.
                    if prec != 8 {
                        return Err(JpegError::Unsupported("non-8-bit JPEG precision".into()));
                    }
                    let height = rd16(data, pos + 3)?;
                    let width = rd16(data, pos + 5)?;
                    // libjpeg caps dimensions at JPEG_MAX_DIMENSION (65500); reject
                    // absurd values so a malformed SOF can't drive a giant block
                    // allocation (OOM) on an otherwise-tiny truncated file.
                    if width == 0 || height == 0 || width > 65500 || height > 65500 {
                        return Err(JpegError::Corrupt("bad JPEG dimensions".into()));
                    }
                    let nc = rb(data, pos + 7)? as usize;
                    if nc == 0 || nc > 4 {
                        return Err(JpegError::Corrupt("bad JPEG component count".into()));
                    }
                    let mut comps = Vec::with_capacity(nc);
                    let mut max_h = 1;
                    let mut max_v = 1;
                    let mut o = pos + 8;
                    let mut raw = Vec::new();
                    for _ in 0..nc {
                        let id = rb(data, o)?;
                        let hv = rb(data, o + 1)?;
                        let h = (hv >> 4) as usize;
                        let v = (hv & 0x0F) as usize;
                        let tq = rb(data, o + 2)? as usize;
                        if h == 0 || v == 0 || tq >= 4 {
                            return Err(JpegError::Corrupt("bad SOF component".into()));
                        }
                        max_h = max_h.max(h);
                        max_v = max_v.max(v);
                        raw.push((id, h, v, tq));
                        o += 3;
                    }
                    for (id, h, v, tq) in raw {
                        let wib_real = divru(width * h, 8 * max_h);
                        let hib_real = divru(height * v, 8 * max_v);
                        let mcus_w = divru(width, 8 * max_h);
                        let mcus_h = divru(height, 8 * max_v);
                        let wib_pad = mcus_w * h;
                        let hib_pad = mcus_h * v;
                        comps.push(Component {
                            id,
                            h,
                            v,
                            tq,
                            wib_real,
                            hib_real,
                            wib_pad,
                            blocks: vec![[0i16; 64]; wib_pad * hib_pad],
                            td: 0,
                            ta: 0,
                        });
                    }
                    img = Some(JpegImage {
                        width,
                        height,
                        progressive,
                        components: comps,
                        qtables,
                        restart_interval,
                    });
                    pos += _len;
                }
                0xC4 => {
                    // DHT
                    let len = rd16(data, pos)?;
                    if len < 2 {
                        return Err(JpegError::Corrupt("bad DHT length".into()));
                    }
                    let end = pos + len;
                    if end > data.len() {
                        return Err(JpegError::Truncated);
                    }
                    let mut o = pos + 2;
                    while o < end {
                        let tc_th = rb(data, o)?;
                        let tc = tc_th >> 4;
                        let th = (tc_th & 0x0F) as usize;
                        if th >= 4 {
                            return Err(JpegError::Corrupt("bad DHT table id".into()));
                        }
                        o += 1;
                        let mut counts = [0u8; 17];
                        let mut total = 0usize;
                        for i in 1..=16 {
                            counts[i] = rb(data, o + i - 1)?;
                            total += counts[i] as usize;
                        }
                        // A Huffman table holds at most 256 codes (JPEG spec);
                        // a larger sum means the DHT segment is corrupt.
                        if total > 256 {
                            return Err(JpegError::Corrupt("DHT declares too many codes".into()));
                        }
                        o += 16;
                        let values = data.get(o..o + total).ok_or(JpegError::Truncated)?.to_vec();
                        o += total;
                        let t = HuffTable::build(&counts, values);
                        if tc == 0 {
                            dc_tables[th] = t;
                        } else {
                            ac_tables[th] = t;
                        }
                    }
                    pos = end;
                }
                0xDB => {
                    // DQT
                    let len = rd16(data, pos)?;
                    if len < 2 {
                        return Err(JpegError::Corrupt("bad DQT length".into()));
                    }
                    let end = pos + len;
                    if end > data.len() {
                        return Err(JpegError::Truncated);
                    }
                    let mut o = pos + 2;
                    while o < end {
                        let pq_tq = rb(data, o)?;
                        let pq = pq_tq >> 4;
                        let tq = (pq_tq & 0x0F) as usize;
                        if tq >= 4 {
                            return Err(JpegError::Corrupt("bad DQT table id".into()));
                        }
                        o += 1;
                        for i in 0..64 {
                            let v = if pq == 0 {
                                let x = rb(data, o)? as u16;
                                o += 1;
                                x
                            } else {
                                let x = ((rb(data, o)? as u16) << 8) | rb(data, o + 1)? as u16;
                                o += 2;
                                x
                            };
                            qtables[tq][NATURAL_ORDER[i]] = v;
                        }
                    }
                    if let Some(ref mut im) = img {
                        im.qtables = qtables;
                    }
                    pos = end;
                }
                0xDD => {
                    restart_interval = rd16(data, pos + 2)?;
                    if let Some(ref mut im) = img {
                        im.restart_interval = restart_interval;
                    }
                    pos += rd16(data, pos)?;
                }
                0xDA => {
                    // SOS — decode a scan
                    let len = rd16(data, pos)?;
                    let ns = rb(data, pos + 2)? as usize;
                    let mut scan_comps = Vec::with_capacity(ns);
                    let mut o = pos + 3;
                    for _ in 0..ns {
                        let cs = rb(data, o)?;
                        let td_ta = rb(data, o + 1)?;
                        let td = (td_ta >> 4) as usize;
                        let ta = (td_ta & 0x0F) as usize;
                        scan_comps.push((cs, td, ta));
                        o += 2;
                    }
                    let ss = rb(data, o)? as usize;
                    let se = rb(data, o + 1)? as usize;
                    let ah_al = rb(data, o + 2)?;
                    let ah = (ah_al >> 4) as u32;
                    let al = (ah_al & 0x0F) as u32;
                    let scan_start = pos + len;
                    if scan_start > data.len() {
                        return Err(JpegError::Truncated);
                    }
                    let im = img
                        .as_mut()
                        .ok_or(JpegError::Corrupt("SOS before SOF".into()))?;
                    let next = im.decode_scan(
                        data,
                        scan_start,
                        &scan_comps,
                        ss,
                        se,
                        ah,
                        al,
                        &dc_tables,
                        &ac_tables,
                    )?;
                    pos = next;
                }
                _ => {
                    // other marker segments with length
                    if pos + 1 < data.len() {
                        let len = rd16(data, pos)?;
                        pos += len;
                    }
                }
            }
        }
        img.ok_or(JpegError::Corrupt("no frame".into()))
    }
    // decode_scan defined in scan.rs include

    /// Linearize coefficients exactly like steghide's `JpegFile::read`:
    /// component-major, raster blocks over the *real* grid, 64 natural-order
    /// coefficients. Returns (all_coeffs, indices_of_nonzero).
    pub fn linearize(&self) -> (Vec<i16>, Vec<u32>) {
        let mut lin = Vec::new();
        let mut idx = Vec::new();
        for c in &self.components {
            for row in 0..c.hib_real {
                for col in 0..c.wib_real {
                    let blk = &c.blocks[row * c.wib_pad + col];
                    for k in 0..64 {
                        let v = blk[k];
                        if v != 0 {
                            idx.push(lin.len() as u32);
                        }
                        lin.push(v);
                    }
                }
            }
        }
        (lin, idx)
    }

    pub fn num_samples(&self) -> u32 {
        let mut n = 0u32;
        for c in &self.components {
            for row in 0..c.hib_real {
                for col in 0..c.wib_real {
                    let blk = &c.blocks[row * c.wib_pad + col];
                    for k in 0..64 {
                        if blk[k] != 0 {
                            n += 1;
                        }
                    }
                }
            }
        }
        n
    }
}

fn dec_baseline(
    block: &mut [i16; 64],
    br: &mut BitReader,
    dctbl: &HuffTable,
    actbl: &HuffTable,
    dc_pred: &mut i32,
) -> Result<()> {
    let t = br.decode(dctbl)? as u32;
    // A coefficient magnitude category is 0..=15 (values are i16). A corrupt
    // Huffman table can decode a raw byte up to 255 here; reject it so
    // `get_bits`/`extend` never shift by an out-of-range amount (debug panic).
    if t > 15 {
        return Err(JpegError::Corrupt("bad DC magnitude category".into()));
    }
    let diff = if t == 0 { 0 } else { extend(br.get_bits(t), t) };
    *dc_pred += diff;
    block[0] = *dc_pred as i16;
    let mut k = 1usize;
    while k <= 63 {
        let rs = br.decode(actbl)?;
        let r = (rs >> 4) as usize;
        let s = (rs & 15) as u32;
        if s == 0 {
            if r == 15 {
                k += 16;
            } else {
                break;
            }
        } else {
            k += r;
            if k > 63 {
                break;
            }
            block[NATURAL_ORDER[k]] = extend(br.get_bits(s), s) as i16;
            k += 1;
        }
    }
    Ok(())
}

fn dec_dc_first(
    block: &mut [i16; 64],
    br: &mut BitReader,
    dctbl: &HuffTable,
    dc_pred: &mut i32,
    al: u32,
) -> Result<()> {
    let t = br.decode(dctbl)? as u32;
    // A coefficient magnitude category is 0..=15 (values are i16). A corrupt
    // Huffman table can decode a raw byte up to 255 here; reject it so
    // `get_bits`/`extend` never shift by an out-of-range amount (debug panic).
    if t > 15 {
        return Err(JpegError::Corrupt("bad DC magnitude category".into()));
    }
    let diff = if t == 0 { 0 } else { extend(br.get_bits(t), t) };
    *dc_pred += diff;
    block[0] = ((*dc_pred) << al) as i16;
    Ok(())
}

fn dec_dc_refine(block: &mut [i16; 64], br: &mut BitReader, al: u32) {
    if br.get_bit() != 0 {
        block[0] |= 1i16 << al;
    }
}

fn dec_ac_first(
    block: &mut [i16; 64],
    br: &mut BitReader,
    actbl: &HuffTable,
    ss: usize,
    se: usize,
    al: u32,
    eob_run: &mut u32,
) -> Result<()> {
    if *eob_run > 0 {
        *eob_run -= 1;
        return Ok(());
    }
    let mut k = ss;
    while k <= se {
        let rs = br.decode(actbl)?;
        let r = (rs >> 4) as usize;
        let s = (rs & 15) as u32;
        if s == 0 {
            if r != 15 {
                *eob_run = (1u32 << r) - 1;
                if r > 0 {
                    *eob_run += br.get_bits(r as u32) as u32;
                }
                break;
            }
            k += 16;
        } else {
            k += r;
            if k > se {
                break;
            }
            block[NATURAL_ORDER[k]] = (extend(br.get_bits(s), s) << al) as i16;
            k += 1;
        }
    }
    Ok(())
}

fn dec_ac_refine(
    block: &mut [i16; 64],
    br: &mut BitReader,
    actbl: &HuffTable,
    ss: usize,
    se: usize,
    al: u32,
    eob_run: &mut u32,
) -> Result<()> {
    let p1: i16 = 1 << al;
    let m1: i16 = (-1i32 << al) as i16;
    let mut k = ss;
    if *eob_run == 0 {
        while k <= se {
            let rs = br.decode(actbl)?;
            let mut r = (rs >> 4) as i32;
            let s = (rs & 15) as u32;
            let mut newval: i16 = 0;
            if s != 0 {
                // s should be 1
                newval = if br.get_bit() != 0 { p1 } else { m1 };
            } else if r != 15 {
                *eob_run = 1u32 << r;
                if r > 0 {
                    *eob_run += br.get_bits(r as u32) as u32;
                }
                break;
            }
            // advance over coefficients: apply correction to nonzeros, count r zeros
            loop {
                let coef = &mut block[NATURAL_ORDER[k]];
                if *coef != 0 {
                    if br.get_bit() != 0 && (*coef & p1) == 0 {
                        // wrapping_add: matches the release build (which wraps) and is
                        // identical to `+` for valid JPEGs (coefficients never overflow),
                        // but avoids a debug-only panic on corrupt successive-approx data.
                        *coef = if *coef >= 0 {
                            coef.wrapping_add(p1)
                        } else {
                            coef.wrapping_add(m1)
                        };
                    }
                } else {
                    r -= 1;
                    if r < 0 {
                        break;
                    }
                }
                k += 1;
                if k > se {
                    break;
                }
            }
            if newval != 0 && k <= se {
                block[NATURAL_ORDER[k]] = newval;
            }
            k += 1;
        }
    }
    if *eob_run > 0 {
        while k <= se {
            let coef = &mut block[NATURAL_ORDER[k]];
            if *coef != 0 && br.get_bit() != 0 && (*coef & p1) == 0 {
                // wrapping_add: matches the release build (which wraps) and is
                // identical to `+` for valid JPEGs (coefficients never overflow),
                // but avoids a debug-only panic on corrupt successive-approx data.
                *coef = if *coef >= 0 {
                    coef.wrapping_add(p1)
                } else {
                    coef.wrapping_add(m1)
                };
            }
            k += 1;
        }
        *eob_run -= 1;
    }
    Ok(())
}

fn find_next_marker(data: &[u8], from: usize) -> usize {
    let mut p = from;
    while p + 1 < data.len() {
        if data[p] == 0xFF {
            let m = data[p + 1];
            if m != 0x00 && !(0xD0..=0xD7).contains(&m) {
                return p;
            }
        }
        p += 1;
    }
    data.len()
}

include!("scan.rs");
include!("encoder.rs");
