//! The crackers: `Cracker` (shared, precomputed file state + the fast
//! `verifyMagic` LCG path + full passphrase/seed checks) and the threaded
//! `crack_wordlist` / `crack_seed` drivers. Ports Cracker.cc / PasswordCracker.cc
//! / SeedCracker.cc / Extractor.cc.

use crate::autils::{div_roundup, log2_ceil};
use crate::bitstring::BitString;
use crate::embdata::{EmbData, MAGIC, NBITS_MAGIC};
use crate::error::{StegError, StegResult};
use crate::format::CvrStgFile;
use crate::rng::PseudoRandomSource;
use crate::selector::Selector;
use crate::utils::strip_dir;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Precomputed, read-only cracking state (Send + Sync -> shareable across threads).
pub struct Cracker {
    num_samples: u32,
    samples_per_vertex: u16,
    emb_value_modulus: u8,
    bits_per_emb_value: u16,
    embvalues_requested_magic: u32,
    embedded_values: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedResult {
    pub seed: u32,
    pub plain_size: u32,
    pub enc_algo: u32,
    pub enc_mode: u32,
}

impl Cracker {
    pub fn new(file: &dyn CvrStgFile) -> Self {
        let modulus = file.emb_value_modulus();
        let bits_per = log2_ceil(modulus as u16);
        let n = file.num_samples();
        let embvalues_requested_magic = div_roundup(NBITS_MAGIC, bits_per as u32);
        let embedded_values: Vec<u8> = (0..n).map(|i| file.get_embedded_value(i)).collect();
        Cracker {
            num_samples: n,
            samples_per_vertex: file.samples_per_vertex(),
            emb_value_modulus: modulus,
            bits_per_emb_value: bits_per,
            embvalues_requested_magic,
            embedded_values,
        }
    }

    /// Fast magic check: inline the LCG to reconstruct the first sample
    /// positions and test the 25 magic bits. On an RNG collision (which the
    /// real Selector resolves differently) we conservatively pass — the full
    /// extractor double-checks. Port of `Cracker::verifyMagic(seed)`.
    pub fn verify_magic_seed(&self, mut seed: u32) -> bool {
        let spv = self.samples_per_vertex as usize;
        // Collision buffer on the STACK — never heap-allocate in this per-passphrase
        // hot path (the C++ uses a `UWORD32 rngBuf[25 * samplesPerVertex]` VLA).
        // 25 magic emb-values x samples-per-vertex; spv <= 3 for every supported
        // format (jpeg=3, bmp<=3, audio=2), so 75 is the true upper bound — 128
        // leaves headroom. The slice keeps the exact `25 * spv` length as upstream.
        let mut rng_storage = [0u32; 128];
        debug_assert!(
            25 * spv <= rng_storage.len(),
            "samples_per_vertex too large for stack buffer"
        );
        let rng_buf = &mut rng_storage[..25 * spv];
        if (self.samples_per_vertex as u32) * self.embvalues_requested_magic >= self.num_samples {
            return false;
        }
        let mut ev = 0u8;
        let mut sv_idx = 0usize;
        for i in 0..self.embvalues_requested_magic {
            for _ in 0..self.samples_per_vertex {
                seed = seed
                    .wrapping_mul(PseudoRandomSource::A)
                    .wrapping_add(PseudoRandomSource::C);
                let val_idx = (sv_idx as f64
                    + (seed as f64 / 4_294_967_296.0_f64)
                        * (self.num_samples as f64 - sv_idx as f64))
                    as u32;
                for k in &rng_buf[..sv_idx] {
                    if *k == val_idx {
                        return true; // rare RNG collision -> tolerate
                    }
                }
                rng_buf[sv_idx] = val_idx;
                ev = (ev + self.embedded_values[val_idx as usize]) % self.emb_value_modulus;
                sv_idx += 1;
            }
            for k in 0..self.bits_per_emb_value {
                let current_bit = (ev >> k) & 1;
                let bits_seen = i * self.bits_per_emb_value as u32 + k as u32;
                if bits_seen < 25 && current_bit != ((MAGIC >> bits_seen) & 1) as u8 {
                    return false;
                }
            }
            ev = 0;
        }
        true
    }

    pub fn verify_magic_passphrase(&self, passphrase: &[u8]) -> bool {
        self.verify_magic_seed(stegseek_crypto::md5_fold_seed(passphrase))
    }

    /// Full passphrase check: fast magic, then a complete EmbData extraction
    /// via the real Selector. Port of `PasswordCracker::tryPassphrase`.
    pub fn try_passphrase(&self, passphrase: &[u8]) -> bool {
        if !self.verify_magic_passphrase(passphrase) {
            return false;
        }
        let mut embdata = EmbData::new_extract(passphrase);
        let mut sel = Selector::from_passphrase(self.num_samples, passphrase);
        let mut sv_idx = 0u32;
        while !embdata.finished() {
            let requested =
                div_roundup(embdata.num_bits_requested(), self.bits_per_emb_value as u32);
            if sv_idx + (self.samples_per_vertex as u32) * requested >= self.num_samples {
                return false;
            }
            let mut bits = BitString::new(self.emb_value_modulus);
            for _ in 0..requested {
                let mut ev = 0u8;
                for _ in 0..self.samples_per_vertex {
                    ev = (ev + self.embedded_values[sel.at(sv_idx) as usize])
                        % self.emb_value_modulus;
                    sv_idx += 1;
                }
                bits.append_nary(ev);
            }
            if embdata.add_bits(bits).is_err() {
                return false;
            }
        }
        true
    }

    /// Seed check: fast magic, then verify magic + read encInfo/plainSize via the
    /// real Selector. Port of `SeedCracker::trySeed`.
    pub fn try_seed(&self, seed: u32) -> Option<SeedResult> {
        if !self.verify_magic_seed(seed) {
            return None;
        }
        let requested_values: u32 = 25 + 3 + 5 + 32;
        let mut sel = Selector::from_seed(self.num_samples, seed);
        let mut ev = 0u8;
        let (mut enc_algo, mut enc_mode, mut plain_size) = (0u32, 0u32, 0u32);
        let mut sv_idx = 0u32;
        let spv = self.samples_per_vertex as u32;
        let budget = self.num_samples.wrapping_sub(requested_values * spv);
        for i in 0..requested_values {
            for _ in 0..self.samples_per_vertex {
                ev = (ev + self.embedded_values[sel.at(sv_idx) as usize]) % self.emb_value_modulus;
                sv_idx += 1;
            }
            for k in 0..self.bits_per_emb_value {
                let current_bit = ((ev >> k) & 1) as u32;
                let bits_seen = i * self.bits_per_emb_value as u32 + k as u32;
                if bits_seen < 25 {
                    if ((MAGIC >> bits_seen) & 1) != current_bit {
                        return None;
                    }
                } else if bits_seen < 30 {
                    enc_algo ^= current_bit << (bits_seen - 25);
                    if enc_algo > 22 {
                        return None;
                    }
                } else if bits_seen < 33 {
                    enc_mode ^= current_bit << (bits_seen - 30);
                } else if bits_seen < 65 {
                    plain_size ^= current_bit << (bits_seen - 33);
                    if plain_size * spv > budget {
                        return None;
                    }
                }
            }
            ev = 0;
        }
        Some(SeedResult {
            seed,
            plain_size,
            enc_algo,
            enc_mode,
        })
    }
}

/// Full extraction with a passphrase (re-run on a confirmed hit, or `--extract`).
/// Port of `Extractor::extract` (passphrase path).
pub fn extract_passphrase(file: &dyn CvrStgFile, passphrase: &[u8]) -> StegResult<EmbData> {
    let mut embdata = EmbData::new_extract(passphrase);
    let mut sel = Selector::from_passphrase(file.num_samples(), passphrase);
    extract_loop(file, &mut sel, &mut embdata)?;
    Ok(embdata)
}

/// Full extraction with a seed (used by `--seed` recovery of unencrypted data).
pub fn extract_seed(file: &dyn CvrStgFile, seed: u32) -> StegResult<EmbData> {
    let mut embdata = EmbData::new_extract(b"");
    let mut sel = Selector::from_seed(file.num_samples(), seed);
    extract_loop(file, &mut sel, &mut embdata)?;
    Ok(embdata)
}

fn extract_loop(
    file: &dyn CvrStgFile,
    sel: &mut Selector,
    embdata: &mut EmbData,
) -> StegResult<()> {
    let modulus = file.emb_value_modulus();
    let bits_per = log2_ceil(modulus as u16);
    let spv = file.samples_per_vertex() as u32;
    let n = file.num_samples();
    let mut sv_idx = 0u32;
    while !embdata.finished() {
        let requested = div_roundup(embdata.num_bits_requested(), bits_per as u32);
        if sv_idx + spv * requested >= n {
            return Err(StegError::CorruptData(
                "the stego file is too short to contain the embedded data.".into(),
            ));
        }
        let mut bits = BitString::new(modulus);
        for _ in 0..requested {
            let mut ev = 0u8;
            for _ in 0..spv {
                ev = (ev + file.get_embedded_value(sel.at(sv_idx))) % modulus;
                sv_idx += 1;
            }
            bits.append_nary(ev);
        }
        embdata.add_bits(bits)?;
    }
    Ok(())
}

/// "Fun" CTF guesses: empty, the stego filename, and the filename without
/// extension. Port of `PasswordCracker::sillyCtfGuesses`.
pub fn silly_ctf_guesses(stego_name: &str) -> Vec<Vec<u8>> {
    let filename = strip_dir(stego_name.as_bytes());
    let stripped = match filename.iter().rposition(|&c| c == b'.') {
        Some(p) => filename[..p].to_vec(),
        None => filename.clone(),
    };
    vec![Vec::new(), filename, stripped]
}

/// Single-threaded wordlist crack over an iterator (handy for tests/embedding).
pub fn crack_words<'a, I: Iterator<Item = &'a [u8]>>(
    cracker: &Cracker,
    words: I,
) -> Option<Vec<u8>> {
    for w in words {
        if cracker.try_passphrase(w) {
            return Some(w.to_vec());
        }
    }
    None
}

/// Live cracking progress, shared across worker threads and read by a reporter
/// thread (port of `Cracker::metrics` / `PasswordCracker`/`SeedCracker::metricLine`).
pub struct Progress {
    done: AtomicU64,
    total: u64,
    /// `true` => format the count as `(N seeds)`, `false` => as a human size.
    seeds: bool,
    accessible: bool,
}

impl Progress {
    pub fn new(total: u64, seeds: bool, accessible: bool) -> Self {
        Progress {
            done: AtomicU64::new(0),
            total: total.max(1),
            seeds,
            accessible,
        }
    }
    #[inline]
    fn add(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }
}

/// Reporter loop: prints `Progress: X.XX% (...)` to stderr every ~40 ms until
/// `finished`, matching steghide's cadence (only once past 500k units).
fn run_reporter(p: &Progress, finished: &AtomicBool) {
    use std::time::Duration;
    let mut prev = -10.0f32;
    while !finished.load(Ordering::Relaxed) {
        let cur = p.done.load(Ordering::Relaxed);
        if cur > 500_000 {
            let pct = 100.0 * (cur as f32 / p.total as f32);
            if p.accessible {
                if pct - prev > 1.0 {
                    eprintln!("{pct:.0}%");
                    prev = pct;
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            } else {
                let amt = if p.seeds {
                    format!("{cur} seeds")
                } else {
                    crate::utils::format_hr_size(cur)
                };
                eprint!("Progress: {pct:.2}% ({amt})           \r");
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    if !p.accessible {
        eprintln!();
    }
}

/// Threaded wordlist crack with byte-offset sharding (overlapping sections, as
/// in PasswordCracker::consume). Returns every passphrase found (a single-element
/// vector unless `cont` — steghide's `--continue` — keeps scanning after a hit to
/// recover multiple embedded files). An optional [`Progress`] drives live metrics.
pub fn crack_wordlist_file(
    cracker: Arc<Cracker>,
    path: &str,
    threads: usize,
    skip_default: bool,
    stego_name: &str,
    cont: bool,
    progress: Option<&Progress>,
) -> std::io::Result<Vec<Vec<u8>>> {
    let size = std::fs::metadata(path)?.len();
    let found: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
    let stopped = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let threads = threads.max(1);
    let part = (size / threads as u64).max(1);

    std::thread::scope(|s| {
        if !skip_default {
            for g in silly_ctf_guesses(stego_name) {
                if cracker.try_passphrase(&g) {
                    found.lock().unwrap().push(g);
                    if !cont {
                        stopped.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
        if let Some(p) = progress {
            let finished = &finished;
            s.spawn(move || run_reporter(p, finished));
        }
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let start = t as u64 * part;
            let end = (t as u64 + 1) * part;
            let cr = &cracker;
            let found = &found;
            let stopped = &stopped;
            handles.push(s.spawn(move || {
                consume_wordlist(cr, path, start, end, found, stopped, cont, progress);
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        finished.store(true, Ordering::Relaxed);
    });
    Ok(found.into_inner().unwrap())
}

#[allow(clippy::too_many_arguments)]
fn consume_wordlist(
    cracker: &Cracker,
    path: &str,
    start: u64,
    end: u64,
    found: &Mutex<Vec<Vec<u8>>>,
    stopped: &AtomicBool,
    cont: bool,
    progress: Option<&Progress>,
) {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    if f.seek(SeekFrom::Start(start)).is_err() {
        return;
    }
    let mut reader = BufReader::new(f);
    let mut line: Vec<u8> = Vec::new();
    // Track the byte offset with a running counter instead of calling
    // `stream_position()` per line — the latter issues an `lseek` syscall every
    // iteration (millions for a big wordlist). C++ uses `ftell`, which is a cheap
    // userspace read of the stdio buffer; this counter is the equivalent and is
    // bit-identical (pos == start + bytes consumed so far).
    let mut pos = start;
    // Batch progress updates to keep the shared atomic off the hot path (steghide
    // flushes every `batchSize` = 20000 lines).
    let mut batch = 0u64;
    let mut lines = 0u32;
    while !stopped.load(Ordering::Relaxed) {
        line.clear();
        let n = match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        pos += n as u64;
        // Progress bookkeeping is skipped entirely when no reporter is attached
        // (e.g. `-q`), keeping the scan hot-path allocation- and syscall-free.
        if let Some(p) = progress {
            batch += n as u64;
            lines += 1;
            if lines >= 20_000 {
                p.add(batch);
                batch = 0;
                lines = 0;
            }
        }
        while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
            line.pop();
        }
        if cracker.try_passphrase(&line) {
            {
                // Guard so a non-`--continue` crack keeps exactly ONE result even
                // if several threads hit (a tiny wordlist has every thread reading
                // the same line before `stopped` propagates).
                let mut g = found.lock().unwrap();
                if cont || g.is_empty() {
                    g.push(line.clone());
                }
            }
            if !cont {
                stopped.store(true, Ordering::Relaxed);
                break;
            }
        }
        if pos > end {
            break;
        }
    }
    if let Some(p) = progress {
        p.add(batch);
    }
}

/// Threaded seed crack over the full 2^32 seed space (all 2^32 seeds, inclusive
/// of 0xFFFFFFFF). Returns every result found (one unless `cont`). An optional
/// [`Progress`] drives live metrics.
pub fn crack_seed_all(
    cracker: Arc<Cracker>,
    threads: usize,
    cont: bool,
    progress: Option<&Progress>,
) -> Vec<SeedResult> {
    let threads = threads.max(1) as u32;
    let found: Mutex<Vec<SeedResult>> = Mutex::new(Vec::new());
    let stopped = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let part = (u32::MAX / threads).max(1);
    std::thread::scope(|s| {
        if let Some(p) = progress {
            let finished = &finished;
            s.spawn(move || run_reporter(p, finished));
        }
        let mut handles = Vec::with_capacity(threads as usize);
        for t in 0..threads {
            let start = t * part;
            // Inclusive upper bound so seed 0xFFFFFFFF is actually tested by the
            // last shard (the old `seed < end` with end==u32::MAX skipped it).
            let end = if t == threads - 1 {
                u32::MAX
            } else {
                (t + 1) * part - 1
            };
            let cr = &cracker;
            let found = &found;
            let stopped = &stopped;
            handles.push(s.spawn(move || {
                let mut seed = start;
                let mut batch = 0u64;
                loop {
                    if stopped.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Some(r) = cr.try_seed(seed) {
                        {
                            let mut g = found.lock().unwrap();
                            if cont || g.is_empty() {
                                g.push(r);
                            }
                        }
                        if !cont {
                            stopped.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    batch += 1;
                    if batch >= 5000 {
                        if let Some(p) = progress {
                            p.add(batch);
                        }
                        batch = 0;
                    }
                    if seed == end {
                        break;
                    }
                    seed += 1;
                }
                if let Some(p) = progress {
                    p.add(batch);
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        finished.store(true, Ordering::Relaxed);
    });
    found.into_inner().unwrap()
}

/// Threaded seed crack — first result only (compatibility wrapper).
pub fn crack_seed(cracker: Arc<Cracker>, threads: usize) -> Option<SeedResult> {
    crack_seed_all(cracker, threads, false, None)
        .into_iter()
        .next()
}
