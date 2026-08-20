//! Comprehensive differential test against the real stegseek 0.6 (oracle).
//! For a matrix of (cover format × cipher × compression) it checks BOTH:
//!   A) Rust embed  → reference extract   (embed fidelity)
//!   B) reference embed → Rust crack+extract (crack/extract fidelity)
//! Gated on env STEGSEEK_REF; skipped (passes trivially) when unset.

use std::process::Command;
use stegseek_core::crack::{crack_words, extract_passphrase, Cracker};
use stegseek_core::embed::embed_file;
use stegseek_core::format::read_bytes;
use stegseek_core::rng::RandomSource;
use stegseek_crypto::{EncryptionAlgorithm, EncryptionMode};

const SECRET: &[u8] = b"Differential corpus secret payload 0123456789!\n";
const PASS: &[u8] = b"K0rrekt-Pferd";

struct Rng(u64);
impl RandomSource for Rng {
    fn get_byte(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 & 0xff) as u8
    }
    fn get_bool(&mut self) -> bool {
        self.get_byte() & 1 != 0
    }
}

fn datafile(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .unwrap()
}
fn refbin() -> Option<String> {
    std::env::var("STEGSEEK_REF").ok()
}
fn ext(cover: &str) -> &str {
    cover.rsplit('.').next().unwrap()
}

/// A) Rust embed -> reference extract
fn dir_a(cover: &str, algo: &str, mode: &str, comp: i32, tag: &str) {
    let Some(refbin) = refbin() else { return };
    let a = EncryptionAlgorithm::from_name(algo).unwrap();
    let m = EncryptionMode::from_name(mode).unwrap();
    let mut rng = Rng(0x1234_5678 ^ tag.len() as u64 | 1);
    let stego = embed_file(
        datafile(cover),
        cover,
        PASS,
        b"d.bin",
        SECRET,
        a,
        m,
        comp,
        true,
        &mut rng,
        None,
        100,
    )
    .unwrap_or_else(|e| panic!("A {tag}: rust embed failed: {e}"));
    let sp = format!("/tmp/diff_a_{tag}.{}", ext(cover));
    std::fs::write(&sp, &stego).unwrap();
    let op = format!("{sp}.out");
    let _ = std::fs::remove_file(&op);
    let out = Command::new(&refbin)
        .args([
            "--extract",
            "-sf",
            &sp,
            "-p",
            std::str::from_utf8(PASS).unwrap(),
            "-xf",
            &op,
            "-f",
        ])
        .output()
        .unwrap();
    let got = std::fs::read(&op).unwrap_or_default();
    assert_eq!(
        got,
        SECRET,
        "A {tag}: ref couldn't extract rust embed. stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// B) reference embed -> Rust crack + extract
fn dir_b(cover: &str, algo: &str, mode: &str, comp: i32, tag: &str) {
    let Some(refbin) = refbin() else { return };
    let sp = format!("/tmp/diff_b_{tag}.{}", ext(cover));
    let secret = "/tmp/diff_secret.bin";
    std::fs::write(secret, SECRET).unwrap();
    let cover_path = format!("{}/../../tests/data/{cover}", env!("CARGO_MANIFEST_DIR"));
    let passs = std::str::from_utf8(PASS).unwrap();
    let mut args: Vec<&str> = vec![
        "--embed",
        "-cf",
        &cover_path,
        "-ef",
        secret,
        "-sf",
        &sp,
        "-p",
        passs,
    ];
    if algo == "none" {
        args.extend(["-e", "none"]);
    } else {
        args.extend(["-e", algo, mode]);
    }
    if comp == 0 {
        args.push("-Z");
    }
    args.extend(["-f", "-q"]);
    let st = Command::new(&refbin).args(&args).output().unwrap();
    assert!(
        std::path::Path::new(&sp).exists(),
        "B {tag}: ref embed failed. stderr={}",
        String::from_utf8_lossy(&st.stderr)
    );

    let file = read_bytes(std::fs::read(&sp).unwrap(), &sp).unwrap();
    let cr = Cracker::new(&*file);
    let wl: Vec<Vec<u8>> = vec![b"nope".to_vec(), PASS.to_vec(), b"other".to_vec()];
    let found = crack_words(&cr, wl.iter().map(|v| v.as_slice()));
    assert_eq!(found.as_deref(), Some(PASS), "B {tag}: rust crack failed");
    let emb = extract_passphrase(&*file, PASS).unwrap();
    assert_eq!(emb.data(), SECRET, "B {tag}: rust extract data mismatch");
}

#[test]
fn jpeg_all_ciphers() {
    // every cipher steghide/libmcrypt supports, on a JPEG cover, both directions
    let ciphers: &[(&str, &str)] = &[
        ("none", "ecb"),
        ("rijndael-128", "cbc"),
        ("rijndael-192", "cbc"),
        ("rijndael-256", "cbc"),
        ("twofish", "cbc"),
        ("serpent", "cfb"),
        ("blowfish", "ofb"),
        ("des", "cbc"),
        ("tripledes", "ncfb"),
        ("cast-128", "ctr"),
        ("cast-256", "nofb"),
        ("rc2", "cbc"),
        ("xtea", "cbc"),
        ("gost", "cbc"),
        ("saferplus", "cbc"),
        ("loki97", "cbc"),
        ("arcfour", "stream"),
    ];
    for (i, (algo, mode)) in ciphers.iter().enumerate() {
        dir_a("std.jpg", algo, mode, 9, &format!("jpg_{algo}_{i}"));
        dir_b("std.jpg", algo, mode, 9, &format!("jpg_{algo}_{i}"));
    }
}

#[test]
fn all_formats_common_ciphers() {
    let covers = [
        "win3x24_std.bmp",
        "win3x8_std.bmp",
        "win3x4_std.bmp",
        "pcm16_std.wav",
        "pcm16_std.au",
        "mulaw_std.au",
    ];
    for cover in covers {
        for (algo, mode, comp) in [
            ("none", "ecb", 0),
            ("rijndael-128", "cbc", 9),
            ("arcfour", "stream", 9),
        ] {
            let tag = format!("{}_{algo}", cover.replace('.', "_"));
            dir_a(cover, algo, mode, comp, &tag);
            dir_b(cover, algo, mode, comp, &tag);
        }
    }
}
