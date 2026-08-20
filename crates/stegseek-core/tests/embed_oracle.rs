//! Validate that data embedded by the Rust embedder is extractable by the real
//! stegseek 0.6 (interoperability gate). Requires env STEGSEEK_REF (path to the
//! reference binary); skips if unset.

use std::process::Command;
use stegseek_core::embed::embed_file;
use stegseek_core::rng::RandomSource;
use stegseek_crypto::{EncryptionAlgorithm, EncryptionMode};

const SECRET: &[u8] = b"the treasure is buried under the old oak tree\n";

struct TestRng(u64);
impl RandomSource for TestRng {
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

fn embed_then_reference_extract(cover: &str, out_stego: &str, algo: &str, mode: &str, comp: i32) {
    let refbin = match std::env::var("STEGSEEK_REF") {
        Ok(v) => v,
        Err(_) => return, // skip when oracle not available
    };
    let a = EncryptionAlgorithm::from_name(algo).unwrap();
    let m = EncryptionMode::from_name(mode).unwrap();
    let mut rng = TestRng(0xABCD_1234_5678_9911);
    let stego = embed_file(
        datafile(cover),
        cover,
        b"Sesame",
        b"secret.txt",
        SECRET,
        a,
        m,
        comp,
        true,
        &mut rng,
        None,
        100,
    )
    .unwrap();
    std::fs::write(out_stego, &stego).unwrap();

    let out_txt = format!("{out_stego}.out");
    let _ = std::fs::remove_file(&out_txt);
    let status = Command::new(&refbin)
        .args([
            "--extract",
            "-sf",
            out_stego,
            "-p",
            "Sesame",
            "-xf",
            &out_txt,
            "-f",
        ])
        .output()
        .expect("run reference");
    let recovered = std::fs::read(&out_txt).unwrap_or_default();
    assert_eq!(
        recovered,
        SECRET,
        "reference must extract Rust-embedded {cover} ({algo}/{mode} comp={comp}); stderr={}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn wav_plain() {
    embed_then_reference_extract("pcm16_std.wav", "/tmp/rust_none.wav", "none", "ecb", 0);
}
#[test]
fn wav_encrypted_compressed() {
    embed_then_reference_extract(
        "pcm16_std.wav",
        "/tmp/rust_aes.wav",
        "rijndael-128",
        "cbc",
        9,
    );
}
#[test]
fn au_plain() {
    embed_then_reference_extract("pcm16_std.au", "/tmp/rust_none.au", "none", "ecb", 0);
}

#[test]
fn bmp_rgb_plain() {
    embed_then_reference_extract("win3x24_std.bmp", "/tmp/rust_none24.bmp", "none", "ecb", 0);
}
#[test]
fn bmp_rgb_encrypted() {
    embed_then_reference_extract(
        "win3x24_std.bmp",
        "/tmp/rust_aes24.bmp",
        "twofish",
        "cbc",
        9,
    );
}
#[test]
fn bmp_palette8_plain() {
    embed_then_reference_extract("win3x8_std.bmp", "/tmp/rust_none8.bmp", "none", "ecb", 0);
}
#[test]
fn bmp_palette4_plain() {
    embed_then_reference_extract("win3x4_std.bmp", "/tmp/rust_none4.bmp", "none", "ecb", 0);
}
#[test]
fn bmp_os2_palette8_plain() {
    embed_then_reference_extract("os21x8_std.bmp", "/tmp/rust_os28.bmp", "none", "ecb", 0);
}

#[test]
fn jpeg_plain() {
    embed_then_reference_extract("std.jpg", "/tmp/rust_none.jpg", "none", "ecb", 0);
}
#[test]
fn jpeg_encrypted_compressed() {
    embed_then_reference_extract("std.jpg", "/tmp/rust_aes.jpg", "rijndael-128", "cbc", 9);
}
