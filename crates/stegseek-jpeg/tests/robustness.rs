//! Robustness of the JPEG header parser against truncated / corrupt / unsupported
//! inputs. Regression coverage for the fix that turned index-out-of-bounds
//! *panics* (decoder.rs ~306/329, aborting under `panic=abort`) into clean
//! `JpegError`s, and added explicit rejection of arithmetic/lossless/12-bit JPEG.

use stegseek_jpeg::{JpegError, JpegImage};

fn datafile(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .unwrap()
}

/// Valid baseline and progressive JPEGs still decode (no regression).
#[test]
fn valid_jpegs_still_parse() {
    assert!(JpegImage::parse(&datafile("std.jpg")).is_ok());
    assert!(JpegImage::parse(&datafile("prog.jpg")).is_ok());
}

/// Truncating a real JPEG at *every* prefix length must never panic — it may
/// return Ok (truncation landed after a complete header) or Err, but the call
/// always returns. Before the fix this aborted the process for many offsets.
#[test]
fn every_truncation_returns_without_panic() {
    for src in ["std.jpg", "prog.jpg"] {
        let data = datafile(src);
        for n in 0..data.len() {
            // The contract is "returns a Result" — a reintroduced panic fails the
            // test run (aborts under --release, unwinds under dev).
            let _ = JpegImage::parse(&data[..n]);
        }
        // Cutting the header off early is definitely an error, not a silent frame.
        assert!(
            JpegImage::parse(&data[..40]).is_err(),
            "{src}: 40-byte prefix must error"
        );
    }
}

/// Deterministic fuzz: exhaustive single-byte substitutions plus LCG-driven
/// multi-byte corruption must never panic (only return Ok/Err). This is the
/// coverage that caught the DHT-overflow and scan-index panics.
#[test]
fn corrupt_bytes_never_panic() {
    for src in ["std.jpg", "prog.jpg"] {
        let base = datafile(src);

        // (a) exhaustive: set every byte (past SOI) to each pathological value —
        // 0x00, 0xFF (marker prefix), and common marker second-bytes.
        let mut data = base.clone();
        for &sub in &[0x00u8, 0xFF, 0xC0, 0xC9, 0xC4, 0xDA] {
            for i in 2..data.len() {
                let orig = data[i];
                data[i] = sub;
                let _ = JpegImage::parse(&data);
                data[i] = orig;
            }
        }

        // (b) LCG random multi-byte corruption over many iterations.
        let mut state = 0x2545_F491_4F6C_DD1Du64 ^ base.len() as u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut buf = base.clone();
        for _ in 0..2500 {
            buf.copy_from_slice(&base);
            let nflips = (next() % 8) + 1;
            for _ in 0..nflips {
                let idx = (next() as usize) % buf.len();
                buf[idx] = (next() & 0xFF) as u8;
            }
            // also try random truncation of the corrupted copy
            let cut = (next() as usize) % (buf.len() + 1);
            let _ = JpegImage::parse(&buf[..cut]);
        }
    }
}

/// Not-a-JPEG / garbage inputs error cleanly.
#[test]
fn garbage_inputs_error() {
    assert!(JpegImage::parse(&[]).is_err());
    assert!(JpegImage::parse(&[0xFF]).is_err());
    assert!(JpegImage::parse(&[0x00, 0x00]).is_err());
    assert!(JpegImage::parse(&[0xFF, 0xD8]).is_err()); // SOI only, no frame
    assert!(JpegImage::parse(&vec![0x41u8; 4096]).is_err());
}

/// Arithmetic-coded (SOF9/10/11), lossless (C3), and differential (C5-C7) frames
/// are rejected with an explicit `Unsupported` message, not a generic error.
#[test]
fn arithmetic_lossless_differential_rejected() {
    // SOI + SOFx + len(11) + prec(8) + h(16) + w(16) + nc(1) + one component
    let sof = |marker: u8| -> Vec<u8> {
        vec![
            0xFF, 0xD8, 0xFF, marker, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11,
            0x00,
        ]
    };
    for marker in [0xC3u8, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF] {
        match JpegImage::parse(&sof(marker)) {
            Err(JpegError::Unsupported(_)) => {}
            Err(e) => panic!("marker 0x{marker:02X}: expected Unsupported, got Err({e})"),
            Ok(_) => panic!("marker 0x{marker:02X}: expected Unsupported, got Ok"),
        }
    }
}

/// Non-8-bit sample precision (e.g. 12-bit) is rejected rather than silently
/// mis-decoded as 8-bit.
#[test]
fn twelve_bit_precision_rejected() {
    // SOF0 baseline but precision byte = 12
    let data = vec![
        0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x0C, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
    ];
    assert!(matches!(
        JpegImage::parse(&data),
        Err(JpegError::Unsupported(_))
    ));
}

/// A frame declaring absurd dimensions must be rejected up front (no giant block
/// allocation / OOM), not accepted.
#[test]
fn absurd_dimensions_rejected() {
    // SOF0, precision 8, height=0xFFFF, width=0xFFFF, 1 component
    let data = vec![
        0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x01, 0x11, 0x00,
    ];
    assert!(matches!(
        JpegImage::parse(&data),
        Err(JpegError::Corrupt(_))
    ));
}
