//! End-to-end cracker validation against stego files produced by the real
//! stegseek 0.6 (the differential oracle). Password "Sesame", secret known.

use stegseek_core::crack::{crack_words, extract_passphrase, extract_seed, Cracker};
use stegseek_core::format::read_file;

const SECRET: &[u8] = b"the treasure is buried under the old oak tree\n";

fn stego(name: &str) -> String {
    format!(
        "{}/../../tests/data/stego/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn wordlist() -> Vec<Vec<u8>> {
    vec![
        b"apple".to_vec(),
        b"banana".to_vec(),
        b"Sesame".to_vec(),
        b"cherry".to_vec(),
    ]
}

fn crack_and_check(file: &str, encrypted: bool) {
    let f = read_file(&stego(file)).unwrap();
    let cr = Cracker::new(&*f);
    let wl = wordlist();
    let found = crack_words(&cr, wl.iter().map(|v| v.as_slice()));
    assert_eq!(
        found.as_deref(),
        Some(&b"Sesame"[..]),
        "{file}: should find password"
    );

    // re-extract with the confirmed passphrase and verify the secret + filename
    let emb = extract_passphrase(&*f, b"Sesame").unwrap();
    assert_eq!(emb.data(), SECRET, "{file}: extracted data");
    assert_eq!(emb.filename(), b"secret.txt", "{file}: filename");
    assert!(emb.checksum_ok(), "{file}: crc");
    assert_eq!(
        emb.enc_algo() != stegseek_crypto::EncryptionAlgorithm::NONE,
        encrypted,
        "{file}: enc"
    );
}

#[test]
fn crack_jpeg_plain() {
    crack_and_check("none.jpg", false);
}
#[test]
fn crack_jpeg_encrypted() {
    crack_and_check("aes.jpg", true);
}
#[test]
fn crack_bmp_plain() {
    crack_and_check("none.bmp", false);
}
#[test]
fn crack_wav_encrypted() {
    crack_and_check("aes.wav", true);
}

#[test]
fn wrong_passwords_dont_match() {
    let f = read_file(&stego("none.jpg")).unwrap();
    let cr = Cracker::new(&*f);
    for w in [
        b"apple".as_slice(),
        b"banana",
        b"cherry",
        b"sesame",
        b"Sesame ",
    ] {
        assert!(!cr.try_passphrase(w), "{:?} must not match", w);
    }
}

#[test]
fn seed_path_recovers_unencrypted() {
    // The passphrase-derived seed; try_seed accepts it, and (since none.jpg is
    // unencrypted) extract_seed recovers the file without the password.
    let seed = stegseek_crypto::md5_fold_seed(b"Sesame");
    let f = read_file(&stego("none.jpg")).unwrap();
    let cr = Cracker::new(&*f);
    let r = cr
        .try_seed(seed)
        .expect("try_seed should accept the real seed");
    assert_eq!(r.enc_algo, 0, "none.jpg is unencrypted");
    let emb = extract_seed(&*f, seed).unwrap();
    assert_eq!(emb.data(), SECRET, "seed extraction recovers the secret");
}

#[test]
fn threaded_wordlist_file_crack() {
    use std::sync::Arc;
    let f = read_file(&stego("aes.jpg")).unwrap();
    let cr = Arc::new(Cracker::new(&*f));
    let wl = stego("wordlist.txt");
    for threads in [1usize, 4, 8] {
        let found = stegseek_core::crack::crack_wordlist_file(
            cr.clone(),
            &wl,
            threads,
            true,
            "aes.jpg",
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            found.first().map(|v| v.as_slice()),
            Some(&b"Sesame"[..]),
            "threads={threads}"
        );
    }
}
