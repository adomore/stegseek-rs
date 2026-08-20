//! Validate the cipher+mode layer against libmcrypt 2.5.8 golden vectors.
//! Collects all results so every implemented algo×mode is reported.

use stegseek_crypto::cipher::block_cipher_by_name;
use stegseek_crypto::cipher::stream::apply_stream;
use stegseek_crypto::modes::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .unwrap_or("")
}

fn block_mode(
    mode: &str,
    c: &dyn stegseek_crypto::cipher::BlockCipher,
    iv: &[u8],
    buf: &mut [u8],
    enc: bool,
) -> bool {
    match (mode, enc) {
        ("ecb", true) => ecb_encrypt(c, buf),
        ("ecb", false) => ecb_decrypt(c, buf),
        ("cbc", true) => cbc_encrypt(c, iv, buf),
        ("cbc", false) => cbc_decrypt(c, iv, buf),
        ("cfb", true) => cfb8_encrypt(c, iv, buf),
        ("cfb", false) => cfb8_decrypt(c, iv, buf),
        ("ncfb", true) => ncfb_encrypt(c, iv, buf),
        ("ncfb", false) => ncfb_decrypt(c, iv, buf),
        ("ofb", _) => ofb8_crypt(c, iv, buf),
        ("nofb", _) => nofb_crypt(c, iv, buf),
        ("ctr", _) => ctr_crypt(c, iv, buf),
        _ => return false,
    }
    true
}

#[test]
fn cipher_modes_match_libmcrypt() {
    let data = include_str!("fixtures/golden_mcrypt.txt");
    let mut ok: std::collections::BTreeSet<String> = Default::default();
    let mut fails: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let algo = it.next().unwrap();
        let mode = it.next().unwrap();
        let key = unhex(field(line, "KEY="));
        let iv = unhex(field(line, "IV="));
        let pt = unhex(field(line, "PT="));
        let ct = unhex(field(line, "CT="));

        if let Some(c) = block_cipher_by_name(algo, &key) {
            let mut enc = pt.clone();
            if !block_mode(mode, &*c, &iv, &mut enc, true) {
                continue;
            }
            let mut dec = ct.clone();
            block_mode(mode, &*c, &iv, &mut dec, false);
            checked += 1;
            if enc == ct && dec == pt {
                ok.insert(algo.into());
            } else {
                fails.push(format!(
                    "{algo}/{mode} enc_ok={} dec_ok={}",
                    enc == ct,
                    dec == pt
                ));
            }
        } else if mode == "stream" {
            let mut enc = pt.clone();
            if apply_stream(algo, &key, &mut enc, true) {
                let mut dec = ct.clone();
                apply_stream(algo, &key, &mut dec, false);
                checked += 1;
                if enc == ct && dec == pt {
                    ok.insert(algo.into());
                } else {
                    fails.push(format!(
                        "{algo}/{mode} enc_ok={} dec_ok={}",
                        enc == ct,
                        dec == pt
                    ));
                }
            }
        }
    }
    eprintln!("golden: {checked} checked, OK algos={:?}", ok);
    if !fails.is_empty() {
        eprintln!("FAILURES ({}):", fails.len());
        for f in &fails {
            eprintln!("  {f}");
        }
    }
    assert!(
        fails.is_empty(),
        "{} algo×mode mismatches vs libmcrypt",
        fails.len()
    );
}
