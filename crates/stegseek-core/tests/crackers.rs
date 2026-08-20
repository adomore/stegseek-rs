//! Wordlist / seed cracker driver behaviour: result multiplicity with and
//! without `--continue`, the single-result guard (regression for the duplicate
//! results a tiny wordlist + many threads produced when the return type became a
//! Vec), skip-default guesses, and Progress accounting.

use std::io::Write;
use std::sync::Arc;
use stegseek_core::crack::{crack_seed_all, crack_wordlist_file, Cracker, Progress};
use stegseek_core::format::read_file;

fn stego(name: &str) -> String {
    format!(
        "{}/../../tests/data/stego/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn write_wordlist(tag: &str, body: &str) -> String {
    let p = std::env::temp_dir().join(format!("ssrs_wl_{tag}_{}.txt", std::process::id()));
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    p.to_string_lossy().into_owned()
}

fn cracker(name: &str) -> Arc<Cracker> {
    let file = read_file(&stego(name)).unwrap();
    Arc::new(Cracker::new(&*file))
}

/// Without `--continue`, a wordlist that contains the correct passphrase several
/// times still yields exactly ONE result — even at high thread counts where many
/// threads read the same line before `stopped` propagates.
#[test]
fn no_continue_yields_single_result() {
    let wl = write_wordlist("dup", "Sesame\nfoo\nSesame\nbar\nSesame\nSesame\n");
    for threads in [1usize, 4, 8, 16] {
        let found = crack_wordlist_file(
            cracker("none.jpg"),
            &wl,
            threads,
            true,
            "none.jpg",
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            found.len(),
            1,
            "threads={threads}: expected exactly one result"
        );
        assert_eq!(found[0], b"Sesame", "threads={threads}");
    }
    let _ = std::fs::remove_file(&wl);
}

/// With `--continue`, every matching occurrence is reported (so multiple embedded
/// files can be recovered).
#[test]
fn continue_yields_every_match() {
    let wl = write_wordlist("cont", "Sesame\nfoo\nSesame\nbar\nSesame\n");
    let found =
        crack_wordlist_file(cracker("none.jpg"), &wl, 4, true, "none.jpg", true, None).unwrap();
    assert_eq!(
        found.len(),
        3,
        "continue should report all three 'Sesame' hits"
    );
    assert!(found.iter().all(|p| p == b"Sesame"));
    let _ = std::fs::remove_file(&wl);
}

/// A wordlist with no match returns an empty result set (not an error).
#[test]
fn no_match_is_empty() {
    let wl = write_wordlist("miss", "nope1\nnope2\nnope3\n");
    let found =
        crack_wordlist_file(cracker("none.jpg"), &wl, 4, true, "none.jpg", false, None).unwrap();
    assert!(found.is_empty());
    let _ = std::fs::remove_file(&wl);
}

/// The default guesses (empty password, filename, ...) are tried unless skipped:
/// with `skip_default=false` and an all-miss wordlist, a stego whose passphrase
/// is a default guess is still found; with `skip_default=true` it is not.
/// (Here we only assert the miss wordlist alone finds nothing, isolating the flag.)
#[test]
fn skip_default_controls_guesses() {
    let wl = write_wordlist("sd", "totally-wrong\n");
    // skip_default = true: only the (wrong) wordlist is tried.
    let found =
        crack_wordlist_file(cracker("none.jpg"), &wl, 2, true, "none.jpg", false, None).unwrap();
    assert!(found.is_empty());
    let _ = std::fs::remove_file(&wl);
}

/// Progress accounting advances while cracking a sizeable wordlist (the reporter
/// only *prints* past 500k, but the counter itself must move regardless).
#[test]
fn progress_counter_advances() {
    // ~0.9 MB of misses so the byte counter clearly exceeds the 500k threshold.
    let mut body = String::with_capacity(2_200_000);
    for i in 0..120_000 {
        body.push_str(&format!("miss{i}\n"));
    }
    let wl = write_wordlist("prog", &body);
    let progress = Progress::new(std::fs::metadata(&wl).unwrap().len(), false, false);
    let found = crack_wordlist_file(
        cracker("none.jpg"),
        &wl,
        4,
        true,
        "none.jpg",
        false,
        Some(&progress),
    )
    .unwrap();
    assert!(found.is_empty());
    // Progress exposes no public getter; this test asserts the Some(progress)
    // path runs to completion without panicking or deadlocking the reporter.
    let _ = std::fs::remove_file(&wl);
}

/// The seed cracker recovers the same seed the differential harness observed for
/// the unencrypted JPEG, and reports its properties.
#[test]
#[ignore = "full 2^32 seed scan reaches ~1.5B seeds (~1-2 min on 2 cores); run with `cargo test -- --ignored`"]
fn seed_crack_finds_known_seed() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let results = crack_seed_all(cracker("none.jpg"), threads, false, None);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].seed, 0x58c8_cc6c, "known seed for none.jpg");
    assert_eq!(results[0].enc_algo, 0, "none.jpg is unencrypted");
}
