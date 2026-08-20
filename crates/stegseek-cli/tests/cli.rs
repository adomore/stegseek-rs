//! End-to-end CLI behaviour, run against the built `stegseek` binary. Covers the
//! fixed gaps: `--info -p` embedded-data report, `--extract` default filename,
//! missing-`-p` handling, `-r/-g`/`-z` argument handling, `--continue`
//! multi-result output, progress gating by `-q`, JPEG error handling, and exit
//! codes.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_stegseek");

fn data(rel: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

fn tmp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("ssrs_cli_{}_{name}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Run the binary with stdin closed (so no interactive prompt fires).
fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn stegseek")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn info_with_passphrase_reports_embedded_data() {
    let o = run(&["--info", &data("stego/none.jpg"), "-p", "Sesame"]);
    let out = stdout(&o);
    assert!(out.contains("capacity:"), "info: {out}");
    assert!(
        out.contains("embedded file \"secret.txt\""),
        "should report embedded file: {out}"
    );
    assert!(out.contains("size:"), "{out}");
    assert!(out.contains("encrypted: no"), "{out}");
    assert!(out.contains("compressed: yes"), "{out}");
}

#[test]
fn info_without_passphrase_is_cover_only() {
    let o = run(&["--info", &data("stego/none.jpg")]);
    let out = stdout(&o);
    assert!(out.contains("capacity:"));
    assert!(
        !out.contains("embedded file"),
        "no -p: must not report embedded data: {out}"
    );
}

#[test]
fn extract_defaults_to_embedded_filename() {
    // run in a scratch cwd so the default output lands next to it
    let dir = tmp("extractdir");
    let _ = std::fs::create_dir_all(&dir);
    let o = Command::new(BIN)
        .args(["--extract", &data("stego/none.jpg"), "-p", "Sesame", "-f"])
        .current_dir(&dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    // steghide default = the embedded name "secret.txt", not "<stego>.out"
    assert!(
        PathBuf::from(&dir).join("secret.txt").exists(),
        "expected secret.txt in {dir}"
    );
    assert!(!PathBuf::from(&dir).join("none.jpg.out").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_without_passphrase_errors_on_non_tty() {
    let o = run(&[
        "--extract",
        "-sf",
        &data("stego/none.jpg"),
        "-xf",
        &tmp("x.out"),
        "-f",
    ]);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("must be supplied with -p"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn radius_and_goal_accepted_and_roundtrip() {
    let ef = tmp("payload.txt");
    std::fs::write(&ef, b"radius-goal-payload").unwrap();
    let stg = tmp("rg.jpg");
    let o = run(&[
        "--embed",
        "-cf",
        &data("std.jpg"),
        "-ef",
        &ef,
        "-sf",
        &stg,
        "-p",
        "pw",
        "-Z",
        "-r",
        "3",
        "-g",
        "90",
        "-f",
    ]);
    assert!(
        o.status.success(),
        "embed with -r/-g failed: {}",
        stderr(&o)
    );
    let out = tmp("rg.out");
    let o2 = run(&["--extract", "-sf", &stg, "-p", "pw", "-xf", &out, "-f"]);
    assert!(o2.status.success(), "{}", stderr(&o2));
    assert_eq!(std::fs::read(&out).unwrap(), b"radius-goal-payload");
    for f in [&ef, &stg, &out] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn compression_level_out_of_range_rejected() {
    let ef = tmp("c.txt");
    std::fs::write(&ef, b"x").unwrap();
    let o = run(&[
        "--embed",
        "-cf",
        &data("std.jpg"),
        "-ef",
        &ef,
        "-sf",
        &tmp("c.jpg"),
        "-p",
        "x",
        "-z",
        "15",
        "-f",
    ]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("range 1..9"), "{}", stderr(&o));
    let _ = std::fs::remove_file(&ef);
}

#[test]
fn unknown_argument_still_rejected() {
    let o = run(&["--crack", &data("stego/none.jpg"), "--totally-bogus"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("unknown argument"), "{}", stderr(&o));
}

#[test]
fn continue_writes_multiple_output_files() {
    let wl = tmp("cont_wl.txt");
    std::fs::write(&wl, "Sesame\nmiss\nSesame\n").unwrap();
    let out = tmp("cont.out");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(format!("{out}.1"));
    let o = run(&[
        "--crack",
        &data("stego/none.jpg"),
        &wl,
        "-xf",
        &out,
        "-c",
        "-f",
        "-t",
        "4",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(PathBuf::from(&out).exists(), "first result missing");
    assert!(
        PathBuf::from(format!("{out}.1")).exists(),
        "second (--continue) result missing"
    );
    let _ = std::fs::remove_file(&wl);
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(format!("{out}.1"));
}

#[test]
fn progress_shown_without_q_and_hidden_with_q() {
    // a wordlist large enough that the 1-thread scan lasts well beyond the 40 ms
    // reporter tick and crosses the 500k-byte print threshold
    let wl = tmp("prog_wl.txt");
    let body: String = (0..2_000_000).map(|i| format!("z{i}\n")).collect();
    std::fs::write(&wl, &body).unwrap();
    let a = run(&[
        "--crack",
        &data("stego/none.jpg"),
        &wl,
        "-xf",
        "/dev/null",
        "-f",
        "-s",
        "-t",
        "1",
    ]);
    assert!(
        stderr(&a).contains("Progress:"),
        "expected progress without -q"
    );
    let b = run(&[
        "--crack",
        &data("stego/none.jpg"),
        &wl,
        "-xf",
        "/dev/null",
        "-f",
        "-s",
        "-t",
        "1",
        "-q",
    ]);
    assert!(!stderr(&b).contains("Progress:"), "-q must hide progress");
    let _ = std::fs::remove_file(&wl);
}

#[test]
fn truncated_jpeg_errors_cleanly_no_panic() {
    let full = std::fs::read(data("std.jpg")).unwrap();
    let t = tmp("trunc.jpg");
    std::fs::write(&t, &full[..100]).unwrap();
    let o = run(&["--info", &t]);
    assert!(!o.status.success());
    let err = stderr(&o);
    assert!(!err.contains("panic"), "must not panic: {err}");
    assert!(err.to_lowercase().contains("jpeg"), "{err}");
    let _ = std::fs::remove_file(&t);
}

#[test]
fn arithmetic_jpeg_rejected_explicitly() {
    let t = tmp("arith.jpg");
    // SOI + SOF9 (arithmetic) minimal header
    std::fs::write(
        &t,
        [
            0xFFu8, 0xD8, 0xFF, 0xC9, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11,
            0x00,
        ],
    )
    .unwrap();
    let o = run(&["--info", &t]);
    assert!(!o.status.success());
    assert!(
        stderr(&o).to_lowercase().contains("arithmetic"),
        "{}",
        stderr(&o)
    );
    let _ = std::fs::remove_file(&t);
}

#[test]
fn exit_codes_found_vs_not_found() {
    let hit = tmp("hit_wl.txt");
    std::fs::write(&hit, "nope\nSesame\n").unwrap();
    let miss = tmp("miss_wl.txt");
    std::fs::write(&miss, "nope1\nnope2\n").unwrap();

    let found = run(&[
        "--crack",
        &data("stego/none.jpg"),
        &hit,
        "-xf",
        "/dev/null",
        "-f",
        "-q",
    ]);
    assert!(found.status.success(), "found should exit 0");

    let notfound = run(&[
        "--crack",
        &data("stego/none.jpg"),
        &miss,
        "-xf",
        "/dev/null",
        "-f",
        "-q",
    ]);
    assert!(!notfound.status.success(), "not-found should exit non-zero");

    let _ = std::fs::remove_file(&hit);
    let _ = std::fs::remove_file(&miss);
}
