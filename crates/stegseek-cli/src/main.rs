//! `stegseek` command-line interface (port of `Session` + `main`).

mod args;

use args::{Args, Command, Verbosity};
use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use stegseek_core::crack::{
    crack_seed_all, crack_wordlist_file, extract_passphrase, extract_seed, Cracker, Progress,
};
use stegseek_core::embdata::EmbData;
use stegseek_core::embed::embed_file;
use stegseek_core::format::read_file;
use stegseek_core::utils::{format_hr_size, strip_dir};
use stegseek_core::StegError;
use stegseek_crypto::{EncryptionAlgorithm, EncryptionMode, ALGORITHMS};

const STEGSEEK_VERSION: &str = "0.6";
const STEGHIDE_VERSION: &str = "0.5.1";

// ANSI helpers (gated on `color`)
fn cblu(a: &Args, s: &str) -> String {
    if a.color {
        format!("\x1b[34m{s}\x1b[0m")
    } else {
        s.into()
    }
}
fn cred(a: &Args, s: &str) -> String {
    if a.color {
        format!("\x1b[31m{s}\x1b[0m")
    } else {
        s.into()
    }
}

fn msg(a: &Args, s: &str) {
    if a.verbosity != Verbosity::Quiet {
        if a.accessible {
            eprint!("{s}");
        } else {
            eprint!("[{}] {s}", cblu(a, "i"));
        }
    }
}
fn warn(a: &Args, s: &str) {
    if a.verbosity != Verbosity::Quiet {
        if a.accessible {
            eprint!("warning: {s}");
        } else {
            eprint!("[{}] warning: {s}", cred(a, "w"));
        }
    }
}

fn print_version(a: &Args) {
    eprintln!("StegSeek {STEGSEEK_VERSION} - https://github.com/RickdeJager/StegSeek");
    if a.verbosity == Verbosity::Verbose {
        eprintln!("based on steghide version {STEGHIDE_VERSION}");
    }
    eprintln!();
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut a = match Args::parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[!] error: {}", e.0);
            return ExitCode::FAILURE;
        }
    };
    a.color = std::io::stderr().is_terminal();
    // re-apply -n if it was given (parse set color=false already, but isatty just overrode)
    if argv.iter().any(|x| x == "-n" || x == "--nocolor") {
        a.color = false;
    }

    match run(&a) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if a.accessible {
                eprintln!("error: {e}");
            } else {
                eprintln!("[{}] error: {e}", cred(&a, "!"));
            }
            ExitCode::FAILURE
        }
    }
}

fn run(a: &Args) -> Result<(), StegError> {
    match a.command {
        Command::Version => {
            print_version(a);
            Ok(())
        }
        Command::Help => {
            print_help(a);
            Ok(())
        }
        Command::License => {
            print_license();
            Ok(())
        }
        Command::EncInfo => {
            print_encinfo();
            Ok(())
        }
        Command::Crack => cmd_crack(a),
        Command::Seed => cmd_seed(a),
        Command::Extract => cmd_extract(a),
        Command::Embed => cmd_embed(a),
        Command::Info => cmd_info(a),
    }
}

fn stg_path(a: &Args) -> Result<String, StegError> {
    a.stg_fn
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StegError::Steghide("No stegofile specified as input.".into()))
}

/// Prompt for a passphrase on the terminal with echo disabled (port of
/// `Arguments::getPassphrase` + `Terminal::EchoOff`). When `confirm` is set
/// (embed) the passphrase is entered twice and must match. If stdin is not a
/// terminal we cannot prompt — error rather than silently using an empty key.
fn prompt_passphrase(confirm: bool) -> Result<Vec<u8>, StegError> {
    use std::io::BufRead;
    if !std::io::stdin().is_terminal() {
        return Err(StegError::Steghide(
            "the passphrase must be supplied with -p when stdin is not a terminal.".into(),
        ));
    }
    let read_line = |label: &str| -> String {
        let _ = std::process::Command::new("stty").arg("-echo").status();
        eprint!("{label}");
        let _ = std::io::stderr().flush();
        let mut s = String::new();
        let _ = std::io::stdin().lock().read_line(&mut s);
        let _ = std::process::Command::new("stty").arg("echo").status();
        eprintln!();
        while matches!(s.as_bytes().last(), Some(b'\n') | Some(b'\r')) {
            s.pop();
        }
        s
    };
    let p1 = read_line("Enter passphrase: ");
    if confirm {
        let p2 = read_line("Re-Enter passphrase: ");
        if p1 != p2 {
            return Err(StegError::Steghide("the passphrases do not match.".into()));
        }
    }
    Ok(p1.into_bytes())
}

/// Resolve the passphrase: an explicit `-p` (even empty) is used verbatim;
/// otherwise prompt on the terminal.
fn resolve_passphrase(a: &Args, confirm: bool) -> Result<Vec<u8>, StegError> {
    match &a.passphrase {
        Some(p) => Ok(p.clone()),
        None => prompt_passphrase(confirm),
    }
}

fn cmd_crack(a: &Args) -> Result<(), StegError> {
    if !a.accessible {
        print_version(a);
    }
    let path = stg_path(a)?;
    let file = read_file(&path)?;
    let cracker = Arc::new(Cracker::new(&*file));
    let wordlist = a
        .wordlist_fn
        .clone()
        .unwrap_or_else(|| "/usr/share/wordlists/rockyou.txt".into());
    let size = std::fs::metadata(&wordlist).map(|m| m.len()).unwrap_or(0);
    let progress = show_progress(a).then(|| Progress::new(size, false, a.accessible));
    let found = crack_wordlist_file(
        cracker,
        &wordlist,
        a.threads,
        a.skip_default,
        &path,
        a.cont,
        progress.as_ref(),
    )
    .map_err(|_| StegError::Steghide(format!("could not open the wordlist \"{wordlist}\".")))?;
    if found.is_empty() {
        return Err(StegError::Steghide(
            "Could not find a valid passphrase.".into(),
        ));
    }
    for (n, pass) in found.iter().enumerate() {
        msg(
            a,
            &format!("Found passphrase: \"{}\"\n", String::from_utf8_lossy(pass)),
        );
        let emb = extract_passphrase(&*file, pass)?;
        write_extracted_indexed(a, &emb, &path, n)?;
    }
    Ok(())
}

/// Live progress metrics are shown unless `-q`/quiet is set (steghide: `-q`
/// "hide performance metrics").
fn show_progress(a: &Args) -> bool {
    a.verbosity != Verbosity::Quiet
}

fn cmd_seed(a: &Args) -> Result<(), StegError> {
    if !a.accessible {
        print_version(a);
    }
    let path = stg_path(a)?;
    let file = read_file(&path)?;
    let cracker = Arc::new(Cracker::new(&*file));
    let progress = show_progress(a).then(|| Progress::new(u32::MAX as u64 + 1, true, a.accessible));
    let results = crack_seed_all(cracker, a.threads, a.cont, progress.as_ref());
    if results.is_empty() {
        return Err(StegError::Steghide("Could not find a valid seed.".into()));
    }
    for (n, r) in results.iter().enumerate() {
        let algo = EncryptionAlgorithm::from_irep(r.enc_algo as u8)
            .map(|x| x.name())
            .unwrap_or("unknown");
        let mode = EncryptionMode::from_irep(r.enc_mode as u8)
            .map(|x| x.name())
            .unwrap_or("unknown");
        msg(a, &format!(
            "Found (possible) seed: \"{:08x}\"\n\tPlain size: {} (compressed)\n\tEncryption Algorithm: {algo}\n\tEncryption Mode:      {mode}\n",
            r.seed, format_hr_size((r.plain_size / 8) as u64)
        ));
        if r.enc_algo == 0 {
            let emb = extract_seed(&*file, r.seed)?;
            write_extracted_indexed(a, &emb, &path, n)?;
        }
    }
    Ok(())
}

fn cmd_extract(a: &Args) -> Result<(), StegError> {
    let path = stg_path(a)?;
    let pass = resolve_passphrase(a, false)?;
    let file = read_file(&path)?;
    let emb = extract_passphrase(&*file, &pass)?;
    if !emb.checksum_ok() {
        warn(
            a,
            "crc32 checksum failed! extracted data is probably corrupted.\n",
        );
    }
    // steghide `--extract` defaults the output to the *embedded* filename (and
    // errors if there is none and no -xf), unlike `--crack` which uses <stego>.out.
    write_extracted_named(a, &emb, &path, true)?;
    Ok(())
}

fn cmd_embed(a: &Args) -> Result<(), StegError> {
    let cvr = a
        .cvr_fn
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StegError::Steghide("no cover file specified.".into()))?;
    let emb = a
        .emb_fn
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StegError::Steghide("no file to embed specified.".into()))?;
    let stg = a.stg_fn.clone().unwrap_or_else(|| cvr.clone());
    let pass = resolve_passphrase(a, true)?;
    let data = std::fs::read(&emb)?;
    let cover_bytes = std::fs::read(&cvr)?;
    let embed_filename: Vec<u8> = if a.embed_name {
        strip_dir(emb.as_bytes())
    } else {
        Vec::new()
    };

    let mut rng = OsRng::new();
    let stego = embed_file(
        cover_bytes,
        &cvr,
        &pass,
        &embed_filename,
        &data,
        a.enc_algo,
        a.enc_mode,
        a.compression,
        a.checksum,
        &mut rng,
        a.radius,
        a.goal,
    )?;
    if std::path::Path::new(&stg).exists() && !a.force {
        return Err(StegError::Steghide(format!(
            "the file \"{stg}\" does already exist. use the force (-f)."
        )));
    }
    std::fs::write(&stg, &stego)?;
    msg(a, &format!("Wrote stego file \"{stg}\".\n"));
    Ok(())
}

fn cmd_info(a: &Args) -> Result<(), StegError> {
    let path = a
        .cvr_fn
        .clone()
        .or_else(|| a.stg_fn.clone())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StegError::Steghide("no file specified.".into()))?;
    let file = read_file(&path)?;
    println!(
        "\"{}\":",
        String::from_utf8_lossy(&strip_dir(path.as_bytes()))
    );
    println!("  format: {}", file.format_name());
    println!("  capacity: {}", format_hr_size(file.capacity_bytes()));

    // With a passphrase, steghide `--info` also reports the embedded data's
    // properties (name, size, encryption, compression). Port of the second half
    // of `Session::printInfo`.
    if let Some(pass) = &a.passphrase {
        match extract_passphrase(&*file, pass) {
            Ok(emb) => {
                let name = emb.filename();
                let shown = if name.is_empty() {
                    "<no name>".to_string()
                } else {
                    format!("\"{}\"", String::from_utf8_lossy(name))
                };
                println!("  embedded file {shown}:");
                println!("    size: {}", format_hr_size(emb.data().len() as u64));
                let enc = if emb.enc_algo() == EncryptionAlgorithm::NONE {
                    "no".to_string()
                } else {
                    format!("{}, {}", emb.enc_algo().name(), emb.enc_mode().name())
                };
                println!("    encrypted: {enc}");
                println!(
                    "    compressed: {}",
                    if emb.compression() != 0 { "yes" } else { "no" }
                );
            }
            Err(_) => {
                warn(a, "could not extract any data with that passphrase!\n");
            }
        }
    }
    Ok(())
}

/// Write extracted data to the output file (or stdout), printing the standard
/// "Original filename"/"Extracting to" messages (port of `Cracker::extract` /
/// `Session::EXTRACT`). `--crack`/`--seed` default the output to `<stego>.out`;
/// `--extract` defaults to the embedded original filename (`use_embedded_name`).
/// Write the `n`-th crack/seed result. The first goes to the normal output name;
/// subsequent `--continue` results get a `.<n>` suffix (port of
/// `Cracker::extract`'s `saveFileIndex`), so multiple embedded files don't
/// overwrite each other.
fn write_extracted_indexed(
    a: &Args,
    emb: &EmbData,
    stg_path: &str,
    n: usize,
) -> Result<(), StegError> {
    if n == 0 {
        return write_extracted_named(a, emb, stg_path, false);
    }
    let orig = emb.filename();
    let base: String = match &a.ext_fn {
        Some(f) if !f.is_empty() => f.clone(),
        _ => format!(
            "{}.out",
            String::from_utf8_lossy(&strip_dir(stg_path.as_bytes()))
        ),
    };
    let outfn = format!("{base}.{n}");
    if !orig.is_empty() {
        msg(
            a,
            &format!(
                "Original filename: \"{}\".\n",
                String::from_utf8_lossy(orig)
            ),
        );
    }
    if std::path::Path::new(&outfn).exists() && !a.force {
        return Err(StegError::Steghide(format!(
            "the file \"{outfn}\" does already exist. use the force (-f)."
        )));
    }
    msg(a, &format!("Extracting to \"{outfn}\".\n"));
    std::fs::write(&outfn, emb.data())?;
    Ok(())
}

fn write_extracted_named(
    a: &Args,
    emb: &EmbData,
    stg_path: &str,
    use_embedded_name: bool,
) -> Result<(), StegError> {
    let orig = emb.filename();
    let outfn: String = match &a.ext_fn {
        Some(f) => f.clone(),
        None if use_embedded_name => {
            if orig.is_empty() {
                return Err(StegError::Steghide(
                    "please specify a file name for the extracted data (there is none embedded in the stego file).".into(),
                ));
            }
            String::from_utf8_lossy(&strip_dir(orig)).into_owned()
        }
        None => format!(
            "{}.out",
            String::from_utf8_lossy(&strip_dir(stg_path.as_bytes()))
        ),
    };
    if !orig.is_empty() {
        msg(
            a,
            &format!(
                "Original filename: \"{}\".\n",
                String::from_utf8_lossy(orig)
            ),
        );
    }
    if outfn.is_empty() {
        msg(a, "Extracting to stdout.\n\n");
        std::io::stdout().write_all(emb.data())?;
    } else {
        if std::path::Path::new(&outfn).exists() && !a.force {
            return Err(StegError::Steghide(format!(
                "the file \"{outfn}\" does already exist. use the force (-f)."
            )));
        }
        msg(a, &format!("Extracting to \"{outfn}\".\n"));
        std::fs::write(&outfn, emb.data())?;
    }
    Ok(())
}

fn print_encinfo() {
    println!("encryption algorithms:");
    println!("<algorithm>: <supported modes>...");
    for ap in ALGORITHMS.iter() {
        if ap.irep == 0 || !ap.supported {
            continue;
        }
        let algo = EncryptionAlgorithm(ap.irep);
        if !stegseek_crypto::is_supported(algo) {
            continue;
        }
        let modes = if ap.is_block {
            "cbc cfb ctr ecb ncfb nofb ofb"
        } else {
            "stream"
        };
        println!("{}: {modes}", ap.name);
    }
}

fn print_help(a: &Args) {
    print_version(a);
    print!(
        "\n=== StegSeek Help ===\n\
         To crack a stegofile:\n\
         stegseek [stegofile.jpg] [wordlist.txt]\n\n\
         Commands:\n\
         \x20--crack                 Crack a stego file using a wordlist. This is the default mode.\n\
         \x20--seed                  Crack a stego file by attempting all embedding patterns.\n\
         \x20--embed                 Embed data (steghide-compatible).\n\
         \x20--extract               Extract data using a passphrase.\n\
         \x20--info                  Display information about a cover- or stego-file.\n\
         \x20--encinfo               Display a list of supported encryption algorithms.\n\n\
         Positional arguments:\n\
         \x20--crack [stegofile.jpg] [wordlist.txt] [output.txt]\n\
         \x20--seed  [stegofile.jpg] [output.txt]\n\n\
         Keyword arguments:\n\
         \x20-sf, --stegofile        select stego file\n\
         \x20-wl, --wordlist         select the wordlist file\n\
         \x20-xf, --extractfile      select file name for extracted data\n\
         \x20-cf, --coverfile        select cover file (embed)\n\
         \x20-ef, --embedfile        select file to embed\n\
         \x20-p,  --passphrase       specify passphrase\n\
         \x20-e,  --encryption       select encryption parameters (embed)\n\
         \x20-Z,  --dontcompress     do not compress before embedding\n\
         \x20-t,  --threads          set the number of threads\n\
         \x20-f,  --force            overwrite existing files\n\
         \x20-v,  --verbose          display detailed information\n\
         \x20-q,  --quiet            hide performance metrics\n\
         \x20-s,  --skipdefault      don't add guesses to the wordlist\n\
         \x20-n,  --nocolor          disable colors in output\n\
         \x20-c,  --continue         continue cracking after a result is found\n\
         \x20-a,  --accessible       screen-reader friendly output\n\n"
    );
}

fn print_license() {
    print!(
        "Copyright (C) 2021 Rick de Jager ( https://github.com/rickdejager )\n\n\
         This program is free software; you can redistribute it and/or\n\
         modify it under the terms of the GNU General Public License\n\
         as published by the Free Software Foundation; either version 2\n\
         of the License, or (at your option) any later version.\n"
    );
}

/// OS random source for embedding (random IV + padding). Reads /dev/urandom,
/// falling back to a time-seeded xorshift.
struct OsRng {
    file: Option<std::fs::File>,
    state: u64,
}
impl OsRng {
    fn new() -> Self {
        let file = std::fs::File::open("/dev/urandom").ok();
        let state = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
        OsRng { file, state }
    }
}
impl stegseek_core::rng::RandomSource for OsRng {
    fn get_byte(&mut self) -> u8 {
        if let Some(f) = &mut self.file {
            use std::io::Read;
            let mut b = [0u8; 1];
            if f.read_exact(&mut b).is_ok() {
                return b[0];
            }
        }
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state & 0xff) as u8
    }
    fn get_bool(&mut self) -> bool {
        self.get_byte() & 1 != 0
    }
}
