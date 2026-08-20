//! Command-line argument parsing (port of `Arguments`): a leading `--command`
//! (default `crack`), keyword arguments, and command-specific positionals.

use stegseek_crypto::{EncryptionAlgorithm, EncryptionMode};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Command {
    Crack,
    Seed,
    Embed,
    Extract,
    Info,
    EncInfo,
    Version,
    License,
    Help,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

#[derive(Debug)]
pub struct Args {
    pub command: Command,
    pub stg_fn: Option<String>,
    pub wordlist_fn: Option<String>,
    pub ext_fn: Option<String>,
    pub cvr_fn: Option<String>,
    pub emb_fn: Option<String>,
    pub passphrase: Option<Vec<u8>>,
    pub enc_algo: EncryptionAlgorithm,
    pub enc_mode: EncryptionMode,
    pub enc_set: bool,
    pub compression: i32,
    pub radius: Option<u32>,
    pub goal: u32,
    pub checksum: bool,
    pub embed_name: bool,
    pub threads: usize,
    pub force: bool,
    pub skip_default: bool,
    pub verbosity: Verbosity,
    pub color: bool,
    pub accessible: bool,
    pub cont: bool,
}

pub struct ArgError(pub String);

impl Args {
    pub fn parse(argv: &[String]) -> Result<Args, ArgError> {
        let mut a = Args {
            command: Command::Crack,
            stg_fn: None,
            wordlist_fn: None,
            ext_fn: None,
            cvr_fn: None,
            emb_fn: None,
            passphrase: None,
            enc_algo: EncryptionAlgorithm::from_name("rijndael-128").unwrap(),
            enc_mode: EncryptionMode::Cbc,
            enc_set: false,
            compression: 9,
            radius: None,
            goal: 100,
            checksum: true,
            embed_name: true,
            threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            force: false,
            skip_default: false,
            verbosity: Verbosity::Normal,
            color: false, // set from isatty by the caller
            accessible: false,
            cont: false,
        };
        if argv.is_empty() {
            a.command = Command::Help;
            return Ok(a);
        }
        let mut i = 0usize;
        // command (must be first and start with --)
        let cmd = &argv[0];
        let mut consumed_cmd = true;
        a.command = match cmd.as_str() {
            "--crack" => Command::Crack,
            "--seed" => Command::Seed,
            "--embed" => Command::Embed,
            "--extract" => Command::Extract,
            "--info" => Command::Info,
            "--encinfo" => Command::EncInfo,
            "--version" => Command::Version,
            "--license" => Command::License,
            "--help" => Command::Help,
            _ => {
                consumed_cmd = false;
                Command::Crack
            }
        };
        if consumed_cmd {
            i = 1;
        }

        let mut positional: Vec<String> = Vec::new();
        while i < argv.len() {
            let arg = argv[i].as_str();
            let next = |i: &mut usize| -> Result<String, ArgError> {
                *i += 1;
                argv.get(*i).cloned().ok_or_else(|| {
                    ArgError(format!(
                        "the argument \"{arg}\" must be followed by a value."
                    ))
                })
            };
            match arg {
                "-sf" | "--stegofile" => a.stg_fn = Some(next(&mut i)?),
                "-wl" | "--wordlist" => a.wordlist_fn = Some(next(&mut i)?),
                "-xf" | "--extractfile" => a.ext_fn = Some(next(&mut i)?),
                "-cf" | "--coverfile" => a.cvr_fn = Some(next(&mut i)?),
                "-ef" | "--embedfile" => a.emb_fn = Some(next(&mut i)?),
                "-p" | "--passphrase" => a.passphrase = Some(next(&mut i)?.into_bytes()),
                "-z" | "--compress" => {
                    let z: i32 = next(&mut i)?
                        .parse()
                        .map_err(|_| ArgError("invalid compression level.".into()))?;
                    if !(1..=9).contains(&z) {
                        return Err(ArgError(
                            "the compression level must be in the range 1..9.".into(),
                        ));
                    }
                    a.compression = z;
                }
                "-Z" | "--dontcompress" => a.compression = 0,
                "-r" | "--radius" => {
                    a.radius =
                        Some(next(&mut i)?.parse().map_err(|_| {
                            ArgError("the radius must be a positive integer.".into())
                        })?);
                }
                "-g" | "--goal" => {
                    let g: u32 = next(&mut i)?.parse().map_err(|_| {
                        ArgError("the goal must be an integer between 0 and 100.".into())
                    })?;
                    if g > 100 {
                        return Err(ArgError(
                            "the goal must be an integer between 0 and 100.".into(),
                        ));
                    }
                    a.goal = g;
                }
                "-K" | "--nochecksum" => a.checksum = false,
                "-N" | "--dontembedname" => a.embed_name = false,
                "-t" | "--threads" => {
                    a.threads = next(&mut i)?
                        .parse()
                        .map_err(|_| ArgError("invalid thread count.".into()))?
                }
                "-f" | "--force" => a.force = true,
                "-s" | "--skipdefault" => a.skip_default = true,
                "-v" | "--verbose" => a.verbosity = Verbosity::Verbose,
                "-q" | "--quiet" => a.verbosity = Verbosity::Quiet,
                "-n" | "--nocolor" => a.color = false,
                "-c" | "--continue" => a.cont = true,
                "-a" | "--accessible" => a.accessible = true,
                "-e" | "--encryption" => {
                    a.enc_set = true;
                    let s1 = next(&mut i)?;
                    let mut s2 = String::new();
                    if i + 1 < argv.len() && !argv[i + 1].starts_with('-') {
                        s2 = next(&mut i)?;
                    }
                    apply_encryption(&mut a, &s1, &s2)?;
                }
                _ => {
                    if arg.starts_with('-') && arg != "-" {
                        return Err(ArgError(format!("unknown argument \"{arg}\".")));
                    }
                    positional.push(argv[i].clone());
                }
            }
            i += 1;
        }

        // positional assignment by command
        macro_rules! pos_assign {
            ($($slot:expr),*) => {{
                let slots: Vec<&mut Option<String>> = vec![$($slot),*];
                for (s, v) in slots.into_iter().zip(positional.iter()) {
                    if s.is_none() { *s = Some(v.clone()); }
                }
            }};
        }
        match a.command {
            Command::Crack => pos_assign!(&mut a.stg_fn, &mut a.wordlist_fn, &mut a.ext_fn),
            Command::Seed => pos_assign!(&mut a.stg_fn, &mut a.ext_fn),
            Command::Embed => pos_assign!(&mut a.emb_fn, &mut a.cvr_fn, &mut a.stg_fn),
            Command::Extract => pos_assign!(&mut a.stg_fn, &mut a.ext_fn),
            Command::Info => pos_assign!(&mut a.cvr_fn),
            _ => {}
        }

        // embed: if stego file unset but cover set, overwrite cover
        if a.command == Command::Embed && a.stg_fn.is_none() && a.cvr_fn.is_some() {
            a.stg_fn = a.cvr_fn.clone();
            a.force = true;
        }
        Ok(a)
    }
}

fn apply_encryption(a: &mut Args, s1: &str, s2: &str) -> Result<(), ArgError> {
    if s1 == "none" && s2.is_empty() {
        a.enc_algo = EncryptionAlgorithm::NONE;
        return Ok(());
    }
    for s in [s1, s2] {
        if s.is_empty() {
            continue;
        }
        if let Some(algo) = EncryptionAlgorithm::from_name(s) {
            a.enc_algo = algo;
        } else if let Some(mode) = EncryptionMode::from_name(s) {
            a.enc_mode = mode;
        } else {
            return Err(ArgError(format!(
                "\"{s}\" is neither an algorithm nor a mode supported by libmcrypt."
            )));
        }
    }
    Ok(())
}
