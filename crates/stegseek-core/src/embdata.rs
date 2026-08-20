//! Port of `EmbData` — steghide's embedded-data frame format and its
//! embed/extract state machine.
//!
//! Frame: magic(24b) → version(unary 1s + terminating 0) → encAlgo(5b) +
//! encMode(3b) → nPlainBits(32b) → encrypted payload. The payload (after
//! decryption + un-truncation to nPlainBits) is: compression flag [+32b
//! uncompressed length] → checksum flag [+32b CRC-32] → filename(\0-terminated)
//! → data.

use crate::autils::bminus;
use crate::bitstring::BitString;
use crate::error::{StegError, StegResult};
use crate::mcrypt;
use crate::rng::RandomSource;
use crate::utils::strip_dir;
use stegseek_crypto::{crc32_steghide, EncryptionAlgorithm, EncryptionMode};

pub const MAGIC: u32 = 0x0073_688D;
pub const NBITS_MAGIC: u32 = 24;
const NBITS_NPLAINBITS: u32 = 32;
const NBITS_NUNCOMPRESSEDBITS: u32 = 32;
const NBITS_CRC32: u32 = 32;
const CODE_VERSION: u16 = 0;
const ALGO_IREP_SIZE: u16 = 5;
const MODE_IREP_SIZE: u16 = 3;

#[derive(PartialEq)]
enum State {
    ReadMagic,
    ReadVersion,
    ReadEncinfo,
    ReadNplainbits,
    ReadEncrypted,
    End,
}

pub struct EmbData {
    state: State,
    nplainbits: u32,
    num_bits_requested: u32,
    num_bits_needed: u32,
    reservoir: BitString,
    passphrase: Vec<u8>,
    version: u16,
    enc_algo: EncryptionAlgorithm,
    enc_mode: EncryptionMode,
    compression: i32,
    checksum: bool,
    crc32: u32,
    filename: Vec<u8>,
    data: Vec<u8>,
}

impl EmbData {
    /// Construct for extraction.
    pub fn new_extract(passphrase: &[u8]) -> Self {
        EmbData {
            state: State::ReadMagic,
            nplainbits: 0,
            num_bits_requested: NBITS_MAGIC,
            num_bits_needed: NBITS_MAGIC,
            reservoir: BitString::new(2),
            passphrase: passphrase.to_vec(),
            version: CODE_VERSION,
            enc_algo: EncryptionAlgorithm::NONE,
            enc_mode: EncryptionMode::Ecb,
            compression: 0,
            checksum: false,
            crc32: 0,
            filename: Vec::new(),
            data: Vec::new(),
        }
    }

    pub fn finished(&self) -> bool {
        self.state == State::End
    }
    pub fn num_bits_requested(&self) -> u32 {
        self.num_bits_requested
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn filename(&self) -> &[u8] {
        &self.filename
    }
    pub fn enc_algo(&self) -> EncryptionAlgorithm {
        self.enc_algo
    }
    pub fn enc_mode(&self) -> EncryptionMode {
        self.enc_mode
    }
    pub fn compression(&self) -> i32 {
        self.compression
    }

    /// Verify the embedded CRC-32 over the extracted data (no-op if no checksum).
    pub fn checksum_ok(&self) -> bool {
        if self.checksum {
            crc32_steghide(&self.data) == self.crc32
        } else {
            true
        }
    }

    /// Feed more bits into the extraction state machine.
    pub fn add_bits(&mut self, addbits: BitString) -> StegResult<()> {
        self.reservoir.append_bitstring(&addbits);
        if self.reservoir.length() < self.num_bits_needed {
            return Err(StegError::Steghide(
                "internal: not enough bits supplied to EmbData".into(),
            ));
        }
        let bits = self.reservoir.cut_bits(0, self.num_bits_needed);

        match self.state {
            State::ReadMagic => {
                if bits.get_value(0, NBITS_MAGIC as u16) == MAGIC {
                    self.num_bits_needed = 1;
                    self.num_bits_requested = bminus(self.num_bits_needed, self.reservoir.length());
                    self.state = State::ReadVersion;
                } else {
                    return Err(StegError::Steghide(
                        "could not extract any data with that passphrase!".into(),
                    ));
                }
            }
            State::ReadVersion => {
                if bits.get(0) == 1 {
                    self.version += 1;
                    self.num_bits_needed = bminus(1u32, self.reservoir.length());
                } else {
                    if self.version > CODE_VERSION {
                        return Err(StegError::CorruptData(format!(
                            "attempting to read an embedding of version {} but only version {} is supported.",
                            self.version, CODE_VERSION
                        )));
                    }
                    self.num_bits_needed = (ALGO_IREP_SIZE + MODE_IREP_SIZE) as u32;
                    self.num_bits_requested = bminus(self.num_bits_needed, self.reservoir.length());
                    self.state = State::ReadEncinfo;
                }
            }
            State::ReadEncinfo => {
                let algo = bits.get_value(0, ALGO_IREP_SIZE);
                if EncryptionAlgorithm::is_valid_irep(algo) {
                    self.enc_algo = EncryptionAlgorithm::from_irep(algo as u8).unwrap();
                }
                let mode = bits.get_value(ALGO_IREP_SIZE as u32, MODE_IREP_SIZE);
                if let Some(m) = EncryptionMode::from_irep(mode as u8) {
                    self.enc_mode = m;
                }
                self.num_bits_needed = NBITS_NPLAINBITS;
                self.num_bits_requested = bminus(self.num_bits_needed, self.reservoir.length());
                self.state = State::ReadNplainbits;
            }
            State::ReadNplainbits => {
                self.nplainbits = bits.get_value(0, NBITS_NPLAINBITS as u16);
                self.num_bits_needed = stegseek_crypto::encrypted_size_bits(
                    self.enc_algo,
                    self.enc_mode,
                    self.nplainbits as u64,
                ) as u32;
                self.num_bits_requested = bminus(self.num_bits_needed, self.reservoir.length());
                self.state = State::ReadEncrypted;
            }
            State::ReadEncrypted => {
                let mut plain = if self.enc_algo == EncryptionAlgorithm::NONE {
                    bits
                } else {
                    mcrypt::decrypt(self.enc_algo, self.enc_mode, &bits, &self.passphrase)?
                };
                plain.truncate(0, self.nplainbits); // cut off random padding

                let mut pos = 0u32;
                // compression
                self.compression = if plain.get(pos) != 0 { 9 } else { 0 };
                pos += 1;
                if self.compression > 0 {
                    let nuncomp = plain.get_value(pos, NBITS_NUNCOMPRESSEDBITS as u16);
                    pos += NBITS_NUNCOMPRESSEDBITS;
                    let len = plain.length();
                    plain.truncate(pos, len);
                    pos = 0;
                    plain.uncompress(nuncomp)?;
                }
                // checksum
                self.checksum = plain.get(pos) != 0;
                pos += 1;
                if self.checksum {
                    self.crc32 = plain.get_value(pos, NBITS_CRC32 as u16);
                    pos += NBITS_CRC32;
                }
                // filename (\0-terminated)
                self.filename.clear();
                loop {
                    if pos + 8 > plain.length() {
                        return Err(StegError::CorruptData(
                            "the embedded data has an invalid length.".into(),
                        ));
                    }
                    let c = plain.get_value(pos, 8) as u8;
                    pos += 8;
                    if c == 0 {
                        break;
                    }
                    self.filename.push(c);
                }
                self.filename = strip_dir(&self.filename);
                // data
                if (plain.length() - pos) % 8 != 0 {
                    return Err(StegError::CorruptData(
                        "the embedded data has an invalid length.".into(),
                    ));
                }
                let extdatalen = (plain.length() - pos) / 8;
                self.data = Vec::with_capacity(extdatalen as usize);
                for _ in 0..extdatalen {
                    self.data.push(plain.get_value(pos, 8) as u8);
                    pos += 8;
                }
                self.num_bits_needed = 0;
                self.num_bits_requested = 0;
                self.state = State::End;
            }
            State::End => {
                return Err(StegError::Steghide("EmbData already finished".into()));
            }
        }
        Ok(())
    }

    /// Assemble the embed bitstring (mode EMBED). `rng` is only used when
    /// encryption is enabled (random IV + padding).
    #[allow(clippy::too_many_arguments)]
    pub fn build_embed(
        passphrase: &[u8],
        filename: &[u8],
        data: &[u8],
        enc_algo: EncryptionAlgorithm,
        enc_mode: EncryptionMode,
        compression: i32,
        checksum: bool,
        rng: &mut dyn RandomSource,
    ) -> StegResult<BitString> {
        // data that can be compressed
        let mut compr = BitString::new(2);
        compr.append_bit(checksum as u8);
        if checksum {
            let crc = crc32_steghide(data);
            compr.append_bytes(&crc.to_le_bytes());
        }
        compr.append_bytes(&strip_dir(filename));
        compr.append_byte_n(0, 8); // end of filename
        compr.append_bytes(data);

        // data that can be encrypted
        let mut plain = BitString::new(2);
        plain.append_bit((compression > 0) as u8);
        if compression > 0 {
            plain.append_u32_n(compr.length(), NBITS_NUNCOMPRESSEDBITS as u16);
            compr.compress(compression)?;
        }
        plain.append_bitstring(&compr);

        // assemble the frame
        let mut main = BitString::new(2);
        main.append_u32_n(MAGIC, NBITS_MAGIC as u16);
        // Unary version encoding: version N = N `1` bits then a `0`. CODE_VERSION
        // is currently 0 (so the loop is empty and only the terminating `0` is
        // written); the loop is kept for forward compatibility if it is ever bumped.
        #[allow(clippy::reversed_empty_ranges)]
        for _ in 0..CODE_VERSION {
            main.append_bit(1);
        }
        main.append_bit(0); // end of version
        main.append_byte_n(enc_algo.irep(), ALGO_IREP_SIZE);
        main.append_byte_n(enc_mode.irep(), MODE_IREP_SIZE);
        main.append_u32_n(plain.length(), NBITS_NPLAINBITS as u16);

        if enc_algo != EncryptionAlgorithm::NONE {
            plain = mcrypt::encrypt(enc_algo, enc_mode, &plain, passphrase, rng)?;
        }
        main.append_bitstring(&plain);
        Ok(main)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn extract(frame: &BitString, passphrase: &[u8]) -> StegResult<EmbData> {
        let mut ext = EmbData::new_extract(passphrase);
        let mut pos = 0u32;
        while !ext.finished() {
            let need = ext.num_bits_requested();
            let chunk = frame.get_bits(pos, need);
            pos += need;
            ext.add_bits(chunk)?;
        }
        Ok(ext)
    }

    fn roundtrip(algo: &str, mode: &str, compression: i32, checksum: bool) {
        let a = EncryptionAlgorithm::from_name(algo).unwrap();
        let m = EncryptionMode::from_name(mode).unwrap();
        let data: Vec<u8> = (0..500u32).map(|i| (i * 31 + 7) as u8).collect();
        let pass = b"correct horse battery staple";
        let mut rng = TestRng(0x1234_5678_9abc_def1);
        let frame = EmbData::build_embed(
            pass,
            b"some/dir/secret.bin",
            &data,
            a,
            m,
            compression,
            checksum,
            &mut rng,
        )
        .unwrap();
        let e = extract(&frame, pass).unwrap();
        assert_eq!(e.data(), &data[..], "{algo}/{mode} data");
        assert_eq!(
            e.filename(),
            b"secret.bin",
            "{algo}/{mode} filename (basename)"
        );
        assert_eq!(e.enc_algo(), a, "{algo} algo");
        assert!(e.checksum_ok(), "{algo}/{mode} crc");
        assert_eq!(
            e.compression() > 0,
            compression > 0,
            "{algo} compression flag"
        );
    }

    #[test]
    fn roundtrip_plain() {
        roundtrip("none", "ecb", 0, true);
        roundtrip("none", "ecb", 0, false);
        roundtrip("none", "ecb", 9, true);
    }

    #[test]
    fn roundtrip_encrypted() {
        // default steghide cipher + a couple others, with/without compression
        roundtrip("rijndael-128", "cbc", 9, true);
        roundtrip("rijndael-256", "cbc", 0, true);
        roundtrip("twofish", "cfb", 9, true);
        roundtrip("blowfish", "ofb", 0, true);
        roundtrip("arcfour", "stream", 9, true);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let a = EncryptionAlgorithm::from_name("none").unwrap();
        let m = EncryptionMode::from_name("ecb").unwrap();
        let mut rng = TestRng(99);
        let frame =
            EmbData::build_embed(b"right", b"f.txt", b"hello", a, m, 0, true, &mut rng).unwrap();
        // Corrupt the magic → extraction must fail cleanly (not panic)
        let mut bad = frame.clone();
        bad.set_bit(0, bad.get(0) ^ 1);
        assert!(extract(&bad, b"right").is_err());
    }
}
