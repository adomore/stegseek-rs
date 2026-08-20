//! Port of `EncryptionAlgorithm` — the 23 algorithm identifiers steghide
//! understands (NONE + 22 ciphers), their 5-bit integer reps, mcrypt string
//! names, and the fixed parameters (key/block/IV size) libmcrypt reports.
//!
//! Parameters were captured from the system libmcrypt 2.5.8. Four algorithms
//! (safer-sk64, safer-sk128, threeway, panama) are absent from that libmcrypt
//! build, so the reference steghide linked against it cannot use them either;
//! they are listed for table fidelity but marked `supported: false`.

/// Number of bits used to encode the algorithm in the stego header.
pub const IREP_SIZE: u16 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgoParams {
    pub irep: u8,
    pub name: &'static str,
    /// Key size (bytes) libmcrypt uses = `mcrypt_enc_get_key_size` (its max).
    pub key_size: usize,
    /// Block size in bytes (1 for stream ciphers).
    pub block_size: usize,
    /// IV size in bytes (equals block size for the block ciphers here; 0 for stream).
    pub iv_size: usize,
    pub is_block: bool,
    /// Whether the system libmcrypt provides this algorithm.
    pub supported: bool,
}

// irep, name, key, block, iv, is_block, supported
const NONE: AlgoParams = AlgoParams {
    irep: 0,
    name: "none",
    key_size: 0,
    block_size: 0,
    iv_size: 0,
    is_block: false,
    supported: true,
};

macro_rules! algo {
    ($irep:expr, $name:expr, $k:expr, $b:expr, $iv:expr, $blk:expr, $sup:expr) => {
        AlgoParams {
            irep: $irep,
            name: $name,
            key_size: $k,
            block_size: $b,
            iv_size: $iv,
            is_block: $blk,
            supported: $sup,
        }
    };
}

/// Table indexed by integer rep (0..=22), order matching steghide's
/// `EncryptionAlgorithm::Translations`.
pub const ALGORITHMS: [AlgoParams; 23] = [
    NONE,
    algo!(1, "twofish", 32, 16, 16, true, true),
    algo!(2, "rijndael-128", 32, 16, 16, true, true),
    algo!(3, "rijndael-192", 32, 24, 24, true, true),
    algo!(4, "rijndael-256", 32, 32, 32, true, true),
    algo!(5, "saferplus", 32, 16, 16, true, true),
    algo!(6, "rc2", 128, 8, 8, true, true),
    algo!(7, "xtea", 16, 8, 8, true, true),
    algo!(8, "serpent", 32, 16, 16, true, true),
    algo!(9, "safer-sk64", 16, 8, 8, true, false),
    algo!(10, "safer-sk128", 16, 8, 8, true, false),
    algo!(11, "cast-256", 32, 16, 16, true, true),
    algo!(12, "loki97", 32, 16, 16, true, true),
    algo!(13, "gost", 32, 8, 8, true, true),
    algo!(14, "threeway", 12, 12, 12, true, false),
    algo!(15, "cast-128", 16, 8, 8, true, true),
    algo!(16, "blowfish", 56, 8, 8, true, true),
    algo!(17, "des", 8, 8, 8, true, true),
    algo!(18, "tripledes", 24, 8, 8, true, true),
    algo!(19, "enigma", 13, 1, 0, false, true),
    algo!(20, "arcfour", 256, 1, 0, false, true),
    algo!(21, "panama", 32, 1, 0, false, false),
    algo!(22, "wake", 32, 1, 0, false, true),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionAlgorithm(pub u8);

impl EncryptionAlgorithm {
    pub const NONE: EncryptionAlgorithm = EncryptionAlgorithm(0);

    pub fn from_irep(irep: u8) -> Option<Self> {
        if (irep as usize) < ALGORITHMS.len() {
            Some(EncryptionAlgorithm(irep))
        } else {
            None
        }
    }
    pub fn from_name(name: &str) -> Option<Self> {
        ALGORITHMS
            .iter()
            .find(|a| a.name == name)
            .map(|a| EncryptionAlgorithm(a.irep))
    }
    pub fn irep(self) -> u8 {
        self.0
    }
    pub fn params(self) -> &'static AlgoParams {
        &ALGORITHMS[self.0 as usize]
    }
    pub fn name(self) -> &'static str {
        self.params().name
    }
    pub fn is_valid_irep(irep: u32) -> bool {
        (irep as usize) < ALGORITHMS.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn table_ireps_are_sequential() {
        for (i, a) in ALGORITHMS.iter().enumerate() {
            assert_eq!(a.irep as usize, i);
        }
    }
    #[test]
    fn name_roundtrip() {
        assert_eq!(
            EncryptionAlgorithm::from_name("rijndael-128")
                .unwrap()
                .irep(),
            2
        );
        assert_eq!(
            EncryptionAlgorithm::from_name("none").unwrap(),
            EncryptionAlgorithm::NONE
        );
        assert_eq!(EncryptionAlgorithm(18).name(), "tripledes");
    }
}
