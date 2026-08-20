//! Port of `EncryptionMode` — 8 modes with 3-bit integer reps.
//! libmcrypt semantics: `cfb`/`ofb` are 8-bit feedback; `ncfb`/`nofb` are
//! full-block feedback; `ctr` is a big-endian counter; `stream` is passthrough.

pub const IREP_SIZE: u16 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionMode {
    Ecb = 0,
    Cbc = 1,
    Ofb = 2,
    Cfb = 3,
    Nofb = 4,
    Ncfb = 5,
    Ctr = 6,
    Stream = 7,
}

impl EncryptionMode {
    pub fn from_irep(irep: u8) -> Option<Self> {
        use EncryptionMode::*;
        Some(match irep {
            0 => Ecb,
            1 => Cbc,
            2 => Ofb,
            3 => Cfb,
            4 => Nofb,
            5 => Ncfb,
            6 => Ctr,
            7 => Stream,
            _ => return None,
        })
    }
    pub fn from_name(name: &str) -> Option<Self> {
        use EncryptionMode::*;
        Some(match name {
            "ecb" => Ecb,
            "cbc" => Cbc,
            "ofb" => Ofb,
            "cfb" => Cfb,
            "nofb" => Nofb,
            "ncfb" => Ncfb,
            "ctr" => Ctr,
            "stream" => Stream,
            _ => return None,
        })
    }
    pub fn irep(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        use EncryptionMode::*;
        match self {
            Ecb => "ecb",
            Cbc => "cbc",
            Ofb => "ofb",
            Cfb => "cfb",
            Nofb => "nofb",
            Ncfb => "ncfb",
            Ctr => "ctr",
            Stream => "stream",
        }
    }
    pub fn has_iv(self) -> bool {
        !matches!(self, EncryptionMode::Ecb | EncryptionMode::Stream)
    }
    pub fn is_block_mode(self) -> bool {
        !matches!(self, EncryptionMode::Stream)
    }
}
