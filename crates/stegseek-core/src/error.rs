//! Error types mirroring steghide's exception hierarchy
//! (`SteghideError`, `CorruptDataError`, `UnSupFileFormat`, `NotImplementedError`).
//!
//! Messages are kept faithful to the originals where they surface on the CLI,
//! so that end-to-end differential tests can match stderr.

use std::fmt;

#[derive(Debug)]
pub enum StegError {
    /// Generic steghide error (maps to `SteghideError`).
    Steghide(String),
    /// Corrupt / unextractable data (maps to `CorruptDataError`).
    CorruptData(String),
    /// Unsupported cover/stego file format (maps to `UnSupFileFormat`).
    UnsupportedFileFormat(String),
    /// Feature not implemented (maps to `NotImplementedError`).
    NotImplemented(String),
    /// Wrapper around an underlying I/O error.
    Io(std::io::Error),
}

pub type StegResult<T> = Result<T, StegError>;

impl fmt::Display for StegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StegError::Steghide(m) => write!(f, "{m}"),
            StegError::CorruptData(m) => write!(f, "{m}"),
            StegError::UnsupportedFileFormat(m) => write!(f, "{m}"),
            StegError::NotImplemented(m) => write!(f, "{m}"),
            StegError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StegError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StegError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StegError {
    fn from(e: std::io::Error) -> Self {
        StegError::Io(e)
    }
}
