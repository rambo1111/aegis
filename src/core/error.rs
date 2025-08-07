// aegis-sealer-service/src/core/error.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AegisError {
    #[error("File I/O error")]
    Io(#[from] std::io::Error),

    // This is a general-purpose crypto error. While not currently constructed
    // by the sealer, it's kept for future logic. We allow dead_code to
    // acknowledge it's unused in the current sealer implementation.
    #[allow(dead_code)]
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    // The InvalidFormat error is only relevant when parsing a file,
    // so we include it only when the 'verifier' feature is enabled.
    #[cfg(feature = "verifier")]
    #[error("Invalid file format")]
    InvalidFormat,
}