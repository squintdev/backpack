use thiserror::Error;

/// Errors returned by `cph-core`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("key derivation failed")]
    Kdf,

    #[error("decryption failed: wrong passphrase or corrupt/tampered data")]
    Decrypt,

    #[error("encryption failed")]
    Encrypt,

    #[error("bad header: not a veil stream or unsupported version")]
    BadHeader,

    #[error("stream too long")]
    TooLong,
}

pub type Result<T> = std::result::Result<T, Error>;
