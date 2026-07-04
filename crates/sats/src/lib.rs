//! `sats` — a thin Bitcoin spending client for the backpack suite.
//!
//! Not a full wallet app: no seed ceremonies, no accounts. Each keyring
//! identity carries a 32-byte BIP32 master seed; `sats` derives standard
//! BIP84 native-segwit addresses from it, reads the chain through an Esplora
//! API, and builds/signs/broadcasts transactions locally. The seed is
//! exportable as an xprv, so funds are recoverable in any BIP84 wallet.
//!
//! Defaults are paranoid: signet unless mainnet is asked for explicitly,
//! RBF always on, foot-gun checks on sends (see [`wallet::build_spend`] and
//! the CLI's `--force`).

pub mod esplora;
pub mod hd;
pub mod wallet;

use thiserror::Error;

pub use bitcoin::Network;

#[derive(Debug, Error)]
pub enum Error {
    #[error("key derivation: {0}")]
    Key(String),
    #[error("network: {0}")]
    Network(String),
    #[error("refused: {0}")]
    Refused(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Parse a network name; `sats` defaults to signet so real money requires
/// an explicit choice.
pub fn parse_network(s: &str) -> Result<Network> {
    match s {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "signet" => Ok(Network::Signet),
        "testnet" => Ok(Network::Testnet),
        _ => Err(Error::Refused(format!("unknown network {s:?}"))),
    }
}

/// Default Esplora endpoint for a network.
pub fn default_esplora(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => esplora::MAINNET,
        Network::Testnet => esplora::TESTNET,
        _ => esplora::SIGNET,
    }
}

/// Format sats with thousands separators, plus BTC for large amounts.
pub fn fmt_sats(sats: i64) -> String {
    let neg = sats < 0;
    let n = sats.unsigned_abs();
    let mut s = n.to_string();
    let mut i = s.len() as i64 - 3;
    while i > 0 {
        s.insert(i as usize, ',');
        i -= 3;
    }
    let sign = if neg { "-" } else { "" };
    if n >= 1_000_000 {
        format!("{sign}{s} sats ({sign}{:.8} BTC)", n as f64 / 1e8)
    } else {
        format!("{sign}{s} sats")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_parsing() {
        assert_eq!(parse_network("mainnet").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("signet").unwrap(), Network::Signet);
        assert!(parse_network("simnet").is_err());
    }

    #[test]
    fn sats_formatting() {
        assert_eq!(fmt_sats(0), "0 sats");
        assert_eq!(fmt_sats(999), "999 sats");
        assert_eq!(fmt_sats(50_000), "50,000 sats");
        assert_eq!(fmt_sats(-1_234), "-1,234 sats");
        assert_eq!(fmt_sats(150_000_000), "150,000,000 sats (1.50000000 BTC)");
    }
}
