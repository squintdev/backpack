//! Esplora HTTP client — the only network surface of `sats`.
//!
//! Privacy note (documented for users too): the Esplora server learns which
//! addresses you query and your IP. Point `--esplora` at your own instance
//! to remove that trust.

use serde::Deserialize;

use crate::{Error, Result};

pub const MAINNET: &str = "https://blockstream.info/api";
pub const SIGNET: &str = "https://mempool.space/signet/api";
pub const TESTNET: &str = "https://blockstream.info/testnet/api";

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Totals Esplora tracks per address (confirmed vs mempool).
#[derive(Debug, Deserialize)]
pub struct AddressStats {
    pub chain_stats: Totals,
    pub mempool_stats: Totals,
}

#[derive(Debug, Deserialize)]
pub struct Totals {
    pub funded_txo_sum: u64,
    pub spent_txo_sum: u64,
    pub tx_count: u64,
}

impl AddressStats {
    pub fn used(&self) -> bool {
        self.chain_stats.tx_count > 0 || self.mempool_stats.tx_count > 0
    }
    pub fn confirmed_sats(&self) -> i64 {
        self.chain_stats.funded_txo_sum as i64 - self.chain_stats.spent_txo_sum as i64
    }
    pub fn pending_sats(&self) -> i64 {
        self.mempool_stats.funded_txo_sum as i64 - self.mempool_stats.spent_txo_sum as i64
    }
}

#[derive(Debug, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: TxStatus,
}

#[derive(Debug, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_time: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct Tx {
    pub txid: String,
    pub fee: u64,
    pub status: TxStatus,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
}

#[derive(Debug, Deserialize)]
pub struct Vin {
    pub prevout: Option<Vout>,
}

#[derive(Debug, Deserialize)]
pub struct Vout {
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

pub struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base: &str) -> Self {
        Client {
            base: base.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(TIMEOUT)
                .user_agent("backpack-sats")
                .build(),
        }
    }

    fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| Error::Network(format!("{url}: {e}")))?;
        resp.into_json()
            .map_err(|e| Error::Network(format!("{url}: bad response: {e}")))
    }

    pub fn address_stats(&self, address: &str) -> Result<AddressStats> {
        self.get_json(&format!("/address/{address}"))
    }

    pub fn utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        self.get_json(&format!("/address/{address}/utxo"))
    }

    /// Recent transactions touching the address (newest first; Esplora
    /// returns up to ~50, including mempool).
    pub fn address_txs(&self, address: &str) -> Result<Vec<Tx>> {
        self.get_json(&format!("/address/{address}/txs"))
    }

    /// sat/vB estimates keyed by confirmation target in blocks.
    pub fn fee_estimates(&self) -> Result<std::collections::HashMap<String, f64>> {
        self.get_json("/fee-estimates")
    }

    pub fn tip_height(&self) -> Result<u64> {
        let url = format!("{}/blocks/tip/height", self.base);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| Error::Network(format!("{url}: {e}")))?;
        resp.into_string()
            .map_err(|e| Error::Network(e.to_string()))?
            .trim()
            .parse()
            .map_err(|_| Error::Network("bad tip height".into()))
    }

    /// Broadcast a raw transaction (hex). Returns the txid.
    pub fn broadcast(&self, tx_hex: &str) -> Result<String> {
        let url = format!("{}/tx", self.base);
        let resp = self
            .agent
            .post(&url)
            .send_string(tx_hex)
            .map_err(|e| match e {
                // Esplora returns the rejection reason in the body.
                ureq::Error::Status(code, r) => Error::Network(format!(
                    "broadcast rejected ({code}): {}",
                    r.into_string().unwrap_or_default().trim()
                )),
                other => Error::Network(format!("{url}: {other}")),
            })?;
        Ok(resp
            .into_string()
            .map_err(|e| Error::Network(e.to_string()))?
            .trim()
            .to_string())
    }
}
