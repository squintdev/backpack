//! Calendar server client: submit a commitment for anchoring, fetch the
//! Bitcoin attestation once it lands, and (for verification) fetch a block's
//! merkle root from an Esplora API.

use crate::ots::Timestamp;
use crate::ser::Reader;
use crate::{Error, Result};

/// Public calendar servers the reference client also uses.
pub const DEFAULT_CALENDARS: &[&str] = &[
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
];

/// Esplora instance for verifying Bitcoin attestations without a node.
pub const DEFAULT_ESPLORA: &str = "https://blockstream.info/api";

const ACCEPT: &str = "application/vnd.opentimestamps.v1";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(TIMEOUT)
        .user_agent("backpack-stamp")
        .build()
}

fn http_err(url: &str, e: ureq::Error) -> Error {
    Error::Calendar(format!("{url}: {e}"))
}

fn read_body(url: &str, resp: ureq::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(1 << 20)
        .read_to_end(&mut body)
        .map_err(|e| Error::Calendar(format!("{url}: {e}")))?;
    Ok(body)
}

/// Submit `commitment` to a calendar; returns its timestamp extending the
/// commitment (normally one op-path ending in a pending attestation).
pub fn submit(calendar: &str, commitment: &[u8]) -> Result<Timestamp> {
    let url = format!("{calendar}/digest");
    let resp = agent()
        .post(&url)
        .set("Accept", ACCEPT)
        .send_bytes(commitment)
        .map_err(|e| http_err(&url, e))?;
    let body = read_body(&url, resp)?;
    Timestamp::deserialize(&mut Reader::new(&body))
}

/// Ask a calendar for the (upgraded) timestamp of a commitment it has seen.
/// 404 means "not anchored yet" and returns `Ok(None)`.
pub fn upgrade(calendar: &str, commitment: &[u8]) -> Result<Option<Timestamp>> {
    let url = format!("{calendar}/timestamp/{}", hex::encode(commitment));
    match agent().get(&url).set("Accept", ACCEPT).call() {
        Ok(resp) => {
            let body = read_body(&url, resp)?;
            Ok(Some(Timestamp::deserialize(&mut Reader::new(&body))?))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(http_err(&url, e)),
    }
}

/// Fetch the merkle root of Bitcoin block `height` (internal byte order)
/// and its timestamp, via Esplora.
pub fn block_merkle_root(esplora: &str, height: u64) -> Result<([u8; 32], u64)> {
    let url = format!("{esplora}/block-height/{height}");
    let resp = agent().get(&url).call().map_err(|e| http_err(&url, e))?;
    let hash = String::from_utf8(read_body(&url, resp)?)
        .map_err(|_| Error::Calendar("esplora: bad block hash".into()))?;

    let url = format!("{esplora}/block/{}", hash.trim());
    let resp = agent().get(&url).call().map_err(|e| http_err(&url, e))?;
    let json = String::from_utf8(read_body(&url, resp)?)
        .map_err(|_| Error::Calendar("esplora: bad block json".into()))?;

    let root_hex = json_str_field(&json, "merkle_root")
        .ok_or_else(|| Error::Calendar("esplora: no merkle_root".into()))?;
    let ts = json_num_field(&json, "timestamp")
        .ok_or_else(|| Error::Calendar("esplora: no timestamp".into()))?;

    let mut root: [u8; 32] = hex::decode(root_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Calendar("esplora: bad merkle_root".into()))?;
    // Explorers show hashes big-endian; attestations commit to the internal
    // little-endian byte order.
    root.reverse();
    Ok((root, ts))
}

/// Minimal field extraction — the two esplora fields we need, without a
/// JSON dependency.
fn json_str_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(&json[start..end])
}

fn json_num_field(json: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let start = json.find(&pat)? + pat.len();
    json[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_extraction() {
        let j = r#"{"id":"abc","merkle_root":"deadbeef","timestamp":1783143647,"height":900000}"#;
        assert_eq!(json_str_field(j, "merkle_root"), Some("deadbeef"));
        assert_eq!(json_num_field(j, "timestamp"), Some(1_783_143_647));
        assert_eq!(json_str_field(j, "missing"), None);
    }
}
