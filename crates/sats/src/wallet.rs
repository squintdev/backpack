//! Wallet operations over HD keys + Esplora: gap-limit scanning, balance,
//! history, and transaction construction/signing (P2WPKH, RBF, largest-first
//! coin selection).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::esplora::Client;
use crate::hd::{Chain, DerivedKey, Wallet};
use crate::{Error, Result};

/// BIP44-conventional gap limit: stop scanning a chain after this many
/// consecutive never-used addresses.
pub const GAP_LIMIT: u32 = 20;

/// Outputs below this are dust for P2WPKH; change under it goes to fees.
pub const DUST_SATS: u64 = 546;

/// Everything learned from one wallet scan.
pub struct Scan {
    /// Derived keys with a used address (either chain), plus the first
    /// unused external key (the next receive address).
    pub keys: Vec<DerivedKey>,
    pub next_receive: u32,
    pub next_change: u32,
    pub confirmed_sats: i64,
    pub pending_sats: i64,
    /// Spendable coins with the key index that controls each.
    pub utxos: Vec<OwnedUtxo>,
}

pub struct OwnedUtxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub confirmed: bool,
    /// Index into `Scan::keys`.
    pub key: usize,
}

/// Walk both chains until `GAP_LIMIT` consecutive unused addresses.
pub fn scan(wallet: &Wallet, client: &Client) -> Result<Scan> {
    let mut keys = Vec::new();
    let mut confirmed = 0i64;
    let mut pending = 0i64;
    let mut next = [0u32; 2];

    for chain in [Chain::External, Chain::Internal] {
        let mut gap = 0u32;
        let mut index = 0u32;
        let mut first_unused: Option<u32> = None;
        while gap < GAP_LIMIT {
            let key = wallet.key(chain, index)?;
            let stats = client.address_stats(&key.address.to_string())?;
            if stats.used() {
                confirmed += stats.confirmed_sats();
                pending += stats.pending_sats();
                keys.push(key);
                gap = 0;
            } else {
                if first_unused.is_none() {
                    first_unused = Some(index);
                }
                gap += 1;
            }
            index += 1;
        }
        next[chain as usize] = first_unused.unwrap_or(index);
    }

    // Collect spendable coins for every used key.
    let mut utxos = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        for u in client.utxos(&key.address.to_string())? {
            let txid = Txid::from_str(&u.txid).map_err(|_| Error::Network("bad txid".into()))?;
            utxos.push(OwnedUtxo {
                outpoint: OutPoint::new(txid, u.vout),
                value: u.value,
                confirmed: u.status.confirmed,
                key: i,
            });
        }
    }

    Ok(Scan {
        keys,
        next_receive: next[Chain::External as usize],
        next_change: next[Chain::Internal as usize],
        confirmed_sats: confirmed,
        pending_sats: pending,
        utxos,
    })
}

/// One line of wallet history: net effect of a transaction on us.
pub struct HistoryEntry {
    pub txid: String,
    /// Positive = received, negative = sent (includes fee when we paid it).
    pub net_sats: i64,
    pub fee: u64,
    pub confirmed: bool,
    pub block_time: Option<u64>,
    pub block_height: Option<u64>,
}

/// Merge per-address transaction lists into net history, newest first.
pub fn history(scan: &Scan, client: &Client) -> Result<Vec<HistoryEntry>> {
    let ours: HashSet<String> = scan.keys.iter().map(|k| k.address.to_string()).collect();
    let mut seen: HashMap<String, HistoryEntry> = HashMap::new();

    for key in &scan.keys {
        for tx in client.address_txs(&key.address.to_string())? {
            if seen.contains_key(&tx.txid) {
                continue;
            }
            let received: i64 = tx
                .vout
                .iter()
                .filter(|o| {
                    o.scriptpubkey_address
                        .as_deref()
                        .is_some_and(|a| ours.contains(a))
                })
                .map(|o| o.value as i64)
                .sum();
            let spent: i64 = tx
                .vin
                .iter()
                .filter_map(|i| i.prevout.as_ref())
                .filter(|p| {
                    p.scriptpubkey_address
                        .as_deref()
                        .is_some_and(|a| ours.contains(a))
                })
                .map(|p| p.value as i64)
                .sum();
            seen.insert(
                tx.txid.clone(),
                HistoryEntry {
                    txid: tx.txid,
                    net_sats: received - spent,
                    fee: tx.fee,
                    confirmed: tx.status.confirmed,
                    block_time: tx.status.block_time,
                    block_height: tx.status.block_height,
                },
            );
        }
    }
    let mut out: Vec<HistoryEntry> = seen.into_values().collect();
    // Newest first; unconfirmed on top.
    out.sort_by_key(|e| {
        std::cmp::Reverse((e.confirmed as u64, e.block_height.unwrap_or(u64::MAX)))
    });
    out.sort_by_key(|e| e.confirmed); // unconfirmed first
    out.reverse();
    out.sort_by(|a, b| match (a.confirmed, b.confirmed) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        _ => b
            .block_height
            .unwrap_or(0)
            .cmp(&a.block_height.unwrap_or(0)),
    });
    Ok(out)
}

/// A built-but-unsigned-yet spend, with everything a confirmation screen
/// must show before signing.
pub struct Spend {
    pub tx: Transaction,
    pub selected: Vec<usize>, // indexes into Scan::utxos
    pub destination: String,
    pub amount: u64,
    pub fee: u64,
    pub fee_rate: f64,
    pub change: u64,
    pub change_address: Option<String>,
    pub spendable_before: u64,
}

/// P2WPKH vbytes: ~10.5 overhead + 68 per input + 31 per output.
fn estimate_vbytes(inputs: usize, outputs: usize) -> u64 {
    11 + 68 * inputs as u64 + 31 * outputs as u64
}

/// Select coins and build an RBF transaction paying `amount` to `dest` at
/// `fee_rate` sat/vB. Only confirmed UTXOs are spent.
pub fn build_spend(
    wallet: &Wallet,
    scan: &Scan,
    dest: &str,
    amount: u64,
    fee_rate: f64,
) -> Result<Spend> {
    if amount < DUST_SATS {
        return Err(Error::Refused(format!(
            "amount {amount} is below dust ({DUST_SATS} sats)"
        )));
    }
    let address = Address::from_str(dest)
        .map_err(|e| Error::Refused(format!("bad address: {e}")))?
        .require_network(wallet.network)
        .map_err(|_| {
            Error::Refused(format!(
                "address is not a {:?} address — wrong network",
                wallet.network
            ))
        })?;

    // Largest-first over confirmed coins.
    let mut candidates: Vec<usize> = (0..scan.utxos.len())
        .filter(|&i| scan.utxos[i].confirmed)
        .collect();
    candidates.sort_by_key(|&i| std::cmp::Reverse(scan.utxos[i].value));
    let spendable: u64 = candidates.iter().map(|&i| scan.utxos[i].value).sum();

    let mut selected = Vec::new();
    let mut in_value = 0u64;
    let mut fee;
    loop {
        // Try with change output first (2 outputs).
        fee = (estimate_vbytes(selected.len(), 2) as f64 * fee_rate).ceil() as u64;
        if in_value >= amount + fee {
            break;
        }
        let Some(&next) = candidates.get(selected.len()) else {
            return Err(Error::Refused(format!(
                "insufficient confirmed funds: need ~{} sats, have {spendable}",
                amount + fee
            )));
        };
        selected.push(next);
        in_value += scan.utxos[next].value;
    }

    let mut change = in_value - amount - fee;
    let mut change_address = None;
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: address.script_pubkey(),
    }];
    if change >= DUST_SATS {
        let change_key = wallet.key(Chain::Internal, scan.next_change)?;
        change_address = Some(change_key.address.to_string());
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: change_key.address.script_pubkey(),
        });
    } else {
        // Sub-dust change goes to the miners.
        fee += change;
        change = 0;
    }

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: selected
            .iter()
            .map(|&i| TxIn {
                previous_output: scan.utxos[i].outpoint,
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    let vbytes = estimate_vbytes(selected.len(), tx.output.len());
    Ok(Spend {
        tx,
        selected,
        destination: dest.to_string(),
        amount,
        fee,
        fee_rate: fee as f64 / vbytes as f64,
        change,
        change_address,
        spendable_before: spendable,
    })
}

/// Sign every input of a built spend. Consumes the spend, returns raw tx hex.
pub fn sign_spend(wallet: &Wallet, scan: &Scan, spend: &mut Spend) -> Result<String> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(&mut spend.tx);
    for (n, &utxo_i) in spend.selected.iter().enumerate() {
        let utxo = &scan.utxos[utxo_i];
        let key = &scan.keys[utxo.key];
        // Re-derive to double-check we hold the exact key for this address.
        let rederived = wallet.key(key.chain, key.index)?;
        if rederived.address != key.address {
            return Err(Error::Key("derivation mismatch".into()));
        }
        let sighash = cache
            .p2wpkh_signature_hash(
                n,
                &key.address.script_pubkey(),
                Amount::from_sat(utxo.value),
                EcdsaSighashType::All,
            )
            .map_err(|e| Error::Key(e.to_string()))?;
        let sig = secp.sign_ecdsa(&Message::from(sighash), &key.private.inner);
        let signature = bitcoin::ecdsa::Signature {
            signature: sig,
            sighash_type: EcdsaSighashType::All,
        };
        *cache
            .witness_mut(n)
            .ok_or_else(|| Error::Key("missing input".into()))? =
            Witness::p2wpkh(&signature, &key.public.0);
    }
    Ok(bitcoin::consensus::encode::serialize_hex(&spend.tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Network;

    fn fake_scan(wallet: &Wallet, values: &[u64]) -> Scan {
        let keys: Vec<DerivedKey> = (0..values.len() as u32)
            .map(|i| wallet.key(Chain::External, i).unwrap())
            .collect();
        let utxos = values
            .iter()
            .enumerate()
            .map(|(i, &v)| OwnedUtxo {
                outpoint: OutPoint::new(Txid::all_zeros(), i as u32),
                value: v,
                confirmed: true,
                key: i,
            })
            .collect();
        Scan {
            keys,
            next_receive: values.len() as u32,
            next_change: 0,
            confirmed_sats: values.iter().sum::<u64>() as i64,
            pending_sats: 0,
            utxos,
        }
    }

    fn w() -> Wallet {
        Wallet::from_seed(&[9u8; 32], Network::Signet).unwrap()
    }

    fn dest(wallet: &Wallet) -> String {
        // A foreign-but-valid signet address: derive from a different seed.
        Wallet::from_seed(&[13u8; 32], wallet.network)
            .unwrap()
            .key(Chain::External, 0)
            .unwrap()
            .address
            .to_string()
    }

    #[test]
    fn build_selects_coins_and_makes_change() {
        let wallet = w();
        let scan = fake_scan(&wallet, &[50_000, 30_000, 10_000]);
        let spend = build_spend(&wallet, &scan, &dest(&wallet), 40_000, 2.0).unwrap();
        assert_eq!(spend.amount, 40_000);
        assert_eq!(spend.selected, vec![0]); // largest-first: 50k covers it
        assert!(spend.change > 0 && spend.change_address.is_some());
        assert_eq!(spend.tx.output.len(), 2);
        // value conservation
        assert_eq!(50_000, spend.amount + spend.fee + spend.change);
        // RBF signalled
        assert!(spend.tx.input[0].sequence.is_rbf());
    }

    #[test]
    fn build_absorbs_dust_change_into_fee() {
        let wallet = w();
        let scan = fake_scan(&wallet, &[41_000]);
        // amount + fee leaves ~sub-dust change
        let spend = build_spend(&wallet, &scan, &dest(&wallet), 40_500, 1.0).unwrap();
        assert_eq!(spend.change, 0);
        assert_eq!(spend.tx.output.len(), 1);
        assert_eq!(41_000, spend.amount + spend.fee);
    }

    #[test]
    fn build_refuses_bad_inputs() {
        let wallet = w();
        let scan = fake_scan(&wallet, &[10_000]);
        let d = dest(&wallet);
        // dust amount
        assert!(matches!(
            build_spend(&wallet, &scan, &d, 100, 1.0),
            Err(Error::Refused(_))
        ));
        // insufficient funds
        assert!(matches!(
            build_spend(&wallet, &scan, &d, 50_000, 1.0),
            Err(Error::Refused(_))
        ));
        // wrong-network address (mainnet dest on signet wallet)
        let mainnet_dest = Wallet::from_seed(&[13u8; 32], Network::Bitcoin)
            .unwrap()
            .key(Chain::External, 0)
            .unwrap()
            .address
            .to_string();
        assert!(matches!(
            build_spend(&wallet, &scan, &mainnet_dest, 5_000, 1.0),
            Err(Error::Refused(_))
        ));
        // garbage address
        assert!(build_spend(&wallet, &scan, "not-an-address", 5_000, 1.0).is_err());
    }

    #[test]
    fn signed_tx_carries_valid_witnesses() {
        let wallet = w();
        let scan = fake_scan(&wallet, &[80_000, 20_000]);
        let mut spend = build_spend(&wallet, &scan, &dest(&wallet), 90_000, 1.5).unwrap();
        assert_eq!(spend.selected.len(), 2);
        let hex = sign_spend(&wallet, &scan, &mut spend).unwrap();
        let raw = hex::decode(&hex).unwrap();
        let parsed: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(parsed.input.len(), 2);
        for input in &parsed.input {
            // P2WPKH witness: [signature, pubkey]
            assert_eq!(input.witness.len(), 2);
            assert_eq!(input.witness.nth(1).unwrap().len(), 33);
        }
        // Fee rate sane for the final size.
        let vsize = parsed.vsize() as u64;
        let implied = spend.fee as f64 / vsize as f64;
        assert!(implied >= 1.0, "must not underpay: {implied} sat/vB");
    }

    #[test]
    fn vbyte_estimate_close_to_real_size() {
        let wallet = w();
        let scan = fake_scan(&wallet, &[100_000]);
        let mut spend = build_spend(&wallet, &scan, &dest(&wallet), 50_000, 1.0).unwrap();
        let hex = sign_spend(&wallet, &scan, &mut spend).unwrap();
        let parsed: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&hex).unwrap()).unwrap();
        let est = estimate_vbytes(1, 2);
        let real = parsed.vsize() as u64;
        assert!(
            est >= real && est - real <= 4,
            "estimate {est} vs real {real} — must never underestimate"
        );
    }
}
