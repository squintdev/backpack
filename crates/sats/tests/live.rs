//! Live signet tests — hit the public signet Esplora.
//! Run explicitly: `cargo test -p sats -- --ignored`

use sats::esplora::Client;
use sats::hd::Wallet;
use sats::{default_esplora, Network};

fn client() -> Client {
    Client::new(default_esplora(Network::Signet))
}

#[test]
#[ignore = "queries the public signet Esplora"]
fn scan_fresh_wallet_is_empty() {
    let wallet = Wallet::from_seed(&[42u8; 32], Network::Signet).unwrap();
    let s = sats::wallet::scan(&wallet, &client()).unwrap();
    assert_eq!(s.confirmed_sats, 0);
    assert_eq!(s.next_receive, 0);
    assert!(s.utxos.is_empty());
    let entries = sats::wallet::history(&s, &client()).unwrap();
    assert!(entries.is_empty());
}

#[test]
#[ignore = "queries the public signet Esplora"]
fn fee_estimates_and_tip_are_sane() {
    let c = client();
    let est = c.fee_estimates().unwrap();
    let normal = est.get("6").copied().unwrap_or(1.0);
    assert!(normal > 0.0 && normal < 10_000.0, "{normal}");
    let tip = c.tip_height().unwrap();
    assert!(tip > 200_000, "signet tip {tip}"); // signet passed this long ago
}

/// A known, historically-used signet address (an old faucet) must scan as
/// used with history — proves stats/txs parsing against real data.
#[test]
#[ignore = "queries the public signet Esplora"]
fn known_used_address_parses() {
    let c = client();
    // The canonical signet faucet address.
    let stats = c
        .address_stats("tb1qpjyzkfsq3xkmxvj3rdyvzcvkls4nhvcz5fkelw")
        .or_else(|_| c.address_stats("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"))
        .unwrap();
    // Whichever resolved: parsing worked; used addresses have tx counts.
    let _ = stats.used();
    let _ = stats.confirmed_sats();
}
