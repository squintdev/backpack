//! Live signer test: run the NIP-46 signer against a real relay, drive it with
//! a mock client, and verify a real remote signature comes back.
//!
//! Ignored by default (network). Run: `cargo test -p bp-nostr --test signer -- --ignored`

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bp_nostr::client::{run_signer, run_signer_multi};
use bp_nostr::event::{pubkey_hex, sign_event, verify_event, Event};
use bp_nostr::nip44;
use bp_nostr::nip46::{Response, KIND_RPC};
use bp_nostr::relay::{parse, publish_frame, req_frame, Filter, RelayMsg};
use tungstenite::stream::MaybeTlsStream as MaybeTls;
use tungstenite::Message;

// nos.lol is the stabler choice for the single-relay test; damus (Cloudflare)
// intermittently 520s WS upgrades and is still covered by the multi-relay test.
const RELAY: &str = "wss://nos.lol";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Publish a NIP-46 request from the client to the signer, then read the
/// signer's encrypted response for our pubkey and decrypt it.
fn rpc(
    client_sk: &[u8; 32],
    client_pk: &str,
    signer_pub: &[u8; 32],
    signer_pk_hex: &str,
    method: &str,
    params: serde_json::Value,
) -> Response {
    rpc_on(
        RELAY,
        client_sk,
        client_pk,
        signer_pub,
        signer_pk_hex,
        method,
        params,
    )
}

/// Same as [`rpc`] but over a specific relay.
#[allow(clippy::too_many_arguments)]
fn rpc_on(
    relay: &str,
    client_sk: &[u8; 32],
    client_pk: &str,
    signer_pub: &[u8; 32],
    signer_pk_hex: &str,
    method: &str,
    params: serde_json::Value,
) -> Response {
    let id = format!("{method}-{}", now());
    let body = serde_json::json!({ "id": id, "method": method, "params": params }).to_string();
    let enc = nip44::encrypt(client_sk, signer_pub, &body).unwrap();
    let ev = sign_event(
        client_sk,
        now(),
        KIND_RPC,
        vec![vec!["p".to_string(), signer_pk_hex.to_string()]],
        enc,
    )
    .unwrap();

    // Kind 24133 is ephemeral: relays forward to live subscribers but do not
    // store it. So subscribe first, then publish on the same live socket, then
    // read the response off the subscription.
    let (mut sock, _) = tungstenite::connect(relay).unwrap();
    if let MaybeTls::Rustls(s) = sock.get_ref() {
        s.get_ref()
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let filter = Filter {
        authors: Some(vec![signer_pk_hex.to_string()]),
        kinds: Some(vec![KIND_RPC]),
        p_tags: Some(vec![client_pk.to_string()]),
        since: Some(now() - 5),
        limit: None,
    };
    sock.send(Message::Text(req_frame("rpc", &filter))).unwrap();
    sock.send(Message::Text(publish_frame(&ev))).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        let msg = match sock.read() {
            Ok(m) => m,
            Err(_) => continue, // read timeout; keep waiting
        };
        if let Message::Text(t) = msg {
            if let RelayMsg::Event(e) = parse(&t) {
                if let Ok(plain) = nip44::decrypt(client_sk, signer_pub, &e.content) {
                    if plain.contains(&id) {
                        let v: serde_json::Value = serde_json::from_str(&plain).unwrap();
                        return Response {
                            id: v["id"].as_str().unwrap().to_string(),
                            result: v["result"].as_str().unwrap_or("").to_string(),
                            error: v["error"]
                                .as_str()
                                .filter(|s| !s.is_empty())
                                .map(str::to_string),
                        };
                    }
                }
            }
        }
    }
    panic!("no signer response for {method}");
}

#[test]
#[ignore = "runs a live signer against a public relay"]
fn remote_sign_over_relay() {
    let signer_sk = [3u8; 32];
    let signer_pk_hex = pubkey_hex(&signer_sk).unwrap();
    let signer_pub: [u8; 32] = hex::decode(&signer_pk_hex).unwrap().try_into().unwrap();
    let client_sk = [4u8; 32];
    let client_pk_hex = pubkey_hex(&client_sk).unwrap();
    let secret = "test-secret";

    let stop = Arc::new(AtomicBool::new(false));
    let log = Arc::new(Mutex::new(Vec::<String>::new()));

    let signer = {
        let stop = stop.clone();
        let log = log.clone();
        std::thread::spawn(move || {
            let _ = run_signer(RELAY, &signer_sk, secret, &stop, |l| {
                log.lock()
                    .unwrap()
                    .push(format!("{} {} {}", l.client, l.method, l.outcome));
            });
        })
    };
    std::thread::sleep(Duration::from_secs(2)); // let the subscription establish

    // connect (authorizes this client), then request a signature.
    let c = rpc(
        &client_sk,
        &client_pk_hex,
        &signer_pub,
        &signer_pk_hex,
        "connect",
        serde_json::json!([signer_pk_hex, secret]),
    );
    assert!(c.error.is_none(), "connect failed: {:?}", c.error);

    let tmpl = serde_json::json!({
        "kind": 1, "created_at": now(), "tags": [], "content": "signed by my backpack"
    })
    .to_string();
    let s = rpc(
        &client_sk,
        &client_pk_hex,
        &signer_pub,
        &signer_pk_hex,
        "sign_event",
        serde_json::json!([tmpl]),
    );
    assert!(s.error.is_none(), "sign failed: {:?}", s.error);

    let signed: Event = serde_json::from_str(&s.result).unwrap();
    assert_eq!(signed.pubkey, signer_pk_hex); // signed by the bunker's key
    assert_eq!(signed.content, "signed by my backpack");
    verify_event(&signed).unwrap();

    stop.store(true, Ordering::Relaxed);
    let _ = signer.join();
    assert!(log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.contains("sign_event ok")));
}

/// Multi-relay signer: authorize via one relay, sign via another. Proves the
/// authorization set and request dedup are shared across relay connections.
#[test]
#[ignore = "runs a live multi-relay signer against public relays"]
fn remote_sign_across_relays() {
    const RELAY_A: &str = "wss://relay.damus.io";
    const RELAY_B: &str = "wss://nos.lol";

    let signer_sk = [5u8; 32];
    let signer_pk_hex = pubkey_hex(&signer_sk).unwrap();
    let signer_pub: [u8; 32] = hex::decode(&signer_pk_hex).unwrap().try_into().unwrap();
    let client_sk = [6u8; 32];
    let client_pk_hex = pubkey_hex(&client_sk).unwrap();
    let secret = "multi-secret";

    let stop = Arc::new(AtomicBool::new(false));
    let signer = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let relays = vec![RELAY_A.to_string(), RELAY_B.to_string()];
            let _ = run_signer_multi(&relays, &signer_sk, secret, &stop, |_| {});
        })
    };
    std::thread::sleep(Duration::from_secs(2));

    // connect on relay A…
    let c = rpc_on(
        RELAY_A,
        &client_sk,
        &client_pk_hex,
        &signer_pub,
        &signer_pk_hex,
        "connect",
        serde_json::json!([signer_pk_hex, secret]),
    );
    assert!(c.error.is_none(), "connect failed: {:?}", c.error);

    // …then sign on relay B: authorization must carry over.
    let tmpl = serde_json::json!({
        "kind": 1, "created_at": now(), "tags": [], "content": "multi-relay"
    })
    .to_string();
    let s = rpc_on(
        RELAY_B,
        &client_sk,
        &client_pk_hex,
        &signer_pub,
        &signer_pk_hex,
        "sign_event",
        serde_json::json!([tmpl]),
    );
    assert!(s.error.is_none(), "sign failed: {:?}", s.error);
    let ev: Event = serde_json::from_str(&s.result).unwrap();
    verify_event(&ev).unwrap();
    assert_eq!(ev.pubkey, signer_pk_hex);

    stop.store(true, Ordering::Relaxed);
    signer.join().unwrap();
}
