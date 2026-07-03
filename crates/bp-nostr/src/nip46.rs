//! NIP-46 remote signing ("Nostr Connect" / bunker).
//!
//! A remote client (a web app like ditto.pub) sends signing **requests** to a
//! signer that holds the private key; the signer approves, signs, and returns
//! only the result. The key never reaches the client.
//!
//! Transport (handled by the client layer) is kind-24133 events whose content
//! is an encrypted JSON request/response between the client's connection key
//! and the signer — NIP-44 for modern clients, NIP-04 for legacy ones. This
//! module is the pure, network-free core: the `bunker://` URL, request/response
//! framing, and [`respond`] — which turns a decrypted request into a response
//! using the signer's key.

use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

use crate::event::sign_event;
use crate::{Error, Result};

/// Event kind for NIP-46 request/response messages.
pub const KIND_RPC: u32 = 24133;

/// A fresh random connection secret for a `bunker://` URL (16 bytes, hex).
pub fn random_secret() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// A decrypted request from a connected client.
#[derive(Debug, Clone)]
pub struct Request {
    pub id: String,
    pub method: String,
    pub params: Vec<Value>,
}

impl Request {
    pub fn parse(json: &str) -> Result<Request> {
        let v: Value = serde_json::from_str(json).map_err(|_| Error::BadFormat("nip46 request"))?;
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .ok_or(Error::BadFormat("nip46 id"))?
            .to_string();
        let method = v
            .get("method")
            .and_then(Value::as_str)
            .ok_or(Error::BadFormat("nip46 method"))?
            .to_string();
        let params = v
            .get("params")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(Request { id, method, params })
    }

    fn param_str(&self, i: usize) -> Option<String> {
        self.params.get(i).map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }
}

/// A response to send back to the client.
#[derive(Debug, Clone)]
pub struct Response {
    pub id: String,
    pub result: String,
    pub error: Option<String>,
}

impl Response {
    fn ok(id: &str, result: impl Into<String>) -> Response {
        Response { id: id.to_string(), result: result.into(), error: None }
    }
    fn err(id: &str, error: impl Into<String>) -> Response {
        Response { id: id.to_string(), result: String::new(), error: Some(error.into()) }
    }
    pub fn to_json(&self) -> String {
        json!({
            "id": self.id,
            "result": self.result,
            "error": self.error.clone().unwrap_or_default(),
        })
        .to_string()
    }
}

/// Build a `bunker://` connection URL for a client to paste into its login box.
pub fn bunker_url(signer_pubkey_hex: &str, relay: &str, secret: &str) -> String {
    format!(
        "bunker://{signer_pubkey_hex}?relay={}&secret={secret}",
        urlencode(relay)
    )
}

fn urlencode(s: &str) -> String {
    // Only the characters that actually occur in a wss relay URL need escaping.
    s.chars()
        .flat_map(|c| match c {
            ':' => "%3A".chars().collect::<Vec<_>>(),
            '/' => "%2F".chars().collect(),
            '?' => "%3F".chars().collect(),
            '&' => "%26".chars().collect(),
            '=' => "%3D".chars().collect(),
            other => vec![other],
        })
        .collect()
}

/// Whether a method only reads (no signature / no key exposure) and can be
/// answered without an approval prompt.
pub fn is_read_only(method: &str) -> bool {
    matches!(method, "connect" | "get_public_key" | "ping" | "get_relays")
}

/// Handle a decrypted request with the signer's key, producing a response.
///
/// `expected_secret` (from the bunker URL) authenticates the initial
/// `connect`. Pure: no network, no I/O.
pub fn respond(signer_sk: &[u8; 32], req: &Request, expected_secret: &str) -> Response {
    match req.method.as_str() {
        "connect" => {
            // Clients place the secret inconsistently: some send
            // [signer_pubkey, secret], others [secret] or add a permissions
            // arg. Accept the connection if the expected secret appears in any
            // param (or if no secret was configured).
            let ok = expected_secret.is_empty()
                || (0..req.params.len())
                    .filter_map(|i| req.param_str(i))
                    .any(|p| p == expected_secret);
            if ok {
                Response::ok(&req.id, "ack")
            } else {
                Response::err(&req.id, "invalid secret")
            }
        }
        "ping" => Response::ok(&req.id, "pong"),
        "get_public_key" => match crate::event::pubkey_hex(signer_sk) {
            Ok(pk) => Response::ok(&req.id, pk),
            Err(_) => Response::err(&req.id, "key error"),
        },
        "get_relays" => Response::ok(&req.id, "{}"),
        "sign_event" => match sign_from_template(signer_sk, req.param_str(0)) {
            Ok(json) => Response::ok(&req.id, json),
            Err(e) => Response::err(&req.id, format!("{e}")),
        },
        "nip04_encrypt" => match (req.param_str(0), req.param_str(1)) {
            (Some(peer), Some(text)) => match encrypt_for(signer_sk, &peer, &text) {
                Ok(ct) => Response::ok(&req.id, ct),
                Err(e) => Response::err(&req.id, format!("{e}")),
            },
            _ => Response::err(&req.id, "nip04_encrypt needs [pubkey, plaintext]"),
        },
        "nip04_decrypt" => match (req.param_str(0), req.param_str(1)) {
            (Some(peer), Some(ct)) => match decrypt_from(signer_sk, &peer, &ct) {
                Ok(pt) => Response::ok(&req.id, pt),
                Err(e) => Response::err(&req.id, format!("{e}")),
            },
            _ => Response::err(&req.id, "nip04_decrypt needs [pubkey, ciphertext]"),
        },
        "nip44_encrypt" => match (req.param_str(0), req.param_str(1)) {
            (Some(peer), Some(text)) => {
                match peer_key(&peer).and_then(|pk| crate::nip44::encrypt(signer_sk, &pk, &text)) {
                    Ok(ct) => Response::ok(&req.id, ct),
                    Err(e) => Response::err(&req.id, format!("{e}")),
                }
            }
            _ => Response::err(&req.id, "nip44_encrypt needs [pubkey, plaintext]"),
        },
        "nip44_decrypt" => match (req.param_str(0), req.param_str(1)) {
            (Some(peer), Some(ct)) => {
                match peer_key(&peer).and_then(|pk| crate::nip44::decrypt(signer_sk, &pk, &ct)) {
                    Ok(pt) => Response::ok(&req.id, pt),
                    Err(e) => Response::err(&req.id, format!("{e}")),
                }
            }
            _ => Response::err(&req.id, "nip44_decrypt needs [pubkey, ciphertext]"),
        },
        other => Response::err(&req.id, format!("unsupported method: {other}")),
    }
}

fn peer_key(peer_hex: &str) -> Result<[u8; 32]> {
    hex::decode(peer_hex.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(Error::BadPubkey)
}

fn encrypt_for(sk: &[u8; 32], peer_hex: &str, text: &str) -> Result<String> {
    crate::nip04::encrypt(sk, &peer_key(peer_hex)?, text)
}

fn decrypt_from(sk: &[u8; 32], peer_hex: &str, ct: &str) -> Result<String> {
    crate::nip04::decrypt(sk, &peer_key(peer_hex)?, ct)
}

/// Sign an event template (from a `sign_event` param) and return the full
/// signed event as JSON. The template's kind, created_at, tags, and content
/// are preserved; pubkey/id/sig are filled in.
fn sign_from_template(sk: &[u8; 32], param: Option<String>) -> Result<String> {
    let raw = param.ok_or(Error::BadFormat("sign_event template"))?;
    let tmpl: Value = serde_json::from_str(&raw).map_err(|_| Error::BadFormat("sign_event json"))?;

    let kind = tmpl
        .get("kind")
        .and_then(Value::as_u64)
        .ok_or(Error::BadFormat("event kind"))? as u32;
    let content = tmpl
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let created_at = tmpl.get("created_at").and_then(Value::as_u64);
    let tags: Vec<Vec<String>> = tmpl
        .get("tags")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_array())
                .map(|t| {
                    t.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default();

    let created_at = created_at.ok_or(Error::BadFormat("event created_at"))?;
    let event = sign_event(sk, created_at, kind, tags, content)?;
    serde_json::to_string(&event).map_err(|_| Error::Serialize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{pubkey_hex, verify_event, Event};

    const SK: [u8; 32] = [9u8; 32];

    #[test]
    fn bunker_url_encodes_relay() {
        let url = bunker_url("deadbeef", "wss://relay.damus.io", "s3cret");
        assert_eq!(url, "bunker://deadbeef?relay=wss%3A%2F%2Frelay.damus.io&secret=s3cret");
    }

    #[test]
    fn parse_and_ping() {
        let req = Request::parse(r#"{"id":"1","method":"ping","params":[]}"#).unwrap();
        let resp = respond(&SK, &req, "");
        assert_eq!(resp.result, "pong");
        assert!(resp.error.is_none());
        assert!(resp.to_json().contains("\"pong\""));
    }

    #[test]
    fn get_public_key_returns_signer_pubkey() {
        let req = Request::parse(r#"{"id":"2","method":"get_public_key","params":[]}"#).unwrap();
        let resp = respond(&SK, &req, "");
        assert_eq!(resp.result, pubkey_hex(&SK).unwrap());
    }

    #[test]
    fn connect_accepts_secret_in_any_position() {
        // [pubkey, secret]
        let a = Request::parse(r#"{"id":"3","method":"connect","params":["x","open"]}"#).unwrap();
        assert!(respond(&SK, &a, "open").error.is_none());
        // [secret] only
        let b = Request::parse(r#"{"id":"3b","method":"connect","params":["open"]}"#).unwrap();
        assert!(respond(&SK, &b, "open").error.is_none());
        // [pubkey, secret, permissions]
        let c = Request::parse(r#"{"id":"3c","method":"connect","params":["x","open","sign_event:1"]}"#).unwrap();
        assert!(respond(&SK, &c, "open").error.is_none());
        // wrong secret anywhere -> rejected
        let bad = Request::parse(r#"{"id":"4","method":"connect","params":["x","wrong"]}"#).unwrap();
        assert!(respond(&SK, &bad, "open").error.is_some());
    }

    #[test]
    fn sign_event_produces_a_valid_event() {
        let tmpl = r#"{"kind":1,"created_at":1700000000,"tags":[["t","backpack"]],"content":"signed remotely"}"#;
        let params = serde_json::to_string(&serde_json::json!([tmpl])).unwrap();
        let req = Request::parse(&format!(
            r#"{{"id":"5","method":"sign_event","params":{params}}}"#
        ))
        .unwrap();
        let resp = respond(&SK, &req, "");
        assert!(resp.error.is_none(), "{:?}", resp.error);
        let ev: Event = serde_json::from_str(&resp.result).unwrap();
        assert_eq!(ev.kind, 1);
        assert_eq!(ev.content, "signed remotely");
        assert_eq!(ev.pubkey, pubkey_hex(&SK).unwrap());
        verify_event(&ev).unwrap();
    }

    #[test]
    fn nip44_encrypt_decrypt_roundtrip() {
        let peer_sk = [21u8; 32];
        let peer_pub = pubkey_hex(&peer_sk).unwrap();
        let enc = Request::parse(&format!(
            r#"{{"id":"e","method":"nip44_encrypt","params":["{peer_pub}","hello dm"]}}"#
        ))
        .unwrap();
        let ct = respond(&SK, &enc, "").result;
        assert!(!ct.is_empty());
        // The peer decrypts what the signer encrypted to them.
        let signer_pub = pubkey_hex(&SK).unwrap();
        let signer_pub_bytes: [u8; 32] = hex::decode(&signer_pub).unwrap().try_into().unwrap();
        let pt = crate::nip44::decrypt(&peer_sk, &signer_pub_bytes, &ct).unwrap();
        assert_eq!(pt, "hello dm");
    }

    #[test]
    fn unsupported_method_errors() {
        let req = Request::parse(r#"{"id":"6","method":"launch_missiles","params":[]}"#).unwrap();
        assert!(respond(&SK, &req, "").error.is_some());
    }

    #[test]
    fn read_only_classification() {
        assert!(is_read_only("get_public_key"));
        assert!(is_read_only("ping"));
        assert!(!is_read_only("sign_event"));
        assert!(!is_read_only("nip04_decrypt"));
    }
}
