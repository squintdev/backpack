//! Synchronous relay client: publish an event, or run a subscription to EOSE.
//!
//! Shared by the `nostr` CLI and the `backpack` launcher. Reads are bounded by
//! a socket timeout so a silent relay cannot hang the caller.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::event::{verify_event, Event};
use crate::relay::{close_frame, parse, publish_frame, req_frame, Filter, RelayMsg};

/// Per-relay socket read timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// TCP connect timeout. Without one, a relay that drops packets (instead of
/// refusing) stalls at the OS default — minutes — before the next relay runs.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Relays used when the caller supplies none.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
];

/// Comma-separated relay list override environment variable.
pub const RELAY_ENV: &str = "BACKPACK_NOSTR_RELAYS";

/// Resolve the relay list: explicit list > `$BACKPACK_NOSTR_RELAYS` > defaults.
pub fn resolve_relays(explicit: &[String]) -> Vec<String> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    if let Ok(env) = std::env::var(RELAY_ENV) {
        let list: Vec<String> = env
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;
type IoResult<T> = std::result::Result<T, String>;

/// Host and port of a `ws://` / `wss://` relay URL.
fn host_port(url: &str) -> IoResult<(String, u16)> {
    let rest = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .ok_or_else(|| format!("{url}: expected a ws:// or wss:// URL"))?;
    let default_port = if url.starts_with("wss://") { 443 } else { 80 };
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            let port = port.parse().map_err(|_| format!("{url}: bad port"))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

/// Connect with a bounded TCP connect and bounded reads, so one dead or
/// blackholed relay can never stall the caller for minutes.
fn connect(url: &str) -> IoResult<Socket> {
    let (host, port) = host_port(url)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("resolving {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}: no addresses"))?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("connecting to {url}: {e}"))?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(READ_TIMEOUT)))
        .map_err(|e| format!("setting timeouts: {e}"))?;
    let (socket, _resp) =
        tungstenite::client_tls(url, stream).map_err(|e| format!("handshake with {url}: {e}"))?;
    Ok(socket)
}

/// Publish one event to one relay and wait for the matching `OK`.
/// Returns the relay's message on acceptance.
pub fn publish_to(url: &str, ev: &Event) -> IoResult<String> {
    let mut socket = connect(url)?;
    socket
        .send(Message::Text(publish_frame(ev)))
        .map_err(|e| format!("send: {e}"))?;
    loop {
        match socket.read().map_err(|e| format!("read: {e}"))? {
            Message::Text(text) => match parse(&text) {
                RelayMsg::Ok(id, true, msg) if id == ev.id => {
                    let _ = socket.close(None);
                    return Ok(msg);
                }
                RelayMsg::Ok(id, false, msg) if id == ev.id => {
                    return Err(format!("rejected: {msg}"));
                }
                _ => {}
            },
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => return Err("relay closed before acknowledging".to_string()),
            _ => {}
        }
    }
}

/// Publish to every relay in the list, in parallel — total wall time is the
/// slowest relay, not the sum. Returns per-relay results in input order:
/// `(url, Ok(relay message) | Err(reason))`.
pub fn publish(relays: &[String], ev: &Event) -> Vec<(String, IoResult<String>)> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = relays
            .iter()
            .map(|url| {
                let ev = ev.clone();
                (url.clone(), scope.spawn(move || publish_to(url, &ev)))
            })
            .collect();
        handles
            .into_iter()
            .map(|(url, h)| {
                let result = h
                    .join()
                    .unwrap_or_else(|_| Err("publish thread panicked".to_string()));
                (url, result)
            })
            .collect()
    })
}

/// Run one subscription against one relay to EOSE. Every received event is
/// re-hashed and signature-verified; failures are dropped and counted.
/// Returns `(verified events, dropped count)`.
pub fn fetch_from(url: &str, filter: &Filter) -> IoResult<(Vec<Event>, u32)> {
    let mut socket = connect(url)?;
    let sub = "backpack";
    socket
        .send(Message::Text(req_frame(sub, filter)))
        .map_err(|e| format!("send: {e}"))?;

    let mut events = Vec::new();
    let mut dropped = 0u32;
    loop {
        match socket.read().map_err(|e| format!("read: {e}"))? {
            Message::Text(text) => match parse(&text) {
                RelayMsg::Event(ev) => {
                    if verify_event(&ev).is_ok() {
                        events.push(*ev);
                    } else {
                        dropped += 1;
                    }
                }
                RelayMsg::Eose => break,
                _ => {}
            },
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }
    let _ = socket.send(Message::Text(close_frame(sub)));
    let _ = socket.close(None);
    events.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    Ok((events, dropped))
}

/// Try relays in order; return the first successful fetch as
/// `(relay url, verified events, dropped count)`.
pub fn fetch(relays: &[String], filter: &Filter) -> IoResult<(String, Vec<Event>, u32)> {
    let mut last = "no relays configured".to_string();
    for url in relays {
        match fetch_from(url, filter) {
            Ok((events, dropped)) => return Ok((url.clone(), events, dropped)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Query **all** relays in parallel and merge the results, deduplicated by
/// event id and sorted newest-first. Succeeds if any relay answered; errors
/// only when every relay failed.
pub fn fetch_all(relays: &[String], filter: &Filter) -> IoResult<Vec<Event>> {
    let results: Vec<IoResult<(Vec<Event>, u32)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = relays
            .iter()
            .map(|url| scope.spawn(move || fetch_from(url, filter)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| Err("fetch thread panicked".into())))
            .collect()
    });

    let mut ok = false;
    let mut last_err = "no relays configured".to_string();
    let mut seen = std::collections::HashSet::new();
    let mut events = Vec::new();
    for r in results {
        match r {
            Ok((evs, _dropped)) => {
                ok = true;
                for ev in evs {
                    if seen.insert(ev.id.clone()) {
                        events.push(ev);
                    }
                }
            }
            Err(e) => last_err = e,
        }
    }
    if !ok {
        return Err(last_err);
    }
    events.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    Ok(events)
}

/// The newest replaceable event of `kind` for `author_hex` across all relays.
///
/// Replaceable events (contact lists, profiles) may differ per relay, so every
/// relay is asked and the freshest `created_at` wins.
pub fn latest_replaceable(
    relays: &[String],
    author_hex: &str,
    kind: u32,
) -> IoResult<Option<Event>> {
    let filter = Filter {
        authors: Some(vec![author_hex.to_string()]),
        kinds: Some(vec![kind]),
        p_tags: None,
        limit: Some(1),
    };
    let events = fetch_all(relays, &filter)?;
    Ok(events.into_iter().max_by_key(|e| e.created_at))
}

/// The newest kind-3 contact list for `author_hex` across all relays, if any.
pub fn latest_contacts(relays: &[String], author_hex: &str) -> IoResult<Option<Event>> {
    latest_replaceable(relays, author_hex, crate::contacts::KIND_CONTACTS)
}

/// The newest kind-0 profile for `author_hex`, parsed to its JSON map.
pub fn latest_profile(
    relays: &[String],
    author_hex: &str,
) -> IoResult<serde_json::Map<String, serde_json::Value>> {
    Ok(latest_replaceable(relays, author_hex, crate::profile::KIND_METADATA)?
        .map(|ev| crate::profile::parse_profile(&ev))
        .unwrap_or_default())
}

/// Update the caller's profile: fetch the newest kind-0, merge `updates` into
/// its raw JSON (unknown fields from other clients are preserved; empty values
/// remove a key), sign, and publish. Succeeds if any relay accepts.
pub fn set_profile(
    relays: &[String],
    sk: &[u8; 32],
    updates: &[(&str, String)],
) -> IoResult<()> {
    let me = crate::event::pubkey_hex(sk).map_err(|e| e.to_string())?;
    let current = latest_profile(relays, &me)?;
    let content = crate::profile::merged_content(current, updates);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let ev = crate::event::sign_event(sk, now, crate::profile::KIND_METADATA, vec![], content)
        .map_err(|e| e.to_string())?;
    let results = publish(relays, &ev);
    if results.iter().any(|(_, r)| r.is_ok()) {
        Ok(())
    } else {
        Err("no relay accepted the profile".to_string())
    }
}

/// The newest kind-0 for each of `authors`, merged across relays. Returns a
/// map from pubkey hex to the profile's JSON map. Missing profiles are absent.
pub fn fetch_profiles(
    relays: &[String],
    authors: Vec<String>,
) -> IoResult<std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>> {
    let limit = authors.len() as u32;
    let filter = Filter {
        authors: Some(authors),
        kinds: Some(vec![crate::profile::KIND_METADATA]),
        p_tags: None,
        limit: Some(limit),
    };
    let events = fetch_all(relays, &filter)?;
    let mut newest: std::collections::HashMap<String, Event> = std::collections::HashMap::new();
    for ev in events {
        match newest.get(&ev.pubkey) {
            Some(cur) if cur.created_at >= ev.created_at => {}
            _ => {
                newest.insert(ev.pubkey.clone(), ev);
            }
        }
    }
    Ok(newest
        .into_iter()
        .map(|(pk, ev)| (pk, crate::profile::parse_profile(&ev)))
        .collect())
}

/// Current follows for the holder of `sk` (their newest kind-3 across relays).
pub fn follows(relays: &[String], author_hex: &str) -> IoResult<Vec<crate::contacts::Contact>> {
    Ok(latest_contacts(relays, author_hex)?
        .map(|ev| crate::contacts::parse_contacts(&ev))
        .unwrap_or_default())
}

/// Follow `target_hex` (optionally with a petname): fetch the newest contact
/// list, merge, sign a replacement kind-3, and publish it to every relay.
/// Returns the new follow count. Succeeds if any relay accepts.
pub fn follow(
    relays: &[String],
    sk: &[u8; 32],
    target_hex: &str,
    petname: Option<String>,
) -> IoResult<usize> {
    let me = crate::event::pubkey_hex(sk).map_err(|e| e.to_string())?;
    let current = follows(relays, &me)?;
    let updated = crate::contacts::with_contact(current, target_hex, petname);
    publish_contacts(relays, sk, &updated)?;
    Ok(updated.len())
}

/// Unfollow `target_hex`. Returns `(new count, was following)`; publishes only
/// if something actually changed.
pub fn unfollow(relays: &[String], sk: &[u8; 32], target_hex: &str) -> IoResult<(usize, bool)> {
    let me = crate::event::pubkey_hex(sk).map_err(|e| e.to_string())?;
    let current = follows(relays, &me)?;
    let (updated, removed) = crate::contacts::without_contact(current, target_hex);
    if removed {
        publish_contacts(relays, sk, &updated)?;
    }
    Ok((updated.len(), removed))
}

/// Sign and publish a full replacement contact list.
fn publish_contacts(
    relays: &[String],
    sk: &[u8; 32],
    contacts: &[crate::contacts::Contact],
) -> IoResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let ev = crate::event::sign_event(
        sk,
        now,
        crate::contacts::KIND_CONTACTS,
        crate::contacts::contact_tags(contacts),
        String::new(),
    )
    .map_err(|e| e.to_string())?;
    let results = publish(relays, &ev);
    if results.iter().any(|(_, r)| r.is_ok()) {
        Ok(())
    } else {
        let last = results
            .into_iter()
            .map(|(url, r)| format!("{url}: {}", r.unwrap_err()))
            .next_back()
            .unwrap_or_else(|| "no relays configured".to_string());
        Err(format!("no relay accepted the contact list ({last})"))
    }
}

/// A decrypted direct-message view: the conversation partner and direction.
pub struct Dm {
    /// The other party's pubkey hex.
    pub partner: String,
    /// True if we sent it.
    pub outgoing: bool,
    pub created_at: u64,
    /// Decrypted text, or an explanatory placeholder if decryption failed.
    pub text: String,
}

/// Fetch and decrypt kind-4 DMs involving the caller, both directions,
/// merged across relays, newest first.
pub fn fetch_dms(relays: &[String], sk: &[u8; 32], limit: u32) -> IoResult<Vec<Dm>> {
    let me = crate::event::pubkey_hex(sk).map_err(|e| e.to_string())?;

    let received = Filter {
        authors: None,
        kinds: Some(vec![crate::nip04::KIND_DM]),
        p_tags: Some(vec![me.clone()]),
        limit: Some(limit),
    };
    let sent = Filter {
        authors: Some(vec![me.clone()]),
        kinds: Some(vec![crate::nip04::KIND_DM]),
        p_tags: None,
        limit: Some(limit),
    };

    let mut events = fetch_all(relays, &received)?;
    if let Ok(out) = fetch_all(relays, &sent) {
        let mut seen: std::collections::HashSet<String> =
            events.iter().map(|e| e.id.clone()).collect();
        for ev in out {
            if seen.insert(ev.id.clone()) {
                events.push(ev);
            }
        }
    }
    events.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    events.truncate(limit as usize);

    let mut dms = Vec::new();
    for ev in events {
        let outgoing = ev.pubkey == me;
        let partner_hex = if outgoing {
            // Recipient is the first p tag.
            match ev.tags.iter().find(|t| t.len() >= 2 && t[0] == "p") {
                Some(t) => t[1].to_ascii_lowercase(),
                None => continue,
            }
        } else {
            ev.pubkey.clone()
        };
        let Ok(partner_key): Result<[u8; 32], _> =
            hex::decode(&partner_hex).map(|v| v.try_into().unwrap_or([0u8; 32]))
        else {
            continue;
        };
        let text = crate::nip04::decrypt(sk, &partner_key, &ev.content)
            .unwrap_or_else(|_| "(could not decrypt)".to_string());
        dms.push(Dm { partner: partner_hex, outgoing, created_at: ev.created_at, text });
    }
    Ok(dms)
}

/// Encrypt, sign, and publish a NIP-04 DM to `recipient_hex`. Succeeds if any
/// relay accepts; returns the per-relay results.
pub fn send_dm(
    relays: &[String],
    sk: &[u8; 32],
    recipient_hex: &str,
    text: &str,
) -> IoResult<Vec<(String, IoResult<String>)>> {
    let recipient: [u8; 32] = hex::decode(recipient_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "bad recipient pubkey".to_string())?;
    let content = crate::nip04::encrypt(sk, &recipient, text).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let ev = crate::event::sign_event(
        sk,
        now,
        crate::nip04::KIND_DM,
        vec![vec!["p".to_string(), recipient_hex.to_string()]],
        content,
    )
    .map_err(|e| e.to_string())?;
    let results = publish(relays, &ev);
    if results.iter().any(|(_, r)| r.is_ok()) {
        Ok(results)
    } else {
        Err("no relay accepted the message".to_string())
    }
}

/// Recent text notes from a set of authors, merged across all relays.
pub fn fetch_timeline(
    relays: &[String],
    authors: Vec<String>,
    limit: u32,
) -> IoResult<Vec<Event>> {
    let filter = Filter {
        authors: Some(authors),
        kinds: Some(vec![crate::event::KIND_TEXT_NOTE]),
        p_tags: None,
        limit: Some(limit),
    };
    let mut events = fetch_all(relays, &filter)?;
    events.truncate(limit as usize);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_parses_relay_urls() {
        assert_eq!(host_port("wss://relay.damus.io").unwrap(), ("relay.damus.io".into(), 443));
        assert_eq!(host_port("wss://relay.damus.io/").unwrap(), ("relay.damus.io".into(), 443));
        assert_eq!(host_port("ws://localhost:7000").unwrap(), ("localhost".into(), 7000));
        assert_eq!(host_port("wss://r.example:8443/sub/path").unwrap(), ("r.example".into(), 8443));
        assert!(host_port("https://not-a-relay").is_err());
    }
}
