//! Synchronous relay client: publish an event, or run a subscription to EOSE.
//!
//! Shared by the `nostr` CLI and the `backpack` launcher. Reads are bounded by
//! a socket timeout so a silent relay cannot hang the caller.

use std::net::TcpStream;
use std::time::Duration;

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::event::{verify_event, Event};
use crate::relay::{close_frame, parse, publish_frame, req_frame, Filter, RelayMsg};

/// Per-relay socket read timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

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

fn connect(url: &str) -> IoResult<Socket> {
    let (socket, _resp) =
        tungstenite::connect(url).map_err(|e| format!("connecting to {url}: {e}"))?;
    let timeout = match socket.get_ref() {
        MaybeTlsStream::Rustls(s) => s.get_ref().set_read_timeout(Some(READ_TIMEOUT)),
        MaybeTlsStream::Plain(s) => s.set_read_timeout(Some(READ_TIMEOUT)),
        _ => Ok(()),
    };
    timeout.map_err(|e| format!("setting timeout: {e}"))?;
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

/// Publish to every relay in the list. Returns per-relay results
/// `(url, Ok(relay message) | Err(reason))`.
pub fn publish(relays: &[String], ev: &Event) -> Vec<(String, IoResult<String>)> {
    relays
        .iter()
        .map(|url| (url.clone(), publish_to(url, ev)))
        .collect()
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
