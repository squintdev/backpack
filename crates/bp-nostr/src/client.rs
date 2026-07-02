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
