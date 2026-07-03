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
    connect_with_timeout(url, READ_TIMEOUT)
}

fn connect_with_timeout(url: &str, read_timeout: Duration) -> IoResult<Socket> {
    let (host, port) = host_port(url)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("resolving {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}: no addresses"))?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("connecting to {url}: {e}"))?;
    stream
        .set_read_timeout(Some(read_timeout))
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
        since: None,
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
        since: None,
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

/// Well-known Nostr accounts used to bootstrap suggestions when the caller
/// follows no one yet. Stored as npub (bech32 has a checksum, so a typo fails
/// to decode and is skipped rather than resolving to a wrong key).
pub const BOOTSTRAP_SEEDS: &[&str] = &[
    "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", // fiatjaf
    "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m", // jack
    "npub1xtscya34g58tk0z605fvr788k263gsu6cy9x0mhnm87echrgufzsevkk5s", // jb55
    "npub1qny3tkh0acurzla8x3zy4nhrjz5zd8l9sy9jys09umwng00manysew95gx", // ODELL
    "npub1dergggklka99wwrs92yz8wdjs952h2ux2ha2ed598ngwu9w7a6fsh9xzpc", // gigi
];

/// A suggested account to follow.
pub struct Suggestion {
    pub pubkey: String,
    pub name: Option<String>,
    pub about: Option<String>,
    /// How many of the seed accounts follow this pubkey (popularity signal).
    pub score: u32,
}

/// Suggest accounts to follow from the social graph: tally who the seed
/// accounts follow, drop the caller and their existing follows, rank by count,
/// and enrich the top `limit` with profile names/bios.
///
/// Seeds are the caller's own follows when they have any (follows-of-follows),
/// otherwise [`BOOTSTRAP_SEEDS`]. Uses only the relay stack — no HTTP.
pub fn suggest_follows(
    relays: &[String],
    my_follows: &[String],
    me_hex: &str,
    limit: u32,
) -> IoResult<Vec<Suggestion>> {
    let mut seeds: Vec<String> = if my_follows.is_empty() {
        BOOTSTRAP_SEEDS
            .iter()
            .filter_map(|s| crate::nip19::npub_decode(s).ok().map(hex::encode))
            .collect()
    } else {
        my_follows.to_vec()
    };
    seeds.sort();
    seeds.dedup();
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    let filter = Filter {
        authors: Some(seeds.clone()),
        kinds: Some(vec![crate::contacts::KIND_CONTACTS]),
        p_tags: None,
        since: None,
        limit: Some(seeds.len() as u32),
    };
    let events = fetch_all(relays, &filter)?;

    // Newest kind-3 per seed author.
    let mut newest: std::collections::HashMap<String, Event> = std::collections::HashMap::new();
    for ev in events {
        match newest.get(&ev.pubkey) {
            Some(cur) if cur.created_at >= ev.created_at => {}
            _ => {
                newest.insert(ev.pubkey.clone(), ev);
            }
        }
    }

    let mine: std::collections::HashSet<&str> = my_follows.iter().map(String::as_str).collect();
    let mut score: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for ev in newest.values() {
        for c in crate::contacts::parse_contacts(ev) {
            if c.pubkey == me_hex || mine.contains(c.pubkey.as_str()) {
                continue;
            }
            *score.entry(c.pubkey).or_default() += 1;
        }
    }

    let mut ranked: Vec<(String, u32)> = score.into_iter().collect();
    // Highest score first; stable tiebreak by pubkey for determinism.
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(limit as usize);

    let pubkeys: Vec<String> = ranked.iter().map(|(k, _)| k.clone()).collect();
    let profiles = fetch_profiles(relays, pubkeys).unwrap_or_default();

    Ok(ranked
        .into_iter()
        .map(|(pubkey, score)| {
            let p = profiles.get(&pubkey);
            Suggestion {
                name: p.and_then(|m| crate::profile::field(m, "name")),
                about: p.and_then(|m| crate::profile::field(m, "about")),
                pubkey,
                score,
            }
        })
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
        since: None,
        limit: Some(limit),
    };
    let sent = Filter {
        authors: Some(vec![me.clone()]),
        kinds: Some(vec![crate::nip04::KIND_DM]),
        p_tags: None,
        since: None,
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
        since: None,
        limit: Some(limit),
    };
    let mut events = fetch_all(relays, &filter)?;
    events.truncate(limit as usize);
    Ok(events)
}

// ---------------------------------------------------------------- NIP-46 signer

use std::sync::atomic::{AtomicBool, Ordering};

/// A log line emitted by the running signer.
pub struct SignerLog {
    pub client: String,
    pub method: String,
    pub outcome: String,
}

/// Run a NIP-46 signer loop on one relay until `stop` is set.
///
/// Subscribes for requests addressed to the signer, decrypts each, enforces
/// connect-before-sign (a client must `connect` with the correct secret before
/// any signing/decryption is honored), signs with `signer_sk`, and publishes
/// the encrypted response. `on_log` is called for each handled request.
///
/// Blocking: the caller runs it on a dedicated thread (TUI) or the main thread
/// (CLI). Reads are short so `stop` is observed within ~2s.
pub fn run_signer(
    relay: &str,
    signer_sk: &[u8; 32],
    secret: &str,
    stop: &AtomicBool,
    mut on_log: impl FnMut(SignerLog),
) -> IoResult<()> {
    use crate::nip46::{is_read_only, respond, Request, KIND_RPC};

    let signer_pk = crate::event::pubkey_hex(signer_sk).map_err(|e| e.to_string())?;
    let mut socket = connect_with_timeout(relay, Duration::from_secs(2))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let filter = Filter {
        authors: None,
        kinds: Some(vec![KIND_RPC]),
        p_tags: Some(vec![signer_pk.clone()]),
        since: Some(now),
        limit: None,
    };
    socket
        .send(Message::Text(req_frame("bpsigner", &filter)))
        .map_err(|e| format!("subscribe: {e}"))?;

    let mut authorized: std::collections::HashSet<String> = std::collections::HashSet::new();

    while !stop.load(Ordering::Relaxed) {
        let msg = match socket.read() {
            Ok(m) => m,
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue; // read timed out; re-check stop flag
            }
            Err(e) => return Err(format!("read: {e}")),
        };
        let text = match msg {
            Message::Text(t) => t,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return Err("relay closed the signer subscription".into()),
            _ => continue,
        };
        let RelayMsg::Event(ev) = parse(&text) else {
            continue;
        };
        if ev.kind != KIND_RPC || verify_event(&ev).is_err() {
            continue;
        }

        let client = ev.pubkey.clone();
        let client_key: [u8; 32] =
            match hex::decode(&client).ok().and_then(|v| v.try_into().ok()) {
                Some(k) => k,
                None => continue,
            };
        // Modern clients use NIP-44; older ones NIP-04. Accept either and
        // remember which, so the response uses the same scheme.
        let (plain, use_nip44) =
            match crate::nip44::decrypt(signer_sk, &client_key, &ev.content) {
                Ok(p) => (p, true),
                Err(_) => match crate::nip04::decrypt(signer_sk, &client_key, &ev.content) {
                    Ok(p) => (p, false),
                    Err(_) => {
                        on_log(SignerLog {
                            client: short_pk(&client),
                            method: "(unreadable)".into(),
                            outcome: "decrypt failed".into(),
                        });
                        continue;
                    }
                },
            };
        let Ok(req) = Request::parse(&plain) else {
            continue;
        };

        // Policy: connect (with secret) authorizes a client; read-only methods
        // are always allowed; signing/decryption require prior authorization.
        let response = if req.method == "connect" {
            let r = respond(signer_sk, &req, secret);
            if r.error.is_none() {
                authorized.insert(client.clone());
            }
            r
        } else if is_read_only(&req.method) || authorized.contains(&client) {
            respond(signer_sk, &req, secret)
        } else {
            crate::nip46::Response {
                id: req.id.clone(),
                result: String::new(),
                error: Some("not connected".into()),
            }
        };

        on_log(SignerLog {
            client: short_pk(&client),
            method: req.method.clone(),
            outcome: match &response.error {
                Some(e) => format!("error: {e}"),
                None => "ok".into(),
            },
        });

        // Encrypt and publish the response back to the client, same scheme.
        let sealed = if use_nip44 {
            crate::nip44::encrypt(signer_sk, &client_key, &response.to_json())
        } else {
            crate::nip04::encrypt(signer_sk, &client_key, &response.to_json())
        };
        if let Ok(enc) = sealed {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(now);
            if let Ok(resp_ev) = crate::event::sign_event(
                signer_sk,
                ts,
                KIND_RPC,
                vec![vec!["p".to_string(), client.clone()]],
                enc,
            ) {
                let _ = socket.send(Message::Text(publish_frame(&resp_ev)));
            }
        }
    }
    let _ = socket.close(None);
    Ok(())
}

fn short_pk(hex: &str) -> String {
    format!("{}…", &hex[..12.min(hex.len())])
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
