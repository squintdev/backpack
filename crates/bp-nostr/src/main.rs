//! `nostr` — publish and read Nostr notes with a backpack keyring identity.
//!
//! ```text
//! nostr whoami --identity alice          # npub + hex pubkey
//! nostr post --identity alice "hello"    # sign + publish a text note
//! nostr fetch --author npub1…            # latest notes by an author
//! ```

use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};
use zeroize::Zeroizing;

use bp_nostr::event::{sign_event, verify_event, Event, KIND_TEXT_NOTE};
use bp_nostr::nip19::{npub_encode, pubkey_to_hex};
use bp_nostr::relay::{close_frame, parse, publish_frame, req_frame, Filter, RelayMsg};

/// Relays used when none are given.
const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
];
/// Keystore passphrase environment variable (shared across the suite).
const PASS_ENV: &str = "BACKPACK_PASSPHRASE";
/// Comma-separated relay list override.
const RELAY_ENV: &str = "BACKPACK_NOSTR_RELAYS";
/// Per-relay socket read timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(
    name = "nostr",
    version,
    about = "Minimal Nostr client (NIP-01) using keyring identities",
    after_help = "EXAMPLES:\n  \
        nostr whoami --identity alice\n  \
        nostr post --identity alice \"hello, uncensorable world\"\n  \
        nostr fetch --author npub1xxxx… --limit 5\n  \
        nostr fetch --author <64-char hex> -r wss://relay.damus.io\n\n\
        RELAYS: -r/--relay (repeatable) > $BACKPACK_NOSTR_RELAYS (comma-\n\
        separated) > built-in defaults. post sends to every relay; fetch\n\
        reads from the first one that answers.\n\n\
        Identities come from the backpack keyring; identities created before\n\
        Nostr support need `keyring nostr-init <name>` once."
)]
struct Cli {
    /// Relay URL (repeatable). Overrides $BACKPACK_NOSTR_RELAYS and defaults.
    #[arg(short, long, global = true)]
    relay: Vec<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show an identity's Nostr public key (npub and hex).
    Whoami {
        #[arg(long)]
        identity: String,
    },
    /// Sign and publish a text note.
    Post {
        #[arg(long)]
        identity: String,
        /// The note text.
        text: String,
    },
    /// Fetch recent text notes by an author (npub or hex pubkey).
    Fetch {
        #[arg(long)]
        author: String,
        /// Maximum number of notes.
        #[arg(long, default_value_t = 10)]
        limit: u32,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("nostr: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let relays = resolve_relays(&cli.relay);
    match &cli.cmd {
        Cmd::Whoami { identity } => whoami(identity),
        Cmd::Post { identity, text } => post(identity, text, &relays),
        Cmd::Fetch { author, limit } => fetch(author, *limit, &relays),
    }
}

fn whoami(identity: &str) -> Result<()> {
    let sk = load_nostr_key(identity)?;
    let pk_hex = bp_nostr::event::pubkey_hex(&sk)?;
    let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();
    println!("{}", npub_encode(&pk));
    println!("{pk_hex}");
    Ok(())
}

fn post(identity: &str, text: &str, relays: &[String]) -> Result<()> {
    if text.trim().is_empty() {
        bail!("refusing to post an empty note");
    }
    let sk = load_nostr_key(identity)?;
    let ev = sign_event(&sk, now(), KIND_TEXT_NOTE, vec![], text.to_string())?;
    println!("event id {}", ev.id);

    let frame = publish_frame(&ev);
    let mut accepted = 0;
    for url in relays {
        match publish_to(url, &frame, &ev.id) {
            Ok(msg) => {
                accepted += 1;
                println!("  {url}: accepted{}", if msg.is_empty() { String::new() } else { format!(" ({msg})") });
            }
            Err(e) => eprintln!("  {url}: {e:#}"),
        }
    }
    if accepted == 0 {
        bail!("no relay accepted the note");
    }
    Ok(())
}

fn fetch(author: &str, limit: u32, relays: &[String]) -> Result<()> {
    let author_hex = pubkey_to_hex(author)?;
    let filter = Filter {
        authors: Some(vec![author_hex]),
        kinds: Some(vec![KIND_TEXT_NOTE]),
        limit: Some(limit),
    };

    let mut last_err = anyhow!("no relays configured");
    for url in relays {
        match fetch_from(url, &filter) {
            Ok(mut events) => {
                events.sort_by_key(|e| std::cmp::Reverse(e.created_at));
                if events.is_empty() {
                    println!("(no notes found on {url})");
                    return Ok(());
                }
                for ev in &events {
                    print_event(ev);
                }
                eprintln!("({} notes from {url}, signatures verified)", events.len());
                return Ok(());
            }
            Err(e) => {
                eprintln!("  {url}: {e:#}");
                last_err = e;
            }
        }
    }
    Err(last_err.context("all relays failed"))
}

// --- relay I/O --------------------------------------------------------------

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

fn connect(url: &str) -> Result<Socket> {
    let (socket, _resp) =
        tungstenite::connect(url).with_context(|| format!("connecting to {url}"))?;
    // Bound reads so a silent relay cannot hang the CLI.
    if let MaybeTlsStream::Rustls(s) = socket.get_ref() {
        s.get_ref().set_read_timeout(Some(READ_TIMEOUT))?;
    } else if let MaybeTlsStream::Plain(s) = socket.get_ref() {
        s.set_read_timeout(Some(READ_TIMEOUT))?;
    }
    Ok(socket)
}

/// Publish one event frame and wait for the matching `OK`.
fn publish_to(url: &str, frame: &str, event_id: &str) -> Result<String> {
    let mut socket = connect(url)?;
    socket.send(Message::Text(frame.to_string()))?;
    loop {
        match socket.read()? {
            Message::Text(text) => match parse(&text) {
                RelayMsg::Ok(id, true, msg) if id == event_id => {
                    let _ = socket.close(None);
                    return Ok(msg);
                }
                RelayMsg::Ok(id, false, msg) if id == event_id => {
                    bail!("rejected: {msg}");
                }
                RelayMsg::Notice(m) => eprintln!("  {url} notice: {m}"),
                _ => {}
            },
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => bail!("relay closed before acknowledging"),
            _ => {}
        }
    }
}

/// Run one subscription to EOSE and return the (verified) events.
fn fetch_from(url: &str, filter: &Filter) -> Result<Vec<Event>> {
    let mut socket = connect(url)?;
    let sub = "backpack";
    socket.send(Message::Text(req_frame(sub, filter)))?;

    let mut events = Vec::new();
    let mut dropped = 0u32;
    loop {
        match socket.read()? {
            Message::Text(text) => match parse(&text) {
                RelayMsg::Event(ev) => {
                    // Never trust relay data: verify id + signature.
                    if verify_event(&ev).is_ok() {
                        events.push(*ev);
                    } else {
                        dropped += 1;
                    }
                }
                RelayMsg::Eose => break,
                RelayMsg::Notice(m) => eprintln!("  {url} notice: {m}"),
                _ => {}
            },
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }
    let _ = socket.send(Message::Text(close_frame(sub)));
    let _ = socket.close(None);
    if dropped > 0 {
        eprintln!("  {url}: dropped {dropped} event(s) with bad signatures");
    }
    Ok(events)
}

// --- helpers -----------------------------------------------------------------

fn resolve_relays(cli_relays: &[String]) -> Vec<String> {
    if !cli_relays.is_empty() {
        return cli_relays.to_vec();
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

/// Load the Nostr secret key for a keyring identity.
fn load_nostr_key(identity: &str) -> Result<Zeroizing<[u8; 32]>> {
    let path = keyring::default_keystore_path()
        .ok_or_else(|| anyhow!("cannot locate keystore; set {}", keyring::PATH_ENV))?;
    let pass = match std::env::var(PASS_ENV) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => Zeroizing::new(
            rpassword::prompt_password("Keystore passphrase: ").context("reading passphrase")?,
        ),
    };
    let store = keyring::KeyStore::open(&path, pass.as_bytes())?;
    let kp = store
        .get(identity)
        .ok_or_else(|| anyhow!("no identity named {identity:?} in keystore"))?;
    kp.nostr_secret().ok_or_else(|| {
        anyhow!("identity {identity:?} predates Nostr support; run `keyring nostr-init {identity}`")
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs()
}

fn print_event(ev: &Event) {
    let when = ev.created_at;
    let short = &ev.pubkey[..12.min(ev.pubkey.len())];
    println!("── {short}… @ {when}");
    for line in ev.content.lines() {
        println!("   {line}");
    }
}
