//! `nostr` CLI — thin wrapper over the bp-nostr library.
//!
//! ```text
//! nostr whoami --identity alice          # npub + hex pubkey
//! nostr post --identity alice "hello"    # sign + publish a text note
//! nostr fetch --author npub1…            # latest notes by an author
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use bp_nostr::client::{fetch, publish, resolve_relays};
use bp_nostr::event::{pubkey_hex, sign_event, Event, KIND_TEXT_NOTE};
use bp_nostr::nip19::{npub_encode, pubkey_to_hex};
use bp_nostr::relay::Filter;

/// Keystore passphrase environment variable (shared across the suite).
const PASS_ENV: &str = "BACKPACK_PASSPHRASE";

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
        Cmd::Fetch { author, limit } => run_fetch(author, *limit, &relays),
    }
}

fn whoami(identity: &str) -> Result<()> {
    let sk = load_nostr_key(identity)?;
    let pk_hex = pubkey_hex(&sk)?;
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

    let results = publish(relays, &ev);
    let mut accepted = 0;
    for (url, result) in &results {
        match result {
            Ok(msg) => {
                accepted += 1;
                println!(
                    "  {url}: accepted{}",
                    if msg.is_empty() { String::new() } else { format!(" ({msg})") }
                );
            }
            Err(e) => eprintln!("  {url}: {e}"),
        }
    }
    if accepted == 0 {
        bail!("no relay accepted the note");
    }
    Ok(())
}

fn run_fetch(author: &str, limit: u32, relays: &[String]) -> Result<()> {
    let filter = Filter {
        authors: Some(vec![pubkey_to_hex(author)?]),
        kinds: Some(vec![KIND_TEXT_NOTE]),
        limit: Some(limit),
    };
    let (url, events, dropped) = fetch(relays, &filter).map_err(|e| anyhow!(e))?;
    if dropped > 0 {
        eprintln!("  {url}: dropped {dropped} event(s) with bad signatures");
    }
    if events.is_empty() {
        println!("(no notes found on {url})");
        return Ok(());
    }
    for ev in &events {
        print_event(ev);
    }
    eprintln!("({} notes from {url}, signatures verified)", events.len());
    Ok(())
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
    let short = &ev.pubkey[..12.min(ev.pubkey.len())];
    println!("── {short}… @ {}", ev.created_at);
    for line in ev.content.lines() {
        println!("   {line}");
    }
}
