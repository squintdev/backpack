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

use bp_nostr::client::{fetch, fetch_dms, fetch_profiles, fetch_timeline, latest_profile, publish, resolve_relays, send_dm, set_profile};
use bp_nostr::profile::{field, KNOWN_FIELDS};
use bp_nostr::contacts::Contact;
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
    /// Follow an author (updates your kind-3 contact list on the relays).
    Follow {
        #[arg(long)]
        identity: String,
        /// Who to follow (npub or hex).
        author: String,
        /// Optional petname shown in your timeline.
        #[arg(long)]
        name: Option<String>,
    },
    /// Unfollow an author.
    Unfollow {
        #[arg(long)]
        identity: String,
        author: String,
    },
    /// List who you follow.
    Follows {
        #[arg(long)]
        identity: String,
    },
    /// Recent notes from everyone you follow, merged across relays.
    Timeline {
        #[arg(long)]
        identity: String,
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
    /// Show a profile: yours (--identity) or anyone's (--author).
    Profile {
        #[arg(long, conflicts_with = "author")]
        identity: Option<String>,
        #[arg(long)]
        author: Option<String>,
    },
    /// Send an encrypted direct message (NIP-04).
    Dm {
        #[arg(long)]
        identity: String,
        /// Recipient (npub or hex).
        to: String,
        /// Message text.
        text: String,
    },
    /// Read your encrypted direct messages (both directions).
    Dms {
        #[arg(long)]
        identity: String,
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
    /// Update your profile (kind-0). Only the flags you pass change; fields
    /// set by other clients are preserved. Pass an empty string to clear.
    SetProfile {
        #[arg(long)]
        identity: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        about: Option<String>,
        #[arg(long)]
        picture: Option<String>,
        #[arg(long)]
        nip05: Option<String>,
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
        Cmd::Follow { identity, author, name } => {
            run_follow(identity, author, name.clone(), &relays)
        }
        Cmd::Unfollow { identity, author } => run_unfollow(identity, author, &relays),
        Cmd::Follows { identity } => run_follows(identity, &relays),
        Cmd::Timeline { identity, limit } => run_timeline(identity, *limit, &relays),
        Cmd::Profile { identity, author } => run_profile(identity.as_deref(), author.as_deref(), &relays),
        Cmd::Dm { identity, to, text } => run_dm(identity, to, text, &relays),
        Cmd::Dms { identity, limit } => run_dms(identity, *limit, &relays),
        Cmd::SetProfile { identity, name, about, picture, nip05 } => run_set_profile(
            identity,
            &[("name", name), ("about", about), ("picture", picture), ("nip05", nip05)],
            &relays,
        ),
    }
}

fn run_dm(identity: &str, to: &str, text: &str, relays: &[String]) -> Result<()> {
    if text.trim().is_empty() {
        bail!("refusing to send an empty message");
    }
    let sk = load_nostr_key(identity)?;
    let recipient = pubkey_to_hex(to)?;
    let results = send_dm(relays, &sk, &recipient, text).map_err(|e| anyhow!(e))?;
    for (url, r) in results {
        match r {
            Ok(_) => println!("  {url}: accepted"),
            Err(e) => eprintln!("  {url}: {e}"),
        }
    }
    println!("note: NIP-04 hides the text but not who/when — metadata is public");
    Ok(())
}

fn run_dms(identity: &str, limit: u32, relays: &[String]) -> Result<()> {
    let sk = load_nostr_key(identity)?;
    let dms = fetch_dms(relays, &sk, limit).map_err(|e| anyhow!(e))?;
    if dms.is_empty() {
        println!("(no direct messages found)");
        return Ok(());
    }
    // Label partners by their profile names where available.
    let partners: Vec<String> = dms.iter().map(|d| d.partner.clone()).collect();
    let profiles = fetch_profiles(relays, partners).unwrap_or_default();
    for dm in &dms {
        let who = profiles
            .get(&dm.partner)
            .and_then(|m| field(m, "name"))
            .unwrap_or_else(|| format!("{}…", &dm.partner[..12.min(dm.partner.len())]));
        let arrow = if dm.outgoing { "→ to  " } else { "← from" };
        println!("{arrow} {who} @ {}", dm.created_at);
        for line in dm.text.lines() {
            println!("   {line}");
        }
    }
    eprintln!("({} messages, decrypted locally)", dms.len());
    Ok(())
}

fn run_profile(identity: Option<&str>, author: Option<&str>, relays: &[String]) -> Result<()> {
    let hex = match (identity, author) {
        (_, Some(a)) => pubkey_to_hex(a)?,
        (Some(id), None) => {
            let sk = load_nostr_key(id)?;
            pubkey_hex(&sk)?
        }
        (None, None) => bail!("pass --identity (your profile) or --author (someone else's)"),
    };
    let map = latest_profile(relays, &hex).map_err(|e| anyhow!(e))?;
    let pk: [u8; 32] = hex::decode(&hex).unwrap().try_into().unwrap();
    println!("{}", npub_encode(&pk));
    if map.is_empty() {
        println!("(no profile published)");
        return Ok(());
    }
    for key in KNOWN_FIELDS {
        if let Some(v) = field(&map, key) {
            println!("{key:<8} {v}");
        }
    }
    let extra: Vec<&String> = map
        .keys()
        .filter(|k| !KNOWN_FIELDS.contains(&k.as_str()))
        .collect();
    if !extra.is_empty() {
        println!("(other fields preserved: {})", extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
    }
    Ok(())
}

fn run_set_profile(
    identity: &str,
    flags: &[(&str, &Option<String>)],
    relays: &[String],
) -> Result<()> {
    let updates: Vec<(&str, String)> = flags
        .iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| (*k, v.clone())))
        .collect();
    if updates.is_empty() {
        bail!("nothing to change — pass --name/--about/--picture/--nip05");
    }
    let sk = load_nostr_key(identity)?;
    set_profile(relays, &sk, &updates).map_err(|e| anyhow!(e))?;
    println!("profile updated ({} field(s))", updates.len());
    Ok(())
}

fn run_follow(
    identity: &str,
    author: &str,
    name: Option<String>,
    relays: &[String],
) -> Result<()> {
    let sk = load_nostr_key(identity)?;
    let target = pubkey_to_hex(author)?;
    let count = bp_nostr::client::follow(relays, &sk, &target, name).map_err(|e| anyhow!(e))?;
    println!("following {count} author(s)");
    Ok(())
}

fn run_unfollow(identity: &str, author: &str, relays: &[String]) -> Result<()> {
    let sk = load_nostr_key(identity)?;
    let target = pubkey_to_hex(author)?;
    let (count, removed) =
        bp_nostr::client::unfollow(relays, &sk, &target).map_err(|e| anyhow!(e))?;
    if removed {
        println!("unfollowed; following {count} author(s)");
    } else {
        println!("you weren't following that key");
    }
    Ok(())
}

fn run_follows(identity: &str, relays: &[String]) -> Result<()> {
    let sk = load_nostr_key(identity)?;
    let me = pubkey_hex(&sk)?;
    let contacts = bp_nostr::client::follows(relays, &me).map_err(|e| anyhow!(e))?;
    if contacts.is_empty() {
        println!("(not following anyone yet — nostr follow --identity {identity} <npub>)");
        return Ok(());
    }
    for c in &contacts {
        let pk: [u8; 32] = hex::decode(&c.pubkey).unwrap().try_into().unwrap();
        match &c.petname {
            Some(name) => println!("{:<20} {}", name, npub_encode(&pk)),
            None => println!("{:<20} {}", "-", npub_encode(&pk)),
        }
    }
    eprintln!("({} follows)", contacts.len());
    Ok(())
}

fn run_timeline(identity: &str, limit: u32, relays: &[String]) -> Result<()> {
    let sk = load_nostr_key(identity)?;
    let me = pubkey_hex(&sk)?;
    let contacts = bp_nostr::client::follows(relays, &me).map_err(|e| anyhow!(e))?;
    if contacts.is_empty() {
        println!("(not following anyone yet — nostr follow --identity {identity} <npub>)");
        return Ok(());
    }
    let authors: Vec<String> = contacts.iter().map(|c| c.pubkey.clone()).collect();
    let events = fetch_timeline(relays, authors.clone(), limit).map_err(|e| anyhow!(e))?;
    let profiles = fetch_profiles(relays, authors).unwrap_or_default();
    for ev in &events {
        let who = label_for(&contacts, &profiles, &ev.pubkey);
        println!("── {who} @ {}", ev.created_at);
        for line in ev.content.lines() {
            println!("   {line}");
        }
    }
    eprintln!("({} notes, {} follows, signatures verified)", events.len(), contacts.len());
    Ok(())
}

fn label_for(
    contacts: &[Contact],
    profiles: &std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>,
    pubkey: &str,
) -> String {
    contacts
        .iter()
        .find(|c| c.pubkey == pubkey)
        .and_then(|c| c.petname.clone())
        .or_else(|| profiles.get(pubkey).and_then(|m| field(m, "name")))
        .unwrap_or_else(|| format!("{}…", &pubkey[..12.min(pubkey.len())]))
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
        p_tags: None,
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
